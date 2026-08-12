// mcp.go implements the "mcp" subcommand: an MCP (Model Context Protocol) proxy over stdio. The
// agent's harness launches this process in place of a real MCP server; runMCPCmd launches the
// real upstream server this wraps as a child process, and JSON-RPC frames flow agent -> proxy ->
// upstream and back, in both directions, for as long as either side has something to send. See
// main.go's package doc for why stdio rather than HTTP is what makes this mode's trust model hold
// at all: the harness starts this process, not the agent, so a session file a later change reads
// from here is not something the agent supplied.
//
// THIS FILE DOES NOT CALL THE PDP. It classifies nothing and decides nothing -- every method,
// including tools/call, is relayed unconditionally, exactly like every other method this proxy
// does not recognise. That is deliberate, not a placeholder: gating tools/call needs a delegation
// reference, a PDP client, and an escalation wait, none of which belong in a file whose job is
// proving the relay itself is correct first. interceptAgentFrame below is the one function a
// later change edits to add that gate -- everything upstream of it (framing, malformed-frame
// handling, shutdown) does not change shape when it does.
//
// RELAY FAITHFULLY, ENFORCE NARROWLY. A proxy that drops a method it has never heard of breaks
// the server it wraps for no security benefit; a proxy that inspects a method's params to decide
// anything has started doing the PDP's job locally -- the same defect (D1; see hook.go's package
// doc) that made every enforcement path in this project's predecessor bypassable. This file never
// unmarshals id, params, result, or error into any Go type it then re-encodes: every frame that
// parses as a JSON object is relayed as the exact bytes it arrived as. That is not a performance
// shortcut, it is what makes an id round-trip exact rather than merely usually correct --
// unmarshaling a JSON number into an interface{} yields a float64 that does not re-encode
// byte-for-byte for every input (large integers lose precision; formatting can change), and no
// amount of care in a hand-written re-encoder closes that gap for every input; only not
// re-encoding does. frameMethod's own doc comment says the same thing from the parsing side.
//
// LIBRARY VS STDLIB. This proxy is built on encoding/json, bufio, and os/exec alone, not an MCP
// client/server library. The two Go options investigated -- github.com/mark3labs/mcp-go
// (v1.0.0-beta.1 as of this writing: no stable release) and the official
// github.com/modelcontextprotocol/go-sdk (v1.7.0: stable, but its public API centers on a
// Client/Server pair built around registering typed handlers per method, e.g. AddTool; reaching a
// generic JSON-RPC frame without going through that dispatch is not part of its documented,
// supported surface) -- are both built to help a program TERMINATE the protocol as a client or a
// server that knows its own methods. A proxy is neither: it must relay methods no library shipped
// today can know about, and the one property that matters most here (id fidelity) is easiest to
// get right by never constructing the typed message a library would hand back in the first place.
// Full investigation notes are in this task's report, not repeated here.
//
// CONCURRENCY. MCP permits multiple in-flight requests, and an authorization call a later change
// adds will take real time (a PDP round trip, occasionally an escalation wait). Nothing in this
// file serializes the stream behind one pending frame: agent->upstream and upstream->agent are two
// independent goroutines (runMCP), and within a direction, relayDirection forwards each frame as
// it arrives rather than waiting for anything about a previous one to resolve. A slow write on one
// direction cannot block a read on the other. This is a property to preserve, not just a current
// fact -- see the note in interceptAgentFrame's doc comment for what that implies there.
//
// FAIL CLOSED ON TRANSPORT FAULTS. A malformed frame (not valid JSON, or valid JSON that is not a
// JSON object) is dropped, not forwarded -- see frameMethod. The child exiting, or its output
// otherwise erroring, stops BOTH directions promptly: runMCP's shared context is cancelled so a
// still-blocked agent->upstream read does not wait forever on a peer that is already gone. The
// agent's stdin closing stops only the agent->upstream direction (and tells the child to shut
// down, by closing its stdin in turn); upstream->agent keeps relaying until the upstream itself
// ends, so a reply already in flight when the agent hangs up is still delivered rather than
// dropped. See runMCP's own doc comment for why that asymmetry is deliberate, not an oversight.
//
// NEVER LOG FRAME CONTENTS. stderr in this file carries only this proxy's own fault diagnostics
// ("dropped a malformed frame") -- never a frame's bytes, which may carry tool arguments, and
// never anything from a session file a later change reads. The upstream server's OWN stderr is
// passed through untouched (cmd.Stderr = stderr in runMCPCmd) because that is the upstream's
// diagnostic output, not this proxy's to interpret or copy from -- the same rule hook.go's package
// doc states for raw_input, applied here to a different channel.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// maxFrameBytes bounds how large a single JSON-RPC line this proxy will read in either direction.
// Some limit must exist -- an unbounded read buffer is a memory-exhaustion vector from a hostile
// or simply buggy peer, one line at a time -- and this one is set well above any legitimate MCP
// payload actually seen (tool listings, file contents, search results) so it only ever trips on
// exactly the failure mode it exists to bound.
const maxFrameBytes = 32 * 1024 * 1024 // 32 MiB

// mcpConfig is what runMCPCmd needs to launch the upstream MCP server this mode wraps: the
// command and its arguments. This is deliberately a small subset of what the "mcp" mode will
// eventually read from the environment -- the PDP address, agent identity, subject, session file
// path, and escalation timing that hookConfig and sessionStartConfig already load (config.go)
// belong to authorizing a tools/call, which this skeleton does not yet do. Adding them here now
// would be configuration this file cannot use, for a shape a later change owns; that change is
// deferred, not forgotten.
type mcpConfig struct {
	UpstreamCommand string
	UpstreamArgs    []string
}

// loadMCPConfigFromEnv reads mcpConfig from the environment, by the same rule requiredEnv
// (config.go) enforces for every other config loader in this binary: no default for a required
// value, and every missing one named at once (moot here with only one required variable, but
// consistent with loadHookConfigFromEnv/loadSessionStartConfigFromEnv rather than a special case).
// STRATIUM_PEP_MCP_UPSTREAM_ARGS is the one optional value -- many MCP servers are launched with
// no arguments at all, so an empty list is a legitimate configuration, not a missing one;
// splitAndTrim (session_start.go) already treats an unset or blank variable as an empty (nil)
// slice, so there is nothing mcp-specific to add for that case.
func loadMCPConfigFromEnv() (mcpConfig, error) {
	var missing []string
	cfg := mcpConfig{
		UpstreamCommand: requiredEnv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", &missing),
	}
	if len(missing) > 0 {
		return mcpConfig{}, missingConfigError(missing)
	}
	cfg.UpstreamArgs = splitAndTrim(os.Getenv("STRATIUM_PEP_MCP_UPSTREAM_ARGS"))
	return cfg, nil
}

// runMCPCmd wires the real upstream process from environment configuration, relays against its
// stdin/stdout, and reports an exit status. Like runHookCmd and runSessionStartCmd, it is the
// only function in this file main's dispatch calls; the relay itself (runMCP) is exercised
// directly by mcp_test.go against in-memory pipes, and this function's own process-lifecycle
// wiring is exercised separately against a real subprocess (see
// TestRunMCPCmd_RealUpstreamProcess_RelaysAndExitsCleanly).
//
// Every error path here writes to stderr, never stdout: stdout is the live JSON-RPC channel the
// agent is parsing frame by frame, and a diagnostic string written there would corrupt that
// stream rather than report a problem -- unlike hook's contract, mcp has no "structured deny on
// stdout" channel to (mis)use for this instead.
func runMCPCmd(stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := loadMCPConfigFromEnv()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: %s\n", err)
		return 1
	}

	cmd := exec.Command(cfg.UpstreamCommand, cfg.UpstreamArgs...) //nolint:gosec // G204: cfg.UpstreamCommand/Args come from operator configuration (STRATIUM_PEP_MCP_UPSTREAM_COMMAND/_ARGS), not attacker-supplied request data -- the same trust boundary loadSessionFile's identical nolint documents for STRATIUM_PEP_SESSION_FILE.
	cmd.Stderr = stderr                                           // the upstream's OWN diagnostics, passed through untouched -- never this proxy's frame logging. See the package doc.

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not open upstream stdin: %s\n", err)
		return 1
	}
	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not open upstream stdout: %s\n", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not start upstream %q: %s\n", cfg.UpstreamCommand, err)
		return 1
	}

	relayErr := runMCP(stdin, stdout, upstreamIn, upstreamOut, stderr)

	// Wait only after runMCP has returned, and so has fully stopped reading upstreamOut, by
	// construction: relayDirection's loop is what reads it, and runMCP does not return until both
	// of its goroutines have. Calling Wait first is documented as unsafe specifically because it
	// races Wait's own pipe-close cleanup against a still-in-progress Read on the same pipe.
	//
	// This assumes the child actually exits once its stdin closes (which the agent-side goroutine
	// does as soon as the agent's own input ends -- see interceptAgentFrame's caller in runMCP).
	// That is the standard shutdown contract for a stdio subprocess, and every MCP server this
	// proxy is expected to wrap follows it; a child that ignores a closed stdin and never exits
	// would block here. Forcibly killing such a child after a grace period is a real production
	// concern but not one this relay skeleton takes a position on -- it is not exercised by
	// anything in this task, and adding a timeout/kill policy without a documented reason to pick
	// one duration over another would be a guess dressed up as a feature.
	waitErr := cmd.Wait()

	if relayErr != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: mcp relay ended: %s\n", relayErr)
		return 1
	}
	if waitErr != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: upstream exited: %s\n", waitErr)
		return 1
	}
	return 0
}

// runMCP relays JSON-RPC frames between the agent (agentIn/agentOut) and the upstream MCP server
// (upstreamIn/upstreamOut) until both directions have ended, then returns. Each direction runs on
// its own goroutine and neither waits on the other for anything about an individual frame -- see
// the package doc's CONCURRENCY note for why that matters beyond this task.
//
// Shutdown is deliberately ASYMMETRIC, not "either side ending stops both": only the upstream
// ending -- the child exits, or its output otherwise errors -- cancels the shared context, which
// is what stops a still-blocked agent->upstream read rather than leaving it waiting on a peer that
// is already gone. The agent ending does NOT cancel upstream->agent: closing upstreamIn (below) is
// this proxy's way of telling the child to shut down, but the child may still have an in-flight
// reply to a request already forwarded, and upstream->agent's job is to keep relaying until the
// child is actually done, not until the agent merely stops sending. Making agent-ends-first also
// cancel upstream->agent was the first version of this function's design, and it was wrong in a
// way only a real subprocess test caught (TestRunMCPCmd_RealUpstreamProcess_RelaysAndExitsCleanly):
// an agent fixture that sends one request and immediately hits EOF -- an ordinary, not even
// adversarial, shape -- cancelled the context before the child's reply had a chance to arrive, and
// the reply was silently dropped instead of relayed. Symmetric cancellation is the more obvious
// design; it is the wrong one.
//
// This does mean runMCP can, in principle, keep running after the agent has gone if the upstream
// never exits and never answers again -- the same "a child that ignores a closed stdin never
// exits" limitation runMCPCmd's own doc comment already names for cmd.Wait, not a new one.
func runMCP(agentIn io.Reader, agentOut io.Writer, upstreamIn io.WriteCloser, upstreamOut io.Reader, stderr io.Writer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fromAgent := newFrameSource(agentIn)
	fromUpstream := newFrameSource(upstreamOut)

	var wg sync.WaitGroup
	var agentToUpstreamErr, upstreamToAgentErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		// Tells the child to shut down, regardless of why this direction ended -- see the
		// package doc. Deliberately not paired with cancel() here; see the doc comment above.
		defer func() { _ = upstreamIn.Close() }()
		agentToUpstreamErr = relayDirection(ctx, fromAgent, upstreamIn, stderr, "agent->upstream", interceptAgentFrame)
	}()
	go func() {
		defer wg.Done()
		defer cancel() // the only trigger that stops the other direction early -- see the doc comment above
		upstreamToAgentErr = relayDirection(ctx, fromUpstream, agentOut, stderr, "upstream->agent", passthroughUpstreamFrame)
	}()
	wg.Wait()

	if agentToUpstreamErr != nil {
		return agentToUpstreamErr
	}
	return upstreamToAgentErr
}

// relayDirection copies frames from src to dst, applying intercept to each well-formed one, until
// src is exhausted, a write to dst fails, or ctx is cancelled -- whichever happens first. label
// names the direction for stderr diagnostics only; this function never writes a frame's contents
// to stderr under any circumstance, malformed or not -- see the package doc's logging rule.
func relayDirection(ctx context.Context, src *frameSource, dst io.Writer, stderr io.Writer, label string, intercept func(method string, line []byte) []byte) error {
	for {
		select {
		case line, ok := <-src.frames:
			if !ok {
				return <-src.errc // clean EOF (nil) or the read/scan error that ended the source
			}
			method, malformed := frameMethod(line)
			if malformed {
				// Dropped, not forwarded -- see the package doc's fail-closed rule for transport
				// faults. The relay keeps running: one bad line from a peer is that peer's bug to
				// surface on its own end, not a reason to tear down an otherwise-healthy session.
				_, _ = fmt.Fprintf(stderr, "stratium-pep: mcp: dropped a malformed %s frame\n", label)
				continue
			}
			out := intercept(method, line)
			if out == nil {
				continue // nothing to relay for this frame -- see interceptAgentFrame's doc comment
			}
			if _, err := dst.Write(append(out, '\n')); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// frameSource reads newline-delimited JSON-RPC frames from r on its own goroutine and publishes
// each one on frames, which it closes once r is exhausted or unreadable; errc then holds exactly
// one value -- nil for a clean EOF, otherwise why reading stopped -- sent before frames closes, so
// a caller that has observed frames closed can safely read errc without racing the goroutine that
// wrote it (a channel close happens-after every send that preceded it in the same goroutine, and
// happens-before any receive that observes the close).
//
// Publishing through a channel, rather than relayDirection calling Scan directly, is what makes a
// blocked Read on a live peer interruptible: relayDirection selects between this channel and
// ctx.Done(), so it can give up on a peer that will never send another frame instead of blocking
// on it forever. The scanning goroutine itself may still be blocked in the underlying Read (or in
// sending a line nobody will ever receive) after the relay gives up on it -- harmless: nothing in
// this process depends on it again, and it is reclaimed the moment this process exits, which
// main's single os.Exit does immediately after runMCPCmd returns.
type frameSource struct {
	frames chan []byte
	errc   chan error
}

func newFrameSource(r io.Reader) *frameSource {
	fs := &frameSource{frames: make(chan []byte), errc: make(chan error, 1)}
	go func() {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 4096), maxFrameBytes)
		for scanner.Scan() {
			// Scan reuses its internal buffer on the next call, so the line must be copied before
			// it is handed to another goroutine via the channel -- not a defensive copy against a
			// receiver mutating it, but against this scanner overwriting it out from under a
			// receiver that has not read it yet.
			line := append([]byte(nil), scanner.Bytes()...)
			fs.frames <- line
		}
		fs.errc <- scanner.Err() // nil on a clean EOF
		close(fs.frames)
	}()
	return fs
}

// frameMethod reports whether line is well-formed enough to relay -- valid JSON, and a JSON
// object, the only shape a JSON-RPC 2.0 message can take -- and, if so, the method it names
// (empty for a response, which has no method field). This is the ONLY validation this proxy
// performs on a frame: it does not require jsonrpc == "2.0", does not check that a message has
// exactly one of method/id or result/error, and does not inspect id's type or presence. Every one
// of those is a property of a *specific* message shape (request vs. notification vs. response),
// and checking it would mean classifying which shape a frame is -- interpreting the protocol, not
// relaying it, the same boundary hook.go's package doc draws around tool_input.
//
// A frame this check accepts is relayed as its original bytes everywhere else in this file --
// never as anything unmarshaled and reconstructed. id, params, result, and error never pass
// through a Go struct on their way through, which is what makes an id round-trip exact rather
// than merely usually correct; see the package doc's fuller explanation.
func frameMethod(line []byte) (method string, malformed bool) {
	var env struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		return "", true
	}
	return env.Method, false
}

// interceptAgentFrame is the one place a frame from the agent, bound for the upstream server, is
// looked at before being relayed -- and today it is a no-op for every method, including
// tools/call: this file wires the relay, authorization is a later change. Keeping this as a
// single named function, rather than inlining the passthrough at relayDirection's call site in
// runMCP, is what makes "gate tools/call" a change to this function's body alone, not a
// restructuring of the relay loop -- and it must stay one that can say no to an individual frame
// without blocking any other: relayDirection calls this once per frame, synchronously, on the
// agent->upstream goroutine, so a future version of this function that blocks on a slow decision
// blocks every frame behind it in this direction. Returning nil drops the frame (a malformed one
// takes this same path today, one level up in relayDirection, before intercept is even called);
// returning line, as this does unconditionally, relays it unchanged.
func interceptAgentFrame(method string, line []byte) []byte {
	_ = method // not yet used for anything -- every method relays unchanged, see the package doc
	return line
}

// passthroughUpstreamFrame relays every frame from the upstream server to the agent unchanged.
// There is no authorization step in this direction -- the PDP gates what the agent may ask the
// upstream to do, never what the upstream may reply -- so, unlike interceptAgentFrame, this one
// has no future gate to grow into.
func passthroughUpstreamFrame(_ string, line []byte) []byte {
	return line
}
