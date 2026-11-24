// mcp.go implements the "mcp" subcommand: an MCP (Model Context Protocol) proxy over stdio. The
// agent's harness launches this process in place of a real MCP server; runMCPCmd launches the
// real upstream server this wraps as a child process, and JSON-RPC frames flow agent -> proxy ->
// upstream and back, in both directions, for as long as either side has something to send. See
// main.go's package doc for why stdio rather than HTTP is what makes this mode's trust model hold
// at all: the harness starts this process, not the agent, so the session file mcp_authorize.go
// reads (via the same loadSessionFile hook.go uses) is not something the agent supplied.
//
// THIS FILE CALLS THE PDP FOR EXACTLY ONE METHOD: tools/call. Every other method, including
// tools/list, is relayed unconditionally, exactly like Task 1 relayed everything. interceptAgentFrame
// (Task 1's placeholder) is now (*mcpAuthorizer).intercept (mcp_authorize.go) -- the actual decision
// logic (building a DecideRequest, calling Decide, resolving an ESCALATE, constructing a JSON-RPC
// error) lives there, not here, so this file stays what it always was: the relay's framing,
// concurrency, and shutdown mechanics. See mcp_authorize.go's own package doc for the classification
// boundary that logic draws, identical to hook.go's for the other enforcement surface.
//
// TOOLS/LIST IS DELIBERATELY NOT FILTERED. Only tools/call is gated -- the advertised tool listing
// passes through unchanged, even when some listed tool would be denied if actually called. This is
// a considered choice, not an oversight, and the omission cuts both ways: filtering tools/list would
// require either (a) this proxy deciding locally which tools are "permitted enough" to advertise,
// which is D1 in a UX-motivated coat of paint -- the PEP would be classifying again, just earlier in
// the conversation -- or (b) issuing one Decide call per listed tool on every tools/list, which
// trades a UX nicety for a PDP round trip multiplied by however many tools the upstream advertises,
// on a method that is not even the one this system enforces. Enforcement happens at call time,
// where a real DecideRequest with real arguments exists to evaluate; tools/list has no arguments to
// evaluate at all, only a name, which is not enough to derive a tier from safely (BuiltinTier needs
// raw_input, not a tool name in isolation -- see internal/authz's own tier derivation). An agent
// that lists a tool it cannot call finds out at call time, via a real, PDP-attributed denial reason
// -- the same place and the same way it always finds out anything about what it may or may not do
// under this system.
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
// mcp_authorize.go's synthesized JSON-RPC error frame is the one exception -- a frame this proxy
// AUTHORS rather than relays, for which it uses a typed struct with a json.RawMessage id field
// specifically because that still emits the original id's bytes verbatim (RawMessage's MarshalJSON
// returns itself unchanged); see that file's jsonrpcErrorFrame doc comment.
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
// CONCURRENCY. MCP permits multiple in-flight requests, and the authorization call tools/call now
// triggers takes real time (a PDP round trip, occasionally an escalation wait measured in the
// configured ApprovalTimeout, not milliseconds). Nothing in this file serializes the stream behind
// one pending frame: agent->upstream and upstream->agent are two independent goroutines (runMCP),
// relayDirection forwards each frame as it arrives rather than waiting on a previous one, and
// (*mcpAuthorizer).intercept extends this same property to tools/call specifically by never
// deciding inline -- it hands the frame to its own goroutine (decideAndRelay, mcp_authorize.go) and
// returns immediately, so relayDirection's loop is free to read the NEXT frame while that decision
// is still in flight. A slow write on one direction cannot block a read on the other, and a slow
// decision on one tools/call cannot block any other frame, tools/call or not, queued behind it.
// TestDecideAndRelay_ConcurrentToolsCalls_DoNotSerialize (mcp_authorize_test.go) is what proves the
// second half of that claim; TestRunMCP_PipelinedRequests_NotSerializedBehindEachOther (mcp_test.go)
// proves the first half, for methods this file never gates at all.
//
// Because a decision can now outlive the frame that started it, two things had to change alongside
// it, both in runMCP: syncWriter below wraps upstreamIn and agentOut so a decision goroutine's
// eventual write (forward on ALLOW, an error frame on deny) cannot interleave with relayDirection's
// own loop-driven writes to the same destination -- a plain io.Writer gives no such guarantee, and a
// JSON-RPC line long enough to cross a pipe's atomic-write boundary could otherwise corrupt both
// writers' output. And runMCP now waits for every decision goroutine it started (mcpAuthorizer.wg)
// before returning, not just its own two relay goroutines -- otherwise a caller that observes
// runMCP has returned could still see a write land afterward, which is exactly the kind of
// ordering runMCPCmd's own Wait()-timing argument (below) depends on not happening.
//
// FAIL CLOSED ON TRANSPORT FAULTS. A malformed frame (not valid JSON, or valid JSON that is not a
// JSON object) is dropped, not forwarded -- see frameMethod. The child exiting, or its output
// otherwise erroring, stops BOTH directions promptly: runMCP's shared context is cancelled so a
// still-blocked agent->upstream read does not wait forever on a peer that is already gone. The
// agent's stdin closing stops only the agent->upstream direction (and tells the child to shut
// down, by closing its stdin in turn); upstream->agent keeps relaying until the upstream itself
// ends, so a reply already in flight when the agent hangs up is still delivered rather than
// dropped. See runMCP's own doc comment for why that asymmetry is deliberate, not an oversight.
// FAIL CLOSED ON AUTHORIZATION FAULTS is mcp_authorize.go's own concern (an unreachable PDP, a
// missing session file, an escalation timeout: all deny, never forward) -- a different axis from
// this section, which is about the TRANSPORT surviving a fault, not about what a decision concludes.
//
// NEVER LOG FRAME CONTENTS. stderr in this file carries only this proxy's own fault diagnostics
// ("dropped a malformed frame") -- never a frame's bytes, which may carry tool arguments, and never
// anything from the session file mcp_authorize.go reads. mcp_authorize.go holds to the same rule for
// its own two possible diagnostic channels (an agentOut error frame, a dropped id-less frame): the
// PDP's own reason text is the one thing that DOES cross into an error frame's message, deliberately
// -- it is not raw_input, not the session file's contents, and not an approval id, and the agent
// needs it to tell a policy "no" apart from a transport failure (see mcp_authorize.go's package
// doc). The upstream server's OWN stderr is passed through untouched (cmd.Stderr = stderr in
// runMCPCmd) because that is the upstream's diagnostic output, not this proxy's to interpret or copy
// from -- the same rule hook.go's package doc states for raw_input, applied here to a different
// channel.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// maxFrameBytes bounds how large a single JSON-RPC line this proxy will read in either direction.
// Some limit must exist -- an unbounded read buffer is a memory-exhaustion vector from a hostile
// or simply buggy peer, one line at a time -- and this one is set well above any legitimate MCP
// payload actually seen (tool listings, file contents, search results) so it only ever trips on
// exactly the failure mode it exists to bound.
const maxFrameBytes = 32 * 1024 * 1024 // 32 MiB

// mcpConfig is what runMCPCmd needs to launch the upstream MCP server this mode wraps: the
// command and its arguments. It deliberately does NOT also hold the PDP address, agent identity,
// subject, session file path, or escalation timing that authorizing a tools/call needs --
// runMCPCmd loads those via loadHookConfigFromEnv (hook.go), unmodified, as a SEPARATE hookConfig
// value alongside this one, rather than folding hook's seven fields into this struct or duplicating
// their loading here. The two configs stay separate structs for the same reason "mcp" and "hook"
// stay separate subcommands: UpstreamCommand/UpstreamArgs are meaningless to hook, and
// PDPAddr/AgentID/Subject/SessionFilePath/ConnectTimeout/ApprovalPollInterval/ApprovalTimeout mean
// exactly the same thing to both surfaces -- reusing hookConfig unchanged for that shared half, as
// the task report notes, is itself evidence it was never a hook-only shape to begin with, only a
// hook-first one.
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
//
// A command that is present but blank after trimming -- all whitespace -- passes requiredEnv's
// v == "" check (a single space is not the empty string) but is exactly as useless as a missing
// one: exec.Command in runMCPCmd would still hand it to LookPath, which still fails, but only once
// cmd.Start() runs -- after this function has already reported success and runMCPCmd has already
// dialed the PDP. Rejecting it HERE keeps "malformed configuration" (this function's job) and "a
// real subprocess failed to launch" (cmd.Start()'s own, distinct failure path in runMCPCmd) as the
// two separate failure modes their own error messages already claim to be, rather than letting a
// whitespace typo masquerade as the second one.
func loadMCPConfigFromEnv() (mcpConfig, error) {
	var missing []string
	cfg := mcpConfig{
		UpstreamCommand: requiredEnv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", &missing),
	}
	if cfg.UpstreamCommand != "" && strings.TrimSpace(cfg.UpstreamCommand) == "" {
		return mcpConfig{}, errors.New("STRATIUM_PEP_MCP_UPSTREAM_COMMAND must not be blank")
	}
	if len(missing) > 0 {
		return mcpConfig{}, missingConfigError(missing)
	}
	cfg.UpstreamArgs = splitAndTrim(os.Getenv("STRATIUM_PEP_MCP_UPSTREAM_ARGS"))
	return cfg, nil
}

// combineConfigErrors reports every non-nil error from loading this mode's two independently
// sourced configs -- mcpConfig (the upstream process, above) and hookConfig (everything
// authorizing a tools/call needs, loaded via loadHookConfigFromEnv in hook.go) -- in one message,
// rather than whichever loader runMCPCmd happened to call first. Without this, an operator missing
// required values in BOTH groups would discover the second group's gaps only after fixing the
// first and rerunning: requiredEnv's own doc comment (config.go) rejects exactly that experience
// for the fields within one loader's own struct ("a developer... should not have to run the binary
// repeatedly to discover each missing value in turn"); this is the same rule, applied across the
// two loaders that only "mcp" composes -- "hook" and "session-start" each load exactly one config,
// so neither has ever needed this.
func combineConfigErrors(errs ...error) error {
	var msgs []string
	for _, err := range errs {
		if err != nil {
			msgs = append(msgs, err.Error())
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return errors.New(strings.Join(msgs, "; "))
}

// runMCPCmd wires the real upstream process from environment configuration, relays against its
// stdin/stdout, and reports an exit status. Like runHookCmd and runSessionStartCmd, it is the
// only function in this file main's dispatch calls; the relay itself (runMCP) is exercised
// directly by mcp_test.go and mcp_authorize_test.go against in-memory pipes, and this function's
// own process-lifecycle wiring is exercised separately against a real subprocess (see
// TestRunMCPCmd_RealUpstreamProcess_RelaysAndExitsCleanly).
//
// Loads THREE configs, not one -- mcpConfig for the upstream process, hookConfig (loadHookConfigFromEnv,
// hook.go) for everything authorizing a tools/call needs, and cacheConfig (loadCacheConfigFromEnv,
// cache.go) for how long a cached decision may be served -- and dials the PDP client the same way
// runHookCmd does, with the same client passed to both the first Decide call and any escalation
// retry. All three loaders always run, even if an earlier one fails: combineConfigErrors below folds
// whichever errors come back into one message, so an operator missing values across groups sees
// every gap in a single run instead of fixing one, rerunning, and only then discovering the next.
// Any config failing to load denies closed here, before any subprocess is even started: a proxy
// that started relaying with no way to reach the PDP would forward every tools/call unauthorized
// by construction, which is a worse failure mode than simply refusing to start.
//
// Every error path here writes to stderr, never stdout: stdout is the live JSON-RPC channel the
// agent is parsing frame by frame, and a diagnostic string written there would corrupt that
// stream rather than report a problem -- unlike hook's contract, mcp has no "structured deny on
// stdout" channel to (mis)use for this instead.
func runMCPCmd(stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, cfgErr := loadMCPConfigFromEnv()
	hookCfg, hookErr := loadHookConfigFromEnv()
	cacheCfg, cacheErr := loadCacheConfigFromEnv()
	if err := combineConfigErrors(cfgErr, hookErr, cacheErr); err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: %s\n", err)
		return 1
	}

	// grpc.NewClient dials lazily -- this succeeds for any syntactically valid target even if
	// nothing is listening yet, exactly like runHookCmd's identical call. An actually-unreachable
	// PDP is a per-Decide-call failure (decideAndRelay's describeRPCError path), not a startup one.
	conn, err := dialPDP(hookCfg.PDPAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create PDP client: %s\n", err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	pdpClient := pdpgrpc.NewPDPServiceClient(conn)

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

	relayErr := runMCP(stdin, stdout, upstreamIn, upstreamOut, stderr, pdpClient, hookCfg, cacheCfg)

	// Wait only after runMCP has returned, and so has fully stopped reading upstreamOut, by
	// construction: relayDirection's loop is what reads it, and runMCP does not return until both
	// of its goroutines have. Calling Wait first is documented as unsafe specifically because it
	// races Wait's own pipe-close cleanup against a still-in-progress Read on the same pipe.
	//
	// This assumes the child actually exits once its stdin closes (which the agent-side goroutine
	// does as soon as the agent's own input ends -- see runMCP's agent->upstream goroutine below).
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
// exits" limitation runMCPCmd's own doc comment already names for cmd.Wait, not a new one. A
// tools/call decision still in flight when the agent disconnects is the same category of "process
// outlives a departed peer" limitation, extended to a new code path rather than a new problem: its
// own Decide/GetApproval calls derive from context.Background() with only their configured
// deadlines (ConnectTimeout, ApprovalTimeout -- see mcp_authorize.go and escalation.go), never from
// this function's own ctx, so it resolves in bounded time regardless of what either peer does
// meanwhile -- deliberately NOT wired to cancel early on ctx, which would have made hook.go's
// describeRPCError need a codes.Canceled case it does not have and should not need to grow just for
// this caller (see that function's own doc comment).
func runMCP(agentIn io.Reader, agentOut io.Writer, upstreamIn io.WriteCloser, upstreamOut io.Reader, stderr io.Writer, client pdpgrpc.PDPServiceClient, cfg hookConfig, cacheCfg cacheConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fromAgent := newFrameSource(agentIn)
	fromUpstream := newFrameSource(upstreamOut)

	// Both destinations can now be written from more than one goroutine -- relayDirection's own
	// loop-driven writes below, and an mcpAuthorizer decision goroutine forwarding an ALLOWed
	// tools/call or replying with a denial (mcp_authorize.go). syncWriter is what keeps two such
	// writers from interleaving mid-frame; see the package doc's CONCURRENCY note.
	syncUpstreamIn := &syncWriter{w: upstreamIn}
	syncAgentOut := &syncWriter{w: agentOut}
	// A new, empty decision cache per proxy run: it only ever holds decisions this process
	// receives from the PDP from here on (cache.go's package doc, "Memory only").
	authz := &mcpAuthorizer{client: client, cfg: cfg, cacheCfg: cacheCfg, cache: newDecisionCache(), upstreamIn: syncUpstreamIn, agentOut: syncAgentOut}

	var wg sync.WaitGroup
	var agentToUpstreamErr, upstreamToAgentErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		// Tells the child to shut down, regardless of why this direction ended -- see the
		// package doc. Deliberately not paired with cancel() here; see the doc comment above.
		defer func() { _ = upstreamIn.Close() }()
		agentToUpstreamErr = relayDirection(ctx, fromAgent, syncUpstreamIn, stderr, "agent->upstream", authz.intercept)
	}()
	go func() {
		defer wg.Done()
		defer cancel() // the only trigger that stops the other direction early -- see the doc comment above
		upstreamToAgentErr = relayDirection(ctx, fromUpstream, syncAgentOut, stderr, "upstream->agent", passthroughUpstreamFrame)
	}()
	wg.Wait()

	// Every tools/call decision authz started must finish -- and, on ALLOW, either land its
	// forwarded write before upstreamIn is closed above or fail harmlessly trying to (see
	// mcp_authorize.go's forward doc comment) -- before this function itself reports done. Without
	// this wait, runMCPCmd's own Wait()-ordering argument (its doc comment) would no longer hold: a
	// decision goroutine could still be running, and still writing, after a caller believes the
	// relay has fully stopped. Every such decision is bounded by its own configured timeout (see
	// this function's doc comment above), so this cannot hang.
	authz.wg.Wait()

	if agentToUpstreamErr != nil {
		return agentToUpstreamErr
	}
	return upstreamToAgentErr
}

// syncWriter serializes concurrent Write calls to an underlying io.Writer. A plain io.Writer gives
// no such guarantee, and once an mcpAuthorizer decision goroutine can write to the same destination
// relayDirection's own loop writes to (see runMCP), two goroutines calling Write on one pipe at once
// is a real possibility, not a hypothetical one: a JSON-RPC line long enough to cross a pipe's
// atomic-write boundary (PIPE_BUF, ordinarily a few KiB, and maxFrameBytes permits lines far larger
// than that) can interleave with another goroutine's write and corrupt both frames on the wire,
// silently -- there is no framing-level way for a reader to detect that this happened after the
// fact. Wrapping the two writers that can now have multiple callers (never upstreamOut/agentIn,
// which only ever have one reader each) is cheaper and more obviously correct than auditing every
// write call site for whether it might race a future one.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
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
				// nothing to relay FROM THIS CALL -- today this means (*mcpAuthorizer).intercept
				// handed a tools/call off to its own decision goroutine (mcp_authorize.go); every
				// other method's intercept returns line, never nil.
				continue
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
	if err := json.Unmarshal(line, &env); err != nil || ambiguousJSONKeys(line, "method", "params", "id") {
		return "", true
	}
	return env.Method, false
}

// ambiguousJSONKeys reports whether obj, a JSON object, names one of keys
// more than once, or under another capitalization. encoding/json matches a
// key to a field whatever its case and keeps the last of several, and other
// JSON parsers do neither, so such an object can read as one request here and
// as another to the server it is forwarded to. An object that is not valid
// JSON reports false: the caller's own decoding refuses it.
func ambiguousJSONKeys(obj []byte, keys ...string) bool {
	dec := json.NewDecoder(bytes.NewReader(obj))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(keys))
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok {
			return false
		}
		for _, k := range keys {
			if strings.EqualFold(key, k) {
				if key != k || seen[k] {
					return true
				}
				seen[k] = true
			}
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return false
		}
	}
	return false
}

// passthroughUpstreamFrame relays every frame from the upstream server to the agent unchanged.
// There is no authorization step in this direction -- the PDP gates what the agent may ask the
// upstream to do, never what the upstream may reply -- so, unlike (*mcpAuthorizer).intercept
// (mcp_authorize.go), which plays the equivalent role for the agent->upstream direction, this one
// has no gate to grow into and stays a plain function rather than a method with state.
func passthroughUpstreamFrame(_ string, line []byte) []byte {
	return line
}

// ambiguousJSONKeysAnywhere reports whether any object in data, at any depth,
// has two keys that differ at most in capitalization. Data that is not valid
// JSON reports false: the caller's own decoding refuses it.
func ambiguousJSONKeysAnywhere(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	// One entry per open object or array: an object's keys so far, nil for
	// an array. wantKey is whether the next token in the innermost object
	// is a key.
	var open []map[string]bool
	wantKey := false
	for {
		t, err := dec.Token()
		if err != nil {
			return false // io.EOF at the end, or invalid JSON
		}
		inObject := len(open) > 0 && open[len(open)-1] != nil
		if key, ok := t.(string); ok && inObject && wantKey {
			// Upper then lower folds every pair encoding/json would match.
			folded := strings.ToLower(strings.ToUpper(key))
			if open[len(open)-1][folded] {
				return true
			}
			open[len(open)-1][folded] = true
			wantKey = false
			continue
		}
		switch t {
		case json.Delim('{'):
			open = append(open, map[string]bool{})
			wantKey = true
			continue
		case json.Delim('['):
			open = append(open, nil)
			continue
		case json.Delim('}'), json.Delim(']'):
			open = open[:len(open)-1]
		}
		// A value has just ended, so the enclosing object wants a key next.
		wantKey = true
	}
}
