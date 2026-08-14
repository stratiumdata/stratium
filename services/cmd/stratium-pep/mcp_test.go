package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"stratium/internal/pdpgrpc"
)

// --- mcpConfig ---------------------------------------------------------

func clearMCPEnv(t *testing.T) {
	t.Helper()
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", "")
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_ARGS", "")
}

func TestLoadMCPConfigFromEnv(t *testing.T) {
	t.Run("command and args set", func(t *testing.T) {
		clearMCPEnv(t)
		t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", "/usr/local/bin/some-mcp-server")
		t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_ARGS", "--stdio, --verbose")

		cfg, err := loadMCPConfigFromEnv()
		if err != nil {
			t.Fatalf("loadMCPConfigFromEnv() error = %v, want nil", err)
		}
		want := mcpConfig{
			UpstreamCommand: "/usr/local/bin/some-mcp-server",
			UpstreamArgs:    []string{"--stdio", "--verbose"}, // comma-separated, trimmed
		}
		if !reflect.DeepEqual(cfg, want) {
			t.Errorf("loadMCPConfigFromEnv() = %+v, want %+v", cfg, want)
		}
	})

	t.Run("args are optional, default empty", func(t *testing.T) {
		clearMCPEnv(t)
		t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", "some-server")

		cfg, err := loadMCPConfigFromEnv()
		if err != nil {
			t.Fatalf("loadMCPConfigFromEnv() error = %v, want nil", err)
		}
		if len(cfg.UpstreamArgs) != 0 {
			t.Errorf("UpstreamArgs = %#v, want empty -- many MCP servers take none", cfg.UpstreamArgs)
		}
	})

	t.Run("missing command is named in the error", func(t *testing.T) {
		clearMCPEnv(t)

		_, err := loadMCPConfigFromEnv()
		if err == nil {
			t.Fatal("loadMCPConfigFromEnv() error = nil, want an error naming STRATIUM_PEP_MCP_UPSTREAM_COMMAND")
		}
		if !strings.Contains(err.Error(), "STRATIUM_PEP_MCP_UPSTREAM_COMMAND") {
			t.Errorf("error = %q, want it to name STRATIUM_PEP_MCP_UPSTREAM_COMMAND", err.Error())
		}
	})

	// Anchors the mutation "drop the blank-after-trim check": a command of pure whitespace is
	// != "" (requiredEnv's own missing check would let it through) but is exactly as unusable as
	// no command at all -- see loadMCPConfigFromEnv's own doc comment for why this is rejected
	// HERE rather than left for cmd.Start()'s own, later, less specific failure.
	t.Run("blank command (whitespace only) is rejected", func(t *testing.T) {
		clearMCPEnv(t)
		t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", "   ")

		_, err := loadMCPConfigFromEnv()
		if err == nil {
			t.Fatal("loadMCPConfigFromEnv() error = nil, want an error rejecting a blank command")
		}
		if !strings.Contains(err.Error(), "STRATIUM_PEP_MCP_UPSTREAM_COMMAND") {
			t.Errorf("error = %q, want it to name STRATIUM_PEP_MCP_UPSTREAM_COMMAND", err.Error())
		}
	})
}

// --- runMCPCmd: config and process-wiring failures ----------------------

// Mirrors TestRunSessionStartCmd_MissingConfig_FailsClosed's property (missing configuration
// fails closed, not with a guessed value) but adds an assertion session-start has no reason to
// make: stdout must stay untouched. mcp's stdout is the live JSON-RPC channel, not a side channel
// for error text -- see runMCPCmd's own doc comment for why that distinction exists at all.
func TestRunMCPCmd_MissingConfig_ExitsOneStdoutUntouched(t *testing.T) {
	clearMCPEnv(t)
	clearCacheEnv(t)

	var stdout, stderr bytes.Buffer
	code := runMCPCmd(strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Fatalf("runMCPCmd() = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty -- an infra error must never land on the JSON-RPC stream", stdout.String())
	}
	if !strings.Contains(stderr.String(), "STRATIUM_PEP_MCP_UPSTREAM_COMMAND") {
		t.Errorf("stderr = %q, want it to name the missing variable", stderr.String())
	}
}

// The second config runMCPCmd now loads (Task 2's addition): mcpConfig loads fine here (a valid
// upstream command is set), but none of hookConfig's seven variables are -- the ones decideAndRelay
// needs to reach the PDP at all. A proxy that started relaying anyway, with no PDP address to call,
// would forward every tools/call unauthorized by construction; this proves runMCPCmd refuses to
// start instead, the same fail-closed rule TestRunMCPCmd_MissingConfig_ExitsOneStdoutUntouched
// already proves for the upstream-command half of startup.
func TestRunMCPCmd_MissingHookConfig_ExitsOneStdoutUntouched(t *testing.T) {
	clearMCPEnv(t)
	clearHookEnv(t)
	clearCacheEnv(t)
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", "some-upstream-server")

	var stdout, stderr bytes.Buffer
	code := runMCPCmd(strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Fatalf("runMCPCmd() = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty -- an infra error must never land on the JSON-RPC stream", stdout.String())
	}
	if !strings.Contains(stderr.String(), "STRATIUM_PEP_PDP_ADDR") {
		t.Errorf("stderr = %q, want it to name a missing hook-config variable (e.g. STRATIUM_PEP_PDP_ADDR)", stderr.String())
	}
}

// Task 3's fix: before this task, loadMCPConfigFromEnv and loadHookConfigFromEnv failed fast in
// sequence, so an operator missing values in BOTH groups learned about the second group's gaps
// only after fixing the first and rerunning -- the two tests directly above each prove one group's
// half of that in isolation (a valid hook config alongside a missing mcp one, and vice versa), but
// neither, on its own, could tell "reports only the first loader's gaps" apart from "reports
// every gap" when BOTH loaders are broken at once. This is the anchor for that specific gap: every
// required variable is unset in both groups, and the combined message must name a representative
// from each -- not just whichever loader runMCPCmd happened to call first. Reverting runMCPCmd to
// its pre-Task-3 fail-fast shape (return immediately after loadMCPConfigFromEnv fails, never
// reaching loadHookConfigFromEnv) makes the hook-variable assertions below fail, because that
// loader is then never even called.
//
// Extended by Task 3 (the decision cache) to a THIRD loader, cacheConfig -- the same property, one
// more time, over combineConfigErrors' now-three-way composition (runMCPCmd, mcp.go): a build that
// reverted to composing only two of the three would still pass every assertion above this one, so
// cacheStalenessWindowEnv gets its own, independent check rather than folding it into the loop over
// requiredHookEnvVars, which knows nothing about cacheConfig's own variable.
func TestRunMCPCmd_BothConfigsMissing_NamesEveryMissingKeyFromBoth(t *testing.T) {
	clearMCPEnv(t)
	clearHookEnv(t)
	clearCacheEnv(t)

	var stdout, stderr bytes.Buffer
	code := runMCPCmd(strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Fatalf("runMCPCmd() = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty -- an infra error must never land on the JSON-RPC stream", stdout.String())
	}
	msg := stderr.String()
	if !strings.Contains(msg, "STRATIUM_PEP_MCP_UPSTREAM_COMMAND") {
		t.Errorf("stderr = %q, want it to name the missing mcp-only variable", msg)
	}
	for _, hookVar := range requiredHookEnvVars {
		if !strings.Contains(msg, hookVar) {
			t.Errorf("stderr = %q, want it to also name the missing hook-shared variable %s -- an "+
				"operator missing values in both groups must see every gap in one run, not just the "+
				"first loader's", msg, hookVar)
		}
	}
	if !strings.Contains(msg, cacheStalenessWindowEnv) {
		t.Errorf("stderr = %q, want it to also name the missing cache variable %s -- the third loader's "+
			"gap must reach the same combined message as the other two", msg, cacheStalenessWindowEnv)
	}
}

// Distinguishes "config rejected at load time" from "cmd.Start failed" (the next test below): a
// blank command must never reach exec.Command at all, so this must fail BEFORE dialing the PDP
// too -- mustReturnWithin guards against a mutation that let this fall through to a hang rather
// than a prompt, clean exit.
func TestRunMCPCmd_BlankUpstreamCommand_ExitsOneWithoutStartingSubprocess(t *testing.T) {
	clearMCPEnv(t)
	clearHookEnv(t)
	setAllHookEnv(t, nil)
	// Set, not cleared: this test is specifically about the blank command, isolated from cacheConfig
	// entirely -- see TestRunMCPCmd_UpstreamCommandNotFound_ExitsOneWithoutHanging's own comment for
	// why leaving this unset would let an unrelated missing-cache-config failure stand in for the
	// property this test's name actually claims.
	t.Setenv(cacheStalenessWindowEnv, "1h")
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", "   ")

	var stdout, stderr bytes.Buffer
	var code int
	mustReturnWithin(t, 2*time.Second, func() {
		code = runMCPCmd(strings.NewReader(""), &stdout, &stderr)
	})

	if code != 1 {
		t.Fatalf("runMCPCmd() = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "STRATIUM_PEP_MCP_UPSTREAM_COMMAND") {
		t.Errorf("stderr = %q, want it to name the blank upstream command", stderr.String())
	}
}

// A command that does not exist fails at cmd.Start, before any relay goroutine is even started --
// proving that failure path itself reports and returns instead of blocking is what this test
// defends; the more elaborate "child exits after relaying" property is
// TestRunMCPCmd_RealUpstreamProcess_RelaysAndExitsCleanly's job. Hook env vars are set to a valid
// baseline (not cleared, like the mcp-only vars above) so this test actually reaches cmd.Start and
// exercises the property its name claims -- runMCPCmd now loads hookConfig too (for the PDP client
// decideAndRelay needs), and a missing HOOK var would deny earlier, at config loading, which would
// still satisfy this test's code==1/stdout-empty assertions for the WRONG reason.
func TestRunMCPCmd_UpstreamCommandNotFound_ExitsOneWithoutHanging(t *testing.T) {
	clearMCPEnv(t)
	clearHookEnv(t)
	setAllHookEnv(t, nil)
	// runMCPCmd now loads cacheConfig too (Task 3), before ever reaching cmd.Start -- a missing
	// value here would deny at config loading instead, which would still satisfy this test's
	// code==1/stdout-empty assertions for the WRONG reason and never actually exercise the
	// cmd.Start failure path its own name and doc comment claim to test.
	t.Setenv(cacheStalenessWindowEnv, "1h")
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", "stratium-pep-mcp-upstream-that-does-not-exist")

	var stdout, stderr bytes.Buffer
	var code int
	mustReturnWithin(t, 2*time.Second, func() {
		code = runMCPCmd(strings.NewReader(""), &stdout, &stderr)
	})

	if code != 1 {
		t.Fatalf("runMCPCmd() = %d, want 1; stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

// --- runMCPCmd against a real subprocess --------------------------------

// TestMCPHelperProcess is not a real test -- it is how TestRunMCPCmd_RealUpstreamProcess below
// gets a controllable, REAL "upstream MCP server" to launch as a subprocess. Re-executing the
// test binary itself, rather than shelling out to `cat` or a shell script, is what keeps this
// hermetic and portable: no dependency on an external command whose exact behavior and
// availability this suite would otherwise be trusting. The standard library's own os/exec tests
// use the same trick.
//
// The unconditional early return keeps this a genuine no-op under a normal `go test ./...` run --
// STRATIUM_MCP_TEST_HELPER is never set then, so execution never reaches the os.Exit(0) below and
// this just reports itself passed like any other test. Under the helper invocation, that same
// os.Exit(0) is what stops execution from continuing into the testing package's own PASS/summary
// output, which would otherwise land on this process's stdout and corrupt the one JSON-RPC line
// the parent test reads as this "server"'s entire response.
func TestMCPHelperProcess(t *testing.T) {
	if os.Getenv("STRATIUM_MCP_TEST_HELPER") != "1" {
		return
	}
	defer os.Exit(0)

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return // parent closed stdin without sending a request -- exit cleanly, nothing to answer
	}
	var req struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal([]byte(line), &req) != nil {
		return // not this helper's job to be a well-formed client -- just don't crash on one
	}
	_, _ = fmt.Fprintf(os.Stdout, `{"jsonrpc":"2.0","id":%s,"result":{"echo":true}}`+"\n", req.ID)
}

// The one test in this file that exercises runMCPCmd's actual process wiring -- exec.Command,
// StdinPipe/StdoutPipe, Start, Wait -- against a REAL OS subprocess, rather than the in-memory
// pipes every other test in this file uses for the relay logic (runMCP) itself. It is what stands
// in for "the child exiting is handled without hanging" at the level that property actually lives
// at: a real process actually exiting, not a simulated EOF.
func TestRunMCPCmd_RealUpstreamProcess_RelaysAndExitsCleanly(t *testing.T) {
	clearMCPEnv(t)
	clearHookEnv(t)
	setAllHookEnv(t, nil) // this test never sends tools/call, so the PDP is dialed but never actually called
	// runMCPCmd now loads cacheConfig too (Task 3): a missing value here would deny before ever
	// reaching cmd.Start, for a reason this test is not about -- see
	// TestRunMCPCmd_UpstreamCommandNotFound_ExitsOneWithoutHanging's own comment for the identical
	// concern on its neighbour.
	t.Setenv(cacheStalenessWindowEnv, "1h")
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", os.Args[0])
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_ARGS", "-test.run=TestMCPHelperProcess")
	t.Setenv("STRATIUM_MCP_TEST_HELPER", "1")

	agentIn := strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}` + "\n")
	var agentOut, agentErr bytes.Buffer

	var code int
	mustReturnWithin(t, 5*time.Second, func() {
		code = runMCPCmd(agentIn, &agentOut, &agentErr)
	})

	if code != 0 {
		t.Fatalf("runMCPCmd() = %d, want 0; stderr: %s", code, agentErr.String())
	}
	const want = `{"jsonrpc":"2.0","id":7,"result":{"echo":true}}` + "\n"
	if agentOut.String() != want {
		t.Errorf("agent received %q, want %q", agentOut.String(), want)
	}
}

// --- runMCP: relay properties, over in-memory pipes ---------------------

// mcpHarness wires runMCP to four in-memory pipes standing in for the agent and the upstream, and
// gives a test a way to act as both: send as the agent, observe what the upstream received, send
// as the upstream, and observe what the agent received. Using real pipes (not bytes.Buffer)
// matters here specifically because several tests need to prove things about a still-open,
// still-blocked stream -- a buffer has no notion of "no more data yet, but not EOF either".
type mcpHarness struct {
	agentSend        *io.PipeWriter
	agentReceived    *frameSource
	upstreamReceived *frameSource
	upstreamSend     *io.PipeWriter
	stderr           *bytes.Buffer
	done             chan error
}

// unusedAuthzFixture returns a client+cfg pair for tests in this file that construct an mcpHarness
// but never send a tools/call frame -- every test below except the ones in mcp_authorize_test.go.
// runMCP now always needs a PDP client and a hookConfig (mcp_authorize.go's mcpAuthorizer holds
// both), but a test proving a property of the relay itself (tools/list, an unknown method, a
// malformed frame, id fidelity, concurrency, shutdown) has no reason to also script a real PDP
// scenario -- nothing here is ever dialed by any of them. Tests that DO send tools/call and care
// what the PDP says construct their own fakePDP directly instead, the same explicit-per-test style
// hook_test.go's escalation tests already use -- see mcp_authorize_test.go.
func unusedAuthzFixture(t *testing.T) (pdpgrpc.PDPServiceClient, hookConfig) {
	t.Helper()
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	return startFakePDP(t, fake), testCfg(t)
}

func newMCPHarness(t *testing.T, client pdpgrpc.PDPServiceClient, cfg hookConfig) *mcpHarness {
	t.Helper()
	agentToProxyR, agentToProxyW := io.Pipe()
	proxyToAgentR, proxyToAgentW := io.Pipe()
	proxyToUpstreamR, proxyToUpstreamW := io.Pipe()
	upstreamToProxyR, upstreamToProxyW := io.Pipe()

	var stderr bytes.Buffer
	h := &mcpHarness{
		agentSend:        agentToProxyW,
		agentReceived:    newFrameSource(proxyToAgentR),
		upstreamReceived: newFrameSource(proxyToUpstreamR),
		upstreamSend:     upstreamToProxyW,
		stderr:           &stderr,
		done:             make(chan error, 1),
	}
	go func() {
		h.done <- runMCP(agentToProxyR, proxyToAgentW, proxyToUpstreamW, upstreamToProxyR, &stderr, client, cfg, testCacheCfg)
	}()
	// Safety net, not the primary shutdown path any individual test relies on: closing both send
	// sides guarantees the background runMCP goroutine (and this harness's own frameSource
	// goroutines) exit even if a test forgets to, so one leaked pipe cannot hang a later test.
	t.Cleanup(func() {
		_ = agentToProxyW.Close()
		_ = upstreamToProxyW.Close()
	})
	return h
}

// sendFromAgent writes one frame, as the agent would, terminated by the newline the stdio
// transport uses as a frame delimiter.
func (h *mcpHarness) sendFromAgent(t *testing.T, frame string) {
	t.Helper()
	if _, err := io.WriteString(h.agentSend, frame+"\n"); err != nil {
		t.Fatalf("write as agent: %v", err)
	}
}

func (h *mcpHarness) sendFromUpstream(t *testing.T, frame string) {
	t.Helper()
	if _, err := io.WriteString(h.upstreamSend, frame+"\n"); err != nil {
		t.Fatalf("write as upstream: %v", err)
	}
}

// shutdown closes both ends the way a real session ends -- the agent hangs up, and (in this
// harness) so does the simulated upstream -- and waits for runMCP to return, failing the test if
// it does not within maxWait. Only used by tests that need to inspect stderr or runMCP's own
// return value afterward; tests that only check what was or was not relayed rely on t.Cleanup
// instead and never call this.
func (h *mcpHarness) shutdown(t *testing.T, maxWait time.Duration) error {
	t.Helper()
	_ = h.agentSend.Close()
	_ = h.upstreamSend.Close()
	select {
	case err := <-h.done:
		return err
	case <-time.After(maxWait):
		t.Fatalf("runMCP did not return within %s of both sides closing -- looks hung", maxWait)
		return nil
	}
}

// readFrame reads the next frame src produces within maxWait, or fails the test -- the same
// bounded-wait discipline mustReturnWithin (hook_test.go) applies to a whole function call,
// applied here to one frame arriving on a channel, so a relay bug that silently drops or never
// forwards a frame is a fast, precisely located test failure instead of a hang.
func readFrame(t *testing.T, src *frameSource, maxWait time.Duration) []byte {
	t.Helper()
	select {
	case line, ok := <-src.frames:
		if !ok {
			t.Fatalf("frame source closed before producing a frame (err: %v)", <-src.errc)
		}
		return line
	case <-time.After(maxWait):
		t.Fatalf("no frame within %s -- relay likely dropped it or never forwarded it", maxWait)
		return nil
	}
}

// assertNoFrame fails the test if src produces a frame within maxWait -- the negative twin of
// readFrame, for proving a frame was dropped (never forwarded) rather than merely delayed.
func assertNoFrame(t *testing.T, src *frameSource, maxWait time.Duration) {
	t.Helper()
	select {
	case line, ok := <-src.frames:
		if ok {
			t.Fatalf("got unexpected frame %q, want none forwarded", line)
		}
	case <-time.After(maxWait):
		// Nothing arrived in the window -- correct.
	}
}

func TestRunMCP_ToolsListRoundTripsUnchanged(t *testing.T) {
	client, cfg := unusedAuthzFixture(t)
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	h.sendFromAgent(t, req)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
		t.Errorf("upstream received %q, want %q unchanged", got, req)
	}

	const resp = `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
	h.sendFromUpstream(t, resp)
	if got := readFrame(t, h.agentReceived, time.Second); string(got) != resp {
		t.Errorf("agent received %q, want %q unchanged", got, resp)
	}
}

// A method this proxy has never heard of, and never will have a case for by name, must relay
// exactly like tools/list does -- the whole point of "relay faithfully" is that this proxy's
// behavior does not depend on recognizing the method at all. See the package doc's RELAY
// FAITHFULLY note.
func TestRunMCP_UnknownMethodRoundTripsUnchanged(t *testing.T) {
	client, cfg := unusedAuthzFixture(t)
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":"req-2","method":"x-vendor/frobnicate","params":{"widget":"a"}}`
	h.sendFromAgent(t, req)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
		t.Errorf("upstream received %q, want %q unchanged", got, req)
	}
}

// A notification (method, no id) is a structurally different frame shape from a request or a
// response -- proves the relay does not assume every frame has an id.
func TestRunMCP_NotificationRoundTripsUnchanged(t *testing.T) {
	client, cfg := unusedAuthzFixture(t)
	h := newMCPHarness(t, client, cfg)

	const notif = `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":50}}`
	h.sendFromAgent(t, notif)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != notif {
		t.Errorf("upstream received %q, want %q unchanged", got, notif)
	}
}

// The property named directly in the task brief: an id may be a string, a number, or null, and
// none of the three may come back changed. Each case asserts the WHOLE frame is byte-identical,
// which is a strictly stronger check than comparing the id field alone -- and correct, because
// this proxy relays raw bytes rather than reconstructing JSON at all (see the package doc); if
// that ever stopped being true, id fidelity would be the first casualty, not an isolated one.
func TestRunMCP_RequestIDTypes_RoundTripExactly(t *testing.T) {
	tests := []struct {
		name string
		id   string // exact JSON text of the id, spliced into the frame below
	}{
		{"string id", `"abc-123"`},
		{"positive integer id", `42`},
		{"zero id", `0`},
		{"negative integer id", `-7`},
		// 2^53+1: the smallest integer a float64 cannot represent exactly. A relay that decoded
		// id through interface{} (json.Unmarshal's default for "any numeric value") and
		// re-encoded it would silently corrupt exactly this case.
		{"integer beyond float64 precision", `9007199254740993`},
		{"null id", `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, cfg := unusedAuthzFixture(t)
			h := newMCPHarness(t, client, cfg)
			req := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"ping"}`, tt.id)
			h.sendFromAgent(t, req)
			if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
				t.Errorf("upstream received %q, want %q unchanged", got, req)
			}

			resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{}}`, tt.id)
			h.sendFromUpstream(t, resp)
			if got := readFrame(t, h.agentReceived, time.Second); string(got) != resp {
				t.Errorf("agent received %q, want %q unchanged", got, resp)
			}
		})
	}
}

// Two properties in one test, because they are two halves of the same fail-closed rule: a
// malformed frame must never reach the upstream, AND it must not be mistaken for a reason to stop
// relaying everything else. A relay that panics or wedges on the first garbled line would be
// exactly as unsafe as one that forwards it.
func TestRunMCP_MalformedFrame_DroppedNotForwardedAndStreamContinues(t *testing.T) {
	client, cfg := unusedAuthzFixture(t)
	h := newMCPHarness(t, client, cfg)

	// A marker embedded in the malformed line itself, checked absent from stderr below -- proof
	// of the "never log frame contents" rule, not just a claim about it in a comment.
	h.sendFromAgent(t, `this is not json at all -- MARKER-DO-NOT-LOG`)
	assertNoFrame(t, h.upstreamReceived, 200*time.Millisecond)

	const validReq = `{"jsonrpc":"2.0","id":9,"method":"ping"}`
	h.sendFromAgent(t, validReq)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != validReq {
		t.Errorf("upstream received %q, want %q -- the relay must keep working after a bad frame", got, validReq)
	}

	if err := h.shutdown(t, 2*time.Second); err != nil {
		t.Errorf("runMCP() returned error %v, want nil on an orderly shutdown", err)
	}
	if strings.Contains(h.stderr.String(), "MARKER-DO-NOT-LOG") {
		t.Errorf("stderr contains the malformed frame's own content: %q", h.stderr.String())
	}
}

// Defends the CONCURRENCY property named in the task brief: the agent may pipeline several
// requests without waiting for a reply to any of them, and the upstream may answer out of order.
// Neither direction may block on the other resolving first. If a later change added synchronous
// per-request correlation to this relay -- e.g. "hold request 2 until request 1's response is
// seen" -- this test is what would catch it, by timing out waiting for request 2 to reach the
// upstream.
//
// Deliberately NOT tools/call (Task 1's version of this test used it as an arbitrary payload, back
// when nothing was gated): as of Task 2, two DIFFERENT tools/call frames each get their own
// decision goroutine (mcp_authorize.go), so which one's forward() call wins the race to upstream is
// no longer guaranteed to match arrival order at all -- asserting req1-then-req2 for tools/call
// specifically would make THIS test flaky rather than proving anything, for a reason that has
// nothing to do with the property it exists to defend. Two arbitrary, ungated method names still
// prove exactly that property (relayDirection's own loop never serializes on a reply), without
// depending on tools/call's now-genuinely-concurrent ordering.
// TestDecideAndRelay_ConcurrentToolsCalls_DoNotSerialize (mcp_authorize_test.go) is tools/call's own
// version of this property, phrased the way that path can actually promise: neither decision blocks
// the other from STARTING, not that either finishes first.
func TestRunMCP_PipelinedRequests_NotSerializedBehindEachOther(t *testing.T) {
	client, cfg := unusedAuthzFixture(t)
	h := newMCPHarness(t, client, cfg)

	const req1 = `{"jsonrpc":"2.0","id":1,"method":"custom/slow_op"}`
	const req2 = `{"jsonrpc":"2.0","id":2,"method":"custom/fast_op"}`
	h.sendFromAgent(t, req1)
	h.sendFromAgent(t, req2)

	// Both must reach the upstream promptly even though NEITHER has been answered yet -- proving
	// the agent->upstream direction does not wait for a response between forwarding requests.
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req1 {
		t.Errorf("upstream received %q first, want %q", got, req1)
	}
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req2 {
		t.Errorf("upstream received %q second, want %q", got, req2)
	}

	// The upstream answers out of order (2 before 1) -- the proxy imposes no ordering or
	// correlation of its own, it only streams what arrives.
	const resp2 = `{"jsonrpc":"2.0","id":2,"result":{"fast":true}}`
	const resp1 = `{"jsonrpc":"2.0","id":1,"result":{"slow":true}}`
	h.sendFromUpstream(t, resp2)
	h.sendFromUpstream(t, resp1)

	if got := readFrame(t, h.agentReceived, time.Second); string(got) != resp2 {
		t.Errorf("agent received %q first, want %q (upstream's own order, unmodified)", got, resp2)
	}
	if got := readFrame(t, h.agentReceived, time.Second); string(got) != resp1 {
		t.Errorf("agent received %q second, want %q", got, resp1)
	}
}

// The other required property from the task brief, in its hardest form: the upstream ends while
// the agent side is still open and has sent nothing more -- there is no natural EOF on the agent
// side to fall back on. Only active cross-direction cancellation (runMCP's shared context) can
// make this return promptly; this is exactly the test mutation (d) in the task's report is
// checked against.
func TestRunMCP_UpstreamExit_TerminatesWithoutHangingEvenIfAgentStaysOpen(t *testing.T) {
	client, cfg := unusedAuthzFixture(t)
	h := newMCPHarness(t, client, cfg)
	// Deliberately do not close or write to h.agentSend -- the agent looks fully alive.

	_ = h.upstreamSend.Close() // the child exiting closes its stdout, which looks like this to runMCP

	var err error
	mustReturnWithin(t, 2*time.Second, func() {
		err = <-h.done
	})
	if err != nil {
		t.Errorf("runMCP() returned error %v, want nil (upstream ending cleanly is not this proxy's error)", err)
	}
}

// The mirror image of the upstream-exit test above, in two steps matching runMCP's deliberately
// asymmetric shutdown (see its doc comment): the agent hanging up must (1) close upstreamIn --
// the signal a well-behaved child relies on to know it should exit -- promptly, WITHOUT waiting
// for the upstream to do anything first, and (2) NOT by itself terminate the whole relay: only
// once the upstream side also ends (simulating the child noticing its closed stdin and exiting in
// turn) does runMCP return. A version of this function that cancelled on agent-exit alone would
// pass step 1 here but would have dropped an in-flight upstream reply in
// TestRunMCPCmd_RealUpstreamProcess_RelaysAndExitsCleanly -- that test is what actually caught it;
// this one pins the fix down at the runMCP level so a regression is caught here too, in
// milliseconds rather than by a subprocess test.
func TestRunMCP_AgentExit_ClosesUpstreamInputThenTerminatesOnceUpstreamAlsoEnds(t *testing.T) {
	client, cfg := unusedAuthzFixture(t)
	h := newMCPHarness(t, client, cfg)

	_ = h.agentSend.Close() // the agent hanging up

	// Step 1: upstreamIn must be closed promptly -- observable as h.upstreamReceived's source
	// seeing a clean EOF -- independent of anything the (still silent) simulated upstream does.
	select {
	case _, ok := <-h.upstreamReceived.frames:
		if ok {
			t.Fatal("got an unexpected frame; want the source closed (upstream's stdin was closed)")
		}
	case <-time.After(time.Second):
		t.Fatal("upstream side was not closed within 1s of the agent hanging up")
	}

	// Confirm runMCP has NOT returned yet: the upstream has not ended, so a still-possible
	// in-flight reply must not be abandoned. A generous window, not a race -- see
	// TestRunMCP_UpstreamExit_TerminatesWithoutHangingEvenIfAgentStaysOpen for the equivalent
	// "does eventually stop" proof in the other direction; this is its "does not stop too early"
	// counterpart.
	select {
	case err := <-h.done:
		t.Fatalf("runMCP() returned (err=%v) before the upstream ended -- an in-flight reply would have been dropped", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Step 2: the upstream ends (the child noticing its closed stdin and exiting, in a real run) --
	// now runMCP must return promptly.
	_ = h.upstreamSend.Close()
	var err error
	mustReturnWithin(t, 2*time.Second, func() {
		err = <-h.done
	})
	if err != nil {
		t.Errorf("runMCP() returned error %v, want nil", err)
	}
}
