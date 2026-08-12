// resource_parity_test.go proves the property the task brief states directly: hook and mcp must
// send the same resource attributes for the same logical tool call, because a resource constraint
// that binds under one surface and not the other is worse than one that binds under neither -- it
// looks enforced. Both call sites (hook.go's runHook, mcp_authorize.go's decideAndRelay) route
// through the identical extractResourceAttrs (resource.go), so this test exists to catch a
// regression in THAT wiring -- e.g. a future edit to one call site that swaps in a different
// function, a different argument, or drops the field entirely -- not to re-prove the extraction
// logic itself, which resource_test.go already covers in isolation. Comparing the two surfaces'
// OWN outputs directly (rather than each separately against a literal) is deliberate: two
// individually-plausible-looking results can still differ from each other, and that is exactly the
// failure this test exists to catch, per the brief's instruction to test the equivalence directly
// rather than by reading both.
package main

import (
	"bytes"
	"fmt"
	"maps"
	"testing"
	"time"

	"stratium/internal/pdpgrpc"
)

func TestHookAndMCP_ResourceAttrsAreIdenticalForEquivalentCalls(t *testing.T) {
	tests := []struct {
		name  string
		tool  string
		input string
	}{
		{"Bash command", "Bash", `{"command":"rm -rf /"}`},
		{"Read file_path", "Read", `{"file_path":"/tmp/notes.txt"}`},
		{"Read path fallback", "Read", `{"path":"/tmp/fallback.txt"}`},
		{"Glob pattern", "Glob", `{"pattern":"**/*.go"}`},
		// Also carries recognized field names alongside the unrecognized tool
		// -- see hook_test.go's identical fixture for why that matters.
		{"unrecognized tool", "some_mcp_tool", `{"anything":"goes","command":"ls","file_path":"/etc/shadow"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hookResource := hookRequestResource(t, tt.tool, tt.input)
			mcpResource := mcpRequestResource(t, tt.tool, tt.input)

			if !maps.Equal(hookResource, mcpResource) {
				t.Errorf("hook sent resource %v, mcp sent resource %v for the same logical call (%s %s) -- "+
					"a resource constraint bound under one surface and not the other is worse than one bound "+
					"under neither, because it looks enforced", hookResource, mcpResource, tt.tool, tt.input)
			}
		})
	}
}

// hookRequestResource drives runHook, as TestRunHook_RequestCarriesResourceAttrs does, and returns
// the resource map the PDP actually received.
func hookRequestResource(t *testing.T, tool, toolInput string) map[string]string {
	t.Helper()
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody(tool, toolInput), &stdout, client, testCfg(t))
	if code != 0 {
		t.Fatalf("runHook() = %d, want 0 (fixture is an ALLOW); stdout: %s", code, stdout.String())
	}
	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request from runHook")
	}
	return req.GetResource()
}

// mcpRequestResource drives decideAndRelay (via the mcp harness) for the same logical tool call and
// returns the resource map the PDP actually received.
func mcpRequestResource(t *testing.T, tool, arguments string) map[string]string {
	t.Helper()
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tool, arguments)
	h.sendFromAgent(t, req)
	readFrame(t, h.upstreamReceived, time.Second) // synchronize: lastRequest is set before this returns

	got := fake.lastRequest()
	if got == nil {
		t.Fatal("PDP never received a request from decideAndRelay")
	}
	return got.GetResource()
}
