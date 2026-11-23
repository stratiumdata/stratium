package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/internal/extmcp"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

func newExtmcpServer(t *testing.T, client pdpgrpc.PDPServiceClient) *extmcpServer {
	t.Helper()
	return &extmcpServer{authz: &mcpAuthorizer{client: client, cfg: testCfg(t), cache: newDecisionCache()}}
}

func toolsCall(target, params string) *extmcp.McpRequest {
	return &extmcp.McpRequest{ServiceNames: []string{target}, Method: "tools/call", McpRequest: []byte(params)}
}

func TestExtmcpCheckRequest(t *testing.T) {
	const call = `{"name":"read_file","arguments":{"path":"/tmp/notes.txt"}}`
	allow := &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}
	deny := &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "no policy permits files_read_file:call"}

	tests := []struct {
		name       string
		pdp        *pdpgrpc.DecideResponse
		req        *extmcp.McpRequest
		wantPass   bool
		wantReason string
		wantAsked  bool // a deny is asked twice: once more after a token reissue
	}{
		{"allow passes", allow, toolsCall("files", call), true, "", true},
		{"deny carries the PDP's reason", deny, toolsCall("files", call), false, deny.Reason, true},
		{"unset effect denies", &pdpgrpc.DecideResponse{}, toolsCall("files", call), false, "", true},
		{"other methods pass undecided", deny, &extmcp.McpRequest{ServiceNames: []string{"files"}, Method: "tools/list"}, true, "", false},
		{"no tool name", allow, toolsCall("files", `{"arguments":{}}`), false, "malformed", false},
		{"params are not JSON", allow, toolsCall("files", `{`), false, "malformed", false},
		{"underscore in the target", allow, toolsCall("my_files", call), false, "underscore", false},
		{"no target", allow, &extmcp.McpRequest{Method: "tools/call", McpRequest: []byte(call)}, false, "malformed", false},
		{"two targets", allow, &extmcp.McpRequest{ServiceNames: []string{"a", "b"}, Method: "tools/call", McpRequest: []byte(call)}, false, "malformed", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakePDP{resp: tt.pdp}
			res, err := newExtmcpServer(t, startFakePDP(t, fake)).CheckRequest(context.Background(), tt.req)
			if err != nil {
				t.Fatalf("CheckRequest returned an RPC error %v; a refusal must be an answer, or failOpen forwards the call", err)
			}
			if got := res.GetPass() != nil; got != tt.wantPass {
				t.Fatalf("pass = %v, want %v (result %v)", got, tt.wantPass, res)
			}
			if !tt.wantPass {
				if res.GetError().GetCode() != extmcp.AuthorizationError_PERMISSION_DENIED {
					t.Errorf("code = %v, want PERMISSION_DENIED", res.GetError().GetCode())
				}
				if !strings.Contains(res.GetError().GetReason(), tt.wantReason) {
					t.Errorf("reason = %q, want it to contain %q", res.GetError().GetReason(), tt.wantReason)
				}
			}
			if got := fake.requestCount() > 0; got != tt.wantAsked {
				t.Errorf("PDP asked = %v, want %v", got, tt.wantAsked)
			}
		})
	}
}

// The PDP is asked about the target-qualified name, with the arguments as
// the caller sent them.
func TestExtmcpCheckRequest_AsksAboutTargetQualifiedTool(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	srv := newExtmcpServer(t, startFakePDP(t, fake))
	if _, err := srv.CheckRequest(context.Background(), toolsCall("files", `{"name":"read_file","arguments":{"path":"/tmp/x"}}`)); err != nil {
		t.Fatal(err)
	}
	got := fake.lastRequest()
	if got.GetTool() != "files_read_file" || got.GetRawInput() != `{"path":"/tmp/x"}` {
		t.Errorf("asked about tool %q with input %q, want files_read_file and the call's arguments", got.GetTool(), got.GetRawInput())
	}
	if got.GetToken() != testSessionToken || got.GetAgentId() != srv.authz.cfg.AgentID {
		t.Errorf("request did not carry the session's token and agent: %v", got)
	}
}

func TestExtmcpCheckRequest_UnreachablePDP_DeniesAsAnAnswer(t *testing.T) {
	res, err := newExtmcpServer(t, unreachablePDPClient(t)).CheckRequest(context.Background(), toolsCall("files", `{"name":"read_file"}`))
	if err != nil {
		t.Fatalf("an unreachable PDP surfaced as an RPC error %v, which failOpen would forward", err)
	}
	if res.GetError() == nil {
		t.Fatalf("an unreachable PDP did not deny: %v", res)
	}
}

func TestExtmcpCheckResponse_Passes(t *testing.T) {
	res, err := (&extmcpServer{}).CheckResponse(context.Background(), &extmcp.McpResponse{Method: "tools/call"})
	if err != nil || res.GetPass() == nil {
		t.Fatalf("CheckResponse = %v, %v; want a pass", res, err)
	}
}

func TestRunExtmcpCmd_NamesEveryMissingVariable(t *testing.T) {
	for _, k := range []string{"STRATIUM_PEP_EXTMCP_LISTEN_ADDR", "STRATIUM_PEP_PDP_ADDR", "STRATIUM_PEP_SESSION_FILE"} {
		t.Setenv(k, "")
	}
	var stderr bytes.Buffer
	if code := runExtmcpCmd(&stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	for _, k := range []string{"STRATIUM_PEP_EXTMCP_LISTEN_ADDR", "STRATIUM_PEP_PDP_ADDR", "STRATIUM_PEP_SESSION_FILE"} {
		if !strings.Contains(stderr.String(), k) {
			t.Errorf("stderr %q does not name %s", stderr.String(), k)
		}
	}
}
