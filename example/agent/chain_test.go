package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"stratium/internal/pdpgrpc"
)

// fakeChainPDP is a real PDPServiceServer implementing only CreateDelegation
// -- chain.go's only RPC -- scripted by call order: response/error index 0
// answers the first call BuildChain makes (the root), index 1 the second
// (the child). Dialled over a real loopback listener, the same
// startFakePDP/dialTestClient shape services/cmd/stratium-pep/pdp_fake_test.go
// already uses for its own fake PDP, so this test exercises the identical
// generated-client code path CreateDelegation (chain.go) uses in production.
type fakeChainPDP struct {
	pdpgrpc.UnimplementedPDPServiceServer
	responses []*pdpgrpc.CreateDelegationResponse
	errs      []error
	calls     []*pdpgrpc.CreateDelegationRequest
}

func (f *fakeChainPDP) CreateDelegation(_ context.Context, req *pdpgrpc.CreateDelegationRequest) (*pdpgrpc.CreateDelegationResponse, error) {
	i := len(f.calls)
	f.calls = append(f.calls, req)
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	if i < len(f.responses) {
		return f.responses[i], nil
	}
	return nil, status.Error(codes.Internal, "fakeChainPDP: no scripted response for this call")
}

func startFakeChainPDP(t *testing.T, srv *fakeChainPDP) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	pdpgrpc.RegisterPDPServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

func TestBuildChain_NarrowingChildSucceeds(t *testing.T) {
	parentScope := &pdpgrpc.RequestedScope{MaxActionTier: 1, Tools: []string{"Read", "Grep"}}
	childScope := &pdpgrpc.RequestedScope{MaxActionTier: 1, Tools: []string{"Read"}}

	fake := &fakeChainPDP{responses: []*pdpgrpc.CreateDelegationResponse{
		{DelegationId: "parent-id", GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 1, Tools: parentScope.Tools}, Token: "parent-token"},
		{DelegationId: "child-id", GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 1, Tools: childScope.Tools}, Token: "child-token"},
	}}
	addr := startFakeChainPDP(t, fake)

	chain, err := BuildChain(addr, "subject@example.com", "parent-agent", "child-agent", parentScope, childScope, "test", 3600)
	if err != nil {
		t.Fatalf("BuildChain() error = %v, want nil", err)
	}
	if chain.Parent.DelegationID != "parent-id" || chain.Child.DelegationID != "child-id" {
		t.Fatalf("chain = %+v, want parent-id/child-id", chain)
	}
	if chain.Child.DelegationID == chain.Parent.DelegationID {
		t.Fatal("child and parent share a delegation id")
	}
	if len(fake.calls) != 2 {
		t.Fatalf("CreateDelegation called %d times, want 2", len(fake.calls))
	}
	if fake.calls[0].GetParentDelegationId() != "" {
		t.Errorf("root request named a parent_delegation_id: %q", fake.calls[0].GetParentDelegationId())
	}
	if got := fake.calls[1].GetParentDelegationId(); got != "parent-id" {
		t.Errorf("child request parent_delegation_id = %q, want %q", got, "parent-id")
	}
	if got := chain.Child.GrantedScope.GetTools(); len(got) != 1 || got[0] != "Read" {
		t.Errorf("child granted tools = %v, want [Read]", got)
	}
}

// A child that widens its parent must come back as an error naming the
// dimension that failed -- chain.go adds no narrowing logic of its own
// (store.CreateDelegation, services/internal/store/delegation.go, is what
// enforces models.ScopeNarrows), so this proves BuildChain propagates that
// refusal verbatim rather than swallowing or re-wording it.
func TestBuildChain_WideningChildNamesTheFailingDimension(t *testing.T) {
	parentScope := &pdpgrpc.RequestedScope{MaxActionTier: 1, Tools: []string{"Read"}}
	widerChildScope := &pdpgrpc.RequestedScope{MaxActionTier: 1, Tools: []string{"Read", "Write"}}

	fake := &fakeChainPDP{
		responses: []*pdpgrpc.CreateDelegationResponse{
			{DelegationId: "parent-id", GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 1, Tools: parentScope.Tools}, Token: "parent-token"},
		},
		errs: []error{nil, status.Error(codes.PermissionDenied,
			`create delegation: store: child delegation does not narrow its parent: child tool "Write" not in parent approved_tools`)},
	}
	addr := startFakeChainPDP(t, fake)

	_, err := BuildChain(addr, "subject@example.com", "parent-agent", "child-agent", parentScope, widerChildScope, "test", 3600)
	if err == nil {
		t.Fatal("BuildChain() error = nil, want the widening child refused")
	}
	if !strings.Contains(err.Error(), "not in parent approved_tools") {
		t.Errorf("error does not name the failing dimension: %v", err)
	}
}

// The session file written for the CHILD must carry the child's own
// delegation id -- not the parent's -- or a surface reading it would
// authenticate as the wrong hop in the chain entirely.
func TestChainLink_WriteSessionFile_CarriesItsOwnDelegationID(t *testing.T) {
	parentScope := &pdpgrpc.RequestedScope{MaxActionTier: 1, Tools: []string{"Read", "Grep"}}
	childScope := &pdpgrpc.RequestedScope{MaxActionTier: 1, Tools: []string{"Read"}}
	fake := &fakeChainPDP{responses: []*pdpgrpc.CreateDelegationResponse{
		{DelegationId: "parent-id", GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 1, Tools: parentScope.Tools}, Token: "parent-token"},
		{DelegationId: "child-id", GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 1, Tools: childScope.Tools}, Token: "child-token"},
	}}
	addr := startFakeChainPDP(t, fake)

	chain, err := BuildChain(addr, "subject@example.com", "parent-agent", "child-agent", parentScope, childScope, "test", 3600)
	if err != nil {
		t.Fatalf("BuildChain() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "child.session.json")
	if err := chain.Child.WriteSessionFile(path); err != nil {
		t.Fatalf("WriteSessionFile() error = %v", err)
	}

	got, err := ReadDelegationID(path)
	if err != nil {
		t.Fatalf("ReadDelegationID() error = %v", err)
	}
	if got != "child-id" {
		t.Errorf("session file names delegation %q, want the child's own %q", got, "child-id")
	}
	if got == chain.Parent.DelegationID {
		t.Fatal("session file for the child carries the PARENT's delegation id")
	}

	// Round-trip through the exact wire shape stratium-pep's own
	// writeSessionFile/loadSessionFile pair uses (session_file.go): plain
	// encoding/json over *pdpgrpc.CreateDelegationResponse, not a shape this
	// package invented for itself.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	var decoded pdpgrpc.CreateDelegationResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("session file is not stratium-pep's own shape: %v", err)
	}
	if decoded.GetDelegationId() != "child-id" {
		t.Errorf("decoded session file delegation_id = %q, want %q", decoded.GetDelegationId(), "child-id")
	}
}
