package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// ChainLink is one delegation minted by BuildChain: its id, what it was
// granted, and (via WriteSessionFile) the means to hand it to a surface that
// reads a session file the way stratium-pep's own session-start writes one.
type ChainLink struct {
	DelegationID string
	GrantedScope *pdpgrpc.GrantedScope

	resp *pdpgrpc.CreateDelegationResponse
}

// Token returns the signed JWT naming this delegation -- the same
// credential WriteSessionFile embeds in the session file, exposed here so a
// caller that wants to decode and display it (e.g. example/depth/hook's own
// narration of the chain it just built) does not have to re-read the
// session file back off disk to get it.
func (l ChainLink) Token() string {
	return l.resp.GetToken()
}

// WriteSessionFile writes path in the exact shape stratium-pep's own
// session-start does (services/cmd/stratium-pep/session_file.go's
// writeSessionFile): l's raw CreateDelegationResponse as indented JSON plus
// a trailing newline, so any surface's loadSessionFile/agent.ReadDelegationID
// reads it back unchanged. Not written atomically (no temp-file-plus-rename)
// -- unlike the product's own version, nothing else can be reading this path
// concurrently: an example calls this once, before ever launching the
// process that will read it.
func (l ChainLink) WriteSessionFile(path string) error {
	data, err := json.MarshalIndent(l.resp, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session file: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for session file %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write session file %s: %w", path, err)
	}
	return nil
}

// childTTLMargin is how much shorter the CHILD's requested TTL is than the
// PARENT's, in seconds -- see BuildChain's own doc comment for why this
// margin has to exist at all.
const childTTLMargin = 60

// Chain is a two-link delegation chain: Parent is a root (depth 0, granted
// directly from the principal); Child narrows it (depth 1,
// ParentDelegationId set to Parent's own id).
type Chain struct {
	Parent ChainLink
	Child  ChainLink
}

// CreateDelegation calls the PDP's CreateDelegation RPC directly, dialling
// pdpAddr fresh for this one call -- the same direct-pdpgrpc-dial precedent
// example/proxy/main.go's own MintBoundToken (setup.go) already establishes
// for IssueToken, reused here for the same reason: there is no
// `stratium-pep session-start` flag that can create a CHILD delegation
// (session-start has no parent concept at all -- ParentDelegationId is not
// among the fields it exposes), so a child has to go through this RPC
// directly. BuildChain, below, uses this for BOTH hops rather than routing
// the root through session-start and only the child through here: one code
// path, not two, and a caller gets both responses back from one call instead
// of shelling out once and then reading a session file back for the second.
//
// Exported so a caller can also mint a delegation this package's own
// two-link BuildChain does not shape -- e.g. a third, deliberately-widening
// child probed against an already-built chain's own parent, to prove
// ErrScopeWidens rather than to build anything usable.
func CreateDelegation(pdpAddr string, req *pdpgrpc.CreateDelegationRequest) (*pdpgrpc.CreateDelegationResponse, error) {
	conn, err := grpc.NewClient(pdpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial pdp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A gRPC status error (e.g. PermissionDenied for a widening child) is
	// returned to the caller as-is, not translated here: callers that care
	// about the difference between a policy refusal and a transport failure
	// use status.FromError themselves, exactly as example/proxy's own
	// proxyTransport.Call already does for Decide's PermissionDenied.
	return pdpgrpc.NewPDPServiceClient(conn).CreateDelegation(ctx, req)
}

// BuildChain mints a two-link delegation chain in one subject's name: a root
// (depth 0) granted parentScope, and a child (depth 1) narrowing it to
// childScope. store.CreateDelegation (services/internal/store/delegation.go)
// enforces the narrowing itself via permset.ScopeNarrows -- this function
// adds nothing on top of that check, so a childScope that widens parentScope
// on any dimension comes back as the PDP's own PermissionDenied error,
// naming the failing dimension in its message, unchanged.
//
// Surface-agnostic on purpose: everything a consumer might need to carry a
// hop's delegation onward -- its id, its granted scope, a session file in
// stratium-pep's own shape -- is on the returned Chain, and nothing here
// assumes how a caller will present the resulting token (a session file, a
// bearer header, a bound one). example/depth/hook is the first consumer;
// example/depth/mcp and example/depth/proxy follow later.
//
// ttlSeconds is requested for the PARENT as given; the CHILD requests
// ttlSeconds-childTTLMargin. Requesting the identical ttlSeconds for both
// would still widen: store.CreateDelegation computes each delegation's own
// ExpiresAt from time.Now() at the moment ITS OWN RPC runs, and the child's
// call unavoidably runs some (small) amount of time after the parent's --
// so an identical duration always yields a strictly LATER absolute expiry
// for the child, which permset.ScopeNarrows correctly refuses (confirmed
// against a live PDP: "child expires_at exceeds parent"). One fixed margin,
// comfortably larger than any realistic round trip between the two calls,
// is simpler and more robust than decoding the parent's own token
// client-side to read its exact expiry back.
func BuildChain(
	pdpAddr, subject, parentAgentID, childAgentID string,
	parentScope, childScope *pdpgrpc.RequestedScope,
	purpose string, ttlSeconds int64,
) (*Chain, error) {
	parentResp, err := CreateDelegation(pdpAddr, &pdpgrpc.CreateDelegationRequest{
		Subject:        subject,
		AgentId:        parentAgentID,
		RequestedScope: parentScope,
		Purpose:        purpose,
		TtlSeconds:     ttlSeconds,
	})
	if err != nil {
		return nil, fmt.Errorf("create parent delegation (depth 0): %w", err)
	}

	childTTL := ttlSeconds - childTTLMargin
	if childTTL < 1 {
		childTTL = 1
	}
	childResp, err := CreateDelegation(pdpAddr, &pdpgrpc.CreateDelegationRequest{
		Subject:            subject,
		AgentId:            childAgentID,
		RequestedScope:     childScope,
		ParentDelegationId: parentResp.GetDelegationId(),
		Purpose:            purpose,
		TtlSeconds:         childTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("create child delegation (depth 1): %w", err)
	}

	return &Chain{
		Parent: ChainLink{DelegationID: parentResp.GetDelegationId(), GrantedScope: parentResp.GetGrantedScope(), resp: parentResp},
		Child:  ChainLink{DelegationID: childResp.GetDelegationId(), GrantedScope: childResp.GetGrantedScope(), resp: childResp},
	}, nil
}
