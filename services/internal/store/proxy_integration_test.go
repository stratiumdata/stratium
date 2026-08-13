//go:build integration

// Task 4's own proof (.superpowers/sdd/2026-08-13-phase-11-proxy/
// task-4-brief.md): Tasks 1-3 built cmd/stratium-pep/proxy.go and proved
// every required property against constructed proxyFrame payloads and a
// fake in-process PDP (proxy_test.go) -- none of it against a real gRPC
// service or a real Postgres-backed PDP. This file is that proof:
// deploy/docker/docker-compose.yml's own pdp-proxy, grpc-target, and
// pep-proxy services, driven the way a real caller would -- a real
// generated gRPC client (services/internal/grpctarget) dialled straight at
// pep-proxy's own published port, exactly as "an agent points its existing
// gRPC client at this process instead of the real target" (proxy.go's own
// package doc) describes.
//
// Six independent top-level tests, one per proof the brief asks for, rather
// than one test with six t.Run subtests -- the same convention
// extauthz_integration_test.go's own package doc establishes: conformance_
// test.go's own provenElsewhere pointer (C22, corrected by this task) needs
// a top-level Go function it can verify by name (conformance_pointer_
// test.go's own doc comment: a t.Run subtest name is a string argument
// evaluated at run time, not a declaration go/ast can see).
//
// ONE SHARED TOOL_CATALOG, VARIED DELEGATIONS. grpc-target exposes exactly
// two unary tool identities (Fetch, Purge) and one streaming one (Chat) --
// real, fixed, compiled-in RPC methods a generated client stub can call,
// unlike extauthz_integration_test.go's own per-proof HTTP paths (an HTTP
// route can be anything a server chooses to route; a gRPC method name is
// fixed at compile time by both ends). ensureProxyCatalog seeds all three,
// ONCE per tenant, idempotently (ON CONFLICT DO NOTHING -- the underlying
// table's own UNIQUE (tenant_id, tool_name), migrations/000013_tool_
// catalog), the same "one shared shape, reused throughout" choice
// escalation_integration_test.go's own package doc already makes and
// justifies: every proof below is independently runnable (go test -run
// selects any subset), so seeding must be safe to repeat, not a one-time
// fixture only the first proof in file order can rely on. What actually
// varies per proof is each proof's OWN delegation ceiling/escalate_at --
// escalation_integration_test.go's own pattern, applied to a second
// surface.
//
// FIXED IDENTITY. proxyAgentID and proxySubject are literal constants, not
// generated per test, because they must equal the compose file's own
// pep-proxy STRATIUM_PEP_AGENT_ID/STRATIUM_PEP_SUBJECT exactly -- proxy.go
// reads both from its own startup configuration, never from the call
// itself (proxy.go's own package doc, NO SESSION FILE), so no live gRPC
// call can ever name a different identity. Mirrors extauthzAgentID/
// extauthzSubject's own doc comment for the identical reason.
package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"stratium/internal/grpctarget"
	"stratium/internal/store"
	"stratium/pkg/models"
)

// proxyAgentID and proxySubject: see this file's own package doc, FIXED
// IDENTITY. The agent id has no meaning beyond matching
// docker-compose.yml's pep-proxy service; no key or secret sits behind it.
var proxyAgentID = uuid.MustParse("04ef809a-849f-404a-9a5c-015b7f73a014")

const proxySubject = "proxy-integration@example.com"

// proxyTrailerKey mirrors cmd/grpc-target/main.go's own trailerKey exactly
// -- duplicated, not imported: grpc-target's source lives in package main,
// which this external test package cannot import (the same reason
// extauthz_integration_test.go duplicates cmd/stratium-pep/extauthz.go's
// own unexported identifiers rather than importing them).
const proxyTrailerKey = "x-grpc-target-call"

// bearerOutgoingCtx attaches "authorization: Bearer token" to ctx as
// OUTGOING gRPC metadata -- what a real caller's own stub sends. Proof 3
// (no token) calls through with ctx unchanged instead, which is what
// actually proves K4 has no fallback: this helper is not involved on that
// path at all.
func bearerOutgoingCtx(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

// ensureProxyAgent idempotently inserts the one agent identity every proof
// in this file shares (proxyAgentID) -- ON CONFLICT DO NOTHING rather than
// a sync.Once guard, for the identical reason seedExtauthzAgentOnce
// (extauthz_integration_test.go) gives: this file's six tests are
// independent top-level functions specifically so `go test -run` can select
// any subset, and a Once keyed to whichever test happens to run first would
// leave a lone later invocation unseeded.
func ensureProxyAgent(t *testing.T) {
	t.Helper()
	withTenantTx(t, proxyTenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`INSERT INTO agents (id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
			proxyAgentID.String(), proxyTenant, "proxy-integration-agent", "anthropic", "claude",
			int64(models.TrustTierPlatformTrusted), true, false, []byte(`[]`),
		); err != nil {
			t.Fatalf("seed proxy agent: %v", err)
		}
	})
}

// ensureProxyCatalog idempotently seeds tool_catalog rows for all three of
// grpc-target's real RPCs -- see this file's own package doc, ONE SHARED
// TOOL_CATALOG, VARIED DELEGATIONS.
func ensureProxyCatalog(t *testing.T) {
	t.Helper()
	withTenantTx(t, proxyTenant, func(tx *sql.Tx) {
		for _, row := range []struct {
			tool string
			tier models.ActionTier
			verb string
		}{
			{"/stratium.target.v1.TargetService/Fetch", models.ActionTierDestructive, "fetch"},
			{"/stratium.target.v1.TargetService/Purge", models.ActionTierDestructive, "purge"},
			{"/stratium.target.v1.TargetService/Chat", models.ActionTierReadOnly, "chat"},
		} {
			if _, err := tx.ExecContext(t.Context(),
				`INSERT INTO tool_catalog (tenant_id, tool_name, action_tier, verb)
				 VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id, tool_name) DO NOTHING`,
				proxyTenant, row.tool, int64(row.tier), row.verb,
			); err != nil {
				t.Fatalf("seed proxy tool_catalog %s: %v", row.tool, err)
			}
		}
	})
}

// ensureProxyPermitPolicy seeds a fresh, uniquely-named blanket-permit
// cedar policy for proxyTenant, so the principal leg always allows and
// every proof's own DENY/ESCALATE below is unambiguously attributable to
// the delegation leg -- mirrors seedExtauthzPermitPolicy exactly, reusing
// escalationBlanketPermit (escalation_integration_test.go, same package)
// rather than redeclaring the identical one-liner a third time. A fresh
// name every call, like that helper: seedPolicy's underlying INSERT has no
// ON CONFLICT clause.
func ensureProxyPermitPolicy(t *testing.T) {
	t.Helper()
	seedPolicy(t, proxyTenant, "proxy-permit-"+uuid.New().String(), escalationBlanketPermit, "allow")
}

// newProxyDelegation seeds one root delegation for proxyAgentID/
// proxySubject with a fresh id, purpose, and expiry -- mirrors
// newExtauthzDelegation exactly.
func newProxyDelegation(t *testing.T, purpose string, maxTier models.ActionTier, escalateAt *models.ActionTier) *models.Delegation {
	t.Helper()
	id := uuid.New()
	return seedDelegation(t, &models.Delegation{
		ID: id, TenantID: proxyTenant, UserID: proxySubject, AgentID: proxyAgentID,
		ApprovedTools: []string{}, MaxActionTier: maxTier, EscalateAt: escalateAt,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: purpose, ExpiresAt: time.Now().Add(time.Hour),
		RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{proxyAgentID},
	})
}

// waitForPendingProxyApproval polls approvals for delegationID until a
// pending row exists, or fails t after 10s. The escalating call in proof 5
// runs on its own goroutine and creates this row synchronously, as part of
// its own first Decide round trip (pdpgrpc.Server.Decide's escalation path)
// -- well before pep-proxy's own poll loop (escalation.go's resolveApproval)
// would ever approach its 30s ApprovalTimeout (docker-compose.yml). 10s is
// generous headroom over a live docker network, not a value this test
// expects to need in full.
func waitForPendingProxyApproval(t *testing.T, delegationID uuid.UUID) *models.Approval {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var found *models.Approval
		withTenantTx(t, proxyTenant, func(tx *sql.Tx) {
			var idStr string
			err := tx.QueryRowContext(t.Context(),
				`SELECT id FROM approvals WHERE delegation_id = $1 AND status = 'pending' ORDER BY requested_at DESC LIMIT 1`,
				delegationID.String(),
			).Scan(&idStr)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return
				}
				t.Fatalf("poll pending approval for delegation %s: %v", delegationID, err)
			}
			id, err := uuid.Parse(idStr)
			if err != nil {
				t.Fatalf("pending approval id %q: %v", idStr, err)
			}
			a, err := store.New(testDB, proxyTenant).LoadApproval(t.Context(), id)
			if err != nil {
				t.Fatalf("LoadApproval(%s): %v", id, err)
			}
			found = a
		})
		if found != nil {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pending approval appeared for delegation %s within 10s", delegationID)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestIntegration_Proxy_PermittedActionReachesUpstream is proof 1: a valid
// token for a permitted method reaches grpc-target, and the response
// returns intact -- trailers included.
func TestIntegration_Proxy_PermittedActionReachesUpstream(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	delegation := newProxyDelegation(t, "proxy proof 1: a permitted action reaches the upstream, trailers included",
		models.ActionTierDestructive, nil)
	token := mintToken(t, proxyPdpClient, delegation.ID)

	ctx := bearerOutgoingCtx(t.Context(), token)
	var trailer metadata.MD
	resp, err := proxyTargetClient.Fetch(ctx, &grpctarget.EchoRequest{Message: "proof1-payload"}, grpc.Trailer(&trailer))
	if err != nil {
		t.Fatalf("Fetch() error = %v, want success (a permitted action must reach the upstream)", err)
	}
	if resp.GetMessage() != "proof1-payload" {
		t.Errorf("response message = %q, want the target's own echoed %q", resp.GetMessage(), "proof1-payload")
	}
	if resp.GetCallNumber() <= 0 {
		t.Errorf("response call_number = %d, want > 0 -- the target's own counter", resp.GetCallNumber())
	}

	wantTrailer := fmt.Sprintf("call-%d", resp.GetCallNumber())
	if got := trailer.Get(proxyTrailerKey); len(got) != 1 || got[0] != wantTrailer {
		t.Errorf("trailer %s = %v, want [%q] -- trailers must relay intact, and name this exact call",
			proxyTrailerKey, got, wantTrailer)
	}

	rows := fetchAuditChain(t, proxyTenant)
	if len(rows) == 0 {
		t.Fatal("no audit rows for proxyTenant")
	}
	if last := rows[len(rows)-1]; last.Decision != "ALLOW" {
		t.Errorf("most recent audit row Decision = %q, want %q", last.Decision, "ALLOW")
	}
}

// TestIntegration_Proxy_DeniedActionNeverReachesUpstream is proof 2: a
// valid token for a denied method does not reach grpc-target -- asserted
// against the target's OWN call counter (CallCount, dialled directly,
// bypassing the proxy entirely), not merely against the caller's own
// PermissionDenied error. See proxy.go's package doc, DENY BY DEFAULT: a
// proxy that forwards and then errors has already leaked the request,
// which checking only the caller's own response would miss entirely.
func TestIntegration_Proxy_DeniedActionNeverReachesUpstream(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	before, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{})
	if err != nil {
		t.Fatalf("CallCount() before error = %v", err)
	}

	// READ_ONLY ceiling under a DESTRUCTIVE-cataloged tool, no EscalateAt:
	// denies outright, never escalates -- deliberately distinct from proof
	// 5's own escalation case.
	delegation := newProxyDelegation(t, "proxy proof 2: a denied action must not reach the upstream",
		models.ActionTierReadOnly, nil)
	token := mintToken(t, proxyPdpClient, delegation.ID)

	ctx := bearerOutgoingCtx(t.Context(), token)
	_, err = proxyTargetClient.Purge(ctx, &grpctarget.EchoRequest{Message: "proof2-payload"})
	if err == nil {
		t.Fatal("Purge() error = nil, want PermissionDenied")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	const wantReason = "exceeds delegation max_action_tier"
	if msg := status.Convert(err).Message(); !strings.Contains(msg, wantReason) {
		t.Errorf("status message = %q, want it to carry the PDP's own tier-ceiling reason (%q)", msg, wantReason)
	}

	after, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{})
	if err != nil {
		t.Fatalf("CallCount() after error = %v", err)
	}
	if after.GetCount() != before.GetCount() {
		t.Errorf("grpc-target's own call count changed %d -> %d, want unchanged: a denied call must never "+
			"reach the target", before.GetCount(), after.GetCount())
	}
}

// TestIntegration_Proxy_NoTokenDeniesNoFallback is proof 3 (K4): a request
// with no token at all is denied, with no fallback credential this surface
// could have reached for instead -- no fixtures needed, mirroring
// extauthz's identical proof 3 (TestIntegration_Envoy_NoTokenDeniedNoFallback).
func TestIntegration_Proxy_NoTokenDeniesNoFallback(t *testing.T) {
	_, err := proxyTargetClient.Fetch(t.Context(), &grpctarget.EchoRequest{Message: "proof3-payload"})
	if err == nil {
		t.Fatal("Fetch() error = nil, want PermissionDenied")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	const wantReason = "no authorization metadata"
	if msg := status.Convert(err).Message(); !strings.Contains(msg, wantReason) {
		t.Errorf("status message = %q, want extractBearerTokenFromMetadata's own K4 wording (%q) -- anything "+
			"else risks masking a fallback path this surface must not have", msg, wantReason)
	}
}

// TestIntegration_Proxy_RevokedDelegationDeniesAtDelegationLeg is proof 4
// (K3): a token naming a delegation that is revoked AFTER the token was
// minted denies at the delegation leg, not the token check -- the property
// that makes a token an authenticated reference rather than a capability.
// Mirrors TestIntegration_Envoy_RevokedDelegationDeniedAtDelegationLeg
// exactly, over the real proxy instead of a real Envoy.
func TestIntegration_Proxy_RevokedDelegationDeniesAtDelegationLeg(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	delegation := newProxyDelegation(t, "proxy proof 4 (K3): a revoked delegation denies at the delegation leg",
		models.ActionTierDestructive, nil)
	token := mintToken(t, proxyPdpClient, delegation.ID) // minted while still active

	withTenantTx(t, proxyTenant, func(tx *sql.Tx) {
		res, err := tx.ExecContext(t.Context(), `UPDATE delegations SET revoked = true WHERE id = $1`, delegation.ID.String())
		if err != nil {
			t.Fatalf("revoke delegation: %v", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			t.Fatalf("revoke delegation: RowsAffected = %d, err = %v, want 1, nil", n, err)
		}
	})

	ctx := bearerOutgoingCtx(t.Context(), token)
	_, err := proxyTargetClient.Fetch(ctx, &grpctarget.EchoRequest{Message: "proof4-payload"})
	if err == nil {
		t.Fatal("Fetch() error = nil, want PermissionDenied")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, "is revoked") {
		t.Errorf("status message = %q, want DelegationLeg's own revocation wording (\"... is revoked\") -- "+
			"anything else means this was denied somewhere other than the real delegation-leg re-evaluation, "+
			"which is exactly what K3 requires", msg)
	}
	if strings.Contains(msg, "token") {
		t.Errorf("status message = %q, mentions \"token\" -- a revoked-delegation denial must come from "+
			"DelegationLeg, which knows nothing about tokens, not from token authentication", msg)
	}
}

// TestIntegration_Proxy_EscalateBlocksThenForwardsOnApproval is proof 5: an
// escalating call BLOCKS -- proxy is a blocking surface (spec §4.6), unlike
// extauthz's own non-blocking degrade (Phase 10 Task 4's proof 5) -- then
// forwards once an out-of-band approval resolves it. This is the blocking
// counterpart to Phase 10's non-blocking degrade, and it is the distinction
// spec §4.6 draws between the two surface classes -- proving both halves is
// what makes that distinction real rather than asserted.
//
// The Fetch call runs on its own goroutine because it blocks: pep-proxy
// holds the caller's own stream open (escalation.go's resolveApproval,
// reused unmodified from hook/mcp -- proxy.go's own package doc, ESCALATE
// BLOCKS) rather than returning immediately the way extauthz's Check must.
// The main goroutine polls for the pending approval row
// (waitForPendingProxyApproval) and approves it out of band, exactly as the
// control plane would -- a direct UPDATE, since the PDP's own serving role
// has no UPDATE grant on approvals (E7, TestIntegration_Approvals_
// ServingRoleCannotUpdate) -- while the call is still blocked. context.
// Background(), not t.Context(), backs the blocked call deliberately: it
// must keep running on its own goroutine independent of anything this test
// function's own context lifecycle does, the same choice proxy_test.go's
// own wire-level escalation test makes.
func TestIntegration_Proxy_EscalateBlocksThenForwardsOnApproval(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	escalateAt := models.ActionTierExternalComms
	delegation := newProxyDelegation(t, "proxy proof 5: an escalating call blocks, then forwards on approval",
		models.ActionTierDestructive, &escalateAt)
	token := mintToken(t, proxyPdpClient, delegation.ID)

	type fetchResult struct {
		resp *grpctarget.EchoResponse
		err  error
	}
	done := make(chan fetchResult, 1)
	go func() {
		ctx := bearerOutgoingCtx(context.Background(), token)
		resp, err := proxyTargetClient.Fetch(ctx, &grpctarget.EchoRequest{Message: "proof5-payload"})
		done <- fetchResult{resp: resp, err: err}
	}()

	// BLOCKS: nothing arrives yet, checked well before pep-proxy's own 30s
	// ApprovalTimeout (docker-compose.yml) could fire.
	select {
	case res := <-done:
		t.Fatalf("Fetch() returned early (resp=%v err=%v) -- the call must still be blocked on escalation", res.resp, res.err)
	case <-time.After(500 * time.Millisecond):
	}

	beforeApprove, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{})
	if err != nil {
		t.Fatalf("CallCount() before-approve error = %v", err)
	}

	pending := waitForPendingProxyApproval(t, delegation.ID)
	if pending.RootPrincipal != proxySubject {
		t.Errorf("pending approval RootPrincipal = %q, want %q", pending.RootPrincipal, proxySubject)
	}
	approveApproval(t, proxyTenant, pending.ID, proxySubject)

	// THEN FORWARDS: once approved, pep-proxy's own poll loop notices
	// (STRATIUM_PEP_APPROVAL_POLL_INTERVAL: 200ms, docker-compose.yml) and
	// forwards to the real target.
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("Fetch() error = %v, want success after approval", res.err)
		}
		if res.resp.GetMessage() != "proof5-payload" {
			t.Errorf("response message = %q, want the target's own echoed %q", res.resp.GetMessage(), "proof5-payload")
		}
		if res.resp.GetCallNumber() <= 0 {
			t.Errorf("response call_number = %d, want > 0 -- the target's own counter", res.resp.GetCallNumber())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Fetch() did not return within 20s after approval -- want the call to unblock and forward")
	}

	afterApprove, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{})
	if err != nil {
		t.Fatalf("CallCount() after-approve error = %v", err)
	}
	if afterApprove.GetCount() != beforeApprove.GetCount()+1 {
		t.Errorf("grpc-target's own call count = %d -> %d, want exactly +1 -- the target must be reached "+
			"exactly once, only after approval", beforeApprove.GetCount(), afterApprove.GetCount())
	}
}

// TestIntegration_Proxy_StreamAuthorizedOnceForwardsBothDirections is proof
// 6: a stream is authorized once at open and forwards in both directions --
// proxy's own P4 property (proxy.go's package doc, pinned at the unit level
// by TestHandleStream_AllowedStream_ForwardsBothDirections), proven here
// against a real bidirectional stream carrying real protobuf messages
// through the passthrough codec, not the hand-rolled proxyFrame payloads
// that unit test constructs directly.
func TestIntegration_Proxy_StreamAuthorizedOnceForwardsBothDirections(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	delegation := newProxyDelegation(t, "proxy proof 6: a stream is authorized once, at open, and forwards both ways",
		models.ActionTierReadOnly, nil)
	token := mintToken(t, proxyPdpClient, delegation.ID)

	before := fetchAuditChain(t, proxyTenant)

	ctx := bearerOutgoingCtx(t.Context(), token)
	stream, err := proxyTargetClient.Chat(ctx)
	if err != nil {
		t.Fatalf("Chat() error = %v", err)
	}

	for _, msg := range []string{"one", "two", "three"} {
		if err := stream.Send(&grpctarget.ChatMessage{Message: msg}); err != nil {
			t.Fatalf("Send(%q) error = %v", msg, err)
		}
		got, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv() error = %v, want the echoed %q", err, msg)
		}
		if got.GetMessage() != msg {
			t.Errorf("Recv() message = %q, want %q", got.GetMessage(), msg)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend() error = %v", err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("final Recv() error = %v, want io.EOF (clean end)", err)
	}

	after := fetchAuditChain(t, proxyTenant)
	if got, want := len(after)-len(before), 1; got != want {
		t.Errorf("new audit rows for this stream = %d, want exactly %d -- a stream is authorized once, at "+
			"open (P4), regardless of how many messages crossed it", got, want)
	}
	if last := after[len(after)-1]; last.Decision != "ALLOW" {
		t.Errorf("most recent audit row Decision = %q, want %q", last.Decision, "ALLOW")
	}
}
