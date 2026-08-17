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
// Nine independent top-level tests, one per proof -- six from Phase 11 Task 4
// and three added by Phase 15 Task 6 for sender-constrained tokens (K5's
// refusal of an unbound token, K7's refusal of a proof bound to the TARGET's
// address, and K10's exclusion of the proof from the audit digest) -- rather
// than one test with nine t.Run subtests -- the same convention
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
	"crypto/ecdsa"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"stratium/internal/grpctarget"
	"stratium/internal/pdpgrpc"
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

// proxyPublicURI is the address every proof in this file ADDRESSES, as
// distinct from the ephemeral host:port it DIALS. It must equal
// docker-compose.yml's own pep-proxy STRATIUM_PEP_PROXY_PUBLIC_URI exactly
// (Phase 15, spec §4.7.2 K7): the proxy builds htu from that configured value
// and from nothing else, so a proof signed against anything but this string
// is refused at the PDP's htu comparison.
//
// The two differ on purpose, and not only because compose publishes 9292 on
// an ephemeral host port. It is the ordinary deployment shape: an agent
// connects to whatever address resolves and signs the stable public address
// into its proof. What makes that gap load-bearing HERE is that the proxy
// never reads the caller's own ":authority" at all -- unlike extauthz, which
// validates the caller's Host against an allowlist, this surface takes its
// identity from configuration and ignores the request entirely. So the live
// stack demonstrates that directly: every call below dials 127.0.0.1:<random>
// and signs proxy.stratium.test:9292, and it is the SIGNED value that has to
// match what the PEP reported for the call to be forwarded at all.
const proxyPublicURI = "http://proxy.stratium.test:9292"

// mintProxyBoundToken mints a token bound to key's public half (spec §4.7.2
// K6) through the real IssueToken RPC, so the containerized PDP's own
// verifier is what decides the token is genuine.
//
// Every proof below that expects to REACH the upstream has to use this rather
// than mintToken: proxy refuses an unbound token outright (K5,
// allowIfSenderConstrained), so a bearer token now produces PermissionDenied
// no matter how permissive the policy behind it is.
// TestIntegration_Proxy_UnboundTokenRefusedEvenWhenPermitted is the proof of
// exactly that.
//
// The proofs that expect a DENIAL deliberately keep calling mintToken, and
// that is not laziness: a denial they attribute to a revoked delegation or a
// tier ceiling must be attributable to THAT and not to a binding requirement
// that would have refused the call anyway. Each one asserts the PDP's own
// reason text, so a K5 refusal arriving instead fails them loudly rather than
// passing on the right status code for the wrong reason. Mirrors
// mintExtauthzBoundToken (extauthz_integration_test.go) exactly.
func mintProxyBoundToken(t *testing.T, delegationID uuid.UUID, key *ecdsa.PrivateKey) string {
	t.Helper()
	doc, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	jwk := string(doc)
	const ttlSeconds = 10 * 365 * 24 * 60 * 60 // always clamped to the delegation's own expiry; see mintToken
	resp, err := proxyPdpClient.IssueToken(t.Context(), &pdpgrpc.IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   ttlSeconds,
		DpopJwk:      &jwk,
	})
	if err != nil {
		t.Fatalf("mint bound token for delegation %s: %v", delegationID, err)
	}
	return resp.GetToken()
}

// proxyProof builds an RFC 9449 proof for the gRPC call this file is about to
// make through pep-proxy, signed by key. jti is fresh per call because K8
// makes it single-use in the database: two proofs sharing one would collide,
// and the second call would deny for replay rather than for whatever the
// calling proof is actually about.
//
// htm is POST unconditionally -- gRPC is HTTP/2 POST (K7) -- and htu is
// stated INDEPENDENTLY here rather than read back from anything the PEP
// computed: proxyPublicURI + fullMethod is the URI a real agent minting a
// proof for this call would use. So a call that reaches the upstream is the
// end-to-end evidence that cmd/stratium-pep/proxy.go built the SAME string
// from its own configuration and the method it was asked for, and that it did
// NOT build it from the address the client dialled, from the caller's
// ":authority", or from grpc-target's address. That is the only way this
// property can be checked from outside: the PDP compares the two, and neither
// side is visible to the other.
func proxyProof(t *testing.T, key *ecdsa.PrivateKey, fullMethod string) string {
	t.Helper()
	return proxyProofFor(t, key, proxyPublicURI+fullMethod)
}

// proxyProofFor is proxyProof with htu supplied outright, for the one proof
// that has to mint a deliberately WRONG one
// (TestIntegration_Proxy_ProofBoundToTheTargetsAddressIsRefused).
func proxyProofFor(t *testing.T, key *ecdsa.PrivateKey, htu string) string {
	t.Helper()
	proof, err := josejwt.Signed(mustDPoPSigner(t, key)).Claims(map[string]any{
		"htm": http.MethodPost,
		"htu": htu,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("serialize proof: %v", err)
	}
	return proof
}

// boundOutgoingCtx attaches both credentials a bound call needs -- the token
// in "authorization" and the RFC 9449 proof in "dpop" -- as OUTGOING gRPC
// metadata, which is what a real caller stub sends. The key is spelled
// "DPoP", the RFC's own spelling: grpc-go lower-cases metadata keys on the
// way out, so this also demonstrates that the casing the PEP actually
// receives is not the casing a client wrote.
func boundOutgoingCtx(ctx context.Context, token, proof string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token, "DPoP", proof)
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
	// Bound, with a proof, and that is now the ONLY shape this surface
	// forwards (K5). It also establishes something only a live stack can:
	// the htu this test signed independently (proxyPublicURI +
	// TargetService_Fetch_FullMethodName) is byte-identical to the one
	// pep-proxy built from its own configuration -- a proxy that reported
	// grpc-target's address, the address this client dialled, or the
	// ":authority" grpc-go put on the wire would deny at the PDP's htu
	// comparison instead of reaching the upstream at all.
	key := dpopKey(t)
	token := mintProxyBoundToken(t, delegation.ID, key)

	ctx := boundOutgoingCtx(t.Context(), token, proxyProof(t, key, grpctarget.TargetService_Fetch_FullMethodName))
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
		t.Errorf("status message = %q, want extractCredentialsFromMetadata's own K4 wording (%q) -- anything "+
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

// TestIntegration_Proxy_EscalateDegradesThenFreshProofRetrySucceeds is proof
// 5, and as of spec §4.7.2 K11 it proves the OPPOSITE of what it proved
// through Phase 11: an escalating call carrying a sender-constrained token
// does NOT block here. It degrades to a denial naming the pending approval,
// exactly as extauthz does -- and the client, once the approval lands,
// retries with a FRESH proof and is forwarded.
//
// WHY THE BLOCKING BEHAVIOUR HAD TO GO, measured rather than argued (this is
// what the pre-K11 version of this test actually failed with):
// escalation.go's resolveApproval must resend the request byte-identical,
// because resolveEscalation binds the approval to input_digest -- so it
// resends the same dpop_proof, whose jti the ORIGINAL call already spent, and
// the PDP refuses the retry with "store: dpop proof already spent" (K8). Had
// it not, a human slower than STRATIUM_DPOP_FRESHNESS_WINDOW would have put
// the same proof outside the window instead (K9). pep-proxy cannot mint a
// replacement: the client holds the private key, and a blocking surface has
// by definition not returned to the client. So §4.6's blocking/non-blocking
// split is narrower than it looked -- A SURFACE MAY BLOCK ONLY WHILE THE
// CREDENTIAL IT WOULD WAIT WITH OUTLIVES THE WAIT -- and a DPoP proof does
// not.
//
// THE SECOND HALF IS THE POINT. Proving the degrade alone would only prove
// that escalation fails. What makes K11 a workable ruling rather than a
// closed door is that the approved retry, carrying a proof the client minted
// after approval, actually reaches the upstream -- with proof of possession
// intact end to end and no approval ever consumed without a live proof. That
// is the second half below, and it is checked against grpc-target's own call
// counter rather than the caller's own success.
//
// The retry carries the approval id in "stratium-approval-id" metadata, the
// same key the degraded denial hands back in its trailer. See
// decideRequestFromStream (cmd/stratium-pep/proxy.go) for why this surface
// consumes that key instead of reporting it: raw_input must stay
// byte-identical to the escalating call's, since that is what the approval is
// bound to.
func TestIntegration_Proxy_EscalateDegradesThenFreshProofRetrySucceeds(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	escalateAt := models.ActionTierExternalComms
	delegation := newProxyDelegation(t, "proxy proof 5 (K11): an escalation degrades, and a fresh-proof retry is forwarded",
		models.ActionTierDestructive, &escalateAt)
	// ONE token, TWO proofs -- which is the whole ruling in one line. The
	// client keeps its key and mints a second proof after approval; nothing
	// re-presents the first.
	key := dpopKey(t)
	token := mintProxyBoundToken(t, delegation.ID, key)

	before, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{})
	if err != nil {
		t.Fatalf("CallCount() before error = %v", err)
	}

	// DEGRADES, and returns promptly rather than holding the stream open.
	// t.Context() with no goroutine is itself part of the assertion: through
	// Phase 11 this call blocked and had to run on one.
	var trailer metadata.MD
	_, err = proxyTargetClient.Fetch(
		boundOutgoingCtx(t.Context(), token, proxyProof(t, key, grpctarget.TargetService_Fetch_FullMethodName)),
		&grpctarget.EchoRequest{Message: "proof5-escalating"}, grpc.Trailer(&trailer))
	if err == nil {
		t.Fatal("Fetch() error = nil, want PermissionDenied -- K11 degrades an escalation on a bound token")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	approvalID := ""
	if got := trailer.Get(approvalIDHeaderName); len(got) == 1 {
		approvalID = got[0]
	}
	if approvalID == "" {
		t.Fatalf("trailer %s is empty -- K11 requires the denial to carry enough to FIND the pending "+
			"approval; without it the degrade is a dead end. status: %s", approvalIDHeaderName, status.Convert(err).Message())
	}
	if msg := status.Convert(err).Message(); !strings.Contains(msg, approvalID) {
		t.Errorf("status message = %q, want it to also carry approval id %q, for a human who captured only "+
			"the error", msg, approvalID)
	}
	if afterDegrade, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{}); err != nil {
		t.Fatalf("CallCount() after-degrade error = %v", err)
	} else if afterDegrade.GetCount() != before.GetCount() {
		t.Errorf("grpc-target's own call count = %d -> %d, want unchanged -- a degraded escalation is a "+
			"denial and must never reach the upstream", before.GetCount(), afterDegrade.GetCount())
	}

	// The id names a real pending row belonging to the right principal --
	// checked against the database, not merely echoed back.
	approvalUUID, err := uuid.Parse(approvalID)
	if err != nil {
		t.Fatalf("trailer %s = %q, want a UUID: %v", approvalIDHeaderName, approvalID, err)
	}
	pending := waitForPendingProxyApproval(t, delegation.ID)
	if pending.ID != approvalUUID {
		t.Fatalf("pending approval id = %s, want the one the denial named (%s)", pending.ID, approvalUUID)
	}
	if pending.RootPrincipal != proxySubject {
		t.Errorf("pending approval RootPrincipal = %q, want %q", pending.RootPrincipal, proxySubject)
	}

	// Out of band, exactly as the control plane would -- a direct UPDATE,
	// since the PDP's own serving role has no UPDATE grant on approvals (E7,
	// TestIntegration_Approvals_ServingRoleCannotUpdate).
	approveApproval(t, proxyTenant, pending.ID, proxySubject)

	// THE RETRY: same token, same method, same payload, a FRESH proof, and
	// the approval id. This is the half that makes K11 a workable ruling.
	retryCtx := metadata.AppendToOutgoingContext(
		boundOutgoingCtx(t.Context(), token, proxyProof(t, key, grpctarget.TargetService_Fetch_FullMethodName)),
		approvalIDHeaderName, approvalID)
	resp, err := proxyTargetClient.Fetch(retryCtx, &grpctarget.EchoRequest{Message: "proof5-escalating"})
	if err != nil {
		t.Fatalf("retry after approval error = %v, want success -- proof of possession has to survive an "+
			"approval end to end, or K11 leaves an escalating call with no way to ever complete", err)
	}
	if resp.GetMessage() != "proof5-escalating" {
		t.Errorf("response message = %q, want the target's own echoed %q", resp.GetMessage(), "proof5-escalating")
	}

	after, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{})
	if err != nil {
		t.Fatalf("CallCount() after error = %v", err)
	}
	if after.GetCount() != before.GetCount()+1 {
		t.Errorf("grpc-target's own call count = %d -> %d, want exactly +1 -- reached exactly once, only "+
			"on the approved retry", before.GetCount(), after.GetCount())
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
	// ONE bound token and ONE proof for the whole stream, which is P4 stated
	// in Phase 15's terms: the stream is authorized once, at open, so it gets
	// one Decide call carrying one proof, whose single-use jti (K8) is spent
	// once. Every message below rides that. There is deliberately no second
	// proof minted here, and a build that asked for one per message would
	// fail this test twice over -- on the audit-row count below, and against
	// the real jti table, which would refuse the second presentation of the
	// same proof outright.
	key := dpopKey(t)
	token := mintProxyBoundToken(t, delegation.ID, key)

	before := fetchAuditChain(t, proxyTenant)

	ctx := boundOutgoingCtx(t.Context(), token, proxyProof(t, key, grpctarget.TargetService_Chat_FullMethodName))
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

// TestIntegration_Proxy_UnboundTokenRefusedEvenWhenPermitted is proof 7 and
// spec §4.7.2 K5's own live proof on this surface: a token minted WITHOUT
// dpop_jwk is refused here, against a delegation and a policy that permit the
// action outright.
//
// It is the converse half of C25 and the migration hole a suite written from
// C25's own sentence leaves wide open: C25 says a BOUND token presented
// without a proof is denied, and says nothing at all about a token that was
// never bound. An attacker who simply asks for an ordinary bearer token never
// has to defeat a binding at all.
//
// The delegation is the same shape proof 1 uses -- DESTRUCTIVE ceiling, no
// EscalateAt, the same permit policy -- so the ONLY difference between this
// call and one that is forwarded is that the token is minted with no
// dpop_jwk. That is what makes this a real negative test rather than a call
// that denies for something it happens to also have wrong. The refusal is
// checked against grpc-target's OWN call counter, not merely against the
// caller's error: a proxy that forwards and then errors has already leaked
// the request.
func TestIntegration_Proxy_UnboundTokenRefusedEvenWhenPermitted(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	before, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{})
	if err != nil {
		t.Fatalf("CallCount() before error = %v", err)
	}

	delegation := newProxyDelegation(t, "proxy proof 7 (K5): an unbound token is refused even when permitted",
		models.ActionTierDestructive, nil)
	// mintToken, not mintProxyBoundToken: no dpop_jwk, so the PDP mints an
	// ordinary bearer token, allows the action, and reports
	// sender_constrained=false. The refusal is the PEP's.
	token := mintToken(t, proxyPdpClient, delegation.ID)

	_, err = proxyTargetClient.Fetch(bearerOutgoingCtx(t.Context(), token), &grpctarget.EchoRequest{Message: "proof7-payload"})
	if err == nil {
		t.Fatal("Fetch() error = nil, want PermissionDenied -- an unbound token must be refused on this surface (K5)")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, "dpop_jwk") {
		t.Errorf("status message = %q, want it to name dpop_jwk -- the only action available to a caller "+
			"holding an unbound token, and what makes this actionable rather than a wall", msg)
	}
	if strings.Contains(msg, "carried no dpop proof") {
		t.Errorf("status message = %q reads as C25's denial (a BOUND token with no proof), not K5's -- the "+
			"two name opposite defects and an operator has to act differently on each", msg)
	}

	after, err := directTargetClient.CallCount(t.Context(), &grpctarget.CallCountRequest{})
	if err != nil {
		t.Fatalf("CallCount() after error = %v", err)
	}
	if after.GetCount() != before.GetCount() {
		t.Errorf("grpc-target's own call count = %d -> %d, want unchanged -- a refused call must never "+
			"reach the upstream", before.GetCount(), after.GetCount())
	}
}

// TestIntegration_Proxy_ProofBoundToTheTargetsAddressIsRefused is proof 8 and
// the live demonstration of the replay spec §4.7.2 K7 exists to close:
// "Reporting the TARGET's address instead would let a proof minted for one
// target be replayed at another behind the same proxy."
//
// The call is identical to proof 1 in every respect -- same catalog, same
// permit policy, same DESTRUCTIVE-ceiling delegation, same bound token, same
// method -- except that its proof's htu names grpc-target's own address
// rather than the proxy's. If cmd/stratium-pep/proxy.go reported the target's
// address, this call would be FORWARDED, and one captured proof would be good
// at every target behind this proxy. It denies, which is what makes the
// authority component of the binding load-bearing rather than decorative.
//
// The second half is the control, and it is what stops this from being a test
// that passes because the fixture is broken in some unrelated way: the SAME
// key, the SAME token, and the SAME delegation, with only htu corrected, is
// forwarded. Without it, a proof that denied for a bad signature, an expired
// delegation, or a mis-seeded catalog would look identical to a proof denied
// for its htu.
func TestIntegration_Proxy_ProofBoundToTheTargetsAddressIsRefused(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	delegation := newProxyDelegation(t, "proxy proof 8 (K7): a proof minted for the target's address is refused",
		models.ActionTierDestructive, nil)
	key := dpopKey(t)
	token := mintProxyBoundToken(t, delegation.ID, key)

	// docker-compose.yml's own STRATIUM_PEP_PROXY_TARGET_ADDR, spelled as a
	// URI an agent would sign if it believed htu named where the call ends up
	// rather than where it was sent.
	const targetHTU = "http://grpc-target:50051" + grpctarget.TargetService_Fetch_FullMethodName
	_, err := proxyTargetClient.Fetch(
		boundOutgoingCtx(t.Context(), token, proxyProofFor(t, key, targetHTU)),
		&grpctarget.EchoRequest{Message: "proof8-wrong-htu"})
	if err == nil {
		t.Fatal("Fetch() error = nil, want PermissionDenied -- a proof bound to the TARGET's address must " +
			"not be usable at the proxy, or one captured proof is good at every target behind it")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	// The denial must be attributable to htu SPECIFICALLY -- not to the
	// signature, the freshness window, the thumbprint, or the jti -- or this
	// proof would pass for a call that was refused for some reason having
	// nothing to do with the target's address.
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, "htu") || !strings.Contains(msg, "does not match the observed uri") {
		t.Errorf("status message = %q, want internal/dpop's own htu-mismatch wording -- anything else means "+
			"this call was refused for a reason other than the authority its proof was minted for, which is "+
			"the one thing this proof is about", msg)
	}
	// NOT asserted here, and recorded as a finding rather than quietly
	// tolerated: that denial echoes BOTH canonical URIs back to the caller,
	// so it hands an arbitrary caller the exact htu that WOULD have matched.
	// That is the same free reconnaissance extauthz's own errUnservedAuthority
	// (cmd/stratium-pep/extauthz.go) deliberately refuses to give, and it is
	// pre-existing behaviour of internal/dpop's MatchesRequest -- shared with
	// hook and mcp, where the caller IS the operator and the text is genuinely
	// the diagnostic that makes a misconfigured client fixable. Narrowing it
	// for the network surfaces only is a change to a Task 1 file with two
	// audiences to weigh, not something this task decides in passing. See
	// task-6-report.md.

	// The control: same key, same token, same everything, htu corrected.
	resp, err := proxyTargetClient.Fetch(
		boundOutgoingCtx(t.Context(), token, proxyProof(t, key, grpctarget.TargetService_Fetch_FullMethodName)),
		&grpctarget.EchoRequest{Message: "proof8-right-htu"})
	if err != nil {
		t.Fatalf("Fetch() with the correct htu error = %v, want success -- without this the denial above "+
			"could have been about the key, the token, the delegation, or the catalog rather than about htu", err)
	}
	if resp.GetMessage() != "proof8-right-htu" {
		t.Errorf("response message = %q, want the target's own echoed %q", resp.GetMessage(), "proof8-right-htu")
	}
}

// TestIntegration_Proxy_ProofExcludedFromAuditDigest is proof 9 and spec
// §4.7.2 K10's own live proof on this surface: the DPoP proof never reaches
// raw_input, and therefore never reaches the append-only audit chain that
// commits to it.
//
// It is proved by DIFFERENCE rather than by reconstruction, unlike extauthz's
// own proof 6. Reconstructing this surface's raw_input would mean
// enumerating every metadata key grpc-go itself puts on the wire
// (content-type, user-agent, grpc-accept-encoding, :authority, ...), which is
// a list this test would silently fall behind. Two calls that are identical
// except for their PROOF are enough, and are stronger against the mutation
// that matters: two proofs are two entirely different JWT strings (fresh jti,
// fresh signature, and they must be fresh -- K8 makes a jti single-use), so
// if either one reached raw_input the two audit rows' input_digests could not
// possibly agree. They must agree exactly.
//
// The control is the second half, and it is what stops the agreement from
// being vacuous: a third call differing only in an ORDINARY metadata value
// must produce a DIFFERENT digest. Without it, "the digests match" would also
// be satisfied by a raw_input that carried no metadata at all, or by a digest
// computed over something that ignores metadata entirely.
//
// context.Background(), not t.Context(): a context carrying a deadline makes
// grpc-go send a "grpc-timeout" header that counts DOWN. It does NOT reach
// raw_input -- the server handles it in its own switch case and isReservedHeader
// keeps it out of metadata entirely (internal/transport/http2_server.go), so
// this is belt-and-braces rather than a load-bearing choice. Kept anyway: the
// comparison below is only meaningful if the two calls are identical for
// reasons this test controls, and depending on a dependency's header filtering
// to keep them so is depending on it never changing.
func TestIntegration_Proxy_ProofExcludedFromAuditDigest(t *testing.T) {
	ensureProxyAgent(t)
	ensureProxyCatalog(t)
	ensureProxyPermitPolicy(t)

	delegation := newProxyDelegation(t, "proxy proof 9 (K10): no proof reaches the audit digest source",
		models.ActionTierDestructive, nil)
	key := dpopKey(t)
	token := mintProxyBoundToken(t, delegation.ID, key)

	digestAfter := func(ctx context.Context, payload string) [32]byte {
		t.Helper()
		if _, err := proxyTargetClient.Fetch(ctx, &grpctarget.EchoRequest{Message: payload}); err != nil {
			t.Fatalf("Fetch(%q) error = %v, want success", payload, err)
		}
		rows := fetchAuditChain(t, proxyTenant)
		if len(rows) == 0 {
			t.Fatalf("no audit rows for proxyTenant after %q", payload)
		}
		return rows[len(rows)-1].InputDigest
	}

	proofA := proxyProof(t, key, grpctarget.TargetService_Fetch_FullMethodName)
	proofB := proxyProof(t, key, grpctarget.TargetService_Fetch_FullMethodName)
	if proofA == proofB {
		t.Fatal("the two proofs are identical -- this proof compares two calls that differ ONLY in their " +
			"proof, so identical proofs would make the comparison below vacuous")
	}

	// The message body differs between the two calls on purpose: this surface
	// never parses a message (P3), so it cannot reach raw_input either, and a
	// digest that changed here would be a different defect worth failing on.
	digestA := digestAfter(boundOutgoingCtx(context.Background(), token, proofA), "proof9-call-a")
	digestB := digestAfter(boundOutgoingCtx(context.Background(), token, proofB), "proof9-call-b")
	if digestA != digestB {
		t.Fatalf("two calls to the same method with DIFFERENT proofs produced different audit input_digests "+
			"(%x vs %x) -- something that varies per call, and the only thing that did vary, is reaching "+
			"raw_input. A credential hashed into an append-only chain cannot be edited back out (K10)",
			digestA, digestB)
	}

	// The control: an ordinary, non-credential metadata value DOES change the
	// digest, so the agreement above is a fact about what raw_input contains
	// rather than about it containing nothing.
	marked := metadata.AppendToOutgoingContext(
		boundOutgoingCtx(context.Background(), token, proxyProof(t, key, grpctarget.TargetService_Fetch_FullMethodName)),
		"x-proof9-marker", "proof9-marker-value")
	if digestMarked := digestAfter(marked, "proof9-call-c"); digestMarked == digestA {
		t.Errorf("adding an ordinary metadata key left the audit input_digest unchanged (%x) -- raw_input "+
			"either carries no metadata at all or the digest does not commit to it, so the equality above "+
			"proves nothing about the proof specifically", digestMarked)
	}
}
