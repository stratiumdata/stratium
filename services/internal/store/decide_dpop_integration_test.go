//go:build integration

// Integration proofs that the PDP's DECISION PATH spends a DPoP proof's jti
// against a real Postgres (spec §4.7.2 K7/K8, Phase 15 Task 4). Task 3's own
// spent_proof_integration_test.go already proves store.SpendProof works;
// what only these can establish is that Decide actually CALLS it, as the
// serving role, through real RLS, with a value the real column accepts.
//
// Three things a fake store cannot show:
//
//  1. A row genuinely lands in spent_proofs when a bound token's proof
//     verifies. The unit suite asserts the fake was called; only this asserts
//     the database has the row — and this phase has already found nine
//     instances of a mechanism plumbed and never populated.
//  2. A replay collides through the real PRIMARY KEY, not through a map in a
//     test double that models it.
//  3. The expiry this writer computes survives the real TIMESTAMPTZ column
//     unchanged. That value is unvalidated by SpendProof on purpose (it has
//     no clock and no window), so an expiry silently mangled in transit
//     would make every row reapable on the next sweep while replay
//     prevention quietly stopped working.
//
// servingDB throughout, never testDB: the PDP serves as stratium_app, and
// migration 000018's GRANT INSERT is invisible to a connection authenticated
// as the table's owner (see servingDB's own doc comment in
// store_integration_test.go).
package store_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"stratium/internal/config"
	"stratium/internal/dpop"
	"stratium/internal/pdpgrpc"
	"stratium/internal/policy"
	"stratium/internal/store"
	"stratium/internal/token"
	"stratium/pkg/models"
)

// The window this PDP is configured with. Odd and un-round on purpose: the
// expiry assertion below is exact, and a round number could coincide with a
// value some other mistake would produce.
const dpopITWindow = 97 * time.Second

const (
	dpopITMethod = "POST"
	dpopITURI    = "https://pep-proxy.example.com/stratium.pdp.v1.PDPService/Decide"
)

// dpopServer builds a real pdpgrpc.Server for tenant on the SERVING
// connection, configured with a real freshness window. tierOverrideServer
// (decide_tier_override_integration_test.go) is the shape this mirrors, down
// to reusing seedPolicy's blanket permit and escalationRegistry — only the
// DPoP window is added, and it is added because config.Load makes it
// required (K9) and Decide reads it on every bound-token call.
func dpopServer(t *testing.T, tenant string) (*pdpgrpc.Server, *token.Signer) {
	t.Helper()
	seedPolicy(t, tenant, "dpop-blanket-permit", escalationBlanketPermit, "allow")
	repo := store.New(servingDB, tenant)
	cfg := config.Config{
		TenantID: tenant, MaxDepth: 5, ApprovalTTL: time.Hour,
		DPoPFreshnessWindow: dpopITWindow,
	}
	signer := escalationSigner(t)
	return pdpgrpc.NewServer(repo, policy.NewMulti(repo, escalationRegistry()), cfg, signer), signer
}

// dpopKey, dpopProof and dpopBoundToken are the integration counterparts of
// internal/pdpgrpc/dpop_test.go's own helpers, deliberately built the same
// way: a real ES256 key, a real proof with the public half embedded in the
// header, and a real token carrying cnf.jkt computed by dpop.Thumbprint —
// the same exported function IssueToken binds with, so this test cannot pass
// against a thumbprint only itself would compute.
func dpopKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

func dpopProof(t *testing.T, key *ecdsa.PrivateKey, jti string, iat time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		t.Fatalf("new jose signer: %v", err)
	}
	proof, err := josejwt.Signed(signer).Claims(map[string]any{
		"htm": dpopITMethod, "htu": dpopITURI, "jti": jti, "iat": iat.Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("serialize proof: %v", err)
	}
	return proof
}

func dpopBoundToken(t *testing.T, signer *token.Signer, delegationID uuid.UUID, key *ecdsa.PrivateKey) string {
	t.Helper()
	doc, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	jkt, err := dpop.Thumbprint(doc)
	if err != nil {
		t.Fatalf("dpop.Thumbprint() = %v, want success", err)
	}
	tok, err := signer.Sign(jwt.MapClaims{
		"sub": delegationID.String(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]string{"jkt": jkt},
	})
	if err != nil {
		t.Fatalf("Sign() error = %v, want success", err)
	}
	return tok
}

// dpopDecideFixture seeds an agent and a delegation whose three legs all
// clear, and returns a request carrying a bound token plus a matching proof.
// escalationRawInput is deliberately NOT used — it derives DESTRUCTIVE and
// would turn these proofs into questions about escalation bands; "ls -la"
// derives READ_ONLY, well under the ceiling.
func dpopDecideFixture(
	t *testing.T, tenant string, signer *token.Signer, key *ecdsa.PrivateKey, jti string, iat time.Time,
) (*pdpgrpc.DecideRequest, *models.Delegation) {
	t.Helper()
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "dpop-agent-"+uuid.NewString(), models.TrustTierCertified)
	d := plainRootDelegation(t, tenant, agentID, "dpop-integration@example.com")

	return &pdpgrpc.DecideRequest{
		Token:          dpopBoundToken(t, signer, d.ID, key),
		AgentId:        agentID.String(),
		Subject:        d.UserID,
		Tool:           "Bash",
		RawInput:       "ls -la",
		DpopProof:      dpopProof(t, key, jti, iat),
		ObservedMethod: dpopITMethod,
		ObservedUri:    dpopITURI,
	}, d
}

// spentProofExpiry reads back one row's expires_at, through servingDB and a
// tenant-scoped transaction for the same reason spentProofJTIs is: what it
// returns is what the serving identity can actually see. A missing row is
// fatal rather than a zero time — "no row" and "a zero expiry" are opposite
// bugs and must not be reported identically.
func spentProofExpiry(t *testing.T, tenant, jti string) time.Time {
	t.Helper()
	var expiresAt time.Time
	withServingTenantTx(t, tenant, func(tx *sql.Tx) {
		if err := tx.QueryRowContext(t.Context(),
			`SELECT expires_at FROM spent_proofs WHERE jti = $1`, jti,
		).Scan(&expiresAt); err != nil {
			t.Fatalf("SELECT expires_at for jti %s as the serving role: %v", jti, err)
		}
	})
	return expiresAt
}

// withServingTenantTx is withTenantTx (store_integration_test.go) on
// servingDB instead of testDB. Separate rather than parameterised: every
// existing caller of withTenantTx is a fixture WRITE that legitimately wants
// the owner connection, and quietly moving them onto the serving role would
// change what a dozen unrelated tests prove.
func withServingTenantTx(t *testing.T, tenant string, fn func(tx *sql.Tx)) {
	t.Helper()
	tx, err := servingDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx as the serving role: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id = %s: %v", tenant, err)
	}
	fn(tx)
}

// The mechanism is populated, not merely plumbed: a real Decide with a bound
// token and a valid proof allows, reports itself sender-constrained, and
// leaves a row in spent_proofs that the serving role can actually see.
//
// The row check is via spentProofJTIs (spent_proof_integration_test.go),
// which reads through servingDB in a tenant-scoped transaction — so it is
// simultaneously an RLS observation and a grant proof, not just a row count.
func TestIntegration_Decide_BoundTokenWithValidProof_SpendsTheJTI(t *testing.T) {
	const tenant = "tenant-dpop-decide-integration"
	srv, signer := dpopServer(t, tenant)
	key := dpopKey(t)
	jti := "decide-spends-" + uuid.NewString()
	iat := time.Now().Add(-45 * time.Second).Truncate(time.Second)
	req, _ := dpopDecideFixture(t, tenant, signer, key, jti, iat)

	resp, err := srv.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision", err)
	}
	if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Effect = %v (denied leg %q, reason %q), want EFFECT_ALLOW",
			resp.GetEffect(), resp.GetDeniedLeg(), resp.GetReason())
	}
	if !resp.GetSenderConstrained() {
		t.Error("SenderConstrained = false, want true")
	}

	got := spentProofJTIs(t, tenant)
	if len(got) != 1 || got[0] != jti {
		t.Fatalf("spent_proofs for %s = %v, want exactly [%s] — a Decide that verified the proof but never "+
			"wrote the row is the mechanism plumbed and never populated", tenant, got, jti)
	}
}

// The expiry Decide computes survives the real column: iat plus the
// configured window, to the second.
//
// This is the property Task 3's review handed to Task 4 specifically.
// store.SpendProof cannot check it — no clock, no window — so a writer
// passing the zero time.Time, or now, or iat with no window added would
// insert cleanly and make EVERY row reapable on the next sweep, with replay
// prevention silently off while the reaper's count looked healthy.
//
// Read back through servingDB in a tenant-scoped transaction, for the same
// reason spentProofJTIs is: what this sees is what the serving identity can
// actually see. The comparison is exact — iat is 45s in the past and the
// window is 97s, so the correct answer is distinct from now, from now+window,
// from iat, and from the zero time, every value a plausible mistake produces.
func TestIntegration_Decide_SpendsWithAnExpiryOfIATPlusTheWindow(t *testing.T) {
	const tenant = "tenant-dpop-expiry-integration"
	srv, signer := dpopServer(t, tenant)
	key := dpopKey(t)
	jti := "decide-expiry-" + uuid.NewString()
	iat := time.Now().Add(-45 * time.Second).Truncate(time.Second)
	req, _ := dpopDecideFixture(t, tenant, signer, key, jti, iat)

	if _, err := srv.Decide(t.Context(), req); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}

	got := spentProofExpiry(t, tenant, jti)
	want := iat.Add(dpopITWindow)
	if !got.Equal(want) {
		t.Errorf("spent_proofs.expires_at = %s, want %s (iat %s + the %s window). Past that instant "+
			"dpop.Verify refuses the proof for staleness anyway, so a row living longer protects nothing "+
			"and one living less leaves a gap where the proof both verifies and no longer collides",
			got.UTC(), want.UTC(), iat.UTC(), dpopITWindow)
	}
	if !got.After(time.Now()) {
		t.Errorf("spent_proofs.expires_at = %s is not in the future: this row is reapable on the very next "+
			"sweep, so the proof it records becomes replayable while the reaper's count still looks healthy",
			got.UTC())
	}
}

// A replay denies through the real PRIMARY KEY on (tenant_id, jti). Two full
// Decide calls presenting the same proof — the actual attack — rather than
// an injected store error.
//
// The first call must ALLOW: if it denied for any reason the second would
// deny too, and this would pass without exercising replay at all.
func TestIntegration_Decide_ReplayedProof_Denies(t *testing.T) {
	const tenant = "tenant-dpop-replay-integration"
	srv, signer := dpopServer(t, tenant)
	key := dpopKey(t)
	jti := "decide-replay-" + uuid.NewString()
	iat := time.Now().Add(-45 * time.Second).Truncate(time.Second)
	req, _ := dpopDecideFixture(t, tenant, signer, key, jti, iat)

	first, err := srv.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("first Decide() error = %v", err)
	}
	if first.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("first Effect = %v (reason %q), want EFFECT_ALLOW: without a first call that succeeds "+
			"there is no spent row for the second to collide with", first.GetEffect(), first.GetReason())
	}

	second, err := srv.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v, want a DENY decision, not an RPC error", err)
	}
	if second.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY: the same proof presented twice is a replay",
			second.GetEffect())
	}
	if !strings.Contains(second.GetReason(), "already spent") {
		t.Errorf("Reason = %q, want store.ErrProofSpent's own wording — an operator must be able to tell a "+
			"replay storm from a database falling over", second.GetReason())
	}
	if second.GetSenderConstrained() {
		t.Error("SenderConstrained = true on a replayed proof")
	}
	if got := spentProofJTIs(t, tenant); len(got) != 1 {
		t.Errorf("spent_proofs = %v, want exactly one row: the replay collides with the first, it does not "+
			"add a second, and it must not roll the first back either", got)
	}
}

// An UNBOUND token still allows through a real PDP and spends nothing (K5).
// The refusal belongs at the two network surfaces, not here — refusing it in
// the PDP would deny the whole hook/mcp fleet.
//
// Differs from the passing fixture above in exactly one property: the token
// carries no cnf claim. The proof, the observed pair, the agent, the
// delegation and the policy are all identical, so nothing but the binding's
// absence can account for the result — including the empty table, which is
// the assertion that would break if an unbound token's accompanying proof
// were verified and spent anyway.
func TestIntegration_Decide_UnboundToken_AllowsAndSpendsNothing(t *testing.T) {
	const tenant = "tenant-dpop-unbound-integration"
	srv, signer := dpopServer(t, tenant)
	key := dpopKey(t)
	jti := "decide-unbound-" + uuid.NewString()
	iat := time.Now().Add(-45 * time.Second).Truncate(time.Second)
	req, d := dpopDecideFixture(t, tenant, signer, key, jti, iat)
	// The one property under test: the SAME delegation, named by a token
	// with no cnf.jkt. escalationToken is the unbound minter.
	req.Token = escalationToken(t, signer, d.ID)

	resp, err := srv.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Effect = %v (reason %q), want EFFECT_ALLOW: a bearer token is legitimate in the PDP",
			resp.GetEffect(), resp.GetReason())
	}
	if resp.GetSenderConstrained() {
		t.Error("SenderConstrained = true for a token carrying no cnf.jkt: a network surface relying on " +
			"this field would then accept exactly the bearer token K5 exists to refuse")
	}
	if got := spentProofJTIs(t, tenant); len(got) != 0 {
		t.Errorf("spent_proofs = %v, want none: nothing was bound, so the accompanying proof substantiates "+
			"no claim and there is no jti worth burning", got)
	}
}
