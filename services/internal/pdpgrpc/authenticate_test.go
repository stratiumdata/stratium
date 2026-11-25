package pdpgrpc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/config"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/token"
)

// decideTokenFixture returns wellFormedFixture's own fixture, plus the exact
// delegation id it names, parsed back out of the fixture's own placeholder
// token (see wellFormedFixture's comment: Token is the delegation id,
// spelled out, for fakeSigner's benefit). Every test below overwrites
// req.Token with a REAL token before calling Decide — this just saves each
// one from re-deriving the id it must name to land on the same delegation
// the fixture's chain actually describes.
func decideTokenFixture(t *testing.T) (*fakeStore, *DecideRequest, uuid.UUID) {
	t.Helper()
	fs, req := wellFormedFixture()
	id, err := uuid.Parse(req.GetToken())
	if err != nil {
		t.Fatalf("wellFormedFixture's own Token is not a UUID: %v", err)
	}
	return fs, req, id
}

// signRealToken mints a genuinely signed, well-formed token naming
// delegationID via signer, valid from issuedAt to expiresAt. A thin wrapper
// over tokenClaims+Sign (token.go) so every test below that needs a real
// token states only what varies (which signer, which delegation, which
// window) rather than repeating the three-line claim-building dance.
//
// Always UNBOUND (empty jkt, hence no cnf claim): every test in this file is
// about authentication, which Phase 15 did not change — a bearer token
// authenticates exactly as it did before cnf existed. Binding is exercised
// where it is decided, in token_test.go.
func signRealToken(t *testing.T, signer *token.Signer, delegationID uuid.UUID, issuedAt, expiresAt time.Time) string {
	t.Helper()
	tok, err := signer.Sign(tokenClaims(delegationID, testTenant, "", issuedAt, expiresAt))
	if err != nil {
		t.Fatalf("Sign() error = %v, want success", err)
	}
	return tok
}

// TestDecide_ValidToken_ReachesNormalDecision is the required "a valid token
// decides normally" property, proven with a REAL signed-and-verified token
// (not fakeSigner's placeholder): DeniedLeg "principal" is reachable ONLY by
// running the full agent-load, chain-load, tier-derivation, and policy-
// evaluation sequence that follows authentication — denyAllPolicy()'s own
// unconditional deny is what stops this fixture short of ALLOW (the same
// reachable-outcome ceiling wellFormedFixture's own doc comment names) — so
// seeing it here proves the token was verified and Decide proceeded exactly
// as it would have from a trusted bare id before this task.
func TestDecide_ValidToken_ReachesNormalDecision(t *testing.T) {
	fs, req, delegationID := decideTokenFixture(t)
	signer := testSigner(t)
	now := time.Now()
	req.Token = signRealToken(t, signer, delegationID, now, now.Add(time.Hour))
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision", err)
	}
	if resp.GetDeniedLeg() != "principal" {
		t.Fatalf("DeniedLeg = %q (reason %q), want %q: a valid token must reach the real three-leg "+
			"evaluation, not deny at authentication", resp.GetDeniedLeg(), resp.GetReason(), "principal")
	}
}

// TestDecide_ExpiredToken_Denies is the required "an expired one denies"
// property. The reason must name expiry specifically -- "expired" is
// jwt/v5's own stable, exported ErrTokenExpired text, wrapped unchanged
// through internal/token.Verify's "token: verify: %w" -- so an operator (or
// a future test) can tell this apart from every other token failure, and so
// this test cannot pass for the wrong reason (e.g. a bad signature) the way
// a bare "was denied" assertion could.
func TestDecide_ExpiredToken_Denies(t *testing.T) {
	fs, req, delegationID := decideTokenFixture(t)
	signer := testSigner(t)
	past := time.Now().Add(-time.Hour)
	req.Token = signRealToken(t, signer, delegationID, past, past.Add(time.Minute)) // expired 59 minutes ago
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a DENY decision, not an RPC error", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}
	if resp.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q (the structural pre-leg bucket -- see denyAndAudit's own doc comment)",
			resp.GetDeniedLeg(), "delegation")
	}
	if !strings.Contains(resp.GetReason(), "expired") {
		t.Errorf("Reason = %q, want it to name expiry specifically", resp.GetReason())
	}
	if len(fs.appended) != 1 {
		t.Fatalf("audit entries appended = %d, want 1: an expired token must still be audited", len(fs.appended))
	}
	if fs.appended[0].DelegationID != nil {
		t.Errorf("audit entry DelegationID = %v, want nil: authentication failed before any delegation was loaded",
			fs.appended[0].DelegationID)
	}
	if fs.calls != 1 {
		t.Errorf("store calls = %d, want exactly 1 (the audit append only): an expired token must not "+
			"reach LoadAgent or LoadChain", fs.calls)
	}
}

// TestDecide_TokenSignedByUnknownKey_Denies is the required "one signed by
// an unknown key denies" property: a token that is otherwise perfectly
// well-formed, signed by a real EC key that simply is not the one this
// server trusts (no current/previous relationship at all -- a stolen or
// forged key, not a stale one). Reason must name the signature, not expiry
// or malformedness, so this stays distinguishable from its neighbors.
func TestDecide_TokenSignedByUnknownKey_Denies(t *testing.T) {
	fs, req, delegationID := decideTokenFixture(t)
	attacker := testSigner(t) // a fresh, unrelated key -- never loaded by the server below
	now := time.Now()
	req.Token = signRealToken(t, attacker, delegationID, now, now.Add(time.Hour))
	srv := NewServer(fs, denyAllPolicy(), testConfig(), testSigner(t)) // the server's OWN, different key

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a DENY decision, not an RPC error", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}
	if !strings.Contains(resp.GetReason(), "signature") {
		t.Errorf("Reason = %q, want it to name the signature specifically", resp.GetReason())
	}
	if fs.calls != 1 {
		t.Errorf("store calls = %d, want exactly 1 (the audit append only): a token signed by an unknown "+
			"key must not reach LoadAgent or LoadChain", fs.calls)
	}
}

// TestDecide_MalformedToken_Denies is the required "a malformed one denies"
// property, table-driven over two shapes of malformed: plain garbage, and —
// the mutation-testing anchor for "restore a bare-id fallback" — the acting
// delegation's OWN, real, well-formed UUID with no JWT structure around it
// at all. The second case is deliberately not distinguishable from the
// first by outcome (both deny, both name malformedness): if Decide ever
// grew a fallback that treated a token failing to parse as a JWT as a bare
// delegation id instead — reintroducing exactly what K4 removed — this
// specific subcase is what would start passing authentication (reaching
// DeniedLeg "principal", per TestDecide_ValidToken_ReachesNormalDecision's
// own proof of what success looks like) while the first subcase kept
// denying, which is precisely the signature a bare-id fallback would leave.
func TestDecide_MalformedToken_Denies(t *testing.T) {
	tests := map[string]func(delegationID uuid.UUID) string{
		"garbage, not JWT-shaped at all": func(uuid.UUID) string { return "not-a-jwt-at-all" },
		"a bare delegation id -- the exact pre-K4 wire shape, unwrapped": func(id uuid.UUID) string {
			return id.String()
		},
	}
	for name, tokenFor := range tests {
		t.Run(name, func(t *testing.T) {
			fs, req, delegationID := decideTokenFixture(t)
			req.Token = tokenFor(delegationID)
			srv := NewServer(fs, denyAllPolicy(), testConfig(), testSigner(t))

			resp, err := srv.Decide(context.Background(), req)
			if err != nil {
				t.Fatalf("Decide() error = %v, want a DENY decision, not an RPC error", err)
			}
			if resp.GetEffect() != Effect_EFFECT_DENY {
				t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
			}
			if resp.GetDeniedLeg() != "delegation" {
				t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
			}
			if !strings.Contains(resp.GetReason(), "malformed") {
				t.Errorf("Reason = %q, want it to name malformedness", resp.GetReason())
			}
			if fs.calls != 1 {
				t.Errorf("store calls = %d, want exactly 1 (the audit append only): a malformed token "+
					"must not reach LoadAgent or LoadChain", fs.calls)
			}
		})
	}
}

// TestDecide_TokenSignedByPreviousKey_StillVerifies is the required "one
// signed by the previous key still verifies" property (K1's rotation
// promise, proven through Decide rather than only through internal/token's
// own suite). Two DISTINCT signer instances, deliberately, learning from
// Task 2's own finding (task-2-report.md): signing and verifying through
// the SAME *token.Signer cannot tell "verified" apart from "verified
// because it happened to be signed by current," since Verify accepts either
// key. oldSigner here has ONLY the old key (current-only, so it can only
// ever sign with what is about to become "previous"); the server's own
// signer is loaded fresh with a DIFFERENT current key plus the old key as
// previous — the same two-instance shape token_test.go's
// TestIssueToken_SignsWithCurrentKeyNotPrevious already established for
// issuance, applied here to verification.
func TestDecide_TokenSignedByPreviousKey_StillVerifies(t *testing.T) {
	fs, req, delegationID := decideTokenFixture(t)
	oldKeyPath := freshECKeyPEM(t)
	newKeyPath := freshECKeyPEM(t) // a genuinely different key, not the same file reused

	oldSigner, err := token.Load(oldKeyPath, "")
	if err != nil {
		t.Fatalf("token.Load(old) = %v, want success", err)
	}
	now := time.Now()
	req.Token = signRealToken(t, oldSigner, delegationID, now, now.Add(time.Hour))

	rotatedSigner, err := token.Load(newKeyPath, oldKeyPath)
	if err != nil {
		t.Fatalf("token.Load(new, old) = %v, want success", err)
	}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), rotatedSigner)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision", err)
	}
	if resp.GetDeniedLeg() != "principal" {
		t.Fatalf("DeniedLeg = %q (reason %q), want %q: a token signed by the previous key must reach the "+
			"real three-leg evaluation exactly like one signed by current",
			resp.GetDeniedLeg(), resp.GetReason(), "principal")
	}
}

// TestDecide_NoToken_Denies is the required "a request with no token denies
// rather than falling back to anything" property. req.Token is simply never
// set (DecideRequest's zero value) — there is no second field left on the
// wire for this to fall back to (K4: delegation_id is reserved, not
// present), so this also stands as the structural proof that no such
// fallback exists to reach.
func TestDecide_NoToken_Denies(t *testing.T) {
	fs, req := wellFormedFixture()
	req.Token = ""
	srv := NewServer(fs, denyAllPolicy(), testConfig(), testSigner(t))

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a DENY decision, not an RPC error", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}
	if resp.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
	}
	if resp.GetReason() != errNoToken.Error() {
		t.Errorf("Reason = %q, want %q", resp.GetReason(), errNoToken.Error())
	}
	if len(fs.appended) != 1 {
		t.Fatalf("audit entries appended = %d, want 1: an absent token must still be audited", len(fs.appended))
	}
	if fs.calls != 1 {
		t.Errorf("store calls = %d, want exactly 1 (the audit append only): an absent token must not "+
			"reach LoadAgent or LoadChain, let alone fall back to treating any other field as a delegation id",
			fs.calls)
	}
}

// TestDecide_TokenNamingRevokedDelegation_DeniesAtTheDelegationLeg is the
// load-bearing test of this whole task (spec K3, restated in the brief: "a
// token naming a delegation that was revoked must be denied BY THE
// DELEGATION LEG, not by the token check"). The token here is completely
// genuine — real signature, unexpired, well-formed, naming a real
// delegation — so authenticateToken has nothing to object to; only the
// delegation ROW's own Revoked flag, discovered by the LoadChain call
// authentication success leads to, can produce this denial. That is what
// proves a token is an authenticated REFERENCE and not a capability: the
// authority it points at is re-checked fresh on every call, not frozen into
// the token at mint time.
//
// Two independent checks make this specific, not just "denied somehow":
// Reason must contain DelegationLeg's own exact revocation wording
// (internal/authz/delegation.go: "... is revoked"), which no token-
// authentication failure ever produces — see
// TestDecide_ExpiredToken_Denies/TestDecide_TokenSignedByUnknownKey_Denies/
// TestDecide_MalformedToken_Denies just above for what those look like
// instead. And the audit entry's DelegationID must be non-nil — appendAudit
// only populates it once chain was actually loaded (its own doc comment) —
// which a token-authentication failure's audit row never has (see this same
// assertion, asserted false, on every test above).
func TestDecide_TokenNamingRevokedDelegation_DeniesAtTheDelegationLeg(t *testing.T) {
	fs, req, delegationID := decideTokenFixture(t)
	signer := testSigner(t)
	now := time.Now()
	req.Token = signRealToken(t, signer, delegationID, now, now.Add(time.Hour))
	// Unlike every other test in this file, this one must NOT use
	// denyAllPolicy(): compound.go's deny loop attributes a denial to the
	// FIRST leg that denies, in fixed order (principal, agent, delegation —
	// C12/C13), so a policy that already denies everything would win that
	// attribution race and mask the revocation this test exists to prove —
	// DeniedLeg would read "principal" no matter what the delegation leg
	// found. escalationPolicy() grants Bash outright, and req.RawInput below
	// matches TestDecide_PopulatesPerLegFields' own already-proven-ALLOW
	// combination for this fixture's agent/delegation shape, so principal
	// and agent both clear and only Revoked, below, has anything left to
	// deny.
	req.RawInput = "ls -la"
	fs.chain[0].Revoked = true // the delegation the (valid) token names, revoked
	srv := NewServer(fs, escalationPolicy(), testConfig(), signer)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}
	if resp.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
	}
	if !strings.Contains(resp.GetReason(), "is revoked") {
		t.Errorf("Reason = %q, want DelegationLeg's own revocation wording (\"... is revoked\") — "+
			"anything else means this was denied somewhere other than the real delegation-leg re-evaluation",
			resp.GetReason())
	}
	if strings.Contains(resp.GetReason(), "token") {
		t.Errorf("Reason = %q, mentions \"token\" — a revoked-delegation denial must come from "+
			"DelegationLeg, which knows nothing about tokens, not from authenticateToken", resp.GetReason())
	}

	if len(fs.appended) != 1 {
		t.Fatalf("audit entries appended = %d, want 1", len(fs.appended))
	}
	entry := fs.appended[0]
	if entry.DelegationID == nil {
		t.Fatal("audit entry DelegationID is nil, want the token-named delegation id: a revoked-delegation " +
			"denial only happens after LoadChain actually ran, which populates this field")
	}
	if *entry.DelegationID != delegationID {
		t.Errorf("audit entry DelegationID = %s, want %s", entry.DelegationID, delegationID)
	}
	if entry.RootDelegationID == nil {
		t.Error("audit entry RootDelegationID is nil, want the chain's root: further proof the real chain " +
			"was loaded and evaluated, not skipped")
	}
}

// --- authenticateToken direct unit tests: claim shapes no signed-and-
// verified round trip can produce, because tokenClaims (token.go) never
// builds them. A verifying but malformed "sub" claim can only come from a
// token this system did not mint in the first place, or a future bug in
// what mints one — this is exercised directly against the method rather
// than through Decide because building a fixture just to get a
// cryptographically valid token with a deliberately broken claim would be
// more machinery than the property needs. ---

func TestAuthenticateToken_SubjectClaimNotAString_Denies(t *testing.T) {
	signer := testSigner(t)
	tok, err := signer.Sign(jwt.MapClaims{
		subjectClaim: 12345, // a number, never a string tokenClaims would produce
		expiryClaim:  time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	srv := NewServer(nil, policy.Multi{}, config.Config{}, signer)

	_, _, err = srv.authenticateToken(tok)
	if err == nil {
		t.Fatal("authenticateToken() error = nil, want an error: \"sub\" is not a string")
	}
	if !strings.Contains(err.Error(), subjectClaim) {
		t.Errorf("error = %q, want it to name the claim %q", err, subjectClaim)
	}
}

func TestAuthenticateToken_SubjectClaimMissing_Denies(t *testing.T) {
	signer := testSigner(t)
	tok, err := signer.Sign(jwt.MapClaims{
		expiryClaim: time.Now().Add(time.Hour).Unix(),
		// subjectClaim deliberately absent.
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	srv := NewServer(nil, policy.Multi{}, config.Config{}, signer)

	_, _, err = srv.authenticateToken(tok)
	if err == nil {
		t.Fatal("authenticateToken() error = nil, want an error: \"sub\" is absent")
	}
}

func TestAuthenticateToken_SubjectClaimZeroUUID_Denies(t *testing.T) {
	signer := testSigner(t)
	tok := signRealToken(t, signer, uuid.Nil, time.Now(), time.Now().Add(time.Hour))
	srv := NewServer(nil, policy.Multi{}, config.Config{}, signer)

	_, _, err := srv.authenticateToken(tok)
	if err == nil {
		t.Fatal("authenticateToken() error = nil, want an error: the zero UUID is never a legitimate " +
			"delegation id (parseNonNilUUID's own rule, applied here exactly as everywhere else)")
	}
}

// A token this package itself never logs, on any path: authenticateToken's
// own doc comment states the constraint; this asserts it holds for the one
// case most tempting to violate — the error message itself, on a failure.
// A leaked token in a log line would be exactly as dangerous as a leaked
// key, since a token IS a live credential until it expires.
func TestAuthenticateToken_ErrorNeverContainsTheTokenString(t *testing.T) {
	signer := testSigner(t)
	// A recognizable marker planted in the input, not the output: if it
	// showed up in an error, that would mean the raw token string leaked
	// into it.
	const marker = "MARKER-THIS-STRING-MUST-NEVER-APPEAR-IN-AN-ERROR"
	srv := NewServer(nil, policy.Multi{}, config.Config{}, signer)

	_, _, err := srv.authenticateToken(marker)
	if err == nil {
		t.Fatal("authenticateToken() error = nil, want an error: marker is not a valid token")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error = %q, contains the raw token string — tokens must never be logged or echoed", err)
	}
}

// Input in which two keys of one object differ at most in capitalization can
// be read two ways, so it is refused before the agent, the chain or any
// policy is consulted, with an audit row and a reason that says why.
func TestDecide_AmbiguousRawInput_DeniesBeforeAnythingIsLoaded(t *testing.T) {
	for name, input := range map[string]string{
		"key twice":         `{"path":"/tmp/a","path":"/etc/passwd"}`,
		"key in other case": `{"path":"/tmp/a","Path":"/etc/passwd"}`,
		"nested":            `{"opts":[{"command":"ls","command":"rm -rf /"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			fs, req, _ := decideTokenFixture(t)
			req.RawInput = input
			srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

			resp, err := srv.Decide(context.Background(), req)
			if err != nil {
				t.Fatalf("Decide() error = %v, want a DENY decision, not an RPC error", err)
			}
			if resp.GetEffect() != Effect_EFFECT_DENY || !strings.Contains(resp.GetReason(), "capitalization") {
				t.Fatalf("Effect = %v, Reason = %q; want EFFECT_DENY naming the keys", resp.GetEffect(), resp.GetReason())
			}
			if fs.calls != 1 {
				t.Errorf("store calls = %d, want exactly 1 (the audit append only)", fs.calls)
			}
		})
	}
}
