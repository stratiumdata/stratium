package pdpgrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"stratium/internal/dpop"
	"stratium/internal/store"
	"stratium/internal/token"
)

// The request the enforcement surface reports observing. A gRPC proxy shape
// deliberately (spec §4.7.2 K7: the PROXY's own address plus the full method
// path, with POST, because gRPC is HTTP/2 POST) — the surface Tasks 5 and 6
// will actually populate these from, rather than an invented REST-looking
// URI that no PEP in this repo would ever send.
const (
	testObservedMethod = "POST"
	testObservedURI    = "https://pep-proxy.example.com/stratium.pdp.v1.PDPService/Decide"
)

// Every proof below is VALID — correctly typed, correctly signed, fresh. The
// malformed, unsigned, alg-none, weak-key, and private-key-in-header cases
// all live in internal/dpop's own suite, where they are the subject; this
// package's subject is what the PDP does with the answers, so building
// proofs here through a real JOSE signer says exactly as much and is a
// tenth of the code.
func newProofKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

// signProof mints an RFC 9449 proof for (htm, htu, jti) at iat, signed by
// key, with key's public half embedded in the header as the jwk parameter
// (EmbedJWK) — which is where dpop.Verify looks and the only place a proof
// carries its key.
func signProof(t *testing.T, key *ecdsa.PrivateKey, htm, htu, jti string, iat time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		t.Fatalf("new jose signer: %v", err)
	}
	proof, err := josejwt.Signed(signer).Claims(map[string]any{
		"htm": htm,
		"htu": htu,
		"jti": jti,
		"iat": iat.Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("serialize proof: %v", err)
	}
	return proof
}

// thumbprintOf is the value a token binds to: dpop.Thumbprint over key's
// PUBLIC half, computed by the same exported function IssueToken uses at
// issuance (its own doc comment covers why there must be exactly one
// implementation of RFC 7638 in this system).
func thumbprintOf(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	doc, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	jkt, err := dpop.Thumbprint(doc)
	if err != nil {
		t.Fatalf("dpop.Thumbprint() = %v, want success", err)
	}
	return jkt
}

// signBoundToken mints a real, signed token naming delegationID and BOUND to
// jkt. The bound counterpart of authenticate_test.go's signRealToken, which
// is deliberately always unbound (see its own doc comment) — kept separate
// rather than adding a parameter there, so nothing in that file silently
// starts exercising binding it does not mean to test.
func signBoundToken(t *testing.T, signer *token.Signer, delegationID uuid.UUID, jkt string, now time.Time) string {
	t.Helper()
	tok, err := signer.Sign(tokenClaims(delegationID, testTenant, jkt, now, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("Sign() error = %v, want success", err)
	}
	return tok
}

// boundFixture is the one shape every test in this file starts from: a real
// signed token bound to a real key, a real valid proof made with that key
// for the request the surface reports observing, and a fixture whose three
// legs all clear so the reachable outcome is a genuine ALLOW.
//
// Returning iat matters. Half the assertions below are about a value derived
// from the proof's own iat (the spent row's expiry), and re-deriving it from
// time.Now() in the test would compare the implementation against a second
// guess rather than against the input.
//
// req.RawInput is the fixture's own already-proven-ALLOW combination — see
// TestDecide_PopulatesPerLegFields, where "ls -la" is what makes the agent
// and delegation legs genuinely allow rather than trivially deny.
type boundFixture struct {
	fs     *fakeStore
	req    *DecideRequest
	srv    *Server
	key    *ecdsa.PrivateKey
	jti    string
	iat    time.Time
	signer *token.Signer
}

func newBoundFixture(t *testing.T) boundFixture {
	t.Helper()
	fs, req, delegationID := decideTokenFixture(t)
	req.RawInput = "ls -la"

	signer := testSigner(t)
	key := newProofKey(t)
	now := time.Now()
	// Inside the window and NOT equal to now, so a spent row's expiry
	// computed from iat is distinguishable from one computed from the
	// server's own clock. Truncated to the second because a proof's iat is a
	// NumericDate — the sub-second part does not survive the JWT, and a
	// comparison that expected it to would fail for the wrong reason.
	iat := now.Add(-45 * time.Second).Truncate(time.Second)
	jti := "proof-" + uuid.NewString()

	req.Token = signBoundToken(t, signer, delegationID, thumbprintOf(t, key), now)
	req.DpopProof = signProof(t, key, testObservedMethod, testObservedURI, jti, iat)
	req.ObservedMethod = testObservedMethod
	req.ObservedUri = testObservedURI

	return boundFixture{
		fs:     fs,
		req:    req,
		srv:    NewServer(fs, escalationPolicy(), testConfig(), signer),
		key:    key,
		jti:    jti,
		iat:    iat,
		signer: signer,
	}
}

// decide runs the fixture's request and fails on an RPC error — every test
// in this file expects a DECISION, never a transport failure, including the
// denials.
func (f boundFixture) decide(t *testing.T) *DecideResponse {
	t.Helper()
	resp, err := f.srv.Decide(context.Background(), f.req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision, not an RPC error", err)
	}
	return resp
}

// --- The required properties (task brief) -------------------------------

// A valid bound token plus a valid proof ALLOWS, reports itself as
// sender-constrained, and spends exactly one jti.
//
// ALLOW, not merely "not denied": EFFECT_DENY is the zero value of the wire
// enum (the proto's own Effect doc comment), so only a positive outcome
// proves the proof check let the call through rather than the response being
// unset. This is also the baseline every negative test below perturbs by
// exactly one property.
func TestDecide_BoundTokenWithValidProof_Allows(t *testing.T) {
	f := newBoundFixture(t)

	resp := f.decide(t)

	if resp.GetEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("Effect = %v (denied leg %q, reason %q), want EFFECT_ALLOW",
			resp.GetEffect(), resp.GetDeniedLeg(), resp.GetReason())
	}
	if !resp.GetSenderConstrained() {
		t.Error("SenderConstrained = false, want true: the token carried cnf.jkt and its proof verified, " +
			"which is the exact fact the network surfaces need to enforce K5")
	}
	if len(f.fs.spentProofs) != 1 {
		t.Fatalf("spent proofs = %d, want exactly 1: a verified proof's jti is spent, once", len(f.fs.spentProofs))
	}
	if f.fs.spentProofs[0].jti != f.jti {
		t.Errorf("spent jti = %q, want %q (the proof's own)", f.fs.spentProofs[0].jti, f.jti)
	}
}

// A bound token with NO proof denies (spec C25's first meaning). Differs
// from the passing fixture in exactly one property: DpopProof is cleared,
// and nothing else — same token, same bound key, same observed request.
func TestDecide_BoundTokenWithNoProof_Denies(t *testing.T) {
	f := newBoundFixture(t)
	f.req.DpopProof = ""

	resp := f.decide(t)

	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY: a sender-constrained token with no proof is exactly "+
			"what C25 names", resp.GetEffect())
	}
	if resp.GetReason() != errNoProof.Error() {
		t.Errorf("Reason = %q, want %q", resp.GetReason(), errNoProof.Error())
	}
	if resp.GetSenderConstrained() {
		t.Error("SenderConstrained = true on a denial with no proof at all")
	}
	if len(f.fs.spentProofs) != 0 {
		t.Errorf("spent proofs = %d, want 0", len(f.fs.spentProofs))
	}
	if f.fs.calls != 1 {
		t.Errorf("store calls = %d, want exactly 1 (the audit append only): a missing proof is caught "+
			"before the epoch read, alongside the token check", f.fs.calls)
	}
}

// A proof whose thumbprint does not match the token's cnf.jkt denies: the
// stolen-token case, where the thief presents a perfectly valid proof made
// with a key of their own.
//
// The ONE property that differs from the passing fixture is which key signed
// the proof. Same claims, same jti, same iat, same observed request, same
// token — so nothing but the binding comparison can produce this denial.
func TestDecide_ProofSignedByADifferentKey_Denies(t *testing.T) {
	f := newBoundFixture(t)
	thief := newProofKey(t)
	f.req.DpopProof = signProof(t, thief, testObservedMethod, testObservedURI, f.jti, f.iat)

	resp := f.decide(t)

	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY: a proof made with a key the token was not bound to "+
			"proves possession of nothing relevant", resp.GetEffect())
	}
	if !strings.Contains(resp.GetReason(), thumbprintKey) {
		t.Errorf("Reason = %q, want it to name the cnf.%s binding specifically — a bare \"denied\" cannot "+
			"be told apart from an htm/htu mismatch by anyone reading the audit trail",
			resp.GetReason(), thumbprintKey)
	}
	if resp.GetSenderConstrained() {
		t.Error("SenderConstrained = true for a proof that did not match the binding")
	}
	if len(f.fs.spentProofs) != 0 {
		t.Errorf("spent proofs = %d, want 0: a wrong-key proof must not burn the jti it names", len(f.fs.spentProofs))
	}
}

// A proof naming a different method or URI denies: the replay-elsewhere
// case, where a proof legitimately minted for one endpoint is presented at
// another.
//
// Each subtest perturbs the PROOF's own claim and leaves the observed pair
// alone — the surface reports what it saw, and what varies is what the
// client signed. Exactly one claim moves per subtest: the method case keeps
// the identical htu, and the URI case keeps the identical htm, so neither
// can pass on the other's mismatch.
func TestDecide_ProofNamingADifferentRequest_Denies(t *testing.T) {
	tests := map[string]struct{ htm, htu string }{
		// GET, not "get": dpop.MatchesRequest compares methods exactly (RFC
		// 9110 §9.1), and a case-only difference would leave this passing
		// for a reason unrelated to naming a different request.
		"a different method, same URI": {htm: "GET", htu: testObservedURI},
		// A different PATH on the same origin: the proof was minted for
		// another RPC behind the same proxy, which is precisely what binding
		// htu to the proxy's own address plus the method path exists to stop.
		// Scheme, host and port are untouched, so this cannot be passing on
		// an origin mismatch instead.
		"a different URI, same method": {
			htm: testObservedMethod,
			htu: "https://pep-proxy.example.com/stratium.pdp.v1.PDPService/CreateDelegation",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newBoundFixture(t)
			f.req.DpopProof = signProof(t, f.key, tc.htm, tc.htu, f.jti, f.iat)

			resp := f.decide(t)

			if resp.GetEffect() != Effect_EFFECT_DENY {
				t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
			}
			if resp.GetSenderConstrained() {
				t.Error("SenderConstrained = true for a proof minted for a different request")
			}
			if len(f.fs.spentProofs) != 0 {
				t.Errorf("spent proofs = %d, want 0", len(f.fs.spentProofs))
			}
		})
	}
}

// Each subtest above must deny for the mismatch it names, not for something
// they happen to share. Asserted separately from the table so the wording
// requirement is stated once per case rather than smeared across a shared
// substring both would satisfy.
func TestDecide_ProofRequestMismatch_ReasonNamesWhichPartMismatched(t *testing.T) {
	t.Run("method", func(t *testing.T) {
		f := newBoundFixture(t)
		f.req.DpopProof = signProof(t, f.key, "GET", testObservedURI, f.jti, f.iat)
		if got := f.decide(t).GetReason(); !strings.Contains(got, "htm") {
			t.Errorf("Reason = %q, want it to name htm", got)
		}
	})
	t.Run("uri", func(t *testing.T) {
		f := newBoundFixture(t)
		f.req.DpopProof = signProof(t, f.key, testObservedMethod,
			"https://pep-proxy.example.com/stratium.pdp.v1.PDPService/CreateDelegation", f.jti, f.iat)
		if got := f.decide(t).GetReason(); !strings.Contains(got, "htu") {
			t.Errorf("Reason = %q, want it to name htu", got)
		}
	})
}

// A replayed jti denies — proven as TWO REAL Decide calls presenting the
// SAME proof, which is the actual attack, rather than by injecting
// store.ErrProofSpent through the fake. fakeStore.SpendProof models the
// primary key on (tenant_id, jti) for exactly this test; see its own doc
// comment.
//
// The first call must ALLOW. That is not a warm-up assertion: if the first
// call denied for any reason, the second would deny too and this test would
// pass without ever exercising replay at all.
func TestDecide_ReplayedProof_Denies(t *testing.T) {
	f := newBoundFixture(t)

	first := f.decide(t)
	if first.GetEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("first Effect = %v (reason %q), want EFFECT_ALLOW: without a first call that succeeds "+
			"there is no spend for the second to collide with", first.GetEffect(), first.GetReason())
	}

	second := f.decide(t)

	if second.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY: the same proof, presented twice, is a replay",
			second.GetEffect())
	}
	if !strings.Contains(second.GetReason(), "already spent") {
		t.Errorf("Reason = %q, want store.ErrProofSpent's own wording — an operator has to be able to tell "+
			"a replay storm from a database falling over, and both merely deny", second.GetReason())
	}
	if second.GetSenderConstrained() {
		t.Error("SenderConstrained = true on a replayed proof")
	}
	if len(f.fs.spentProofs) != 1 {
		t.Errorf("spent proofs = %d, want 1: the replay must collide with the first row, not add a second",
			len(f.fs.spentProofs))
	}
	// The jti stays spent. A denial that also rolled the row back would make
	// the proof replayable again on the next attempt, which is the whole
	// failure mode "exactly once" exists to prevent.
	if f.fs.spentProofs[0].jti != f.jti {
		t.Errorf("spent jti = %q, want %q", f.fs.spentProofs[0].jti, f.jti)
	}
}

// An UNBOUND token still allows here, and that is spec K5, not a gap: on the
// local surfaces (hook, mcp) the caller already holds the session file the
// token lives in, so binding buys nothing, and refusing an unbound token in
// the PDP would deny that entire fleet. The refusal belongs at the two
// network surfaces (Tasks 5 and 6), and sender_constrained = false is what
// lets them make it.
//
// Both subtests use a token with no cnf claim at all. The second sends a
// perfectly valid proof alongside it, pinning the deliberate choice that
// such a proof is IGNORED rather than verified: it proves possession of a
// key nothing was bound to. This cannot be a downgrade path — cnf is covered
// by the token's signature, so an attacker holding a bound token cannot
// strip it to land here.
func TestDecide_UnboundToken_StillAllowsAndIsNotSenderConstrained(t *testing.T) {
	tests := map[string]bool{
		"no proof, the ordinary hook/mcp shape": false,
		"a valid proof sent anyway":             true,
	}
	for name, withProof := range tests {
		t.Run(name, func(t *testing.T) {
			fs, req, delegationID := decideTokenFixture(t)
			req.RawInput = "ls -la"
			signer := testSigner(t)
			now := time.Now()
			// signRealToken, the UNBOUND minter: no cnf claim at all, which
			// is the single property under test here.
			req.Token = signRealToken(t, signer, delegationID, now, now.Add(time.Hour))
			if withProof {
				key := newProofKey(t)
				req.DpopProof = signProof(t, key, testObservedMethod, testObservedURI, "proof-ignored", now)
				req.ObservedMethod = testObservedMethod
				req.ObservedUri = testObservedURI
			}
			srv := NewServer(fs, escalationPolicy(), testConfig(), signer)

			resp, err := srv.Decide(context.Background(), req)
			if err != nil {
				t.Fatalf("Decide() error = %v", err)
			}
			if resp.GetEffect() != Effect_EFFECT_ALLOW {
				t.Fatalf("Effect = %v (reason %q), want EFFECT_ALLOW: a bearer token is legitimate in the "+
					"PDP — K5 puts the refusal at the network surfaces", resp.GetEffect(), resp.GetReason())
			}
			if resp.GetSenderConstrained() {
				t.Error("SenderConstrained = true for a token carrying no cnf.jkt: the PDP must report what " +
					"it saw, and a bound-looking answer here would let a network surface accept a bearer token")
			}
			if len(fs.spentProofs) != 0 {
				t.Errorf("spent proofs = %d, want 0: nothing was bound, so there is no proof worth spending "+
					"and no jti to burn", len(fs.spentProofs))
			}
		})
	}
}

// The jti is NOT spent when an earlier check fails — the brief's own
// requirement, and the reason spending runs last.
//
// Stated as a fact about the WRITE, not about the reply: every case asserts
// SpendProof was never CALLED (len(spentProofs) == 0 with a fake that
// appends unconditionally on success). A jti that was never written cannot
// be un-written by a rollback that never happened, so this is strictly
// stronger than reading back "not spent" afterwards.
//
// Every case carries a REAL, well-formed proof with a real jti — a case
// where the proof is simply absent would satisfy the assertion vacuously and
// prove nothing. The token failure at the end is the one case where the
// proof is entirely valid and the burn is prevented by ordering alone.
func TestDecide_ProofNotSpentWhenAnEarlierCheckFails(t *testing.T) {
	tests := map[string]func(t *testing.T, f *boundFixture){
		"the proof is stale, outside the freshness window": func(t *testing.T, f *boundFixture) {
			t.Helper()
			stale := time.Now().Add(-testDPoPWindow - time.Minute).Truncate(time.Second)
			f.req.DpopProof = signProof(t, f.key, testObservedMethod, testObservedURI, f.jti, stale)
		},
		"the proof was made with a key the token is not bound to": func(t *testing.T, f *boundFixture) {
			t.Helper()
			f.req.DpopProof = signProof(t, newProofKey(t), testObservedMethod, testObservedURI, f.jti, f.iat)
		},
		"the proof names a different method": func(t *testing.T, f *boundFixture) {
			t.Helper()
			f.req.DpopProof = signProof(t, f.key, "GET", testObservedURI, f.jti, f.iat)
		},
		"the proof names a different uri": func(t *testing.T, f *boundFixture) {
			t.Helper()
			f.req.DpopProof = signProof(t, f.key, testObservedMethod,
				"https://pep-proxy.example.com/stratium.pdp.v1.PDPService/CreateDelegation", f.jti, f.iat)
		},
		"the TOKEN fails to verify, though the proof is perfect": func(t *testing.T, f *boundFixture) {
			t.Helper()
			// The proof is untouched and entirely valid. Only the token is
			// broken — so the only thing that can stop this jti being spent
			// is that the token check runs first and denies before the spend
			// is ever reached.
			f.req.Token = "not-a-token-at-all"
		},
	}
	for name, breakIt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newBoundFixture(t)
			breakIt(t, &f)

			resp := f.decide(t)

			if resp.GetEffect() != Effect_EFFECT_DENY {
				t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
			}
			if len(f.fs.spentProofs) != 0 {
				t.Fatalf("spent proofs = %d, want 0: a check that fails before the spend must not burn a "+
					"jti — an honest client may legitimately retry with it, and burning it turns a garbage "+
					"request into a denial of service against that client", len(f.fs.spentProofs))
			}
		})
	}
}

// --- The writer's computed expiry (Task 3's review handed this over) -----

// The expiry SpendProof is called with is pinned exactly, against the
// proof's own iat plus the configured window.
//
// store.SpendProof cannot check this itself — it has no clock and no window,
// so it cannot tell a legitimately short expiry from a broken one — which
// makes it this writer's problem entirely. A writer passing the zero
// time.Time, or now, or iat with no window added would compile, insert
// cleanly, and make EVERY row reapable on the very next sweep: replay
// prevention would silently stop working while the reaper's count looked
// healthy and the table looked reassuringly small.
//
// Exact equality, not "in the future" and not "roughly right". testDPoPWindow
// is 97s, reapSkewMargin is 60s, and the fixture's iat is 45s in the past, so
// the correct answer (iat+157s ≈ now+112s) is distinct from now+window, from
// now+window+margin, from iat+window, from now, from iat, and from the zero
// time — every value a plausible mistake would produce. A tolerance check
// would accept several of them.
func TestDecide_SpendsTheProofWithAnExpiryOfIATPlusTheWindow(t *testing.T) {
	f := newBoundFixture(t)

	if resp := f.decide(t); resp.GetEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("Effect = %v (reason %q), want EFFECT_ALLOW", resp.GetEffect(), resp.GetReason())
	}
	if len(f.fs.spentProofs) != 1 {
		t.Fatalf("spent proofs = %d, want 1", len(f.fs.spentProofs))
	}

	got := f.fs.spentProofs[0].expiresAt
	want := f.iat.Add(testDPoPWindow + reapSkewMargin)
	if !got.Equal(want) {
		t.Errorf("SpendProof expiresAt = %s, want %s (the proof's iat %s, plus the %s freshness window, "+
			"plus the %s clock-skew margin). Past iat+window dpop.Verify refuses this proof for staleness "+
			"whether or not the table still remembers it, so a row living much longer protects nothing and "+
			"one living any shorter leaves a gap where the same proof both verifies and no longer collides",
			got.UTC(), want.UTC(), f.iat.UTC(), testDPoPWindow, reapSkewMargin)
	}
	// Stated as the property the margin exists for, not as arithmetic: the
	// row must outlive the instant this PDP stops accepting the proof, because
	// that instant is measured on the PDP's clock and the reaping boundary is
	// measured on the DATABASE's. Setting them equal assumes the two agree
	// exactly; a database clock running even slightly ahead would then delete
	// the row while the proof still verifies here, and the proof becomes
	// replayable. See reapSkewMargin's own doc comment.
	if !got.After(f.iat.Add(testDPoPWindow)) {
		t.Errorf("SpendProof expiresAt = %s does not outlive iat+window (%s): with no margin, a database "+
			"clock running ahead of this process reaps the row inside the band where the proof still "+
			"verifies, and a replay of it stops colliding",
			got.UTC(), f.iat.Add(testDPoPWindow).UTC())
	}
	// Named separately because it is the specific failure Task 3's review
	// handed over, and because it is the one a "the expiry is in the future"
	// assertion would still catch while missing everything else: a zero
	// time.Time makes every row reapable immediately.
	if got.IsZero() {
		t.Error("SpendProof expiresAt is the zero time: every row would be reapable on the next sweep, " +
			"and replay prevention would stop working while the reaper's count still looked healthy")
	}
}

// --- Ordering: V3 versus the spend --------------------------------------

// The epoch is still the first store call on a request that SPENDS a proof.
//
// TestDecide_EpochIsTheFirstStoreRead (tier_override_test.go) asserts the
// same property, but through wellFormedFixture's unbound placeholder token —
// so it never reaches SpendProof, and a spend placed beside the local proof
// checks would sail past it. This is that test's bound counterpart, and it
// exists specifically because SpendProof is a WRITE: V3 admits no store call
// of any kind ahead of LoadTenantEpoch.
//
// The spend assertion at the end is what stops this passing vacuously: with
// no spend at all, zero reads before the epoch is trivially true.
func TestDecide_EpochIsStillTheFirstStoreCallWhenAProofIsSpent(t *testing.T) {
	f := newBoundFixture(t)
	f.fs.epoch = 41077

	resp := f.decide(t)

	if resp.GetEpoch() != 41077 {
		t.Errorf("Epoch = %d, want 41077", resp.GetEpoch())
	}
	if f.fs.epochReadAfterCalls != 0 {
		t.Errorf("%d store calls ran before LoadTenantEpoch, want 0: spending a jti is a store WRITE, and "+
			"V3 admits nothing ahead of the epoch read — a decision must only ever be labelled older than "+
			"the state it reflects, never newer", f.fs.epochReadAfterCalls)
	}
	if len(f.fs.spentProofs) != 1 {
		t.Fatalf("spent proofs = %d, want 1: without a spend on this path the ordering assertion above is "+
			"vacuous", len(f.fs.spentProofs))
	}
}

// A spend that fails for a reason OTHER than a replay still denies, and says
// so differently. Both outcomes deny — a replay check that fails open is not
// a replay check, exactly as a failed audit write denies (D3) — but an
// operator watching a spike of denials has to know whether they are looking
// at a replay storm or a database falling over, and those demand opposite
// responses.
func TestDecide_SpendFailure_DeniesAndIsDistinguishableFromAReplay(t *testing.T) {
	f := newBoundFixture(t)
	f.fs.spendErr = context.DeadlineExceeded

	resp := f.decide(t)

	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY: a jti write this system could not perform must fail "+
			"closed, never proceed as though the proof were fresh", resp.GetEffect())
	}
	if strings.Contains(resp.GetReason(), "already spent") {
		t.Errorf("Reason = %q reads as a replay, but the store failed for an unrelated reason", resp.GetReason())
	}
	if resp.GetSenderConstrained() {
		t.Error("SenderConstrained = true on a decision whose jti was never spent")
	}
	// The epoch WAS read before this failure, unlike the local-check
	// denials: the spend runs after it, so this denial can honestly report
	// one where those cannot (toResponse's nil-vs-zero doc comment).
	if resp.Epoch == nil {
		t.Error("Epoch is nil, want it populated: the spend runs after loadEpochOrDeny, so this denial " +
			"genuinely has an epoch to report")
	}
	if len(f.fs.appended) != 1 {
		t.Errorf("audit entries appended = %d, want 1: a failed spend is audited like any other "+
			"pre-decision denial", len(f.fs.appended))
	}
}

// --- K10: proof material never reaches the audit chain -------------------

// No denial on this path writes the proof JWT or its jti into the audit
// chain (spec §4.7.2 K10). The audit chain is append-only and designed to be
// retained, so a credential-bearing artifact written there cannot be edited
// out later.
//
// Reason is the field at risk and the reason it is at risk is structural:
// denyAndAudit builds the audit entry's Reason from err.Error(), so any
// error text that echoed its input would land in the record permanently.
// Every DPoP denial shape is checked, including the replay — store.
// ErrProofSpent deliberately carries no jti for this exact reason, and this
// asserts that decision survives the trip through the PDP.
func TestDecide_ProofDenials_NeverWriteProofMaterialToTheAuditChain(t *testing.T) {
	tests := map[string]func(t *testing.T, f *boundFixture){
		"wrong key": func(t *testing.T, f *boundFixture) {
			t.Helper()
			f.req.DpopProof = signProof(t, newProofKey(t), testObservedMethod, testObservedURI, f.jti, f.iat)
		},
		"wrong request": func(t *testing.T, f *boundFixture) {
			t.Helper()
			f.req.DpopProof = signProof(t, f.key, "GET", testObservedURI, f.jti, f.iat)
		},
		"stale": func(t *testing.T, f *boundFixture) {
			t.Helper()
			stale := time.Now().Add(-testDPoPWindow - time.Minute).Truncate(time.Second)
			f.req.DpopProof = signProof(t, f.key, testObservedMethod, testObservedURI, f.jti, stale)
		},
		"replayed": func(t *testing.T, f *boundFixture) {
			t.Helper()
			// Spend it first, through the same path a real first call would,
			// so the second call below collides.
			if resp := f.decide(t); resp.GetEffect() != Effect_EFFECT_ALLOW {
				t.Fatalf("priming call Effect = %v, want EFFECT_ALLOW", resp.GetEffect())
			}
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			f := newBoundFixture(t)
			setup(t, &f)
			before := len(f.fs.appended)

			resp := f.decide(t)

			if resp.GetEffect() != Effect_EFFECT_DENY {
				t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
			}
			if len(f.fs.appended) != before+1 {
				t.Fatalf("audit entries appended = %d, want %d", len(f.fs.appended), before+1)
			}
			entry := f.fs.appended[before]
			for field, value := range map[string]string{"Reason": entry.Reason, "Action": entry.Action} {
				if strings.Contains(value, f.req.GetDpopProof()) {
					t.Errorf("audit %s = %q contains the proof JWT (K10)", field, value)
				}
				if strings.Contains(value, f.jti) {
					t.Errorf("audit %s = %q contains the proof's jti (K10)", field, value)
				}
			}
		})
	}
}

// --- tokenThumbprint: claim shapes tokenClaims never mints ---------------

// A verifying token whose cnf claim is malformed is REFUSED, never read as a
// bearer token. tokenClaims (token.go) writes cnf only for a non-empty
// thumbprint and never writes an empty one, precisely so that "absent means
// bearer, present means bound" has no third state — so anything here came
// from outside this system or from a future bug in what mints one, and
// silently downgrading it to "bearer" would be the more dangerous reading.
//
// Exercised directly against tokenThumbprint rather than through Decide:
// building a cryptographically valid token with a deliberately broken claim
// is more machinery than the property needs, the same reasoning
// authenticate_test.go's own direct unit tests already record.
func TestTokenThumbprint_RefusesAMalformedConfirmationClaim(t *testing.T) {
	tests := map[string]any{
		"cnf is a string, not an object": "some-thumbprint",
		"cnf carries no jkt":             map[string]any{"kid": "key-1"},
		"cnf.jkt is not a string":        map[string]any{thumbprintKey: 12345},
		// The state tokenClaims specifically refuses to mint: a token whose
		// cnf.jkt is "" looks bound to any reader that checks for presence,
		// while being matchable by no key at all.
		"cnf.jkt is the empty string": map[string]any{thumbprintKey: ""},
	}
	for name, cnf := range tests {
		t.Run(name, func(t *testing.T) {
			jkt, err := tokenThumbprint(jwtClaims(confirmationClaim, cnf))
			if err == nil {
				t.Fatalf("tokenThumbprint() = %q, nil; want an error: a malformed binding must never be "+
					"silently read as an unbound bearer token", jkt)
			}
			if jkt != "" {
				t.Errorf("tokenThumbprint() = %q on an error, want the empty string", jkt)
			}
		})
	}
}

// The absent case, stated separately because its answer is the opposite: no
// cnf at all is a BEARER token and not an error, which is the whole of K5's
// "an unbound token is not an error in the PDP".
func TestTokenThumbprint_AbsentConfirmationClaimIsABearerToken(t *testing.T) {
	jkt, err := tokenThumbprint(jwtClaims(subjectClaim, uuid.NewString()))
	if err != nil {
		t.Fatalf("tokenThumbprint() error = %v, want nil: a token with no cnf is a bearer token, which is "+
			"legitimate on the local surfaces (K5)", err)
	}
	if jkt != "" {
		t.Errorf("tokenThumbprint() = %q, want the empty string", jkt)
	}
}

// A verified token's claims decode through JSON, so cnf arrives as
// map[string]any regardless of what tokenClaims put in. Built here the same
// way rather than as a Go map[string]string, so these tests exercise the
// shape the real path actually sees.
func jwtClaims(key string, value any) map[string]any {
	return map[string]any{key: value}
}

// A sanity check on the fake that the replay test depends on: without
// single-use enforcement, TestDecide_ReplayedProof_Denies would pass on any
// implementation at all. Asserted here rather than trusted, since a fake
// that silently stopped enforcing would make that test vacuous rather than
// failing.
func TestFakeStore_SpendProofIsSingleUse(t *testing.T) {
	fs := &fakeStore{}
	if err := fs.SpendProof(context.Background(), "jti-1", time.Now()); err != nil {
		t.Fatalf("first SpendProof() = %v, want nil", err)
	}
	if err := fs.SpendProof(context.Background(), "jti-1", time.Now()); !errors.Is(err, store.ErrProofSpent) {
		t.Fatalf("second SpendProof() = %v, want store.ErrProofSpent", err)
	}
	if err := fs.SpendProof(context.Background(), "jti-2", time.Now()); err != nil {
		t.Fatalf("SpendProof() for a different jti = %v, want nil: single-use is per jti", err)
	}
}

// --- The control the V3 ordering tests actually rest on -------------------

// Every method on the Store interface increments fakeStore.calls.
//
// Both V3 ordering tests — TestDecide_EpochIsTheFirstStoreRead
// (tier_override_test.go) and TestDecide_EpochIsStillTheFirstStoreCallWhenA
// ProofIsSpent above — work by comparing LoadTenantEpoch's observed call
// count against zero. That is only a proof of "the epoch is read first" if
// EVERY other method counts. Twelve of them do, by convention, and until this
// test nothing checked it: removing the single `f.calls++` from SpendProof
// left TestDecide_EpochIsStillTheFirstStoreCallWhenAProofIsSpent GREEN with
// the spend deliberately moved ahead of the epoch read. Verified, not
// supposed.
//
// That is the same defect class as a reaper with no caller, one level up: the
// guard depends on a convention no test enforces, so the thirteenth store
// method added without that line silently hollows out both V3 tests and
// nothing fails.
//
// Driven by reflection over the Store interface rather than by a hand-written
// list, which is the whole point: a list would have to be extended by the
// same person who forgot the increment. Zero values for every argument —
// nothing here reads them, and the fake's error fields are all nil, so each
// method takes its success path and returns.
func TestFakeStore_EveryStoreMethodCountsItsCall(t *testing.T) {
	storeType := reflect.TypeOf((*Store)(nil)).Elem()
	if storeType.NumMethod() == 0 {
		t.Fatal("the Store interface has no methods: this test would pass vacuously")
	}

	fs := &fakeStore{}
	v := reflect.ValueOf(fs)
	for i := range storeType.NumMethod() {
		name := storeType.Method(i).Name
		t.Run(name, func(t *testing.T) {
			method := v.MethodByName(name)
			args := make([]reflect.Value, method.Type().NumIn())
			for j := range args {
				args[j] = reflect.New(method.Type().In(j)).Elem()
			}

			before := fs.calls
			method.Call(args)

			if fs.calls != before+1 {
				t.Errorf("fakeStore.%s did not increment calls (%d -> %d). Every store method must, or "+
					"the two V3 tests that assert \"zero store calls ran before LoadTenantEpoch\" silently "+
					"stop counting this one and pass for a decision that read it first", name, before, fs.calls)
			}
		})
	}
}

// --- The audit row a replay leaves behind ---------------------------------

// A denial after the token verified records WHICH delegation's token it was.
//
// This is the fix for a real gap, not a hypothetical: a replay denial used to
// write delegation_id NULL, root_delegation_id NULL, chain_depth 0 — because
// appendAudit gated DelegationID on `chain`, and chain is not loaded yet at
// that point. The id was in scope and verified the whole time. An operator
// investigating a replay storm therefore saw the agent and the actor and
// nothing tying either to a credential, in the one feature built specifically
// to make replay visible.
//
// Both DPoP denial shapes are covered, because they sit either side of the
// epoch read and it would be easy to fix one call site and miss the other.
//
// RootDelegationID staying nil is asserted too, and is not an oversight: it
// comes from chain[0] and chain genuinely was not loaded, so claiming a root
// would be inventing one. DelegationID and the chain-derived fields answer
// different questions, which is the whole point of the fix.
func TestDecide_ProofDenial_AuditRowNamesTheDelegationTheTokenIdentified(t *testing.T) {
	tests := map[string]func(t *testing.T, f *boundFixture){
		"the proof fails to verify (before the epoch read)": func(t *testing.T, f *boundFixture) {
			t.Helper()
			f.req.DpopProof = signProof(t, newProofKey(t), testObservedMethod, testObservedURI, f.jti, f.iat)
		},
		"the proof is a replay (after the epoch read)": func(t *testing.T, f *boundFixture) {
			t.Helper()
			if resp := f.decide(t); resp.GetEffect() != Effect_EFFECT_ALLOW {
				t.Fatalf("priming call Effect = %v, want EFFECT_ALLOW", resp.GetEffect())
			}
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			f := newBoundFixture(t)
			// The delegation the fixture's token names, read back from the
			// fixture's own chain rather than re-derived, so this asserts
			// against the same row Decide would have loaded.
			want := f.fs.chain[0].ID
			setup(t, &f)
			before := len(f.fs.appended)

			if resp := f.decide(t); resp.GetEffect() != Effect_EFFECT_DENY {
				t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
			}

			if len(f.fs.appended) != before+1 {
				t.Fatalf("audit entries appended = %d, want %d", len(f.fs.appended), before+1)
			}
			entry := f.fs.appended[before]
			if entry.DelegationID == nil {
				t.Fatal("audit entry DelegationID is nil: the token VERIFIED on this path, so the " +
					"delegation id was known — dropping it leaves an operator investigating a replay " +
					"storm unable to say which credential is being replayed")
			}
			if *entry.DelegationID != want {
				t.Errorf("audit entry DelegationID = %s, want %s", entry.DelegationID, want)
			}
			if entry.RootDelegationID != nil {
				t.Errorf("audit entry RootDelegationID = %v, want nil: it comes from chain[0] and the "+
					"chain was never loaded on this path, so any value here would be invented",
					entry.RootDelegationID)
			}
			if entry.ChainDepth != 0 {
				t.Errorf("audit entry ChainDepth = %d, want 0 for the same reason", entry.ChainDepth)
			}
		})
	}
}

// The converse, so the fix above cannot have been "always write an id": a
// token that never verified yields no delegation id at all, and that row must
// stay honest rather than pointing at the zero UUID. Asserted here alongside
// its positive counterpart rather than only in authenticate_test.go, because
// the two are now one decision in appendAudit and a change to either belongs
// in front of both.
func TestDecide_TokenFailure_AuditRowNamesNoDelegation(t *testing.T) {
	f := newBoundFixture(t)
	f.req.Token = "not-a-token-at-all"

	if resp := f.decide(t); resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}

	if len(f.fs.appended) != 1 {
		t.Fatalf("audit entries appended = %d, want 1", len(f.fs.appended))
	}
	if got := f.fs.appended[0].DelegationID; got != nil {
		t.Errorf("audit entry DelegationID = %v, want nil: this decision never identified a delegation "+
			"at all, which is a different fact from identifying the zero UUID", got)
	}
}
