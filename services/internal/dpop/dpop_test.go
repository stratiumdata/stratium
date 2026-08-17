package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// --- RFC 7638's own worked example ---------------------------------------
//
// Both values below are transcribed from RFC 7638 §3.1 — the JWK it publishes
// and the thumbprint it publishes FOR that JWK. The expectation therefore does
// not share a code path with the implementation: a thumbprint computed by
// running this package twice would agree with itself no matter how wrong the
// canonicalization was, which is precisely the defect this vector exists to
// catch. Member order here is deliberately NOT lexicographic (kty, n, e, alg,
// kid), because RFC 7638 canonicalizes the parsed key, not the document.
const rfc7638ExampleJWK = `{
  "kty": "RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e": "AQAB",
  "alg": "RS256",
  "kid": "2011-04-29"
}`

const rfc7638ExampleThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

// A thumbprint carrying base64 padding or computed over a different digest
// would still "work" against an expectation this package produced itself, so
// pin the shape the cnf.jkt claim actually carries.
func TestThumbprint_IsUnpaddedBase64URLOfSHA256(t *testing.T) {
	got, err := Thumbprint([]byte(rfc7638ExampleJWK))
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if strings.ContainsAny(got, "=+/") {
		t.Fatalf("thumbprint %q is not unpadded base64url", got)
	}
	raw, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("thumbprint %q does not decode as base64url: %v", got, err)
	}
	if len(raw) != sha256.Size {
		t.Fatalf("thumbprint decodes to %d bytes, want %d (SHA-256)", len(raw), sha256.Size)
	}
}

// Extra members and a different member order in the document must not change
// the thumbprint: RFC 7638 canonicalizes the required members of the parsed
// key, never the bytes it arrived as.
func TestThumbprint_IgnoresDocumentOrderAndExtraMembers(t *testing.T) {
	reordered := `{"e":"AQAB","use":"sig","kid":"2011-04-29","alg":"RS256","kty":"RSA","n":"` +
		mustJWKMember(t, rfc7638ExampleJWK, "n") + `"}`
	got, err := Thumbprint([]byte(reordered))
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got != rfc7638ExampleThumbprint {
		t.Fatalf("reordering the document changed the thumbprint: got %q want %q", got, rfc7638ExampleThumbprint)
	}
}

// The EC vector, from the RFC this package implements. RFC 9449 §4.2 (Figure
// 4) publishes this P-256 key in its example proof header, and §6.1 (Figures 8
// and 9) publishes the cnf.jkt of the token that proof is bound to. ES256 is
// what DPoP clients actually use; RFC 7638's own worked example is RSA-only,
// which is the key type DPoP is least likely to see.
const (
	rfc9449ExampleJWK = `{
  "kty":"EC",
  "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
  "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
  "crv":"P-256"
}`
	rfc9449ExampleThumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
)

// The OKP vector, from RFC 8037 §A.3, which publishes both the Ed25519 JWK and
// its thumbprint.
const (
	rfc8037ExampleJWK        = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	rfc8037ExampleThumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
)

// One published vector per key type this package can thumbprint. Each of the
// three has a different required-member set and a different lexicographic
// order ({e,kty,n}, {crv,kty,x,y}, {crv,kty,x}), so a canonicalization that is
// right for one can still be wrong for another — a single RSA vector would not
// have caught it.
func TestThumbprint_MatchesPublishedVectors(t *testing.T) {
	for _, tc := range []struct{ name, jwk, want, source string }{
		{"RSA", rfc7638ExampleJWK, rfc7638ExampleThumbprint, "RFC 7638 §3.1"},
		{"EC P-256", rfc9449ExampleJWK, rfc9449ExampleThumbprint, "RFC 9449 §4.2 key, §6.1 jkt"},
		{"OKP Ed25519", rfc8037ExampleJWK, rfc8037ExampleThumbprint, "RFC 8037 §A.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Thumbprint([]byte(tc.jwk))
			if err != nil {
				t.Fatalf("Thumbprint: %v", err)
			}
			if got != tc.want {
				t.Fatalf("thumbprint disagrees with %s:\n got %q\nwant %q", tc.source, got, tc.want)
			}
		})
	}
}

func TestThumbprint_RejectsPrivateKey(t *testing.T) {
	key := newECKey(t)
	private, err := (&jose.JSONWebKey{Key: key}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal private jwk: %v", err)
	}
	if got, err := Thumbprint(private); err == nil {
		t.Fatalf("a JWK carrying private key material must be refused, got %q", got)
	}
}

func TestThumbprint_RejectsSymmetricKey(t *testing.T) {
	if got, err := Thumbprint([]byte(`{"kty":"oct","k":"c2VjcmV0LXNoYXJlZC1rZXktdmFsdWU"}`)); err == nil {
		t.Fatalf("a symmetric JWK must be refused, got %q", got)
	}
}

func TestThumbprint_RejectsWeakRSA(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak rsa key: %v", err)
	}
	doc, err := (&jose.JSONWebKey{Key: &weak.PublicKey}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal weak jwk: %v", err)
	}
	if got, err := Thumbprint(doc); err == nil {
		t.Fatalf("a 1024-bit RSA key is below RFC 7518 §3.3's floor and must be refused, got %q", got)
	}
}

func TestThumbprint_RejectsMalformedJWK(t *testing.T) {
	if _, err := Thumbprint([]byte(`{"kty":"RSA"`)); err == nil {
		t.Fatal("a truncated JWK document must be refused")
	}
}

// --- Verify ---------------------------------------------------------------

const (
	testHTM = "POST"
	testHTU = "https://pdp.example.com/v1/decide"
)

func TestVerify_ValidProof(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	proof := makeProof(t, header(t, key.Public()), claims(now), es256(key))

	got, err := Verify(proof, now, time.Minute)
	if err != nil {
		t.Fatalf("a well-formed, self-signed, fresh proof must verify: %v", err)
	}
	if got.htm != testHTM || got.htu != testHTU {
		t.Fatalf("htm/htu reported as %q/%q, want %q/%q", got.htm, got.htu, testHTM, testHTU)
	}
	// jkt, jti and iat are reachable only through MatchesRequest — a proof
	// that has not been shown to be for the request in hand yields nothing a
	// caller could bind or spend. See Proof's own doc comment.
	matched, err := got.MatchesRequest(testHTM, testHTU)
	if err != nil {
		t.Fatalf("the proof must match the request it was made for: %v", err)
	}
	if matched.JTI != "proof-0001" {
		t.Fatalf("jti reported as %q", matched.JTI)
	}
	if !matched.IssuedAt.Equal(now) {
		t.Fatalf("iat reported as %v, want %v", matched.IssuedAt, now)
	}
	pub, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	want, err := Thumbprint(pub)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if matched.JKT != want {
		t.Fatalf("jkt %q does not match the header key's thumbprint %q", matched.JKT, want)
	}
}

// The signature must verify against the key the header names. A proof that
// advertises one key and is signed by another proves possession of neither.
func TestVerify_RejectsWrongKeySignature(t *testing.T) {
	advertised := newECKey(t)
	actual := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	proof := makeProof(t, header(t, advertised.Public()), claims(now), es256(actual))
	if _, err := Verify(proof, now, time.Minute); err == nil {
		t.Fatal("a proof signed by a key other than the one in its header must fail")
	}
}

func TestVerify_RejectsAlgNone(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	h := header(t, key.Public())
	h["alg"] = "none"
	proof := makeProof(t, h, claims(now), unsigned())

	if _, err := Verify(proof, now, time.Minute); err == nil {
		t.Fatal("alg: none must be rejected")
	}
}

// An HS256 proof whose "secret" is the public key is the classic alg-confusion
// defeat: if the verifier honours the header's alg, anyone holding the public
// key can mint proofs.
//
// READ THE NEXT SENTENCE BEFORE TRUSTING THIS TEST. Like TestVerify_RejectsAlgNone
// above it, this test passes for a reason other than the one it is named for,
// verified by mutation: adding jose.HS256/384/512 to allowedAlgorithms leaves
// all three subtests GREEN. The header JWK parses to an *ecdsa.PublicKey, and
// go-jose's HMAC verifier refuses a non-[]byte key a layer deeper, so the
// allowlist is never what rejects this. The attack is not executable through
// this code path at all. What actually holds the allowlist shut is
// TestAllowedAlgorithms_MatchExactlyTheRegisteredAsymmetricSet.
func TestVerify_RejectsSymmetricAlg(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	pub, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		t.Run(alg, func(t *testing.T) {
			h := header(t, key.Public())
			h["alg"] = alg
			proof := makeProof(t, h, claims(now), hs256(pub))
			if _, err := Verify(proof, now, time.Minute); err == nil {
				t.Fatalf("a symmetric alg (%s) must be rejected", alg)
			}
		})
	}
}

// The allowlist is the security control, and behaviour alone cannot hold it
// shut in EITHER direction. Mutation-testing this package showed both halves:
//
//   - Adding "none" — or HS256/384/512 — leaves every behavioural test above
//     green, because go-jose's verifier refuses the algorithm one step later
//     and the proof is rejected anyway. Widening the list is invisible.
//   - Narrowing the list to {ES256, RS256} also survives the whole suite,
//     because nothing exercised the other eight entries. Dropping EdDSA would
//     break every Ed25519 client and ship green.
//
// So pin the set exactly. Both halves matter: the forbidden half is a security
// property, the required half is an interoperability one, and each has its own
// silent failure mode.
func TestAllowedAlgorithms_MatchExactlyTheRegisteredAsymmetricSet(t *testing.T) {
	want := map[jose.SignatureAlgorithm]bool{
		jose.ES256: true, jose.ES384: true, jose.ES512: true,
		jose.PS256: true, jose.PS384: true, jose.PS512: true,
		jose.RS256: true, jose.RS384: true, jose.RS512: true,
		jose.EdDSA: true,
	}
	got := map[jose.SignatureAlgorithm]bool{}
	for _, alg := range allowedAlgorithms {
		s := string(alg)
		switch {
		case s == "":
			t.Error("the allowlist contains an empty algorithm")
		case strings.EqualFold(s, "none"):
			t.Errorf("%q must never be in the allowlist (RFC 9449 §4.3 item 5)", s)
		case strings.HasPrefix(s, "HS"):
			t.Errorf("%q is symmetric and must never be in the allowlist", s)
		}
		if got[alg] {
			t.Errorf("%q appears twice in the allowlist", s)
		}
		got[alg] = true
	}
	for alg := range want {
		if !got[alg] {
			t.Errorf("%q is missing from the allowlist; dropping it breaks every client using it", alg)
		}
	}
	for alg := range got {
		if !want[alg] {
			t.Errorf("%q was added to the allowlist without being added here", alg)
		}
	}
}

// The positive half again, behaviourally: every advertised algorithm must
// actually round-trip a proof. An entry that is listed but unusable is the
// same interoperability failure as one that is missing, and the exact-set test
// above cannot see it.
func TestVerify_AcceptsEveryAdvertisedAlgorithm(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, alg := range allowedAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			signer, err := jose.NewSigner(
				jose.SigningKey{Algorithm: alg, Key: signingKeyFor(t, alg)},
				(&jose.SignerOptions{EmbedJWK: true}).WithType(proofType),
			)
			if err != nil {
				t.Fatalf("new signer: %v", err)
			}
			payload, err := json.Marshal(claims(now))
			if err != nil {
				t.Fatalf("marshal claims: %v", err)
			}
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			compact, err := signed.CompactSerialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			got, err := Verify(compact, now, time.Minute)
			if err != nil {
				t.Fatalf("a proof signed with the advertised alg %s must verify: %v", alg, err)
			}
			matched, err := got.MatchesRequest(testHTM, testHTU)
			if err != nil {
				t.Fatalf("a %s proof must match the request it was made for: %v", alg, err)
			}
			if matched.JKT == "" {
				t.Fatalf("no thumbprint computed for a %s proof", alg)
			}
		})
	}
}

func TestVerify_RejectsNonPositiveWindow(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	proof := makeProof(t, header(t, key.Public()), claims(now), es256(key))

	for _, window := range []time.Duration{0, -time.Second} {
		if _, err := Verify(proof, now, window); err == nil {
			t.Fatalf("a window of %s is a configuration error and must be refused, "+
				"not silently treated as very strict: an iat on the same second as now "+
				"satisfies both bounds", window)
		}
	}
}

func TestVerify_RejectsMissingOrWrongTyp(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	for name, typ := range map[string]any{
		"absent":     nil,
		"empty":      "",
		"jwt":        "JWT",
		"wrong case": "DPOP+JWT",
		"not string": 42,
	} {
		t.Run(name, func(t *testing.T) {
			h := header(t, key.Public())
			if typ == nil {
				delete(h, "typ")
			} else {
				h["typ"] = typ
			}
			proof := makeProof(t, h, claims(now), es256(key))
			if _, err := Verify(proof, now, time.Minute); err == nil {
				t.Fatalf("typ %v must be rejected", typ)
			}
		})
	}
}

func TestVerify_RejectsMissingJWK(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	h := header(t, key.Public())
	delete(h, "jwk")
	proof := makeProof(t, h, claims(now), es256(key))

	if _, err := Verify(proof, now, time.Minute); err == nil {
		t.Fatal("a proof with no jwk header must be rejected")
	}
}

// RFC 9449 §4.3 item 7: the jwk header must not contain a private key.
func TestVerify_RejectsPrivateKeyInHeader(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	h := header(t, key) // the private key, not key.Public()
	proof := makeProof(t, h, claims(now), es256(key))

	if _, err := Verify(proof, now, time.Minute); err == nil {
		t.Fatal("a jwk header carrying private key material must be rejected")
	}
}

// RFC 7518 §3.3 floors RS*/PS* at 2048 bits and go-jose enforces no floor of
// its own, so a proof signed with a forgeable RSA key parses and verifies
// unless this package refuses it.
func TestVerify_RejectsWeakRSAKey(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak rsa key: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	h := header(t, &weak.PublicKey)
	h["alg"] = "RS256"
	proof := makeProof(t, h, claims(now), rs256(weak))

	if _, err := Verify(proof, now, time.Minute); err == nil {
		t.Fatal("a proof signed with a 1024-bit RSA key must be rejected")
	}
}

// A 2048-bit RSA proof is the control for the case above: the floor must
// reject weak keys without rejecting RS256 outright.
func TestVerify_AcceptsRSAAtTheFloor(t *testing.T) {
	strong, err := rsa.GenerateKey(rand.Reader, minRSABits)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	h := header(t, &strong.PublicKey)
	h["alg"] = "RS256"
	proof := makeProof(t, h, claims(now), rs256(strong))

	if _, err := Verify(proof, now, time.Minute); err != nil {
		t.Fatalf("a 2048-bit RS256 proof must verify: %v", err)
	}
}

// The signature can be perfectly good over a payload that is not JSON at all.
func TestVerify_RejectsNonJSONPayload(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	payload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	signingInput := segment(t, header(t, key.Public())) + "." + payload
	proof := signingInput + "." + es256(key)(t, signingInput)

	if _, err := Verify(proof, now, time.Minute); err == nil {
		t.Fatal("a proof whose payload is not JSON must be rejected")
	}
}

func TestVerify_RejectsMissingClaim(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	for _, claim := range []string{"htm", "htu", "jti", "iat"} {
		t.Run(claim, func(t *testing.T) {
			c := claims(now)
			delete(c, claim)
			proof := makeProof(t, header(t, key.Public()), c, es256(key))
			if _, err := Verify(proof, now, time.Minute); err == nil {
				t.Fatalf("a proof with no %s claim must be rejected", claim)
			}
		})
	}
}

// The window is symmetric: a client whose clock runs fast is as much a
// freshness failure as one whose proof is old, and a one-sided check would
// silently accept one of them forever.
func TestVerify_RejectsIATOutsideWindowInBothDirections(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	const window = time.Minute

	for name, iat := range map[string]time.Time{
		"too old":    now.Add(-window - time.Second),
		"too future": now.Add(window + time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			proof := makeProof(t, header(t, key.Public()), claims(iat), es256(key))
			if _, err := Verify(proof, now, window); err == nil {
				t.Fatalf("an iat %s must be rejected", name)
			}
		})
	}
}

func TestVerify_AcceptsIATAtWindowEdgeInBothDirections(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	const window = time.Minute

	for name, iat := range map[string]time.Time{
		"oldest allowed": now.Add(-window),
		"newest allowed": now.Add(window),
		"exactly now":    now,
	} {
		t.Run(name, func(t *testing.T) {
			proof := makeProof(t, header(t, key.Public()), claims(iat), es256(key))
			if _, err := Verify(proof, now, window); err != nil {
				t.Fatalf("an iat %s must be accepted: %v", name, err)
			}
		})
	}
}

// The window is a parameter, not a constant: the same proof and the same clock
// must give opposite answers under different configured windows (spec K9).
func TestVerify_WindowIsAParameter(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	proof := makeProof(t, header(t, key.Public()), claims(now.Add(-90*time.Second)), es256(key))

	if _, err := Verify(proof, now, time.Minute); err == nil {
		t.Fatal("a 90s-old proof must fail a 60s window")
	}
	if _, err := Verify(proof, now, 2*time.Minute); err != nil {
		t.Fatalf("the same proof must pass a 120s window: %v", err)
	}
}

// RFC 9449 §4.1 carries the proof in an HTTP header field. The JWS JSON
// serialization has no business there and raises "which signature verified?".
func TestVerify_RejectsJSONSerialization(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	compact := makeProof(t, header(t, key.Public()), claims(now), es256(key))

	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a three-part compact JWS, got %d parts", len(parts))
	}
	jsonForm := `{"protected":"` + parts[0] + `","payload":"` + parts[1] + `","signature":"` + parts[2] + `"}`

	if _, err := Verify(jsonForm, now, time.Minute); err == nil {
		t.Fatal("the JWS JSON serialization must be rejected")
	}
}

func TestVerify_RejectsGarbage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, s := range []string{"", "not-a-jwt", "a.b.c", "..", strings.Repeat("x", 100)} {
		if _, err := Verify(s, now, time.Minute); err == nil {
			t.Fatalf("%q must not verify", s)
		}
	}
}

// --- MatchesRequest -------------------------------------------------------

func TestMatchesRequest_IgnoresQueryAndFragmentButNotPath(t *testing.T) {
	p := Proof{htm: "GET", htu: "https://pdp.example.com/v1/decide"}

	matching := []string{
		"https://pdp.example.com/v1/decide",
		"https://pdp.example.com/v1/decide?tenant=acme&x=1",
		"https://pdp.example.com/v1/decide#section",
		"https://pdp.example.com/v1/decide?a=1#section",
	}
	for _, uri := range matching {
		if _, err := p.MatchesRequest("GET", uri); err != nil {
			t.Errorf("%s should match (query and fragment are ignored): %v", uri, err)
		}
	}

	notMatching := []string{
		"https://pdp.example.com/v1/decide/",  // trailing slash is a different path
		"https://pdp.example.com/v1/DECIDE",   // path is case-sensitive
		"https://pdp.example.com/v2/decide",   // different path
		"https://pdp.example.com/v1",          // prefix, not the path
		"https://other.example.com/v1/decide", // different host
		"http://pdp.example.com/v1/decide",    // different scheme
	}
	for _, uri := range notMatching {
		if _, err := p.MatchesRequest("GET", uri); err == nil {
			t.Errorf("%s must not match", uri)
		}
	}
}

// The proof's own htu is normalized the same way the observed URI is, so the
// query has to be ignored from whichever side carries it.
func TestMatchesRequest_IgnoresQueryOnTheClaimSideToo(t *testing.T) {
	p := Proof{htm: "GET", htu: "https://pdp.example.com/v1/decide?stale=1#frag"}
	if _, err := p.MatchesRequest("GET", "https://pdp.example.com/v1/decide"); err != nil {
		t.Fatalf("a query in the htu claim must be ignored: %v", err)
	}
}

func TestMatchesRequest_SchemeAndHostAreCaseInsensitive(t *testing.T) {
	p := Proof{htm: "POST", htu: "HTTPS://PDP.Example.COM/v1/decide"}
	if _, err := p.MatchesRequest("POST", "https://pdp.example.com/v1/decide"); err != nil {
		t.Fatalf("scheme and host compare case-insensitively (RFC 3986 §6.2.2.1): %v", err)
	}
}

// RFC 3986 §6.2.3 scheme-based normalization, which RFC 9449 §4.3 asks for:
// the default port for the scheme is equivalent to no port at all. Without it
// a correct client is denied for naming the same resource in a legal way.
func TestMatchesRequest_DropsTheDefaultPort(t *testing.T) {
	cases := map[string][2]string{
		"https default": {"https://pdp.example.com:443/v1/decide", "https://pdp.example.com/v1/decide"},
		"http default":  {"http://pdp.example.com:80/v1/decide", "http://pdp.example.com/v1/decide"},
		"empty path":    {"https://pdp.example.com", "https://pdp.example.com/"},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			p := Proof{htm: "POST", htu: pair[0]}
			if _, err := p.MatchesRequest("POST", pair[1]); err != nil {
				t.Fatalf("%s and %s name the same resource: %v", pair[0], pair[1], err)
			}
		})
	}
}

// A non-default port is part of the authority and must still be compared.
func TestMatchesRequest_KeepsANonDefaultPort(t *testing.T) {
	p := Proof{htm: "POST", htu: "https://pdp.example.com:8443/v1/decide"}
	if _, err := p.MatchesRequest("POST", "https://pdp.example.com/v1/decide"); err == nil {
		t.Fatal("a non-default port must not be dropped")
	}
}

func TestMatchesRequest_MethodIsExact(t *testing.T) {
	p := Proof{htm: "POST", htu: testHTU}
	if _, err := p.MatchesRequest("GET", testHTU); err == nil {
		t.Fatal("a different method must not match")
	}
	if _, err := p.MatchesRequest("post", testHTU); err == nil {
		t.Fatal("HTTP methods are case-sensitive (RFC 9110 §9.1)")
	}
}

// A relative or schemeless htu is an error, not a match. Comparing bare paths
// would let a proof minted for one origin satisfy a request to another.
func TestMatchesRequest_RejectsNonAbsoluteURI(t *testing.T) {
	if _, err := (Proof{htm: "GET", htu: "/v1/decide"}).MatchesRequest("GET", "/v1/decide"); err == nil {
		t.Fatal("a relative htu must be an error, not a match")
	}
	// Deliberately NOT self-matched, and it cannot be: isolating the observed
	// side needs a valid htu, which is inherently a mismatch. So this case
	// would still error with the absolute-URI guard removed entirely — from
	// the mismatch, not the guard. What it does assert, and what no other case
	// covers, is that the OBSERVED side is validated at all rather than only
	// the claim. Do not "strengthen" it by self-matching; that would delete
	// the one property it holds.
	if _, err := (Proof{htm: "GET", htu: testHTU}).MatchesRequest("GET", "/v1/decide"); err == nil {
		t.Fatal("a relative observed URI must be an error")
	}
	// Self-matched, so a plain mismatch cannot produce the error: with the
	// guard removed these two canonicalize identically and the call succeeds.
	if _, err := (Proof{htm: "GET", htu: "pdp.example.com/v1/decide"}).
		MatchesRequest("GET", "pdp.example.com/v1/decide"); err == nil {
		t.Fatal("a schemeless htu must be an error")
	}
}

// url.Host excludes userinfo, so reading it would silently drop the
// credentials and compare the URI equal to a bare one — a normalization
// RFC 3986 §6.2.3 does not authorize. Reject instead (RFC 9110 §4.2.1).
func TestMatchesRequest_RejectsUserinfo(t *testing.T) {
	withUser := "https://alice:secret@pdp.example.com/v1/decide"
	if _, err := (Proof{htm: "GET", htu: withUser}).MatchesRequest("GET", testHTU); err == nil {
		t.Fatal("userinfo in the htu claim must be refused, not dropped")
	} else if strings.Contains(err.Error(), "secret") {
		t.Fatalf("the error echoed the userinfo password: %v", err)
	}
	if _, err := (Proof{htm: "GET", htu: testHTU}).MatchesRequest("GET", withUser); err == nil {
		t.Fatal("userinfo in the observed URI must be refused")
	}
}

// RFC 3986 §6.2.2.1 case normalization is US-ASCII. strings.ToLower applies
// full Unicode case mapping, under which U+212A KELVIN SIGN folds to "k".
func TestMatchesRequest_CaseFoldIsASCIIOnly(t *testing.T) {
	p := Proof{htm: "GET", htu: "https://Kelvin.example.com/p"}
	if _, err := p.MatchesRequest("GET", "https://kelvin.example.com/p"); err == nil {
		t.Fatal("U+212A must not fold to ASCII 'k': RFC 3986 §6.2.2.1 is ASCII-only")
	}
	// The ASCII fold itself must still work.
	if _, err := (Proof{htm: "GET", htu: "https://KELVIN.example.com/p"}).
		MatchesRequest("GET", "https://kelvin.example.com/p"); err != nil {
		t.Fatalf("ASCII case folding must still apply: %v", err)
	}
}

// The empty-host guard has to run AFTER the default port comes off, or
// "https://:443/p" is non-empty when it is checked and canonicalizes to
// "https:///p" three lines later.
//
// Each URI is matched against ITSELF on purpose. Comparing against some other
// host would let a plain mismatch produce the error and the test would pass
// with the guard misplaced — which is exactly what the first version of this
// test did, and the mutation suite caught it. Against itself, a mismatch
// cannot be the reason, so only the guard can be.
func TestMatchesRequest_RejectsEmptyHostAfterPortTrim(t *testing.T) {
	for _, bad := range []string{"https://:443/p", "http://:80/p", "https:///p"} {
		if _, err := (Proof{htm: "GET", htu: bad}).MatchesRequest("GET", bad); err == nil {
			t.Errorf("%q has no host and must be refused even against itself", bad)
		}
	}
}

func TestMatchesRequest_RejectsUnparseableURI(t *testing.T) {
	bad := "https://pdp.example.com/\x7f\x00" // control characters: url.Parse fails
	if _, err := (Proof{htm: "GET", htu: bad}).MatchesRequest("GET", testHTU); err == nil {
		t.Fatal("an unparseable htu must be an error")
	}
	if _, err := (Proof{htm: "GET", htu: testHTU}).MatchesRequest("GET", bad); err == nil {
		t.Fatal("an unparseable observed URI must be an error")
	}
}

// url.Path is percent-decoded; comparing it would make %2F equal to a real
// path separator, which is a different resource on any segment-routing server.
func TestMatchesRequest_DoesNotDecodePercentEncodedPath(t *testing.T) {
	p := Proof{htm: "GET", htu: "https://pdp.example.com/a%2Fb"}
	if _, err := p.MatchesRequest("GET", "https://pdp.example.com/a/b"); err == nil {
		t.Fatal("%2F must not compare equal to /")
	}
}

// A verified proof feeds straight into MatchesRequest; check the seam rather
// than only the two halves.
func TestVerifyThenMatchesRequest(t *testing.T) {
	key := newECKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	proof := makeProof(t, header(t, key.Public()), claims(now), es256(key))

	p, err := Verify(proof, now, time.Minute)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := p.MatchesRequest(testHTM, testHTU+"?trace=1"); err != nil {
		t.Fatalf("the verified proof should match the request it was made for: %v", err)
	}
	if _, err := p.MatchesRequest(testHTM, "https://pdp.example.com/v1/other"); err == nil {
		t.Fatal("the verified proof must not match a different path")
	}
}

// --- helpers --------------------------------------------------------------
//
// Proofs are assembled by hand rather than with a JOSE signer, because half
// the cases here are ones no correct signer will produce: alg: none with an
// empty signature, a header advertising one key and a signature made with
// another, a missing typ. A helper that could only emit valid proofs could not
// test the rejections that matter.

type signFunc func(t *testing.T, signingInput string) string

// signingKeyFor returns a key of the right type and size for alg. One RSA key
// serves all six RSA algorithms — generating six 2048-bit keys is seconds of
// test time for no extra coverage.
var (
	sharedRSAOnce sync.Once
	sharedRSAKey  *rsa.PrivateKey
)

func signingKeyFor(t *testing.T, alg jose.SignatureAlgorithm) any {
	t.Helper()
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512:
		curve := map[jose.SignatureAlgorithm]elliptic.Curve{
			jose.ES256: elliptic.P256(), jose.ES384: elliptic.P384(), jose.ES512: elliptic.P521(),
		}[alg]
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("generate %s key: %v", alg, err)
		}
		return key
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		sharedRSAOnce.Do(func() {
			sharedRSAKey, _ = rsa.GenerateKey(rand.Reader, minRSABits)
		})
		if sharedRSAKey == nil {
			t.Fatal("generate rsa key")
		}
		return sharedRSAKey
	case jose.EdDSA:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate ed25519 key: %v", err)
		}
		return key
	default:
		t.Fatalf("no test key for algorithm %q -- was it added to allowedAlgorithms?", alg)
		return nil
	}
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

// header builds a default-valid DPoP header around whatever key it is given.
// Passing a private key is how the "jwk contains a private key" case is built.
func header(t *testing.T, key any) map[string]any {
	t.Helper()
	doc, err := (&jose.JSONWebKey{Key: key}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(doc, &jwk); err != nil {
		t.Fatalf("unmarshal jwk: %v", err)
	}
	return map[string]any{"typ": proofType, "alg": "ES256", "jwk": jwk}
}

func claims(iat time.Time) map[string]any {
	return map[string]any{
		"htm": testHTM,
		"htu": testHTU,
		"jti": "proof-0001",
		"iat": iat.Unix(),
	}
}

func makeProof(t *testing.T, hdr, cl map[string]any, sign signFunc) string {
	t.Helper()
	signingInput := segment(t, hdr) + "." + segment(t, cl)
	return signingInput + "." + sign(t, signingInput)
}

func segment(t *testing.T, v map[string]any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal segment: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func es256(key *ecdsa.PrivateKey) signFunc {
	return func(t *testing.T, signingInput string) string {
		t.Helper()
		sum := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		// JWS ECDSA signatures are fixed-width R||S, 32 bytes each for P-256
		// (RFC 7518 §3.4) — not the ASN.1 form crypto/ecdsa marshals.
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return base64.RawURLEncoding.EncodeToString(sig)
	}
}

func rs256(key *rsa.PrivateKey) signFunc {
	return func(t *testing.T, signingInput string) string {
		t.Helper()
		sum := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(sig)
	}
}

func hs256(secret []byte) signFunc {
	return func(t *testing.T, signingInput string) string {
		t.Helper()
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signingInput))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
}

func unsigned() signFunc {
	return func(*testing.T, string) string { return "" }
}

func mustJWKMember(t *testing.T, doc, member string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("unmarshal jwk: %v", err)
	}
	s, ok := m[member].(string)
	if !ok {
		t.Fatalf("jwk has no string member %q", member)
	}
	return s
}
