package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// testIdP is a minimal, real HTTP OIDC provider for tests: a discovery
// document plus a JWKS endpoint, backed by an RSA key pair generated fresh
// per test and never written to disk -- see the task's "generate them at
// test time" rule. It exists so every test in this file exercises
// NewVerifier's actual discovery-and-verification path against real HTTP,
// the same path a customer's real IdP goes through, rather than a
// hand-rolled stand-in for coreos/go-oidc's own behavior.
type testIdP struct {
	server *httptest.Server
	signer *rsa.PrivateKey // the key this IdP vouches for via its JWKS
}

const testKeyID = "test-key-1"

// idpAuthorizationEndpoint and idpTokenEndpoint are the endpoints
// newTestIdP's discovery document advertises, both on an origin that is NOT
// the issuer's own -- see that document's own comment.
const (
	idpAuthorizationEndpoint = "https://authorize.idp-example.test/o/oauth2/v2/auth"
	idpTokenEndpoint         = "https://oauth2.idp-example.test/token"
)

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test IdP signing key: %v", err)
	}

	idp := &testIdP{signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// idp.server is read here, at request time, not at registration
		// time above -- by the time any request reaches this handler,
		// idp.server has already been assigned below, since
		// httptest.NewServer does not serve until it returns.
		// authorization_endpoint and token_endpoint are deliberately on a
		// DIFFERENT host from the issuer, mirroring Google Workspace (issuer
		// accounts.google.com, token endpoint oauth2.googleapis.com). Nothing
		// about token verification reads them -- they exist so the admin UI's
		// connect-src is exercised against the shape that actually breaks a
		// CSP derived from the issuer alone. Not a live server: no test here
		// fetches either URL.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.server.URL,
			"jwks_uri":                              idp.server.URL + "/jwks",
			"authorization_endpoint":                idpAuthorizationEndpoint,
			"token_endpoint":                        idpTokenEndpoint,
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		jwk := jose.JSONWebKey{Key: &idp.signer.PublicKey, KeyID: testKeyID, Algorithm: "RS256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// validClaims returns a claim set NewVerifier's Verify accepts outright
// against idp for audience aud: correct iss, correct aud, not expired.
// Every refusal test below starts from a copy of this and breaks exactly
// one field, so a pass proves THAT check specifically runs, not just that
// something about the token looked wrong.
func (idp *testIdP) validClaims(aud string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": idp.server.URL,
		"aud": aud,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sub": "operator-1",
	}
}

// mintToken signs claims as a compact RS256 JWT under kid using signer's
// private key -- signer and kid are passed separately (rather than always
// idp.signer/testKeyID) so TestVerifier_WronglySignedToken_Refused can mint
// a token claiming the real kid while actually signing with a different
// key, the shape a spoofed signature takes.
func mintToken(t *testing.T, signer *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(signer)
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return signed
}

func TestNewVerifier_DiscoversProviderAndVerifiesValidToken(t *testing.T) {
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v, want nil", err)
	}

	claims := idp.validClaims("stratium-pap")
	claims["roles"] = "org-admins"
	tok := mintToken(t, idp.signer, testKeyID, claims)

	got, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil for a validly signed, unexpired, "+
			"correctly issued-and-audienced token", err)
	}
	if got["roles"] != "org-admins" {
		t.Errorf("claims[\"roles\"] = %v, want %q -- Verify must return the token's real "+
			"claims for resolveRole to read", got["roles"], "org-admins")
	}
}

func TestNewVerifier_UnreachableIssuer_FailsFast(t *testing.T) {
	idp := newTestIdP(t)
	idp.server.Close() // the URL now refuses connections immediately

	_, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 2*time.Second)
	if err == nil {
		t.Fatal("NewVerifier() error = nil, want discovery against an unreachable issuer to fail startup")
	}
}

// --- Five separate refusal modes, five separate tests -----------------
//
// A single "a bad token is refused" test would leave four of these five
// checks unguarded: a mutant that, say, verified the signature but forgot
// to compare aud would still pass every other bad-token case, and only the
// wrong-audience test specifically would catch it. See the task brief's own
// mutation-testing requirement.

func TestVerifier_ExpiredToken_Refused(t *testing.T) {
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	claims := idp.validClaims("stratium-pap")
	claims["exp"] = time.Now().Add(-time.Hour).Unix() // the one broken field
	tok := mintToken(t, idp.signer, testKeyID, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() error = nil, want a refusal for an expired token")
	}
}

func TestVerifier_WronglySignedToken_Refused(t *testing.T) {
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	impostor, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate impostor key: %v", err)
	}
	claims := idp.validClaims("stratium-pap")
	// Signed by a key NOT in the IdP's published JWKS, but still claiming
	// the real kid -- proves Verify cryptographically checks the
	// signature rather than trusting "a key with this kid is known."
	tok := mintToken(t, impostor, testKeyID, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() error = nil, want a refusal for a token whose signature does not match the published key")
	}
}

func TestVerifier_WrongAudience_Refused(t *testing.T) {
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	claims := idp.validClaims("some-other-service") // the one broken field
	tok := mintToken(t, idp.signer, testKeyID, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() error = nil, want a refusal for a token whose audience is not this deployment's")
	}
}

func TestVerifier_WrongIssuer_Refused(t *testing.T) {
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	claims := idp.validClaims("stratium-pap")
	claims["iss"] = "https://not-this-idp.example.com" // the one broken field
	tok := mintToken(t, idp.signer, testKeyID, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() error = nil, want a refusal for a token issued by a different issuer")
	}
}

func TestVerifier_MalformedToken_Refused(t *testing.T) {
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	for _, malformed := range []string{"", "not-a-jwt-at-all", "only.two-parts", "a.b.c.d-too-many-parts"} {
		if _, err := v.Verify(context.Background(), malformed); err == nil {
			t.Errorf("Verify(%q) error = nil, want a refusal for a malformed token", malformed)
		}
	}
}

// TestVerifier_RefusalErrorNeverEchoesTokenClaims defends the phase's
// logging rule at its narrowest, most concrete point: go-oidc's own errors
// routinely quote the rejected token's actual claim values back (e.g. an
// issuer mismatch's error text is "expected %q got %q" naming the token's
// real iss) -- exactly what "never log a bearer token, an operator's
// claims, or anything derived from them" forbids. Verify swallows that
// detail into a fixed errTokenInvalid rather than passing it through, so
// even a future caller careless enough to log err cannot leak a claim
// value -- this test is what would catch that swallow being removed.
func TestVerifier_RefusalErrorNeverEchoesTokenClaims(t *testing.T) {
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	const leakCanary = "leaked-issuer-marker-should-never-appear-in-an-error"
	claims := idp.validClaims("stratium-pap")
	claims["iss"] = "https://" + leakCanary + ".example.com"
	tok := mintToken(t, idp.signer, testKeyID, claims)

	_, verifyErr := v.Verify(context.Background(), tok)
	if verifyErr == nil {
		t.Fatal("Verify() error = nil, want a refusal for a token issued by a different issuer")
	}
	if strings.Contains(verifyErr.Error(), leakCanary) {
		t.Errorf("Verify() error = %q, leaked a claim value from the rejected token", verifyErr.Error())
	}
}

// TestNewVerifier_CapturesTheDiscoveredBrowserEndpoints closes the wiring gap
// between OIDC discovery and the admin UI's Content-Security-Policy. The
// endpoints a browser reaches during sign-in are named only in the IdP's
// discovery document, and this process is the only thing that reads it --
// so if they are not captured here, ui.go has no way to learn them and
// connect-src falls back to the issuer's origin alone, silently blocking the
// token exchange for every IdP that serves it from a different host.
func TestNewVerifier_CapturesTheDiscoveredBrowserEndpoints(t *testing.T) {
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	got := v.BrowserEndpoints()
	want := []string{idpAuthorizationEndpoint, idpTokenEndpoint}
	if !slices.Equal(got, want) {
		t.Errorf("BrowserEndpoints() = %v, want %v -- these come from the discovery document and "+
			"nowhere else; without them the admin UI's connect-src cannot name the token endpoint's origin",
			got, want)
	}
}
