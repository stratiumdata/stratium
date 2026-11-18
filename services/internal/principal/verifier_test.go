package principal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// fakeIssuer is a minimal OIDC provider: discovery plus a JWKS, with the
// private key kept so tests can mint tokens it will vouch for.
type fakeIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/keys",
			"authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) token(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifier_Identify(t *testing.T) {
	iss := newFakeIssuer(t)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(context.Background(), iss.srv.URL, "stratium", "email", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	good := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": iss.srv.URL, "aud": "stratium", "sub": "u-1",
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"email": "alice@example.com", "email_verified": true,
		}
	}
	with := func(k string, val any) jwt.MapClaims { c := good(); c[k] = val; return c }
	without := func(k string) jwt.MapClaims { c := good(); delete(c, k); return c }

	tests := []struct {
		name  string
		token string
		want  string // "" means ErrNotIdentified
	}{
		{"a valid token names its verified email", iss.token(t, iss.key, good()), "alice@example.com"},
		{"empty", "", ""},
		{"not a token", "not-a-jwt", ""},
		{"signed by a key the issuer does not publish", iss.token(t, stranger, good()), ""},
		{"another audience", iss.token(t, iss.key, with("aud", "someone-else")), ""},
		{"another issuer", iss.token(t, iss.key, with("iss", "https://evil.example")), ""},
		{"expired", iss.token(t, iss.key, with("exp", time.Now().Add(-time.Hour).Unix())), ""},
		{"email not verified", iss.token(t, iss.key, with("email_verified", false)), ""},
		{"email_verified absent", iss.token(t, iss.key, without("email_verified")), ""},
		{"no identity claim", iss.token(t, iss.key, without("email")), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := v.Identify(context.Background(), tt.token)
			if tt.want == "" {
				if !errors.Is(err, ErrNotIdentified) || got != "" {
					t.Fatalf("Identify() = %q, %v; want ErrNotIdentified", got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("Identify() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestNewVerifier_FailsAtStartupForAnUnreachableOrWrongIssuer(t *testing.T) {
	if _, err := NewVerifier(context.Background(), "http://127.0.0.1:1/nope", "a", "email", time.Second); err == nil {
		t.Error("unreachable issuer: want an error at construction")
	}
	iss := newFakeIssuer(t)
	if _, err := NewVerifier(context.Background(), iss.srv.URL, "a", "", time.Second); err == nil {
		t.Error("empty claim name: want an error")
	}
}

func TestIdentity(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		claim  string
		want   string
	}{
		{"plain claim", map[string]any{"upn": "a@x"}, "upn", "a@x"},
		{"absent", map[string]any{}, "upn", ""},
		{"not a string", map[string]any{"upn": 7}, "upn", ""},
		{"verified email", map[string]any{"email": "a@x", "email_verified": true}, "email", "a@x"},
		{"unverified email", map[string]any{"email": "a@x", "email_verified": false}, "email", ""},
		{"email_verified as a string is not verified", map[string]any{"email": "a@x", "email_verified": "true"}, "email", ""},
	}
	for _, tt := range tests {
		if got := Identity(tt.claims, tt.claim); got != tt.want {
			t.Errorf("%s: Identity() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// The PDP builds its verifier under a startup context it cancels straight
// away. Verification happens long after, and fetches signing keys lazily, so
// it must not be tied to that context.
func TestVerifier_OutlivesTheContextItWasBuiltWith(t *testing.T) {
	iss := newFakeIssuer(t)
	ctx, cancel := context.WithCancel(context.Background())
	v, err := NewVerifier(ctx, iss.srv.URL, "stratium", "email", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	cancel()

	tok := iss.token(t, iss.key, jwt.MapClaims{
		"iss": iss.srv.URL, "aud": "stratium", "sub": "u-1",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": "alice@example.com", "email_verified": true,
	})
	if got, err := v.Identify(context.Background(), tok); err != nil || got != "alice@example.com" {
		t.Fatalf("Identify() after the construction context was cancelled = %q, %v", got, err)
	}
}
