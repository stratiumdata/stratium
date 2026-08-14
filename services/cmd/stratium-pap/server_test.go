package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// testServer builds a real Server backed by a real, freshly-generated-key
// test IdP (newTestIdP, oidc_test.go) and the three-tier role mapping
// routeTable's own GET/POST/DELETE routes exercise -- shared setup for
// every test below so each one only states what it varies.
type testServerFixture struct {
	idp    *testIdP
	server *Server
}

func newTestServerFixture(t *testing.T) *testServerFixture {
	t.Helper()
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	roles, err := newRoleMapping([]string{"org-admins"}, []string{"org-editors"}, []string{"org-viewers"})
	if err != nil {
		t.Fatalf("newRoleMapping() error = %v", err)
	}
	return &testServerFixture{idp: idp, server: NewServer(v, "roles", roles)}
}

// token mints a validly signed, unexpired token for group (one of the
// fixture's own configured group names, or "" for "no roles claim at
// all") against this fixture's IdP and audience.
func (f *testServerFixture) token(t *testing.T, group string) string {
	t.Helper()
	claims := f.idp.validClaims("stratium-pap")
	if group != "" {
		claims["roles"] = group
	}
	return mintToken(t, f.idp.signer, testKeyID, claims)
}

func doRequest(t *testing.T, server *Server, method, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

// --- "a valid token with a sufficient role reaches the handler" --------

func TestServer_SufficientRole_ReachesHandler(t *testing.T) {
	f := newTestServerFixture(t)

	tests := []struct {
		name   string
		method string
		path   string
		group  string
	}{
		{"viewer reads", http.MethodGet, "/v1/policies", "org-viewers"},
		{"editor writes", http.MethodPost, "/v1/policies", "org-editors"},
		{"admin deletes", http.MethodDelete, "/v1/policies/abc-123", "org-admins"},
		// Each role also meets every route with a lower minimum -- editor
		// can read, admin can read and write.
		{"editor reads too", http.MethodGet, "/v1/policies", "org-editors"},
		{"admin reads too", http.MethodGet, "/v1/policies", "org-admins"},
		{"admin writes too", http.MethodPost, "/v1/policies", "org-admins"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(t, f.server, tt.method, tt.path, f.token(t, tt.group))
			// 501 is notImplemented's own status -- the ONLY handler
			// behind authorize, so reaching it (rather than a 401/403
			// authorize would have returned on its own) is exactly what
			// proves the request passed both verification and the role
			// check.
			if rec.Code != http.StatusNotImplemented {
				t.Errorf("%s %s as %s: status = %d, want %d (the request should have reached the handler)",
					tt.method, tt.path, tt.group, rec.Code, http.StatusNotImplemented)
			}
		})
	}
}

// --- "an insufficient role is refused" ----------------------------------

func TestServer_InsufficientRole_Refused(t *testing.T) {
	f := newTestServerFixture(t)

	tests := []struct {
		name   string
		method string
		path   string
		group  string
	}{
		{"viewer cannot write", http.MethodPost, "/v1/policies", "org-viewers"},
		{"viewer cannot delete", http.MethodDelete, "/v1/policies/abc-123", "org-viewers"},
		{"editor cannot delete", http.MethodDelete, "/v1/policies/abc-123", "org-editors"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(t, f.server, tt.method, tt.path, f.token(t, tt.group))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as %s: status = %d, want %d", tt.method, tt.path, tt.group, rec.Code, http.StatusForbidden)
			}
		})
	}
}

// --- "an absent role claim is refused" ----------------------------------
//
// The HTTP-level counterpart of TestResolveRole_AbsentClaim_Refuses
// (role_test.go): proves authorize itself, not just resolveRole in
// isolation, refuses a verified-but-roleless token -- the anchor for the
// required mutation "treat an absent role claim as viewer" at the layer
// that actually serves requests.
func TestServer_AbsentRoleClaim_Refused(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/v1/policies", f.token(t, ""))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d for a verified token with no role claim", rec.Code, http.StatusForbidden)
	}
}

// --- "an unverifiable token is refused", end to end through authorize --
//
// oidc_test.go already proves Verify itself rejects each of these five
// shapes; this proves authorize correctly turns EVERY Verify failure into
// a refusal rather than, say, checking the error and forgetting to
// return -- a wiring bug oidc_test.go's direct Verify() calls could never
// see, since they never go through authorize at all.
func TestServer_UnverifiableToken_Refused(t *testing.T) {
	f := newTestServerFixture(t)

	expired := f.idp.validClaims("stratium-pap")
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	wrongAud := f.idp.validClaims("some-other-service")

	wrongIss := f.idp.validClaims("stratium-pap")
	wrongIss["iss"] = "https://not-this-idp.example.com"

	tests := []struct {
		name  string
		token string
	}{
		{"expired", mintToken(t, f.idp.signer, testKeyID, expired)},
		{"wrong audience", mintToken(t, f.idp.signer, testKeyID, wrongAud)},
		{"wrong issuer", mintToken(t, f.idp.signer, testKeyID, wrongIss)},
		{"malformed", "not-a-jwt-at-all"},
		{"no token at all", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(t, f.server, http.MethodGet, "/v1/policies", tt.token)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestServer_MalformedAuthorizationHeader_Refused(t *testing.T) {
	f := newTestServerFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/policies", nil)
	req.Header.Set("Authorization", f.token(t, "org-admins")) // missing "Bearer " scheme
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for an Authorization header missing the Bearer scheme", rec.Code, http.StatusUnauthorized)
	}
}

// --- N1: no route accepts a tenant in any form --------------------------

// TestRouteTable_NoPatternNamesATenant is the structural check over every
// registered route path -- see server.go's package doc, point 3.
func TestRouteTable_NoPatternNamesATenant(t *testing.T) {
	for _, rt := range routeTable {
		if strings.Contains(strings.ToLower(rt.Pattern), "tenant") {
			t.Errorf("route pattern %q must not name a tenant (N1): the tenant is startup "+
				"configuration, never a request", rt.Pattern)
		}
	}
}

// TestOperator_HasNoTenantField is the structural check over the identity
// type every handler receives -- see server.go's package doc, point 2.
func TestOperator_HasNoTenantField(t *testing.T) {
	typ := reflect.TypeOf(Operator{})
	for i := 0; i < typ.NumField(); i++ {
		if strings.Contains(strings.ToLower(typ.Field(i).Name), "tenant") {
			t.Errorf("Operator.%s: no field on Operator may carry a tenant (N1)", typ.Field(i).Name)
		}
	}
}

// TestRouteHandlerSignature_HasNoTenantParameter is the structural check
// over routeHandler itself -- see server.go's package doc, point 1. A
// fourth parameter (or a different third parameter) is exactly how a
// tenant could quietly ride along on every route at once; this fails the
// moment that type changes, rather than relying on a future reviewer to
// notice the diff.
func TestRouteHandlerSignature_HasNoTenantParameter(t *testing.T) {
	typ := reflect.TypeOf(routeHandler(nil))
	if typ.NumIn() != 3 {
		t.Fatalf("routeHandler has %d parameters, want exactly 3 (http.ResponseWriter, *http.Request, Operator)",
			typ.NumIn())
	}
	if got, want := typ.In(2), reflect.TypeOf(Operator{}); got != want {
		t.Errorf("routeHandler's third parameter is %s, want %s", got, want)
	}
}

// TestNoRequestFieldInfluencesAuthorization_TenantSmuggling is the
// behavioral check: with a fixed, valid, sufficient-role token, offering a
// tenant through every plausible request channel -- query string, a
// custom header, and a JSON body field -- must change nothing, since
// nothing in this task's code reads any of them. This cannot prove a
// FUTURE handler will keep ignoring these (that guarantee is the
// structural tests above); it proves that TODAY, no code path -- not
// authorize, not notImplemented -- honors one, which is the strongest
// claim expressible before Task 3 gives any handler something a tenant
// could actually change the outcome of.
func TestNoRequestFieldInfluencesAuthorization_TenantSmuggling(t *testing.T) {
	f := newTestServerFixture(t)
	bearer := f.token(t, "org-admins")

	baseline := doRequest(t, f.server, http.MethodGet, "/v1/policies", bearer)

	t.Run("query parameter", func(t *testing.T) {
		rec := doRequest(t, f.server, http.MethodGet, "/v1/policies?tenant_id=some-other-tenant", bearer)
		if rec.Code != baseline.Code {
			t.Errorf("status = %d with a smuggled tenant query param, want %d (same as no tenant offered)",
				rec.Code, baseline.Code)
		}
	})

	t.Run("header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/policies", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Tenant-Id", "some-other-tenant")
		rec := httptest.NewRecorder()
		f.server.ServeHTTP(rec, req)
		if rec.Code != baseline.Code {
			t.Errorf("status = %d with a smuggled X-Tenant-Id header, want %d", rec.Code, baseline.Code)
		}
	})

	t.Run("JSON body field", func(t *testing.T) {
		body, err := json.Marshal(map[string]string{"tenant_id": "some-other-tenant", "name": "a policy"})
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/policies", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+f.token(t, "org-editors"))
		rec := httptest.NewRecorder()
		f.server.ServeHTTP(rec, req)

		// Compared against a POST with the same role and no tenant field
		// in its body, not against the GET baseline above -- POST is
		// gated at a different minimum role than GET, so its own outcome
		// is what must stay unaffected by the smuggled field.
		wantRec := doRequest(t, f.server, http.MethodPost, "/v1/policies", f.token(t, "org-editors"))
		if rec.Code != wantRec.Code {
			t.Errorf("status = %d with a smuggled tenant_id body field, want %d (same as a body without one)",
				rec.Code, wantRec.Code)
		}
	})
}

// TestServer_ConcurrentRequests_NoCrossContamination is a dimension no
// other test in this file exercises: every case above drives one request
// at a time against a Server, sequentially. authorize's own closure state
// (min, next) is fixed at NewServer time and never mutated, and Verifier
// wraps go-oidc's IDTokenVerifier/RemoteKeySet, which does its own
// internal locking (sync.RWMutex, an inflight-request de-duplicator)
// specifically because concurrent callers are its normal case -- but "the
// shared library is documented as concurrency-safe" deserves one real
// test against THIS Server rather than only ever being exercised one
// request at a time. This fires many concurrent requests at the same
// Server (and so the same underlying RemoteKeySet, mid its own
// first-fetch cache population) alternating a sufficient-role and an
// insufficient-role outcome, and checks every individual result -- not
// just "no crash" -- so a bug that let one goroutine's resolved role leak
// into another's response would show up as a wrong status code on a
// specific index, not only as a race detector flag. Tokens are minted
// before any goroutine starts: *testing.T's Fatal/FailNow family is not
// safe to call from a spawned goroutine, so nothing in the goroutines below
// touches t at all, only f.server.ServeHTTP and plain httptest values.
func TestServer_ConcurrentRequests_NoCrossContamination(t *testing.T) {
	f := newTestServerFixture(t)
	const n = 100
	sufficientToken := f.token(t, "org-viewers")   // meets GET's viewer minimum
	insufficientToken := f.token(t, "org-viewers") // does not meet POST's editor minimum

	var wg sync.WaitGroup
	results := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var req *http.Request
			if i%2 == 0 {
				req = httptest.NewRequest(http.MethodGet, "/v1/policies", nil)
				req.Header.Set("Authorization", "Bearer "+sufficientToken)
			} else {
				req = httptest.NewRequest(http.MethodPost, "/v1/policies", nil)
				req.Header.Set("Authorization", "Bearer "+insufficientToken)
			}
			rec := httptest.NewRecorder()
			f.server.ServeHTTP(rec, req)
			results[i] = rec.Code // each goroutine owns a disjoint index -- no shared write
		}(i)
	}
	wg.Wait()

	for i, code := range results {
		want := http.StatusNotImplemented
		if i%2 != 0 {
			want = http.StatusForbidden
		}
		if code != want {
			t.Errorf("result[%d] = %d, want %d -- a concurrency bug would surface here as a wrong "+
				"status on one goroutine, not necessarily a crash", i, code, want)
		}
	}
}
