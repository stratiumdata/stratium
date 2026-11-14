package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/internal/policy"
)

// Sorting is the property under test, so the handler is called directly with a
// registry this test controls. nil engines are fine: listPolicyLanguages reads
// keys and never calls one.
func TestPolicyLanguages_ReturnsTheRegistrysKeysSorted(t *testing.T) {
	s := &Server{registry: policy.Registry{"xacml": nil, "cedar": nil, "rego": nil, "json": nil}}
	rec := httptest.NewRecorder()

	listPolicyLanguages(s, rec, httptest.NewRequest(http.MethodGet, "/v1/policy-languages", nil), Operator{})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got struct {
		Languages []string `json:"languages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"cedar", "json", "rego", "xacml"}
	if len(got.Languages) != len(want) {
		t.Fatalf("languages = %v, want %v", got.Languages, want)
	}
	for i, w := range want {
		if got.Languages[i] != w {
			t.Errorf("languages[%d] = %q, want %q -- output must be sorted, because Go randomises map iteration and a selector that reorders itself per request is a bug", i, got.Languages[i], w)
		}
	}
}

// An empty registry must serialise as [] and never as null. `var xs []string`
// marshals to null, which would make the console's languages.map(...) throw
// rather than render an empty selector -- a build with no engines registered
// should produce an empty list, not a broken screen.
func TestPolicyLanguages_EmptyRegistryIsAnEmptyArrayNotNull(t *testing.T) {
	s := &Server{registry: policy.Registry{}}
	rec := httptest.NewRecorder()

	listPolicyLanguages(s, rec, httptest.NewRequest(http.MethodGet, "/v1/policy-languages", nil), Operator{})

	if body := rec.Body.String(); !strings.Contains(body, `"languages":[]`) {
		t.Errorf("body = %s, want an empty ARRAY -- null would break the caller", body)
	}
}

// The route is wired at RoleViewer, like every other read on this table. The
// fixture's registry is empty by design, so this asserts reachability and the
// role floor, not the contents.
func TestPolicyLanguages_ViewerMayRead(t *testing.T) {
	f := newTestServerFixture(t)
	tok := f.tokenWithClaims(t, "org-viewers", map[string]any{"email": "v@example.com", "email_verified": true})
	if rec := doRequest(t, f.server, http.MethodGet, "/v1/policy-languages", tok); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
