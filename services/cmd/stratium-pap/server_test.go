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

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/store"
)

// testServerFixture builds a real Server backed by a real,
// freshly-generated-key test IdP (newTestIdP, oidc_test.go), the three-tier
// role mapping routeTable's own routes exercise, and (Task 3) a
// sqlmock-backed *store.Store so a handler that reaches all the way to the
// database still has something real, if empty, to talk to -- shared setup
// for every test below so each one only states what it varies.
type testServerFixture struct {
	idp    *testIdP
	server *Server
	mock   sqlmock.Sqlmock
}

// fixtureTenant is this file's own store's fixed tenant -- never read by
// any test here (N1 keeps it out of every request; see server.go's package
// doc), only needed to construct a *store.Store at all.
const fixtureTenant = "tenant-server-test"

func newTestServerFixture(t *testing.T) *testServerFixture {
	t.Helper()
	idp := newTestIdP(t)
	v, err := NewVerifier(context.Background(), idp.server.URL, "stratium-pap", 5*time.Second, 0)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	roles, err := newRoleMapping([]string{"org-admins"}, []string{"org-editors"}, []string{"org-viewers"})
	if err != nil {
		t.Fatalf("newRoleMapping() error = %v", err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := store.New(db, fixtureTenant)
	// An empty Registry is deliberate, not an oversight: every test in this
	// file is about identity and role gating, never about a specific
	// policy's own language or content, so no case here needs a real
	// engine wired -- see policies_test.go for the tests that do.
	//
	// approverClaim is fixed to "email" -- N8's own named example, and the
	// one claim name that additionally exercises email_verified -- so
	// approvals_test.go's fixture (built on this one) matches what a real
	// deployment is likeliest to configure. No test in THIS file depends on
	// it: f.token below never sets "email", so every route gated on Role/
	// Subject alone behaves exactly as it did before Task 4 added this
	// parameter.
	//
	// fixtureUIConfig (below) is Task 6's own addition, and matters to
	// exactly the two tests in ui_test.go that read it back; no route gated
	// by authorize consults any of its fields.
	return &testServerFixture{
		idp:    idp,
		server: NewServer(v, "roles", "email", roles, repo, policy.Registry{}, fixtureUIConfig(idp.server.URL)),
		mock:   mock,
	}
}

// fixtureUIConfig mirrors what main.go builds from Config, pointed at this
// fixture's own test IdP so contentSecurityPolicy has a real origin to derive
// a connect-src from.
func fixtureUIConfig(issuer string) uiConfig {
	return uiConfig{
		Issuer:   issuer,
		ClientID: "stratium-pap-ui",
		Audience: "stratium-pap",
		Scope:    "openid profile email",
		// Both on origins that are NOT the issuer's, matching what
		// newTestIdP's discovery document advertises and what main.go passes
		// from Verifier.BrowserEndpoints. This is the shape that breaks a
		// connect-src derived from the issuer alone.
		IdPEndpoints: []string{idpAuthorizationEndpoint, idpTokenEndpoint},
	}
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

// tokenWithClaims mints a token like token(t, group) but layers extra
// claims on top (overwriting any that collide) -- approvals_test.go's own
// need to additionally control "email"/"email_verified" (N7/N8), which
// token's own single-purpose "roles" parameter has no room for.
func (f *testServerFixture) tokenWithClaims(t *testing.T, group string, extra map[string]any) string {
	t.Helper()
	claims := f.idp.validClaims("stratium-pap")
	if group != "" {
		claims["roles"] = group
	}
	for k, v := range extra {
		claims[k] = v
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

// policyListColumns is listPoliciesQuery's own column list
// (internal/store/policy.go), duplicated here rather than imported: it is
// unexported, in a different package, and this file only ever needs an
// empty result set shaped like it, never its own logic.
func policyListColumns() []string {
	return []string{"id", "tenant_id", "name", "description", "language",
		"policy_content", "effect", "version", "enabled", "created_at", "updated_at"}
}

// expectEmptyPolicyList registers the ordered sqlmock sequence
// ListPolicies issues for a tenant with no rows -- begin, set the tenant,
// the list query, commit -- so a GET /v1/policies in this file (the one
// route shape with no request body to short-circuit validation on before
// ever reaching the store; see TestServer_SufficientRole_ReachesHandler's
// own comment) can prove "reached the handler" with a real 200 rather than
// only a validation-driven 400.
func expectEmptyPolicyList(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM policies").WillReturnRows(sqlmock.NewRows(policyListColumns()))
	mock.ExpectCommit()
}

// reachedHandler reports whether rec's status proves next() was actually
// called -- i.e. authorize did not block the request. It is deliberately
// NOT "status == 2xx": a handler that ran and then refused the request for
// its own reasons (a 400 from decodeJSON on an empty POST body, a 400 from
// pathID on a non-UUID path segment, a 404 from a lookup that legitimately
// found nothing) still proves the request reached the handler just as
// certainly as a 200 would. Only 401 (bearerToken/Verify/resolveSubject
// failed) and 403 (resolveRole failed, or the role does not meet the
// route's minimum) are outcomes authorize itself produces without ever
// calling next.
func reachedHandler(code int) bool {
	return code != http.StatusUnauthorized && code != http.StatusForbidden
}

// --- "a valid token with a sufficient role reaches the handler" --------

// TestServer_SufficientRole_ReachesHandler previews Task 3's own "viewer
// reads, editor writes, admin writes and deletes" rule across all three
// role tiers on /v1/policies, representative of every resource routeTable
// registers (each resource-specific handler file has its own, narrower
// role-boundary tests against its own real behavior; this file's job is
// only the generic authorize mechanism). A fresh fixture per case (not one
// shared across the whole table, unlike Task 1's original version of this
// test) is deliberate: each case's own sqlmock expectations, if any, must
// not leak into or be starved by a sibling case's.
func TestServer_SufficientRole_ReachesHandler(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		group  string
		// needsEmptyList is set only for the GET-list case: it is the one
		// route shape in this table with no request body for the handler
		// to refuse on before ever reaching the store (POST/PUT below send
		// no body at all, so they 400 out of decodeJSON; DELETE targets a
		// non-UUID path segment, so it 400s out of pathID) -- see
		// expectEmptyPolicyList's own doc comment.
		needsEmptyList bool
	}{
		{"viewer reads", http.MethodGet, "/v1/policies", "org-viewers", true},
		{"editor writes", http.MethodPost, "/v1/policies", "org-editors", false},
		{"admin deletes", http.MethodDelete, "/v1/policies/abc-123", "org-admins", false},
		// Each role also meets every route with a lower minimum -- editor
		// can read, admin can read and write.
		{"editor reads too", http.MethodGet, "/v1/policies", "org-editors", true},
		{"admin reads too", http.MethodGet, "/v1/policies", "org-admins", true},
		{"admin writes too", http.MethodPost, "/v1/policies", "org-admins", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newTestServerFixture(t)
			if tt.needsEmptyList {
				expectEmptyPolicyList(f.mock)
			}
			rec := doRequest(t, f.server, tt.method, tt.path, f.token(t, tt.group))
			if !reachedHandler(rec.Code) {
				t.Errorf("%s %s as %s: status = %d, want anything but 401/403 (the request should have reached the handler)",
					tt.method, tt.path, tt.group, rec.Code)
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

// TestServer_AbsentSubjectClaim_Refused is the HTTP-level counterpart of
// TestResolveSubject_AbsentClaim_Refuses (role_test.go), the same relation
// TestServer_AbsentRoleClaim_Refused has to its own pure-function test: a
// verified token with no usable "sub" claim must be refused by authorize
// itself, not merely by resolveSubject in isolation. 401, not 403 --
// authorize treats this as an identity problem (who is this), the same
// bucket a Verify failure falls into, not an authorization problem (this
// identity is known and not permitted here).
func TestServer_AbsentSubjectClaim_Refused(t *testing.T) {
	f := newTestServerFixture(t)

	claims := f.idp.validClaims("stratium-pap")
	claims["roles"] = "org-admins"
	delete(claims, "sub")
	tok := mintToken(t, f.idp.signer, testKeyID, claims)

	rec := doRequest(t, f.server, http.MethodGet, "/v1/policies", tok)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for a verified token with no subject claim", rec.Code, http.StatusUnauthorized)
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
// registered route path -- see server.go's package doc, point 3. Iterates
// the package-level routeTable directly: Task 3 added routes and real
// handlers, but never changed how this list is declared or inspected.
func TestRouteTable_NoPatternNamesATenant(t *testing.T) {
	for _, rt := range routeTable {
		if strings.Contains(strings.ToLower(rt.Pattern), "tenant") {
			t.Errorf("route pattern %q must not name a tenant (N1): the tenant is startup "+
				"configuration, never a request", rt.Pattern)
		}
	}
}

// --- Role gating: "viewer reads; editor reads and writes; admin reads,
// writes, and deletes" (task brief, phase plan Task 3) ------------------

// actionRoutes names Task 4's three single-purpose action routes -- POST,
// but gated at RoleAdmin rather than the blanket "POST/PUT -> editor" rule
// every CRUD route below still follows: each is a single, consequential
// action, not a create (approve/deny for the reason N7 requires a role to be
// merely necessary, never sufficient, on top of; revoke because it is this
// system's DELETE-equivalent for a delegation -- see routeTable's own
// comment for the full reasoning). TestRouteTable_RoleGatingMatchesSpec and
// TestRouteTable_CoversEveryCRUDRouteForEveryResource both consult this map
// so the "admin, not editor" and "these routes exist" properties are stated
// once, not duplicated between the two tests.
var actionRoutes = map[string]bool{
	"POST /v1/approvals/{id}/approve":  true,
	"POST /v1/approvals/{id}/deny":     true,
	"POST /v1/delegations/{id}/revoke": true,
	// Task 7's classification-caps write, gated RoleAdmin rather than the
	// blanket PUT -> editor rule: see this route's own comment in
	// routeTable (above) for why a classification ceiling is not ordinary
	// agent configuration.
	"PUT /v1/agents/{id}/classification-caps": true,
	// resource-constraints' own write, gated RoleAdmin for the identical
	// reason: a resource-identity ceiling is a security boundary, not
	// ordinary agent configuration.
	"PUT /v1/agents/{id}/resource-constraints": true,
	// escalation's write, RoleAdmin again: raising a threshold lets an agent
	// act unattended where a human was asked.
	"PUT /v1/agents/{id}/escalation": true,
	// Creating a label rule or a catalog entry, RoleAdmin: both set what a
	// classification cap or an escalation threshold is measured against,
	// with nothing beneath them to compare a new row to.
	"POST /v1/resource-label-rules": true,
	"POST /v1/tool-catalog":         true,
}

// TestRouteTable_RoleGatingMatchesSpec checks the stated role mapping
// structurally, against every registered route at once, rather than by
// firing one HTTP request per route: GET -> viewer, POST/PUT -> editor,
// DELETE -> admin, EXCEPT actionRoutes above, which are POST but must still
// be admin. This is the direct target of three required mutations at once --
// "let viewer write" (any POST/PUT CRUD route's MinRole weakened to
// RoleViewer), "let editor delete" (any DELETE route's MinRole weakened to
// RoleEditor), and "let editor decide/revoke" (any actionRoutes entry
// weakened to RoleEditor) -- for whichever resource and route a mutation
// happened to target, not only the one route
// TestServer_SufficientRole_ReachesHandler/TestServer_InsufficientRole_
// Refused exercise live. Those two tests remain: this one proves the DATA
// (routeTable's own MinRole values) is right; they prove the WIRING
// (authorize actually enforces whatever MinRole says) is right. Neither
// alone proves both.
func TestRouteTable_RoleGatingMatchesSpec(t *testing.T) {
	for _, rt := range routeTable {
		if actionRoutes[rt.Pattern] {
			if rt.MinRole != RoleAdmin {
				t.Errorf("route %q: MinRole = %s, want %s (a single consequential action, not CRUD -- N7 needs a role that is "+
					"necessary but never sufficient on its own)", rt.Pattern, rt.MinRole, RoleAdmin)
			}
			continue
		}
		method, _, ok := strings.Cut(rt.Pattern, " ")
		if !ok {
			t.Fatalf("route pattern %q has no method prefix", rt.Pattern)
		}
		var want Role
		switch method {
		case http.MethodGet:
			want = RoleViewer
		case http.MethodPost, http.MethodPut:
			want = RoleEditor
		case http.MethodDelete:
			want = RoleAdmin
		default:
			t.Fatalf("route %q: unrecognised method %q", rt.Pattern, method)
		}
		if rt.MinRole != want {
			t.Errorf("route %q: MinRole = %s, want %s", rt.Pattern, rt.MinRole, want)
		}
	}
}

// TestRouteTable_CoversEveryCRUDRouteForEveryResource guards the guard
// above: TestRouteTable_RoleGatingMatchesSpec only checks routes that
// EXIST, so a mutation that deleted a route entirely (e.g. dropping DELETE
// /v1/agents/{id}, silently leaving that resource with no delete path at
// all) would not fail it. This pins the count and the resource/verb
// coverage directly: five routes (list, create, get, update, delete) for
// each of the three resources A5 names, fifteen total (Task 3), plus Task
// 4's own seven -- tool-catalog's four (list, create, get, update; no
// delete -- migrations/000016_stratium_pap_role withholds that grant) and
// actionRoutes' three (approve, deny, revoke) -- plus Task 5's own two
// (validate, test), plus Task 6's own two list routes (GET /v1/approvals,
// GET /v1/delegations), plus resource-label-rules' own five, plus the
// containment route -- thirty-two total.
//
// The two Task 6 routes are pinned here, in the same test that pins every
// other route's existence, for the reason this test exists at all: without
// it, deleting either one would leave TestRouteTable_RoleGatingMatchesSpec
// perfectly green while making both write actions on that resource
// undiscoverable again.
//
// resource-label-rules' five are pinned for a sharper version of the same
// reason. Its DELETE is the one route in this table whose REMOVAL would be
// invisible in exactly the wrong direction: deleting a label rule is how a
// tenant un-labels a subtree, and with no delete route an operator faced with
// a wrong rule can only edit it -- and every rule that exists matches
// something, so there is no edit that means "off."
func TestRouteTable_CoversEveryCRUDRouteForEveryResource(t *testing.T) {
	const wantTotal = 15 + 4 + 3 + 2 + 2 + 5 + 3 + 1 + 3 + 1 + 1 + 1 + 3
	if len(routeTable) != wantTotal {
		t.Fatalf("routeTable has %d routes, want %d (15 Task-3 CRUD routes + 4 tool-catalog + 3 action routes + "+
			"2 Task-5 authoring routes + 2 Task-6 list routes + 5 resource-label-rules routes + "+
			"3 Task-7 classification-caps routes + 1 Task-2 configuration route + "+
			"3 resource-constraints routes + 1 principals/effective route + 1 containment route + "+
			"1 audit read route + 3 escalation routes)",
			len(routeTable), wantTotal)
	}

	// The number gated above RoleViewer, pinned alongside the total because
	// something outside this package depends on it and cannot see it.
	// internal/store/pap_e2e_integration_test.go keeps a hand-maintained
	// mirror of this table (it cannot import a main package) and sweeps
	// every write route asserting a viewer is refused, and every route at
	// all asserting an unverified token is refused -- and conformance
	// property C5's machine-checked pointer cites that sweep as evidence the
	// tier_overrides write surface is unreachable without an operator's OIDC
	// token. A route added HERE and not mirrored THERE goes unswept in both
	// proofs, silently, while C5 goes on citing them. That mirror cannot
	// detect its own omission; this can. Adding a route is meant to fail
	// here and send the author to that file.
	writes := 0
	for _, rt := range routeTable {
		if rt.MinRole != RoleViewer {
			writes++
		}
	}
	const wantWrites = 19 + 2 + 2 + 1 + 2 // escalation adds PUT and DELETE .../escalation, admin like caps and scope.
	// Task 7 adds PUT and DELETE .../classification-caps; resource-constraints adds
	// PUT and DELETE .../resource-constraints the same way; both GETs are not writes. The containment route adds
	// one more: POST /v1/containment is RoleEditor like every other POST here, so it counts as gated above
	// RoleViewer even though its handler persists nothing -- see internal/store/pap_e2e_integration_test.go's
	// papRouteTable, which this count's own Fatalf message below points at.
	if writes != wantWrites {
		t.Fatalf("routeTable has %d routes gated above RoleViewer, want %d -- if that is a deliberate new "+
			"route, papRouteTable in internal/store/pap_e2e_integration_test.go must gain it too, or proofs "+
			"2 and 3 will never sweep it and conformance C5's pointer will overclaim", writes, wantWrites)
	}

	want := map[string]bool{}
	for _, resource := range []string{"policies", "agents", "tier-overrides", "resource-label-rules"} {
		want["GET /v1/"+resource] = false
		want["POST /v1/"+resource] = false
		want["GET /v1/"+resource+"/{id}"] = false
		want["PUT /v1/"+resource+"/{id}"] = false
		want["DELETE /v1/"+resource+"/{id}"] = false
	}
	// tool-catalog: the same four verbs as above, minus delete.
	for _, verb := range []string{"GET /v1/tool-catalog", "POST /v1/tool-catalog", "GET /v1/tool-catalog/{id}", "PUT /v1/tool-catalog/{id}"} {
		want[verb] = false
	}
	for pattern := range actionRoutes {
		want[pattern] = false
	}
	// Task 5's two authoring routes: POST at the generic editor floor, not
	// actionRoutes (RoleAdmin) -- see routeTable's own doc comment for why.
	for _, verb := range []string{"POST /v1/policies/validate", "POST /v1/policies/test"} {
		want[verb] = false
	}
	// Task 6's two list routes -- the read half of the two resources whose
	// write actions actionRoutes above already covers.
	for _, verb := range []string{"GET /v1/approvals", "GET /v1/delegations"} {
		want[verb] = false
	}
	// Task 7's classification-caps sub-resource: GET and DELETE named here;
	// PUT is already covered by the actionRoutes range below (RoleAdmin, not
	// the blanket PUT -> editor rule).
	for _, verb := range []string{"GET /v1/agents/{id}/classification-caps", "DELETE /v1/agents/{id}/classification-caps"} {
		want[verb] = false
	}
	// resource-constraints sub-resource: GET and DELETE named here; PUT is
	// already covered by the actionRoutes range above (RoleAdmin, not the
	// blanket PUT -> editor rule).
	for _, verb := range []string{"GET /v1/agents/{id}/resource-constraints", "DELETE /v1/agents/{id}/resource-constraints"} {
		want[verb] = false
	}
	// Task 2's configuration route: the languages this build can evaluate.
	want["GET /v1/policy-languages"] = false
	// The audit chain's read path. A plain viewer read with no write
	// sibling: nothing in this API mutates audit_chain, which is the point
	// of an append-only log.
	want["GET /v1/audit"] = false
	// The union of a principal's live root delegations -- reports, does not
	// enforce, so it is a plain read and needs no write-route sibling.
	want["GET /v1/principals/{id}/effective"] = false
	// Does this candidate permission set allow anything the baseline does
	// not -- reports and does not enforce, but still gated RoleEditor like
	// every other POST here (POST /v1/policies/test is its nearest
	// analogue, also a non-persisting query gated RoleEditor), so it needs
	// no write-route sibling but does need a Viewer to be refused.
	want["POST /v1/containment"] = false

	for _, rt := range routeTable {
		if _, ok := want[rt.Pattern]; ok {
			want[rt.Pattern] = true
		}
	}
	for pattern, found := range want {
		if !found {
			t.Errorf("routeTable is missing %q", pattern)
		}
	}
}

// TestRouteTable_ExposesNoWriteSurfaceForAClassificationCap guards a NEGATIVE
// claim docs/pep.md makes about this table, in its section "Nothing in the
// admin plane can change a cap": that no route, at any role, sets, raises,
// lowers or repairs a delegation's classification_caps. Three operator
// remedies in that document are ruled out by it, and one warning depends on
// it — "revoking removes classification enforcement entirely", which is
// correct today and becomes advice that talks an operator out of the right
// fix on the day a cap-editing route lands.
//
// A negative claim about what a system can observe is a claim to check, not
// to reason to. Nothing checked this one: the sibling test above pins the
// route COUNT, which a new delegation route would fail — but it would fail
// naming a count, sending the author to update a number rather than to the
// documentation whose warning just became false.
//
// Asserted as "the delegation routes are exactly these two", not as "no
// route contains the word caps". A cap-writing route would almost certainly
// be spelled PUT /v1/delegations/{id} or POST /v1/delegations/{id}/caps, and
// a keyword guard would miss both. The claim is about the delegation
// resource's whole write surface, so that is what is pinned.
//
// This is the same dependency structure as R11, where a proto comment said
// "it narrows, it does not widen" and stayed true until R2 inverted the
// default beneath it. That comment had no guard either.
func TestRouteTable_ExposesNoWriteSurfaceForAClassificationCap(t *testing.T) {
	// The whole delegation surface, both routes read-or-revoke. Neither
	// carries a request body that could name a cap: the GET has none, and
	// revoke names only the delegation it ends.
	want := map[string]bool{
		"GET /v1/delegations":              true,
		"POST /v1/delegations/{id}/revoke": true,
	}

	var got []string
	for _, rt := range routeTable {
		if strings.Contains(rt.Pattern, "/v1/delegations") {
			got = append(got, rt.Pattern)
		}
	}

	// A floor, for the reason TestResourceLabelRule_RuleCopiesEveryMatcherField
	// carries one: the loop below is the whole test, and a loop over zero
	// matches passes silently. A guard that can check nothing and report
	// success is the failure mode this exists to prevent.
	if len(got) < len(want) {
		t.Fatalf("found %d /v1/delegations routes, want at least %d — either the delegation surface was "+
			"removed or this guard is about to verify nothing", len(got), len(want))
	}

	for _, pattern := range got {
		if !want[pattern] {
			t.Errorf("routeTable exposes %q, which docs/pep.md does not know about.\n"+
				"That document's section \"Nothing in the admin plane can change a cap\" tells operators "+
				"no route sets, raises, lowers or repairs a classification cap, and warns that revoking a "+
				"delegation returns a session with NO cap rather than a different one. If this route can "+
				"write classification_caps, BOTH claims are now false and the warning actively misleads. "+
				"Update docs/pep.md in this commit, then add the route here.", pattern)
		}
	}
	if len(got) != len(want) {
		t.Errorf("routeTable has %d /v1/delegations routes, want exactly %d (%v) — a delegation write "+
			"surface beyond revoke is what docs/pep.md's cap claims deny exists", len(got), len(want), got)
	}
}

// TestOperator_HasNoTenantField is the structural check over the identity
// type every handler receives -- see server.go's package doc, point 2.
// Operator gained a Subject field in Task 3 (N4 attribution); this test's
// field-name scan already covers it automatically, with no update needed,
// which is exactly what a substring scan over every field (rather than a
// fixed list of names) buys.
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
// notice the diff. routeHandler's own definition is untouched by Task 3 --
// resourceHandler (server.go), the type routeTable's entries actually use,
// is a separate type this test does not and should not reach, by design:
// see resourceHandler's own doc comment for why introducing it did not
// require widening routeHandler.
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
// authorize, not any CRUD handler -- honors one. Each subtest gets its own
// fresh fixture (and, for the two GET-based subtests, its own pair of
// mocked list-query expectations) rather than sharing one across the whole
// test, so a mismatch between how many times a shared mock was primed and
// how many requests actually ran cannot mask a real difference in
// behavior as a sqlmock bookkeeping error instead.
func TestNoRequestFieldInfluencesAuthorization_TenantSmuggling(t *testing.T) {
	t.Run("query parameter", func(t *testing.T) {
		f := newTestServerFixture(t)
		bearer := f.token(t, "org-admins")
		expectEmptyPolicyList(f.mock) // baseline
		expectEmptyPolicyList(f.mock) // smuggled

		baseline := doRequest(t, f.server, http.MethodGet, "/v1/policies", bearer)
		smuggled := doRequest(t, f.server, http.MethodGet, "/v1/policies?tenant_id=some-other-tenant", bearer)
		if smuggled.Code != baseline.Code {
			t.Errorf("status = %d with a smuggled tenant query param, want %d (same as no tenant offered)",
				smuggled.Code, baseline.Code)
		}
	})

	t.Run("header", func(t *testing.T) {
		f := newTestServerFixture(t)
		bearer := f.token(t, "org-admins")
		expectEmptyPolicyList(f.mock) // baseline
		expectEmptyPolicyList(f.mock) // smuggled

		baseline := doRequest(t, f.server, http.MethodGet, "/v1/policies", bearer)

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
		f := newTestServerFixture(t)
		// Both requests below are POST with an incomplete body (no
		// language/policy_content/effect), so both 400 out of
		// validatePolicyName before ever reaching f.mock -- no list
		// expectations needed here, unlike the two GET-based subtests
		// above.
		body, err := json.Marshal(map[string]string{"tenant_id": "some-other-tenant", "name": "a policy"})
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/policies", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+f.token(t, "org-editors"))
		rec := httptest.NewRecorder()
		f.server.ServeHTTP(rec, req)

		// Compared against a POST with the same role and no body at all,
		// not against the GET baseline above -- POST is gated at a
		// different minimum role than GET, so its own outcome is what must
		// stay unaffected by the smuggled field.
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
// internal locking specifically because concurrent callers are its normal
// case -- but "the shared library is documented as concurrency-safe"
// deserves one real test against THIS Server rather than only ever being
// exercised one request at a time.
//
// Both sides POST the same (empty) body to the same route, differing only
// by the token's role -- editor's token reaches createPolicy and 400s out
// of decodeJSON (an empty body, never touching f.mock); viewer's token
// never reaches createPolicy at all, refused 403 by authorize. This
// isolates exactly the property under test (does a per-request role
// decision ever leak across goroutines) without needing a mock database to
// somehow arbitrate genuinely concurrent, unordered transactions -- Task
// 1's original version of this test used GET for "sufficient" specifically
// because every route was still a stateless stub; once GET means "read
// the database," proving concurrency safety for it would be proving
// something about sqlmock's own ordering guarantees, not about this
// package.
func TestServer_ConcurrentRequests_NoCrossContamination(t *testing.T) {
	f := newTestServerFixture(t)
	const n = 100
	sufficientToken := f.token(t, "org-editors")   // meets POST's editor minimum
	insufficientToken := f.token(t, "org-viewers") // does not meet POST's editor minimum

	var wg sync.WaitGroup
	results := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/policies", nil)
			if i%2 == 0 {
				req.Header.Set("Authorization", "Bearer "+sufficientToken)
			} else {
				req.Header.Set("Authorization", "Bearer "+insufficientToken)
			}
			rec := httptest.NewRecorder()
			f.server.ServeHTTP(rec, req)
			results[i] = rec.Code // each goroutine owns a disjoint index -- no shared write
		}(i)
	}
	wg.Wait()

	for i, code := range results {
		want := http.StatusBadRequest // reached createPolicy, refused on its empty body
		if i%2 != 0 {
			want = http.StatusForbidden // never reached createPolicy at all
		}
		if code != want {
			t.Errorf("result[%d] = %d, want %d -- a concurrency bug would surface here as a wrong "+
				"status on one goroutine, not necessarily a crash", i, code, want)
		}
	}
}
