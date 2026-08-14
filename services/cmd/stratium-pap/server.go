// server.go is the PAP's HTTP surface. Task 1 built the security foundation
// -- every route refuses an unverified or under-privileged caller before
// reaching a handler -- behind stub handlers that all returned "not
// implemented." Task 3 replaces those stubs with the real CRUD handlers
// (policies.go, agents.go, tier_overrides.go) for policies, agents, and
// tier_overrides; nothing about how a route reaches its handler changed to
// do that, only routeTable's own Handler field per route -- exactly as
// Task 1's own doc comment here anticipated.
//
// N1's "no request may carry a tenant" is enforced here, structurally
// rather than by convention, in three ways this file's own tests
// (server_test.go) check directly:
//
//  1. routeHandler -- the only signature a route handler may have --
//     takes an Operator and nothing else naming a tenant. Every route is
//     registered through authorize, the one function that builds an
//     http.HandlerFunc from a routeHandler, so there is no per-route way
//     to smuggle in a tenant-carrying parameter without changing
//     routeHandler itself, a type every route shares -- not a quiet,
//     local opt-out.
//  2. Operator, the identity a routeHandler receives, carries a Role and
//     nothing else: no tenant field to read one from even if a handler
//     wanted to.
//  3. routeTable's own pattern strings register no {tenant} path segment
//     (TestRouteTable_NoPatternNamesATenant).
//
// None of this claims Go's type system makes reading a tenant out of
// r.URL.Query() or a header impossible -- *http.Request is generic, and
// nothing stops a careless handler body from calling
// r.URL.Query().Get("tenant_id"). What IS true: no code path here does
// that today (TestNoRequestFieldInfluencesAuthorization_TenantSmuggling
// proves the server's behavior is identical whether or not one is offered),
// and doing so in the future means editing routeTable or routeHandler --
// shared infrastructure every route already goes through -- rather than a
// one-line addition inside a single handler nobody else reviews as
// carefully. The deeper guarantee -- a cross-tenant WRITE being
// structurally impossible, not merely checked -- lives one layer down, at
// the store Task 3 adds: internal/store.New(db, tenantID) fixes the
// tenant once, at construction, and never again (see that package's own
// doc comment). This file's job is to make sure nothing upstream of that
// call ever manufactures a per-request tenant value for a future store
// call to trust.
package main

import (
	"net/http"
	"strings"

	"stratium/internal/policy"
	"stratium/internal/store"
)

// Operator is a verified operator's identity as it reaches a route
// handler: a resolved Role, plus (Task 3) the Subject from the verified
// token's "sub" claim -- N4's own attribution requirement, "who did what,"
// needs a genuine identity to write into audit_chain.actor and, for tier
// overrides, tier_overrides.created_by. No tenant field -- see the package
// doc above; Subject does not change that, since it names an operator, not
// a tenant, and there remains no field here (or anywhere upstream of it)
// capable of carrying one.
//
// Subject is not "an operator's claims" in the sense the phase's own
// logging rule forbids: that rule is about never writing a bearer token or
// arbitrary claim values into an application log (see oidc.go's Verify,
// which swallows go-oidc's own claim-echoing error text for exactly this
// reason), not about the audit chain itself -- audit_chain.actor exists
// specifically to record who performed a write, durably, by design, the
// same way pdpgrpc's own decision and delegation-creation audit entries
// already record req.Subject there. Nothing in this file ever passes
// Operator to a logger.
type Operator struct {
	Role    Role
	Subject string
}

// routeHandler is the only signature a PAP route handler may have -- see
// the package doc's point 1. Unchanged since Task 1, byte for byte: this is
// exactly the type TestRouteHandlerSignature_HasNoTenantParameter reflects
// on, and it is what authorize (below) still requires of next.
type routeHandler func(w http.ResponseWriter, r *http.Request, op Operator)

// resourceHandler is a route handler shaped with an explicit *Server
// receiver as its first parameter -- routeTable's own Handler field type,
// deliberately NOT routeHandler itself. routeTable is a package-level var,
// built at init time, before any *Server exists for a bound method value
// to close over; NewServer's own wiring loop below supplies the receiver,
// once per route, and adapts each entry into the routeHandler shape
// authorize actually requires. This keeps routeHandler's own definition
// exactly as Task 1 left it -- "do not widen routeHandler" -- while still
// giving every CRUD handler (policies.go, agents.go, tier_overrides.go)
// what none of Task 1's stub handlers ever needed: access to s.store and
// s.registry.
type resourceHandler func(s *Server, w http.ResponseWriter, r *http.Request, op Operator)

// routeSpec pairs one route pattern (net/http's Go 1.22+
// "METHOD /path/{wildcard}" syntax) with the minimum Role required to
// reach it.
type routeSpec struct {
	Pattern string
	MinRole Role
	Handler resourceHandler
}

// routeTable is the single source of truth routes are registered from --
// NewServer below loops over exactly this, and server_test.go inspects
// exactly this, so there is no second list either could fall out of sync
// with. Five routes per resource (list, create, get, update,
// delete) across the three tables Task 3 covers -- A5's own CRUD scope --
// each gated at the role spec §4.10/the phase plan state by name: viewer
// reads (GET), editor reads and writes (GET/POST/PUT), admin reads, writes,
// and deletes (GET/POST/PUT/DELETE). Handlers live in policies.go,
// agents.go, and tier_overrides.go respectively -- one file per resource,
// matching internal/store's own per-table file split.
var routeTable = []routeSpec{
	{Pattern: "GET /v1/policies", MinRole: RoleViewer, Handler: listPolicies},
	{Pattern: "POST /v1/policies", MinRole: RoleEditor, Handler: createPolicy},
	{Pattern: "GET /v1/policies/{id}", MinRole: RoleViewer, Handler: getPolicy},
	{Pattern: "PUT /v1/policies/{id}", MinRole: RoleEditor, Handler: updatePolicy},
	{Pattern: "DELETE /v1/policies/{id}", MinRole: RoleAdmin, Handler: deletePolicy},

	{Pattern: "GET /v1/agents", MinRole: RoleViewer, Handler: listAgents},
	{Pattern: "POST /v1/agents", MinRole: RoleEditor, Handler: createAgent},
	{Pattern: "GET /v1/agents/{id}", MinRole: RoleViewer, Handler: getAgent},
	{Pattern: "PUT /v1/agents/{id}", MinRole: RoleEditor, Handler: updateAgent},
	{Pattern: "DELETE /v1/agents/{id}", MinRole: RoleAdmin, Handler: deleteAgent},

	{Pattern: "GET /v1/tier-overrides", MinRole: RoleViewer, Handler: listTierOverrides},
	{Pattern: "POST /v1/tier-overrides", MinRole: RoleEditor, Handler: createTierOverride},
	{Pattern: "GET /v1/tier-overrides/{id}", MinRole: RoleViewer, Handler: getTierOverride},
	{Pattern: "PUT /v1/tier-overrides/{id}", MinRole: RoleEditor, Handler: updateTierOverride},
	{Pattern: "DELETE /v1/tier-overrides/{id}", MinRole: RoleAdmin, Handler: deleteTierOverride},
}

// Server is the PAP's HTTP server: identity verification and role gating
// (Task 1) in front of the CRUD handlers (Task 3) routeTable wires up.
// store and registry are both nil-checked nowhere in this file -- NewServer
// requires both, the same "no zero-configuration construction" discipline
// policy.NewMulti already applies to its own two required arguments (see
// that function's own doc comment).
type Server struct {
	verify    *Verifier
	roleClaim string
	roles     RoleMapping
	store     *store.Store
	registry  policy.Registry
	mux       *http.ServeMux
}

// NewServer wires routeTable behind authorize and returns a Server ready
// to serve. Every argument is fixed here, from startup configuration,
// exactly once -- the same treatment Verifier itself gives issuer/audience.
// store is tenant-scoped at its own construction (internal/store.New,
// called once by main.go's run) and never re-scoped per request -- N1's
// "the tenant is fixed at startup" holds all the way down to the
// connection this Server ultimately writes through.
func NewServer(verify *Verifier, roleClaim string, roles RoleMapping, st *store.Store, registry policy.Registry) *Server {
	s := &Server{verify: verify, roleClaim: roleClaim, roles: roles, store: st, registry: registry, mux: http.NewServeMux()}
	for _, rt := range routeTable {
		// Adapts rt.Handler (resourceHandler, needs *Server) into the
		// routeHandler shape authorize requires, closing over s (this
		// Server) and rt.Handler (this route's specific handler) once per
		// route -- Go 1.22+ gives each loop iteration its own rt, so no
		// per-iteration copy is needed to close over it safely.
		s.mux.HandleFunc(rt.Pattern, s.authorize(rt.MinRole, func(w http.ResponseWriter, r *http.Request, op Operator) {
			rt.Handler(s, w, r, op)
		}))
	}
	return s
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// authorize wraps next so it is reached only by a request bearing a token
// that verifies, names a usable subject, AND resolves to a role meeting
// min -- the security foundation this task exists to prove before anything
// can depend on it. Every failure path writes a response and returns,
// never falling through to next: a missing or malformed Authorization
// header, a token that fails Verify, or a verified token with no usable
// "sub" claim all refuse with 401 (an identity problem -- who is this); a
// token that verifies but carries no usable role, or a role that does not
// meet min, both refuse with 403 (an authorization problem -- this
// identity is known and not permitted here). N2 draws no distinction
// between "no role claim" and "role claim names an unconfigured group";
// neither does this function -- resolveRole's error is enough on its own
// to refuse, without this code caring which of its two named errors it
// was, and the identical treatment applies to resolveSubject's one error.
func (s *Server) authorize(min Role, next routeHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := s.verify.Verify(r.Context(), token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		subject, err := resolveSubject(claims)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		role, err := resolveRole(claims, s.roleClaim, s.roles)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !role.meets(min) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r, Operator{Role: role, Subject: subject})
	}
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header. A header that is absent, uses a different scheme, or trims down
// to an empty token are all treated identically (ok == false) -- every one
// of them fails closed the same way in authorize above, and none of them
// is a shape worth a different error message to a caller who is, by
// definition, not yet verified.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if token == "" {
		return "", false
	}
	return token, true
}
