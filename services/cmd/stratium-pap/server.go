// server.go is the PAP's HTTP surface for Task 1: every route refuses an
// unverified or under-privileged caller, then returns "not implemented" to
// everyone else. Task 3 onward replaces notImplemented per route with real
// behavior; nothing about how a route reaches that behavior changes then,
// only what routeTable's Handler field points to.
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
)

// Operator is a verified operator's identity as it reaches a route
// handler: a resolved Role and nothing else. No tenant field -- see the
// package doc above -- and no raw claims or subject either: a handler
// that logged this value could not violate "never log ... an operator's
// claims" even by accident, because there is nothing on this type capable
// of it. Task 3/4 will extend this with whatever the audit chain needs to
// attribute a write to an operator (N4); Task 1 has no writes, so nothing
// speculative is added ahead of that need.
type Operator struct {
	Role Role
}

// routeHandler is the only signature a PAP route handler may have -- see
// the package doc's point 1.
type routeHandler func(w http.ResponseWriter, r *http.Request, op Operator)

// routeSpec pairs one route pattern (net/http's Go 1.22+
// "METHOD /path/{wildcard}" syntax) with the minimum Role required to
// reach it.
type routeSpec struct {
	Pattern string
	MinRole Role
	Handler routeHandler
}

// routeTable is the single source of truth routes are registered from --
// (*Server).routes below loops over exactly this, and server_test.go
// inspects exactly this, so there is no second list either could fall out
// of sync with. It previews Task 3's own "viewer reads, editor writes,
// admin writes and deletes" rule (phase plan, Task 3) on the resource CRUD
// starts with, policies, so the role-gating mechanism is proven across all
// three tiers now rather than only against one made-up route. Every
// handler is notImplemented today; Task 3 changes a route's Handler field,
// never the authorize wrapping that reaches it.
var routeTable = []routeSpec{
	{Pattern: "GET /v1/policies", MinRole: RoleViewer, Handler: notImplemented},
	{Pattern: "POST /v1/policies", MinRole: RoleEditor, Handler: notImplemented},
	{Pattern: "DELETE /v1/policies/{id}", MinRole: RoleAdmin, Handler: notImplemented},
}

// notImplemented is routeTable's only handler for this task -- the phase
// brief's "every route returns not implemented until Task 3." Reaching it
// at all already proves authorize let the request through, which is what
// every TestServer_SufficientRole_ReachesHandler case checks for.
func notImplemented(w http.ResponseWriter, _ *http.Request, _ Operator) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Server is the PAP's HTTP server for Task 1: identity verification and
// role gating in front of routeTable's stub handlers.
type Server struct {
	verify    *Verifier
	roleClaim string
	roles     RoleMapping
	mux       *http.ServeMux
}

// NewServer wires routeTable behind authorize and returns a Server ready
// to serve. verify, roleClaim, and roles are all fixed here, from startup
// configuration, exactly once -- the same treatment Verifier itself gives
// issuer/audience.
func NewServer(verify *Verifier, roleClaim string, roles RoleMapping) *Server {
	s := &Server{verify: verify, roleClaim: roleClaim, roles: roles, mux: http.NewServeMux()}
	for _, rt := range routeTable {
		s.mux.HandleFunc(rt.Pattern, s.authorize(rt.MinRole, rt.Handler))
	}
	return s
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// authorize wraps next so it is reached only by a request bearing a token
// that verifies AND resolves to a role meeting min -- the security
// foundation this task exists to prove before anything can depend on it.
// Every failure path writes a response and returns, never falling through
// to next: a missing or malformed Authorization header and a token that
// fails Verify both refuse with 401 (an identity problem -- who is this);
// a token that verifies but carries no usable role, or a role that does
// not meet min, both refuse with 403 (an authorization problem -- this
// identity is known and not permitted here). N2 draws no distinction
// between "no role claim" and "role claim names an unconfigured group";
// neither does this function -- resolveRole's error is enough on its own
// to refuse, without this code caring which of its two named errors it
// was.
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
		role, err := resolveRole(claims, s.roleClaim, s.roles)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !role.meets(min) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r, Operator{Role: role})
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
