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

	// ApproverIdentity is the operator's identity for N7's comparison
	// against an approval's root_principal (spec §4.10.1) — resolved from a
	// SECOND, independently configured claim (N8, role.go's
	// resolveApproverIdentity), never Subject's own "sub": root_principal is
	// populated from a PEP's own DecideRequest.Subject configuration (an
	// email, in most deployments), which an IdP's opaque "sub" claim was
	// never going to match by coincidence.
	//
	// Resolved once per request, here in authorize, the same as Role and
	// Subject — but unlike them, its being empty does not by itself refuse
	// the request: nothing about a routine policy or agent write depends on
	// this identity, so failing every route over a claim N7/N8 exist only to
	// gate ONE of them on would refuse work those rulings were never written
	// to touch. approvals.go's decideApproval is the one caller that
	// requires a non-empty value, and it checks that itself, immediately,
	// before ever reaching internal/store.
	//
	// Not tenant-carrying, so the package doc's "do not widen Operator"
	// constraint (N1) does not apply to it: that constraint is specifically
	// about a per-request TENANT, and this field names an operator, exactly
	// as Subject already does.
	ApproverIdentity string
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
//
// Task 4 adds three more resources, each shaped differently on purpose (spec
// §4.10.1 -- "the admin plane performs three writes that look alike and are
// not"), so none of them reuses the five-route CRUD shape above uniformly:
//
//   - tool-catalog: list/create/get/update, viewer/editor as above, but no
//     delete route -- migrations/000016_stratium_pap_role deliberately
//     withholds DELETE on tool_catalog ("no delete caller in this phase"),
//     and a route with no grant behind it would only ever answer
//     insufficient_privilege.
//   - approvals: two POST actions, not a PUT replace -- an approval has no
//     sensible "full replace" (its request-identity columns are immutable
//     once created), only a disposition. Gated at RoleAdmin, the same floor
//     DELETE routes use elsewhere in this table, because N7 makes a role
//     NECESSARY but never SUFFICIENT here: decideApproval (approvals.go)
//     layers the operator-identity-equals-root-principal check on top,
//     inside the handler, which is the part no role can stand in for.
//   - delegations: one POST action (revoke), also RoleAdmin -- matching
//     this table's existing DELETE-tier operations, since revocation is
//     this table's own sanctioned "delete" (revoked/revoked_at, not a row
//     removal). Unlike approvals, there is no additional identity check:
//     N7's own contrast rules that taking authority away needs only a role.
//
// Task 6 adds the one route each of those two resources was missing: a GET
// list, at RoleViewer, exactly like every other list route here. Task 4's own
// comment in this spot recorded the gap deliberately ("discovering a pending
// approval's id is Task 6's UI concern") -- both write actions above are
// keyed by an id that, until now, no endpoint in this table returned. Neither
// resource gets the other three CRUD verbs: there is no create (the PDP
// creates a pending approval; a delegation is created over gRPC), no update
// (the two POST actions above ARE the sanctioned mutations), and no delete
// (migrations/000016_stratium_pap_role withholds DELETE on both tables, and
// says at length why). Adding a read at RoleViewer does not touch either
// resource's RoleAdmin write floor -- a viewer can now find an approval and
// still cannot decide it.
//
// Task 5 adds two more, both POST, both under /v1/policies, and both
// deliberately at the generic "POST -> editor" floor rather than a
// RoleAdmin exception like actionRoutes below: validate and test read
// policy and evaluate hypotheticals, but change nothing, which argues for
// viewer -- except a pure viewer (GET only, by this table's own convention)
// has no route that could ever ACT on either answer, since they cannot
// POST/PUT a policy even if validate says it is fine. Authoring a candidate
// -- even one that never persists -- is part of the write workflow, not the
// read one, so gating it below editor would carve out the one POST route in
// this whole table a viewer could reach while still never being able to use
// what it produces. The other candidate concern -- that test-against-
// sample-input can reveal what an existing policy would decide for a given
// input, a disclosure question -- does not raise the floor either: a viewer
// already has full-fidelity GET access to every stored policy's own text
// (GET /v1/policies/{id}), so this endpoint's folded verdict discloses
// strictly less than a viewer holding that text could already work out by
// hand. Editor is the floor because of the workflow argument, not the
// disclosure one.
var routeTable = []routeSpec{
	{Pattern: "GET /v1/policies", MinRole: RoleViewer, Handler: listPolicies},
	{Pattern: "POST /v1/policies", MinRole: RoleEditor, Handler: createPolicy},
	{Pattern: "GET /v1/policies/{id}", MinRole: RoleViewer, Handler: getPolicy},
	{Pattern: "PUT /v1/policies/{id}", MinRole: RoleEditor, Handler: updatePolicy},
	{Pattern: "DELETE /v1/policies/{id}", MinRole: RoleAdmin, Handler: deletePolicy},
	{Pattern: "POST /v1/policies/validate", MinRole: RoleEditor, Handler: validatePolicy},
	{Pattern: "POST /v1/policies/test", MinRole: RoleEditor, Handler: testPolicyAgainstSampleInput},

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

	{Pattern: "GET /v1/tool-catalog", MinRole: RoleViewer, Handler: listToolCatalog},
	{Pattern: "POST /v1/tool-catalog", MinRole: RoleEditor, Handler: createToolCatalogEntry},
	{Pattern: "GET /v1/tool-catalog/{id}", MinRole: RoleViewer, Handler: getToolCatalogEntry},
	{Pattern: "PUT /v1/tool-catalog/{id}", MinRole: RoleEditor, Handler: updateToolCatalogEntry},

	{Pattern: "GET /v1/approvals", MinRole: RoleViewer, Handler: listApprovals},
	{Pattern: "POST /v1/approvals/{id}/approve", MinRole: RoleAdmin, Handler: approveApproval},
	{Pattern: "POST /v1/approvals/{id}/deny", MinRole: RoleAdmin, Handler: denyApproval},

	{Pattern: "GET /v1/delegations", MinRole: RoleViewer, Handler: listDelegations},
	{Pattern: "POST /v1/delegations/{id}/revoke", MinRole: RoleAdmin, Handler: revokeDelegation},
}

// Server is the PAP's HTTP server: identity verification and role gating
// (Task 1) in front of the CRUD handlers (Task 3) routeTable wires up.
// store and registry are both nil-checked nowhere in this file -- NewServer
// requires both, the same "no zero-configuration construction" discipline
// policy.NewMulti already applies to its own two required arguments (see
// that function's own doc comment).
type Server struct {
	verify        *Verifier
	roleClaim     string
	approverClaim string
	roles         RoleMapping
	store         *store.Store
	registry      policy.Registry
	mux           *http.ServeMux
}

// NewServer wires routeTable behind authorize and returns a Server ready
// to serve. Every argument is fixed here, from startup configuration,
// exactly once -- the same treatment Verifier itself gives issuer/audience.
// store is tenant-scoped at its own construction (internal/store.New,
// called once by main.go's run) and never re-scoped per request -- N1's
// "the tenant is fixed at startup" holds all the way down to the
// connection this Server ultimately writes through.
//
// approverClaim is Task 4's own addition (N8): the OIDC claim
// resolveApproverIdentity reads to decide who may satisfy N7, a second and
// independently configured claim from roleClaim -- see Operator.
// ApproverIdentity's own doc comment for why the two must not be conflated.
// ui is Task 6's own addition: the public configuration the embedded admin UI
// is served alongside (see ui.go). It is the only argument here that is not
// about authorizing a request, and the only one whose value reaches an
// unauthenticated caller -- deliberately, since a browser cannot present a
// token before being told where to obtain one. It carries no secret; see
// uiConfig's own doc comment.
func NewServer(
	verify *Verifier, roleClaim, approverClaim string, roles RoleMapping,
	st *store.Store, registry policy.Registry, ui uiConfig,
) *Server {
	s := &Server{
		verify: verify, roleClaim: roleClaim, approverClaim: approverClaim,
		roles: roles, store: st, registry: registry, mux: http.NewServeMux(),
	}
	// Registered BEFORE routeTable's own loop only for readability -- net/http
	// resolves by pattern specificity, not registration order (Go 1.22+), so
	// "GET /" never shadows "GET /v1/policies" regardless of which is added
	// first. TestUI_DoesNotShadowAnyAPIRoute proves that rather than trusting
	// it.
	registerUI(s.mux, ui)
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
		// resolveApproverIdentity is a pure, local computation over claims
		// already decoded above -- no extra I/O -- so running it for every
		// request costs nothing and needs no route-specific special case.
		// Its result being empty does not refuse the request here; see
		// Operator.ApproverIdentity's own doc comment for why that check is
		// deferred to the one handler (decideApproval) that actually needs a
		// non-empty value.
		approverIdentity := resolveApproverIdentity(claims, s.approverClaim)
		next(w, r, Operator{Role: role, Subject: subject, ApproverIdentity: approverIdentity})
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
