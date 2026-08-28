//go:build integration

// Phase 14 Task 8's live-stack proofs for the admin plane
// (.superpowers/sdd/2026-08-14-phase-14-pap/task-8-brief.md). Everything
// before this task proved a piece of stratium-pap against a fake: sqlmock
// for the store, a hand-built claim map for the verifier, a direct SQL write
// standing in for an operator. Nothing here does. Every request below is a
// real HTTP request to a real containerized stratium-pap process, carrying a
// real bearer token a real OIDC provider issued to a real operator, and
// every consequence is read back through a real containerized PDP over real
// gRPC.
//
// # The IdP
//
// Keycloak, imported from deploy/docker/keycloak/stratium-realm.json -- see
// the compose file's own `keycloak` comment for why Keycloak rather than
// Dex, which was the brief's stated intent. The short version: the role
// claim has to be an ARRAY. resolveRole (cmd/stratium-pap/role.go) accepts a
// string claim or a []any claim, and only the array branch carries
// highest-role-wins, which is the branch every real deployment uses and the
// one where a wrong answer silently OVER-privileges an operator. Dex's
// staticPasswords carry no groups at all, and its only groups-bearing
// connector needing no external directory returns one hardcoded identity in
// one group. Pointing STRATIUM_PAP_ROLE_CLAIM at "email" instead would have
// exercised the string branch and left production's shape unproven; the
// brief is explicit that accepting that narrower proof was not a decision to
// make quietly.
//
// The array shape is not assumed here either. TestIntegration_PAPE2E_
// MultiGroupOperatorResolvesToTheHighestRole decodes the token this stack
// actually issues, asserts "groups" arrives as a JSON array with two mapped
// group names in it, and then proves behaviorally that the HIGHER of the two
// roles is what the PAP granted.
//
// # Tenancy
//
// These proofs run against tenant-pap-e2e-integration, served by its own
// stratium-pap and its own pdp-pap (compose). A dedicated tenant is not
// politeness here: every proof below writes control-plane state and most of
// them bump tenant_epoch (migrations/000015_tenant_epoch_trigger), which
// would move any epoch assertion a test sharing the tenant had made. N1
// forbids a request from carrying a tenant, so "one PAP process, one tenant,
// for the life of the process" is the only shape available -- which is also
// why proof 4 (extauthz_integration_test.go, not this file) needs a SECOND
// stratium-pap on the extauthz tenant rather than reusing this one.
//
// # Tool names
//
// Every proof below picks tool names no other proof in this file touches.
// tier_overrides and tool_catalog are keyed per tenant, not per test, so two
// proofs sharing a tool name would silently couple through the database --
// the ordering trap Part A of this same task removed from proof6's
// audit_chain revoke, and not one worth reintroducing in a new form.
package store_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"stratium/internal/pdpgrpc"
	"stratium/pkg/models"
)

// The realm's operators (deploy/docker/keycloak/stratium-realm.json). Group
// membership, not the username, is what decides each one's role -- the
// compose file's STRATIUM_PAP_{ADMIN,EDITOR,VIEWER}_GROUPS map the realm's
// group names, and resolveRole reads only the "groups" claim.
//
// papMultiUser is in TWO mapped groups: "all-staff" (mapped to viewer) and
// "stratium-admins" (mapped to admin). It exists solely so highest-role-wins
// is a branch this suite actually runs.
//
// The passwords are local-dev-only fixtures in a realm document that lives
// in this repository and is imported into a throwaway, in-memory Keycloak
// torn down with the rest of the stack -- the same convention
// deploy/docker/init-db.sql already uses for its own role passwords. Nothing
// here is a credential to anything outside `make integration`.
const (
	papAdminUser = "pap-admin"
	papAdminPass = "pap_admin_local_dev_only"

	papEditorUser = "pap-editor"
	papEditorPass = "pap_editor_local_dev_only"

	papViewerUser = "pap-viewer"
	papViewerPass = "pap_viewer_local_dev_only"

	papMultiUser = "pap-multi"
	papMultiPass = "pap_multi_local_dev_only"

	// papExtauthzApproverUser is proof 4's operator: the realm user whose
	// email equals pep-extauthz's own STRATIUM_PEP_SUBJECT, which is what
	// the PDP records as an escalation's root_principal and what N7
	// requires an approving operator's own identity to equal. Used from
	// extauthz_integration_test.go, not this file.
	papExtauthzApproverUser = "extauthz-approver"
	papExtauthzApproverPass = "extauthz_approver_local_dev_only"

	// papOIDCClientID is the realm's public client. The same value the PAP
	// containers are configured with as both STRATIUM_PAP_OIDC_CLIENT_ID and
	// STRATIUM_PAP_OIDC_AUDIENCE -- the realm's audience mapper puts the
	// client id in "aud", which is what go-oidc's ClientID check compares
	// against (cmd/stratium-pap/oidc.go's NewVerifier).
	papOIDCClientID = "stratium-pap"
)

// papAccessToken obtains a real access token for username from the real
// Keycloak in the compose stack, via the OAuth 2.0 resource-owner password
// grant (the realm's client has directAccessGrants enabled).
//
// The ACCESS token, not the id token, deliberately: that is what the admin
// UI actually sends (clients/ui/src/auth.ts keeps `access_token` and builds
// `Authorization: Bearer ${accessToken}`), so verifying anything else here
// would prove a shape production does not use. It is also why the realm
// carries an explicit audience mapper -- an id token gets "aud" = client id
// for free, an access token does not, and without that mapper every request
// below would fail go-oidc's audience check for a reason that has nothing to
// do with what is being tested.
//
// The password grant, not the authorization-code flow the UI uses, because
// the two differ only in how the browser and the IdP negotiate; what comes
// back is the same signed token from the same issuer with the same claims,
// and driving a real login form from Go would add a browser to this suite to
// prove nothing this does not.
func papAccessToken(t *testing.T, username, password string) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {papOIDCClientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid email"},
	}
	endpoint := "http://" + keycloakAddr + "/realms/stratium/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request for %s: %v", username, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request to %s for %s: %v", endpoint, username, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read token response for %s: %v", username, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint status = %d for %s, want 200; body: %s", resp.StatusCode, username, body)
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode token response for %s: %v", username, err)
	}
	if decoded.AccessToken == "" {
		t.Fatalf("token endpoint returned no access_token for %s", username)
	}
	return decoded.AccessToken
}

// papClaims decodes a JWT's payload WITHOUT verifying anything. Legitimate
// only because of what it is used for: asserting the SHAPE of what the IdP
// issued (that "groups" is an array, not a string), from the test's own side
// of the wire. Nothing in any binary does this -- N2 forbids it absolutely,
// and cmd/stratium-pap/oidc.go has no path that returns claims without
// go-oidc's Verify succeeding first. This helper lives in a _test.go file in
// internal/store, imports nothing from cmd/stratium-pap, and could not be
// reached from a binary if someone tried.
func papClaims(t *testing.T, rawToken string) map[string]any {
	t.Helper()
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d dot-separated parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal token payload: %v", err)
	}
	return claims
}

// papDo performs one HTTP request against a stratium-pap process and returns
// its status and body. addr selects WHICH pap: papAddr (tenant-pap-e2e-
// integration) for every proof in this file, papExtauthzAddr for proof 4's.
//
// token == "" sends no Authorization header at all, which is one of the
// shapes proof 3 needs; anything else is sent verbatim as a Bearer
// credential, including deliberately malformed values.
func papDo(t *testing.T, addr, method, path, token string, body any) (int, string) {
	t.Helper()
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		payload = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+addr+path, payload)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, path, err)
	}
	return resp.StatusCode, strings.TrimSpace(string(raw))
}

// papJSON is papDo for a request expected to succeed, decoding the response
// into out and failing on any status outside 2xx. Keeps every happy-path
// call site from repeating the same four-line status check.
func papJSON(t *testing.T, addr, method, path, token string, body, out any) {
	t.Helper()
	status, raw := papDo(t, addr, method, path, token, body)
	if status < 200 || status > 299 {
		t.Fatalf("%s %s status = %d, want 2xx; body: %s", method, path, status, raw)
	}
	if out == nil {
		return
	}
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		t.Fatalf("decode %s %s response: %v; body: %s", method, path, err, raw)
	}
}

// papRoute is one row of the route table proofs 2 and 3 sweep. Mirrors
// cmd/stratium-pap/server.go's own routeTable, which this package cannot
// import (it is a main package).
//
// Drift is caught in ONE direction here and in the other direction there,
// and it took a review to notice the asymmetry. A route this table names but
// the server does not register fails here (it answers 404 where a 401/403 is
// asserted), and proof 2's own `writes != 23` catches a write route deleted
// from this copy. Neither catches a route ADDED to server.go: proof 2 would
// still count 16 and pass, proof 3's "everywhere" sweep would never touch
// the new route, and C5's machine-checked pointer would go on citing proof 3
// as evidence that the tier-override write surface is unreachable without a
// token. TestRouteTable_CoversEveryCRUDRouteForEveryResource
// (cmd/stratium-pap/server_test.go) is where that direction is pinned -- it
// asserts both the total route count and the number gated above RoleViewer,
// so adding a route fails THERE and names this table as the other place to
// update. The two counts must stay equal: 37 routes, 23 of them writes
// (Task 7 added 3 routes, 2 of them writes, to what was 31/19; the
// resource-constraints task added 3 more, 2 of them writes, to what was
// 34/21).
//
// write records whether the route is gated above RoleViewer, which is the
// only thing proof 2 needs to know about it.
type papRoute struct {
	method string
	path   string
	write  bool
}

// papRouteTable enumerates every route stratium-pap serves, with id
// substituted into each {id} wildcard. The id never has to exist: both
// proofs that use this table assert a refusal that authorize (server.go)
// issues BEFORE any handler runs, so a route reaching its handler at all is
// already the failure.
func papRouteTable(id string) []papRoute {
	return []papRoute{
		{http.MethodGet, "/v1/policies", false},
		{http.MethodPost, "/v1/policies", true},
		{http.MethodGet, "/v1/policies/" + id, false},
		{http.MethodPut, "/v1/policies/" + id, true},
		{http.MethodDelete, "/v1/policies/" + id, true},
		{http.MethodPost, "/v1/policies/validate", true},
		{http.MethodPost, "/v1/policies/test", true},

		{http.MethodGet, "/v1/agents", false},
		{http.MethodPost, "/v1/agents", true},
		{http.MethodGet, "/v1/agents/" + id, false},
		{http.MethodPut, "/v1/agents/" + id, true},
		{http.MethodDelete, "/v1/agents/" + id, true},

		// Task 7's classification-caps sub-resource: GET is not a write, PUT
		// and DELETE are, and both writes are gated RoleAdmin -- see
		// cmd/stratium-pap/server.go's routeTable, this table's own mirror.
		{http.MethodGet, "/v1/agents/" + id + "/classification-caps", false},
		{http.MethodPut, "/v1/agents/" + id + "/classification-caps", true},
		{http.MethodDelete, "/v1/agents/" + id + "/classification-caps", true},

		// resource-constraints sub-resource: GET is not a write, PUT and
		// DELETE are, and both writes are gated RoleAdmin -- see
		// cmd/stratium-pap/server.go's routeTable, this table's own mirror.
		{http.MethodGet, "/v1/agents/" + id + "/resource-constraints", false},
		{http.MethodPut, "/v1/agents/" + id + "/resource-constraints", true},
		{http.MethodDelete, "/v1/agents/" + id + "/resource-constraints", true},

		{http.MethodGet, "/v1/tier-overrides", false},
		{http.MethodPost, "/v1/tier-overrides", true},
		{http.MethodGet, "/v1/tier-overrides/" + id, false},
		{http.MethodPut, "/v1/tier-overrides/" + id, true},
		{http.MethodDelete, "/v1/tier-overrides/" + id, true},

		{http.MethodGet, "/v1/tool-catalog", false},
		{http.MethodPost, "/v1/tool-catalog", true},
		{http.MethodGet, "/v1/tool-catalog/" + id, false},
		{http.MethodPut, "/v1/tool-catalog/" + id, true},

		{http.MethodGet, "/v1/approvals", false},
		{http.MethodPost, "/v1/approvals/" + id + "/approve", true},
		{http.MethodPost, "/v1/approvals/" + id + "/deny", true},

		{http.MethodGet, "/v1/delegations", false},
		{http.MethodPost, "/v1/delegations/" + id + "/revoke", true},

		{http.MethodGet, "/v1/resource-label-rules", false},
		{http.MethodPost, "/v1/resource-label-rules", true},
		{http.MethodGet, "/v1/resource-label-rules/" + id, false},
		{http.MethodPut, "/v1/resource-label-rules/" + id, true},
		{http.MethodDelete, "/v1/resource-label-rules/" + id, true},
	}
}

// papBlanketPermit seeds a cedar permit for tenant-pap-e2e-integration under
// a name unique to the calling proof, so the principal leg allows and every
// assertion below is about the leg the proof is actually testing. Seeded
// directly rather than created through the PAP: this is fixture, not the
// thing under test, and proof 1 is the one proof that needs a policy WRITE
// to be the subject rather than the setup.
func papBlanketPermit(t *testing.T, name string) {
	t.Helper()
	seedPolicy(t, papTenant, name, `permit(principal, action, resource);`, "allow")
}

// papDecide calls the real pdp-pap container over real gRPC. Every proof
// that asserts "the admin plane's write reached a decision" ends here, in a
// different process from the one that performed the write, reading through
// the serving role's own grants -- which is the only way that claim means
// anything.
func papDecide(t *testing.T, req *pdpgrpc.DecideRequest) *pdpgrpc.DecideResponse {
	t.Helper()
	resp, err := papPdpClient.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("Decide(tool=%s) error = %v, want a decision", req.GetTool(), err)
	}
	return resp
}

// papChainFixture seeds an agent and a root delegation for one proof, and
// returns both. maxTier is DESTRUCTIVE throughout this file so no proof
// denies at the delegation leg before the thing it is testing can be read
// off the response.
func papChainFixture(t *testing.T, name, principal string) (uuid.UUID, *models.Delegation) {
	t.Helper()
	agentID := uuid.New()
	seedAgent(t, papTenant, agentID, name, models.TrustTierPlatformTrusted)
	id := uuid.New()
	root := seedDelegation(t, &models.Delegation{
		ID: id, TenantID: papTenant, UserID: principal, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: name, ExpiresAt: time.Now().Add(time.Hour),
		RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})
	return agentID, root
}

// ---------------------------------------------------------------------------
// Proof 1
// ---------------------------------------------------------------------------

// TestIntegration_PAPE2E_AdminPolicyWriteBumpsEpochAndReachesTheNextDecision
// is the brief's proof 1, and the whole loop in one test: an operator
// authenticated by a real IdP writes through the admin plane, the database
// trigger fires, and a DIFFERENT process -- the PDP, connected as a
// different role with no write grant of its own -- decides differently on
// its very next call because of it.
//
// The policy created is a forbid scoped to ONE action, not a blanket one,
// deliberately. A blanket forbid would prove the write arrived but would
// also leave every later proof in this file staring at a tenant where
// nothing is permitted, and it would make this proof's own "after" assertion
// unable to distinguish "the new policy reached the decision" from "some
// policy reached the decision." The control call on a second, untouched tool
// is what pins that difference: the same agent, the same token, the same
// delegation, one tool newly denied and the other still allowed.
func TestIntegration_PAPE2E_AdminPolicyWriteBumpsEpochAndReachesTheNextDecision(t *testing.T) {
	const forbiddenTool = "papProof1ForbiddenTool"
	const controlTool = "papProof1ControlTool"
	const principal = "pap-proof1@example.com"

	papBlanketPermit(t, "pap-proof1-blanket-permit")
	agentID, root := papChainFixture(t, "pap-proof1-agent", principal)
	tok := mintToken(t, papPdpClient, root.ID)

	decide := func(tool string) *pdpgrpc.DecideResponse {
		return papDecide(t, &pdpgrpc.DecideRequest{
			Token: tok, AgentId: agentID.String(), Subject: principal, Tool: tool, RawInput: "proof1",
		})
	}

	if before := decide(forbiddenTool); before.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("before the admin's write, Decide(%s) = %v (reason: %s), want ALLOW -- this proof reads "+
			"the CHANGE the write causes, so the starting state has to be the other one",
			forbiddenTool, before.GetEffect(), before.GetReason())
	}

	epochBefore, _ := readTenantEpoch(t, papTenant)

	admin := papAccessToken(t, papAdminUser, papAdminPass)
	var created models.Policy
	papJSON(t, papAddr, http.MethodPost, "/v1/policies", admin, map[string]any{
		"name":        "pap-proof1-forbid-one-tool",
		"description": "Task 8 proof 1: written by a real operator through the real admin plane",
		"language":    "cedar",
		// "policy_content", not "text": models.Policy's own JSON tag. A
		// request naming the wrong field is accepted as an EMPTY policy and
		// refused by the engine with "expected exactly one policy statement,
		// found 0" -- a real 400, but one that names the symptom rather than
		// the field, which is how this was found.
		"policy_content": `forbid(principal, action == Action::"` + forbiddenTool + `", resource);`,
		"effect":         "deny",
		"enabled":        true,
	}, &created)
	if created.ID == uuid.Nil {
		t.Fatal("POST /v1/policies returned the zero UUID -- nothing was actually created")
	}

	assertEpochBumped(t, papTenant, epochBefore)

	after := decide(forbiddenTool)
	if after.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("after the admin's write, Decide(%s) = %v (reason: %s), want DENY -- the admin plane wrote, "+
			"the epoch bumped, and the decision plane did not observe it",
			forbiddenTool, after.GetEffect(), after.GetReason())
	}
	if got := after.GetDecidedPolicyId(); got != created.ID.String() {
		t.Errorf("denying decision attributed to policy %q, want the just-created %q -- the DENY has to come "+
			"from THIS write, not from something else in the tenant", got, created.ID)
	}

	if control := decide(controlTool); control.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Decide(%s) = %v (reason: %s), want ALLOW -- the new policy names one action, so a second "+
			"tool going dark means something broader than this write reached the decision",
			controlTool, control.GetEffect(), control.GetReason())
	}
}

// ---------------------------------------------------------------------------
// Proof 2
// ---------------------------------------------------------------------------

// TestIntegration_PAPE2E_ViewerIsRefusedEveryWrite is the brief's proof 2,
// swept across every write route stratium-pap serves rather than a
// representative sample: a role floor that holds for fifteen routes and
// leaks on the sixteenth is not a role floor.
//
// Two controls make each 403 mean what it claims. The viewer's own GET
// succeeding rules out "this operator can do nothing at all" (a broken token
// would produce sixteen refusals just as tidily), and an EDITOR's write to
// the same route succeeding rules out "this route is broken" -- which would
// otherwise be indistinguishable from a role refusal on a route nothing else
// in this file exercises.
func TestIntegration_PAPE2E_ViewerIsRefusedEveryWrite(t *testing.T) {
	viewer := papAccessToken(t, papViewerUser, papViewerPass)
	id := uuid.New().String()

	// Control 1: this token works. Without it, every refusal below is
	// consistent with the viewer simply never having been authenticated.
	var listed []models.Policy
	papJSON(t, papAddr, http.MethodGet, "/v1/policies", viewer, nil, &listed)

	var writes int
	for _, rt := range papRouteTable(id) {
		if !rt.write {
			// Not "200": every {id} route here names a UUID that does not
			// exist, so 404 is the correct answer and is the STRONGER
			// signal -- it means the request passed authorize entirely and
			// reached a handler. What must never appear is 403 (or 401).
			status, body := papDo(t, papAddr, rt.method, rt.path, viewer, nil)
			if status == http.StatusForbidden || status == http.StatusUnauthorized {
				t.Errorf("viewer %s %s status = %d, want past authorize -- a viewer reads; body: %s",
					rt.method, rt.path, status, body)
			}
			continue
		}
		writes++
		status, body := papDo(t, papAddr, rt.method, rt.path, viewer, map[string]any{})
		if status != http.StatusForbidden {
			t.Errorf("viewer %s %s status = %d, want 403 -- a viewer writes nothing; body: %s",
				rt.method, rt.path, status, body)
		}
	}
	// Catches a write route DELETED from papRouteTable. A route added to
	// server.go is caught by TestRouteTable_CoversEveryCRUDRouteForEveryResource
	// instead -- see papRoute's own doc comment for why the two halves live
	// in different packages and must agree.
	if writes != 23 {
		t.Errorf("swept %d write routes, want 23 -- papRouteTable has drifted from "+
			"cmd/stratium-pap/server.go's routeTable", writes)
	}

	// Control 2: the same route, one role higher, succeeds. This is what
	// separates "the viewer was refused" from "POST /v1/policies is broken."
	editor := papAccessToken(t, papEditorUser, papEditorPass)
	var created models.Policy
	papJSON(t, papAddr, http.MethodPost, "/v1/policies", editor, map[string]any{
		"name": "pap-proof2-editor-control", "description": "Task 8 proof 2 control: an editor may write",
		"language": "cedar", "policy_content": `permit(principal, action == Action::"papProof2ControlTool", resource);`,
		"effect": "allow", "enabled": true,
	}, &created)
	if created.ID == uuid.Nil {
		t.Fatal("the editor's control write returned the zero UUID")
	}

	// ...and the delete the editor is still refused, one role above their
	// own floor: proof 2's claim is about a role ceiling as much as a floor.
	if status, body := papDo(t, papAddr, http.MethodDelete, "/v1/policies/"+created.ID.String(), editor, nil); status != http.StatusForbidden {
		t.Errorf("editor DELETE /v1/policies/{id} status = %d, want 403 -- DELETE is admin-only; body: %s", status, body)
	}
}

// TestIntegration_PAPE2E_MultiGroupOperatorResolvesToTheHighestRole is the
// half of proof 2 that only a real IdP can supply, and the reason this stack
// runs Keycloak rather than a hand-built token: resolveRole's array branch,
// with an operator in more than one mapped group.
//
// pap-multi belongs to "all-staff" (mapped to viewer) and "stratium-admins"
// (mapped to admin). The proof is behavioral, not a claim inspection: the
// operator reaches a route gated at RoleAdmin and is NOT refused. If
// resolveRole took the first match, or the last, or anything other than the
// highest-ranked, this operator would be a viewer and that route would
// answer 403.
//
// A 404 is the expected success here, and is a stronger signal than a 200
// would be: it means the request passed authorize (server.go) entirely and
// reached deletePolicy, which then found no such row. A 403 never reaches a
// handler at all.
func TestIntegration_PAPE2E_MultiGroupOperatorResolvesToTheHighestRole(t *testing.T) {
	multi := papAccessToken(t, papMultiUser, papMultiPass)

	// The claim shape first: production reads an array, and a string claim
	// that happened to work would prove the wrong branch.
	claims := papClaims(t, multi)
	raw, ok := claims["groups"]
	if !ok {
		t.Fatal(`the IdP issued no "groups" claim -- STRATIUM_PAP_ROLE_CLAIM names it, so every operator would be refused`)
	}
	groups, ok := raw.([]any)
	if !ok {
		t.Fatalf(`"groups" claim decoded as %T, want []any -- resolveRole's array branch (the one carrying `+
			`highest-role-wins) is only reached for an array, so a string here would mean this suite proves `+
			`the string branch instead of production's`, raw)
	}
	var names []string
	for _, g := range groups {
		s, ok := g.(string)
		if !ok {
			t.Fatalf(`"groups" contains a %T, want every entry to be a string`, g)
		}
		names = append(names, s)
	}
	const viewerGroup, adminGroup = "all-staff", "stratium-admins"
	if len(names) != 2 || !slicesContains(names, viewerGroup) || !slicesContains(names, adminGroup) {
		t.Fatalf(`"groups" = %v, want exactly [%s %s] in some order -- with fewer than two MAPPED groups `+
			`there is no highest to win`, names, viewerGroup, adminGroup)
	}
	// Recorded, not asserted: Keycloak decides this order, and the point is
	// that the answer must not depend on it. Task 8 observed
	// [all-staff stratium-admins] -- viewer first -- which means a
	// first-match-wins implementation would fail the assertion below.
	t.Logf(`"groups" arrived as a JSON array in the order %v; STRATIUM_PAP_VIEWER_GROUPS maps %q and `+
		`STRATIUM_PAP_ADMIN_GROUPS maps %q`, names, viewerGroup, adminGroup)

	status, body := papDo(t, papAddr, http.MethodDelete, "/v1/policies/"+uuid.New().String(), multi, nil)
	if status == http.StatusForbidden {
		t.Fatalf("DELETE /v1/policies/{id} as an operator in %v = 403 -- the lower of the two mapped roles "+
			"was taken; N2's array branch must yield the highest; body: %s", names, body)
	}
	if status != http.StatusNotFound {
		t.Fatalf("DELETE /v1/policies/{id} as an operator in %v = %d, want 404 (past authorize, into the "+
			"handler, which found no such row); body: %s", names, status, body)
	}
}

// slicesContains is a two-line local rather than an import purely because
// this file's one use of it is over a []string built from a claim.
func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Proof 3
// ---------------------------------------------------------------------------

// TestIntegration_PAPE2E_UnverifiedTokenIsRefusedEverywhere is the brief's
// proof 3, and the live-stack half of N2: OIDC against a real IdP or
// nothing. It sweeps EVERY route, read and write alike, because the claim is
// "everywhere" -- a single route that accepted an unverified credential
// would be the whole system's front door.
//
// Four shapes, each failing for a different reason:
//
//   - a forged token, signed by a key this test generated seconds ago, whose
//     claims are otherwise perfect -- correct issuer, correct audience, a
//     real subject, and a "groups" array naming the admin group. Everything
//     except the cryptography says "admin".
//
//     What is established is "an unverifiable token is refused", not
//     specifically "the SIGNATURE check refused it". go-oidc leaves
//     SupportedSigningAlgs unset (oidc.go's NewVerifier, deliberately, so the
//     IdP's own discovery document decides), Keycloak signs RS256 and
//     advertises ES256 among its supported algorithms, and this token is
//     ES256 with a "kid" the realm's JWKS has never published -- so the
//     refusal most likely comes from the key lookup rather than an algorithm
//     rejection, which is if anything the stronger of the two. This test
//     cannot tell which, and deliberately does not try: the PAP answers a
//     bare "unauthorized" for every 401 (server.go's authorize), because
//     telling an unverified caller WHY they failed is how a probe maps an
//     IdP's configuration. The `tampered` case below is what pins the
//     signature check specifically -- same key, same alg, same kid, one byte
//     of signature inverted.
//
//   - a genuine token with one byte of its signature inverted.
//
//   - no Authorization header.
//
//   - a non-Bearer scheme.
//
// The positive control at the end is what makes all four mean something: the
// same sweep with a real admin token must NOT answer 401 anywhere, or a
// server that refused everything unconditionally would pass this test
// perfectly.
func TestIntegration_PAPE2E_UnverifiedTokenIsRefusedEverywhere(t *testing.T) {
	genuine := papAccessToken(t, papAdminUser, papAdminPass)

	// Perfect claims, wrong key. escalationSigner generates a fresh EC key
	// into t.TempDir(), so nothing this token is signed with has ever been
	// published in the realm's JWKS.
	forged, err := escalationSigner(t).Sign(jwt.MapClaims{
		"iss":            "http://keycloak:8080/realms/stratium",
		"aud":            papOIDCClientID,
		"sub":            uuid.New().String(),
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"groups":         []string{"stratium-admins"},
		"email":          "forged-admin@example.com",
		"email_verified": true,
	})
	if err != nil {
		t.Fatalf("sign the forged token: %v", err)
	}

	// A real token with a mangled signature: same header, same payload, a
	// signature that cannot verify.
	tampered := tamperSignature(t, genuine)

	unverified := map[string]string{
		"forged_signature_perfect_claims": forged,
		"tampered_signature":              tampered,
		"absent":                          "",
		"not_a_jwt_at_all":                "definitely-not-a-token",
	}

	routes := papRouteTable(uuid.New().String())
	for name, tok := range unverified {
		t.Run(name, func(t *testing.T) {
			for _, rt := range routes {
				var body any
				if rt.write {
					body = map[string]any{}
				}
				status, respBody := papDo(t, papAddr, rt.method, rt.path, tok, body)
				if status != http.StatusUnauthorized {
					t.Errorf("%s %s with an unverified token = %d, want 401; body: %s",
						rt.method, rt.path, status, respBody)
				}
			}
		})
	}

	// A wrong SCHEME, not a wrong token: bearerToken (server.go) refuses
	// anything not prefixed "Bearer ", and this is the one shape papDo
	// cannot express because it builds that prefix itself.
	t.Run("wrong_auth_scheme", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+papAddr+"/v1/policies", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:hunter2")))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /v1/policies: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET /v1/policies with a Basic credential = %d, want 401", resp.StatusCode)
		}
	})

	// The positive control. Not "every route returns 200" -- most of these
	// name an id that does not exist -- but "no route answers 401", which is
	// the exact assertion the four sweeps above would also satisfy if this
	// server refused everything unconditionally.
	t.Run("positive_control_a_real_token_is_never_401", func(t *testing.T) {
		for _, rt := range routes {
			var body any
			if rt.write {
				body = map[string]any{}
			}
			status, respBody := papDo(t, papAddr, rt.method, rt.path, genuine, body)
			if status == http.StatusUnauthorized {
				t.Errorf("%s %s with a REAL admin token = 401 -- the refusals above prove nothing if a "+
					"verified operator is refused too; body: %s", rt.method, rt.path, respBody)
			}
		}
	})
}

// tamperSignature returns tok with one byte of its signature inverted:
// decoded, altered, re-encoded, so the result is still a syntactically valid
// three-segment JWT carrying the identical header and payload, whose
// signature cannot verify.
//
// It decodes rather than editing the base64 text, and that is the whole
// point of the helper. The first version of this simply changed the LAST
// CHARACTER of the signature segment, which does not reliably tamper with
// anything: a base64url segment's final character carries only the leftover
// significant bits of the last byte, and an edit confined to the padding
// bits below them decodes to the identical signature. Found live, in the
// worst possible way -- that version passed against one token and, on the
// next run, was handed a token whose signature happened to end in a
// character where the edit landed entirely in padding, so the "tampered"
// token was byte-for-byte genuine and the PAP correctly accepted it. The
// test reported that as the PAP admitting an unverified credential. It was
// not; the mutation was a no-op. A tamper test that silently does not tamper
// is worse than no tamper test at all.
func tamperSignature(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d dot-separated parts, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature segment: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("token carries an empty signature -- nothing to tamper with")
	}
	sig[0] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if tampered == tok {
		t.Fatal("tamperSignature produced the original token unchanged -- the mutation did nothing")
	}
	return tampered
}

// ---------------------------------------------------------------------------
// Proof 5
// ---------------------------------------------------------------------------

// TestIntegration_PAPE2E_RevokingRootDelegationThroughThePAPDeniesDescendants
// is the brief's proof 5 -- V4 and cascade -- against a three-hop chain, so
// "every descendant" has more than one member to be true of.
//
// The revoke is a single PAP request naming the ROOT alone. Nothing writes
// to the child or the grandchild, and nothing needs to: DelegationLeg
// (internal/authz/delegation.go) checks Revoked at every hop of the chain it
// is handed, on every decision, so the cascade is a property of how a
// decision is made rather than of how a revocation is stored. Asserting the
// two descendants deny is what turns that from a design claim into a
// measured one.
func TestIntegration_PAPE2E_RevokingRootDelegationThroughThePAPDeniesDescendants(t *testing.T) {
	const principal = "pap-proof5@example.com"
	const tool = "papProof5Tool"

	papBlanketPermit(t, "pap-proof5-blanket-permit")
	agentID, root := papChainFixture(t, "pap-proof5-agent", principal)

	childID := uuid.New()
	child := seedDelegation(t, &models.Delegation{
		ID: childID, TenantID: papTenant, UserID: principal, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "pap proof 5: one hop below the root", ExpiresAt: time.Now().Add(time.Hour),
		ParentDelegationID: &root.ID, RootDelegationID: root.ID, Depth: 1,
		ChainAgentIDs: []uuid.UUID{agentID, agentID},
	})
	grandchildID := uuid.New()
	grandchild := seedDelegation(t, &models.Delegation{
		ID: grandchildID, TenantID: papTenant, UserID: principal, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "pap proof 5: two hops below the root", ExpiresAt: time.Now().Add(time.Hour),
		ParentDelegationID: &child.ID, RootDelegationID: root.ID, Depth: 2,
		ChainAgentIDs: []uuid.UUID{agentID, agentID, agentID},
	})

	hops := map[string]*models.Delegation{"root": root, "child": child, "grandchild": grandchild}
	tokens := make(map[string]string, len(hops))
	for name, d := range hops {
		tokens[name] = mintToken(t, papPdpClient, d.ID)
	}

	decide := func(name string) *pdpgrpc.DecideResponse {
		return papDecide(t, &pdpgrpc.DecideRequest{
			Token: tokens[name], AgentId: agentID.String(), Subject: principal, Tool: tool, RawInput: "proof5",
		})
	}

	for name := range hops {
		if got := decide(name); got.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("before the revocation, Decide via the %s delegation = %v (reason: %s), want ALLOW -- "+
				"this proof reads the change a revocation causes", name, got.GetEffect(), got.GetReason())
		}
	}

	epochBefore, _ := readTenantEpoch(t, papTenant)

	admin := papAccessToken(t, papAdminUser, papAdminPass)
	var revoked models.Delegation
	papJSON(t, papAddr, http.MethodPost, "/v1/delegations/"+root.ID.String()+"/revoke", admin, nil, &revoked)
	if !revoked.Revoked {
		t.Fatalf("POST /v1/delegations/{root}/revoke returned Revoked = false")
	}
	if revoked.ID != root.ID {
		t.Fatalf("revoked delegation id = %s, want the root %s", revoked.ID, root.ID)
	}

	// delegations UPDATE is in migrations/000015_tenant_epoch_trigger's own
	// list, so a revocation is one of the writes that invalidates a cache.
	assertEpochBumped(t, papTenant, epochBefore)

	for name := range hops {
		got := decide(name)
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Errorf("after revoking the ROOT, Decide via the %s delegation = %v (reason: %s), want DENY -- "+
				"V4 requires the whole subtree to go with the root", name, got.GetEffect(), got.GetReason())
			continue
		}
		if leg := got.GetDeniedLeg(); leg != "delegation" {
			t.Errorf("after revoking the root, the %s delegation denied at leg %q, want %q -- a denial for "+
				"some other reason would prove the cascade without proving it is the revocation",
				name, leg, "delegation")
		}
		// The leg alone is not enough, and mutation testing is how that was
		// established rather than guessed. DelegationLeg checks Revoked
		// explicitly and then checks IsActive, and IsActive is
		// `!Revoked && !now.After(ExpiresAt)` -- so a revoked hop fails BOTH.
		// With the explicit Revoked branch neutered, every assertion above
		// still passed: the child and grandchild denied at the delegation
		// leg, at depth 0, reporting the revoked root as "expired at
		// <time>". A proof that cannot tell "denied because revoked" from
		// "denied because something else about the same hop" is not proving
		// V4. The reason and the root's own id are what pin it.
		reason := got.GetReason()
		if !strings.Contains(reason, "revoked") {
			t.Errorf("after revoking the root, the %s delegation denied with reason %q, want it to name the "+
				"REVOCATION -- IsActive treats a revoked hop as inactive too, so a denial that does not say "+
				"\"revoked\" is consistent with the per-hop revocation check having been removed entirely",
				name, reason)
		}
		if !strings.Contains(reason, root.ID.String()) {
			t.Errorf("after revoking the root, the %s delegation denied with reason %q, want it to name the "+
				"ROOT delegation %s -- the cascade claim is that the ancestor's flag denies its descendants, "+
				"which means the denial has to be attributed to the ancestor", name, reason, root.ID)
		}
		if depth := got.GetDeniedAtDepth(); depth != 0 {
			t.Errorf("after revoking the root, the %s delegation denied at depth %d, want 0 (the root's own "+
				"depth)", name, depth)
		}
	}
}

// ---------------------------------------------------------------------------
// Proof 6
// ---------------------------------------------------------------------------

// TestIntegration_PAPE2E_TierOverrideRaisesAndLoweringIsRefusedOnBothBaselines
// is the brief's proof 6. It means something only because Task 7 wired
// TierTable.Overrides into the decision at all: before that, an override was
// a row nothing read.
//
// The raise-only rule is checked against the resolution BENEATH the override
// (spec §4.4.3, T5), and that resolution has two sources -- the tenant's own
// tool_catalog entry where one exists, the built-in classification
// otherwise. Those are different code paths inside
// authz.OverrideBaseline/baselineFrom, so a proof covering one covers half
// the rule. Both are exercised below, each with a control that isolates the
// baseline as the cause of the refusal:
//
//   - built-in baseline: "Write" is INTERNAL_MODIFY in authz.DefaultCatalog
//     with no tenant row anywhere. Lowering it to READ_ONLY is refused;
//     raising the SAME key to DESTRUCTIVE is accepted, so the 400 is about
//     direction, not about the key.
//   - catalog baseline: two invented tool names, neither of which any
//     built-in knows. One has a tenant tool_catalog row at DESTRUCTIVE and
//     one has nothing. The IDENTICAL proposed tier is refused for the first
//     and accepted for the second, so the refusal is attributable to the
//     catalog row and to nothing else.
func TestIntegration_PAPE2E_TierOverrideRaisesAndLoweringIsRefusedOnBothBaselines(t *testing.T) {
	const principal = "pap-proof6@example.com"
	editor := papAccessToken(t, papEditorUser, papEditorPass)

	createOverride := func(t *testing.T, toolOrVerb string, tier models.ActionTier) (int, string) {
		t.Helper()
		return papDo(t, papAddr, http.MethodPost, "/v1/tier-overrides", editor, map[string]any{
			"tool_or_verb": toolOrVerb, "action_tier": int(tier),
		})
	}

	t.Run("raise_reaches_a_real_decision", func(t *testing.T) {
		papBlanketPermit(t, "pap-proof6-blanket-permit")
		agentID, root := papChainFixture(t, "pap-proof6-agent", principal)
		tok := mintToken(t, papPdpClient, root.ID)

		decide := func() *pdpgrpc.DecideResponse {
			return papDecide(t, &pdpgrpc.DecideRequest{
				Token: tok, AgentId: agentID.String(), Subject: principal, Tool: "Bash", RawInput: "ls -la",
			})
		}

		// `ls -la` classifies READ_ONLY through BuiltinTier's command
		// classifier, with no catalog entry for Bash at any level. That is
		// the baseline the override has to move.
		if before := decide().GetDerivedTier(); before != int32(models.ActionTierReadOnly) {
			t.Fatalf("before the override, DerivedTier for `ls -la` = %d, want %d (READ_ONLY) -- this proof "+
				"reads the change the override causes", before, models.ActionTierReadOnly)
		}

		epochBefore, _ := readTenantEpoch(t, papTenant)
		status, body := createOverride(t, "Bash", models.ActionTierDestructive)
		if status != http.StatusCreated {
			t.Fatalf("POST /v1/tier-overrides raising Bash = %d, want 201; body: %s", status, body)
		}
		assertEpochBumped(t, papTenant, epochBefore)

		if after := decide().GetDerivedTier(); after != int32(models.ActionTierDestructive) {
			t.Fatalf("after the override, DerivedTier for `ls -la` = %d, want %d (DESTRUCTIVE) -- an override "+
				"written through the admin plane must reach the decision", after, models.ActionTierDestructive)
		}
	})

	t.Run("lowering_refused_against_the_builtin_baseline", func(t *testing.T) {
		// Write is INTERNAL_MODIFY in authz.DefaultCatalog and this tenant
		// has no tool_catalog row for it, so the baseline can only have come
		// from the built-in resolution.
		status, body := createOverride(t, "Write", models.ActionTierReadOnly)
		if status != http.StatusBadRequest {
			t.Fatalf("POST /v1/tier-overrides lowering Write to READ_ONLY = %d, want 400 -- its built-in "+
				"classification is INTERNAL_MODIFY; body: %s", status, body)
		}
		if !strings.Contains(body, "lower") {
			t.Errorf("refusal body = %q, want it to name the lowering (authz.ErrOverrideLowersTier)", body)
		}

		// Control: the same key, the other direction, accepted. Without this
		// the 400 above is equally consistent with "Write cannot be
		// overridden at all."
		raiseStatus, raiseBody := createOverride(t, "Write", models.ActionTierDestructive)
		if raiseStatus != http.StatusCreated {
			t.Fatalf("POST /v1/tier-overrides raising Write to DESTRUCTIVE = %d, want 201 -- the refusal "+
				"above has to be about direction, not about the key; body: %s", raiseStatus, raiseBody)
		}
	})

	t.Run("lowering_refused_against_the_catalog_baseline", func(t *testing.T) {
		const cataloged = "papProof6CatalogedTool"
		const uncataloged = "papProof6UncatalogedTool"

		// Neither name is in authz.DefaultCatalog and neither is a verb, so
		// the built-in resolution contributes nothing for either. The only
		// difference between them is this row.
		seedToolCatalogEntry(t, papTenant, cataloged, tierPtr(models.ActionTierDestructive), "", nil, nil)

		status, body := createOverride(t, cataloged, models.ActionTierInternalModify)
		if status != http.StatusBadRequest {
			t.Fatalf("POST /v1/tier-overrides lowering %s to INTERNAL_MODIFY = %d, want 400 -- the tenant's "+
				"own catalog entry beneath it is DESTRUCTIVE; body: %s", cataloged, status, body)
		}
		if !strings.Contains(body, "lower") {
			t.Errorf("refusal body = %q, want it to name the lowering (authz.ErrOverrideLowersTier)", body)
		}

		// Control: identical proposed tier, no catalog row. Accepted. This
		// is what attributes the refusal above to the catalog entry rather
		// than to the tier value or to anything else in the request.
		controlStatus, controlBody := createOverride(t, uncataloged, models.ActionTierInternalModify)
		if controlStatus != http.StatusCreated {
			t.Fatalf("POST /v1/tier-overrides setting %s to INTERNAL_MODIFY = %d, want 201 -- with no catalog "+
				"row beneath it, the identical tier is a raise; body: %s", uncataloged, controlStatus, controlBody)
		}
	})
}

// ---------------------------------------------------------------------------
// Phase 7 Task 6 -- resource labelling, through the real admin plane
// ---------------------------------------------------------------------------

// TestIntegration_PAPE2E_ResourceLabelRuleWriteBumpsEpochAndReachesTheNextDecision
// is proof 1 of the resource-labelling task, and it is proof 1 of THIS file
// re-run over a different resource: an operator authenticated by a real IdP
// writes a label rule through the real admin plane, the epoch bumps, and a
// different process -- the PDP, connected as a role with no write grant --
// classifies a resource by it on its very next call.
//
// # What was already proven, and why this is not that
//
// Task 3's TestIntegration_Live_ResourceLabelling (store_integration_test.go)
// already proves labelling live: an unmatched resource denies, the carve-out
// is honoured, the caller cannot choose its own label. Task 5's
// TestIntegration_PAPCRUD_ResourceLabelRuleRoundTrip already proves the CRUD
// and the epoch bump. Neither goes through the HTTP routes an operator
// actually uses -- both call internal/store's methods directly on papDB. So
// the five routes cmd/stratium-pap registers have been swept for ROLE
// refusals by proofs 2 and 3 above and never once exercised for what they DO.
// A route that 403s the right operators and writes the wrong row passes
// everything in this file today.
//
// # The four steps are the operator documentation's own narrative
//
// docs/pep.md's "Labelling resources for classification caps" tells an
// operator, in order: a configured cap denies everything unmatched, the
// empty-prefix catch-all is the fix, a longer prefix overrides it, and
// deleting the catch-all puts them back at the start. Each step below is one
// of those sentences, executed. If the documentation is wrong, this test is
// what goes red.
//
// Step 3 is also the raising direction of longest-prefix-wins, which nothing
// live covered: Task 3's proof2 has the longer prefix carrying the LOWER
// level (R6's carve-out), so an implementation that ranked by severity rather
// than by prefix length would fail there and an implementation that ranked by
// insertion order would pass it. Here the longer prefix is the MORE
// classified one and it still wins, over a rule written earlier.
//
// The sibling id is the control throughout. It is covered by the catch-all
// and by nothing else, so it holds still while the capped id moves -- which
// is what makes each transition attributable to the rule just written rather
// than to anything else reaching the tenant.
func TestIntegration_PAPE2E_ResourceLabelRuleWriteBumpsEpochAndReachesTheNextDecision(t *testing.T) {
	const tool = "papLabelProofReadTool"
	const principal = "pap-label-proof@example.com"
	// Both ids are fictional and local to this proof. The capped one sits
	// under the prefix step 3 writes; the sibling deliberately does not, so
	// only the catch-all ever covers it.
	const cappedID = "/pap-label-proof/reports/q3.pdf"
	const siblingID = "/pap-label-proof-elsewhere/notes.txt"

	papBlanketPermit(t, "pap-label-proof-blanket-permit")

	// Seeded inline rather than through papChainFixture, which hardcodes an
	// EMPTY cap map -- correct for every other proof here, and the one thing
	// this proof cannot have: CheckCap returns allow on len(caps) == 0 before
	// it ever looks at a label, so a capless delegation would allow all four
	// steps identically and prove nothing. DESTRUCTIVE max tier follows this
	// file's own convention, leaving the cap as the only axis that can deny.
	agentID := uuid.New()
	seedAgent(t, papTenant, agentID, "pap-label-proof-agent", models.TrustTierPlatformTrusted)
	rootID := uuid.New()
	root := seedDelegation(t, &models.Delegation{
		ID: rootID, TenantID: papTenant, UserID: principal, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"}, ResourceConstraints: map[string]string{},
		Purpose: "pap-label-proof", ExpiresAt: time.Now().Add(time.Hour),
		RootDelegationID: rootID, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})
	tok := mintToken(t, papPdpClient, root.ID)

	admin := papAccessToken(t, papAdminUser, papAdminPass)

	// The catalog row is a precondition, not the subject: a label may only be
	// resolved against an id the PDP extracted for itself (R1/R4), so without
	// a resource_field naming "path" nothing here could ever be labelled and
	// all four steps would deny identically. Written through the admin plane
	// too, because that is where an operator writes it.
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": tool, "action_tier": int(models.ActionTierReadOnly),
		"verb": "read", "resource_field": "path",
	}, nil)

	decide := func(id string) *pdpgrpc.DecideResponse {
		return papDecide(t, &pdpgrpc.DecideRequest{
			Token: tok, AgentId: agentID.String(), Subject: principal, Tool: tool,
			RawInput: `{"path":"` + id + `"}`,
		})
	}
	createRuleViaPAP := func(t *testing.T, prefix, hierarchy, level string) models.ResourceLabelRule {
		t.Helper()
		epochBefore, _ := readTenantEpoch(t, papTenant)
		var created models.ResourceLabelRule
		papJSON(t, papAddr, http.MethodPost, "/v1/resource-label-rules", admin, map[string]any{
			"prefix": prefix, "hierarchy": hierarchy, "level": level,
		}, &created)
		if created.ID == uuid.Nil {
			t.Fatalf("POST /v1/resource-label-rules (prefix %q) returned the zero UUID -- nothing was created", prefix)
		}
		if created.Prefix != prefix {
			t.Errorf("created rule prefix = %q, want %q", created.Prefix, prefix)
		}
		assertEpochBumped(t, papTenant, epochBefore)
		return created
	}

	// Step 1 -- R7's cliff, live and through the operator's own front door.
	// A configured cap with no rule covering the id denies, and this is the
	// state a tenant is in the moment they configure their first cap. The
	// documentation calls it a cliff because it reads as an outage; it is one
	// assertion here.
	for _, id := range []string{cappedID, siblingID} {
		before := decide(id)
		if before.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("with no label rule written, Decide() = %v (reason: %s), want DENY -- a configured cap "+
				"over an unmatched resource cannot be evaluated (R2/R7), and every step below reads the "+
				"CHANGE from this state", before.GetEffect(), before.GetReason())
		}
		if !strings.Contains(before.GetReason(), "cannot be evaluated") {
			t.Errorf("Reason = %q, want the uncheckable-cap wording rather than an ordinary cap violation "+
				"-- an operator acts differently on the two", before.GetReason())
		}
	}

	// Step 2 -- the catch-all is the documented remedy, and it works. One
	// POST with an empty prefix, and every id in the tenant is labelled.
	catchAll := createRuleViaPAP(t, "", "nato", "UNCLASSIFIED")
	for _, id := range []string{cappedID, siblingID} {
		after := decide(id)
		if after.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("after the catch-all was written, Decide() = %v (reason: %s), want ALLOW -- the empty "+
				"prefix matches every id, which is the whole of R7's answer to the cliff",
				after.GetEffect(), after.GetReason())
		}
	}

	// Step 3 -- longest prefix wins, raising. The rule written SECOND and
	// carrying the HIGHER level takes the subtree it names, and takes nothing
	// else: the sibling still allows under the catch-all.
	createRuleViaPAP(t, "/pap-label-proof/", "nato", "TOP-SECRET")

	raised := decide(cappedID)
	if raised.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("Decide() on the capped id = %v (reason: %s), want DENY -- the longer prefix labels it "+
			"TOP-SECRET, which exceeds the delegation's CONFIDENTIAL cap",
			raised.GetEffect(), raised.GetReason())
	}
	if !strings.Contains(raised.GetReason(), "TOP-SECRET") {
		t.Errorf("Reason = %q, want it to name TOP-SECRET -- the longer prefix has to be what decided, and "+
			"the uncheckable-cap wording here would mean nothing labelled it at all", raised.GetReason())
	}
	if control := decide(siblingID); control.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Decide() on the sibling id = %v (reason: %s), want ALLOW -- the new rule names one prefix, "+
			"so a sibling going dark means something broader than this write reached the decision",
			control.GetEffect(), control.GetReason())
	}

	// Step 4 -- deleting the catch-all un-labels everything only it covered.
	// This is the hazard Task 5's delete records after the fact and the
	// documentation warns about before it: the DELETE takes no confirmation
	// flag, and the sibling's allow becomes a denial with no further warning.
	//
	// The capped id is the other half, and it is why the delete's own audit
	// claim is narrow: a longer rule still covers its own subtree, so
	// "unlabelled" is not "the tenant went dark".
	epochBefore, _ := readTenantEpoch(t, papTenant)
	papJSON(t, papAddr, http.MethodDelete, "/v1/resource-label-rules/"+catchAll.ID.String(), admin, nil, nil)
	assertEpochBumped(t, papTenant, epochBefore)

	unlabelled := decide(siblingID)
	if unlabelled.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("after the catch-all was deleted, Decide() on the sibling id = %v (reason: %s), want DENY "+
			"-- nothing else covered it, so deleting the empty-prefix rule un-labelled it",
			unlabelled.GetEffect(), unlabelled.GetReason())
	}
	if !strings.Contains(unlabelled.GetReason(), "cannot be evaluated") {
		t.Errorf("Reason = %q, want the uncheckable-cap wording", unlabelled.GetReason())
	}
	if survived := decide(cappedID); !strings.Contains(survived.GetReason(), "TOP-SECRET") {
		t.Errorf("Decide() on the capped id after the delete: reason = %q, want it still labelled TOP-SECRET "+
			"by the longer rule -- deleting a catch-all does not un-label what another rule covers",
			survived.GetReason())
	}
}

// ---------------------------------------------------------------------------
// Proof 8
// ---------------------------------------------------------------------------

// TestIntegration_PAPE2E_ClassificationDenialReachableWithoutSQL is Task 8's
// proof (.superpowers/sdd/2026-08-21-classification-caps-api/task-8-brief.md):
// the denial string documented at docs/architecture.md:366 --
// `resource classification SECRET exceeds delegation cap CONFIDENTIAL in
// hierarchy "nato" (depth 0)` -- has never been reachable through a supported
// interface. This test reaches it through nothing but supported interfaces:
// two resource-label-rules and an agent's classification-caps are written
// through the real admin plane (papJSON, same as every proof above), and the
// delegation is minted through the real CreateDelegation RPC
// (internal/pdpgrpc/delegation.go), never seedDelegation -- seedDelegation
// would let the test set ClassificationCaps itself, which is exactly the one
// thing this proof cannot assume: that a ROOT delegation inherits its cap
// from the agent is Task 4's own claim, so the delegation's caps are read
// back afterward through GET /v1/delegations rather than trusted.
func TestIntegration_PAPE2E_ClassificationDenialReachableWithoutSQL(t *testing.T) {
	const tool = "papCapsProofReadTool"
	const principal = "pap-caps-proof@example.com"
	const allowedID = "/tmp/pap-caps-proof/notes.txt"
	const deniedID = "/secret/pap-caps-proof/plans.txt"

	papBlanketPermit(t, "pap-caps-proof-blanket-permit")
	admin := papAccessToken(t, papAdminUser, papAdminPass)

	// The catalog row: without a resource_field naming "path", the PDP can
	// never resolve either id to a label and every Decide below would deny
	// identically -- see proof 7's own catalog row for the same reason.
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": tool, "action_tier": int(models.ActionTierReadOnly),
		"verb": "read", "resource_field": "path",
	}, nil)

	// Both rules are cleaned up unconditionally: resource_label_rules has a
	// UNIQUE(tenant_id, prefix) constraint (internal/store/resource_label.go),
	// so a prefix "" left behind by a failed or repeated run would 409 the
	// next one. Proof 7 above cleans up its own catch-all for the same reason.
	createRule := func(prefix, hierarchy, level string) models.ResourceLabelRule {
		t.Helper()
		var created models.ResourceLabelRule
		papJSON(t, papAddr, http.MethodPost, "/v1/resource-label-rules", admin, map[string]any{
			"prefix": prefix, "hierarchy": hierarchy, "level": level,
		}, &created)
		if created.ID == uuid.Nil {
			t.Fatalf("POST /v1/resource-label-rules (prefix %q) returned the zero UUID -- nothing was created", prefix)
		}
		// context.Background(), not t.Context(): a Cleanup func runs AFTER
		// the test's own context is already canceled (testing.T.Context's own
		// doc comment), so a papJSON call here would fail on a canceled
		// context rather than actually deleting anything.
		t.Cleanup(func() {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
				"http://"+papAddr+"/v1/resource-label-rules/"+created.ID.String(), nil)
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+admin)
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
		})
		return created
	}
	// The catch-all has to exist BEFORE the caps write below: SetAgentClassificationCaps
	// refuses an uncovered hierarchy (ErrNoCatchAllRule) unless one already covers it.
	createRule("", "nato", "UNCLASSIFIED")
	createRule("/secret/", "nato", "SECRET")

	// The agent: an empty allowed_tools is unrestricted (models.Agent.HasTool),
	// and platform-trusted so nothing about its own trust tier can be what
	// denies below -- the cap is meant to be the only axis that can.
	var agent models.Agent
	papJSON(t, papAddr, http.MethodPost, "/v1/agents", admin, map[string]any{
		"name": "pap-caps-proof-agent", "provider": "anthropic", "model_id": "claude",
		"trust_tier": int(models.TrustTierPlatformTrusted), "enabled": true, "allowed_tools": []string{},
	}, &agent)
	if agent.ID == uuid.Nil {
		t.Fatal("POST /v1/agents returned the zero UUID -- nothing was created")
	}

	// Task 7's route: the ceiling only an operator can set, through the front
	// door it now has.
	var view models.AgentCapsView
	papJSON(t, papAddr, http.MethodPut, "/v1/agents/"+agent.ID.String()+"/classification-caps", admin,
		map[string]any{"classification_caps": map[string]string{"nato": "CONFIDENTIAL"}}, &view)
	if got := view.ClassificationCaps["nato"]; got != "CONFIDENTIAL" {
		t.Fatalf("PUT classification-caps returned nato=%q, want CONFIDENTIAL", got)
	}

	// The root delegation: issued through the real CreateDelegation RPC, the
	// same path a delegating agent uses in production, so Task 4's copy from
	// the agent row is what actually runs here -- see this test's own doc
	// comment for why seedDelegation cannot stand in for this step.
	created, err := papPdpClient.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
		Subject: principal, AgentId: agent.ID.String(),
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: int32(models.ActionTierReadOnly), Tools: []string{tool},
		},
		Purpose: "pap-caps-proof", TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateDelegation: %v", err)
	}
	if created.GetDelegationId() == "" {
		t.Fatal("CreateDelegation returned no delegation_id")
	}

	// Read the delegation back through the admin plane, proving the agent's
	// cap actually landed on the delegation the RPC issued rather than
	// merely that the RPC succeeded.
	var delegations []models.Delegation
	papJSON(t, papAddr, http.MethodGet, "/v1/delegations", admin, nil, &delegations)
	var deleg *models.Delegation
	for i := range delegations {
		if delegations[i].ID.String() == created.GetDelegationId() {
			deleg = &delegations[i]
			break
		}
	}
	if deleg == nil {
		t.Fatalf("GET /v1/delegations did not list %s", created.GetDelegationId())
	}
	if got := deleg.ClassificationCaps["nato"]; got != "CONFIDENTIAL" {
		t.Fatalf("delegation classification_caps[nato] = %q, want CONFIDENTIAL -- Task 4's inheritance did not run",
			got)
	}

	decide := func(id string) *pdpgrpc.DecideResponse {
		return papDecide(t, &pdpgrpc.DecideRequest{
			Token: created.GetToken(), AgentId: agent.ID.String(), Subject: principal, Tool: tool,
			RawInput: `{"path":"` + id + `"}`,
		})
	}

	allow := decide(allowedID)
	if allow.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Decide(%s) = %v (reason: %s), want ALLOW -- UNCLASSIFIED under a CONFIDENTIAL cap",
			allowedID, allow.GetEffect(), allow.GetReason())
	}

	deny := decide(deniedID)
	if deny.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("Decide(%s) = %v (reason: %s), want DENY -- SECRET exceeds a CONFIDENTIAL cap",
			deniedID, deny.GetEffect(), deny.GetReason())
	}
	const want = `resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)`
	if deny.GetReason() != want {
		t.Errorf("Reason = %q, want %q -- this exact string is documented at docs/architecture.md:366 as "+
			"unreachable through any supported interface; this proof is what makes that false",
			deny.GetReason(), want)
	}
}

// papE2EEnvError formats TestMain's failure (store_integration_test.go's
// runTestMain) when one of Phase 14 Task 8's PAP environment variables is
// missing.
func papE2EEnvError(missing []string) error {
	return fmt.Errorf("%s must be set — run via `make integration`, not `go test` directly",
		strings.Join(missing, ", "))
}
