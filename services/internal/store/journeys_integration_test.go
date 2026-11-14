//go:build integration

// journeys_integration_test.go is the live half of the validation harness for
// docs/validation-journeys.md. Its pure counterpart is
// internal/authz/journeys_test.go, which pins the same journeys' mechanisms
// in milliseconds without a stack; this file proves the whole path end to
// end, through real HTTP to a real containerized stratium-pap, a real
// CreateDelegation RPC, and a real containerized PDP.
//
// Read the unit file first. It explains why several of these are
// CHARACTERIZATION tests that assert behaviour the document argues is wrong,
// and what a WHEN THIS FAILS marker means when one breaks.
//
// # Tenancy
//
// These run against tenant-pap-e2e-integration (papTenant/papPdpClient/
// papAddr), not the resource tenant, for one hard reason and one soft one:
//
//   - Hard: store_integration_test.go:2293 asserts resourceTenant has ZERO
//     tool_catalog rows at the moment its own subtest runs, and Go orders
//     test files lexically -- "journeys" sorts before "store", so a catalog
//     row seeded here would run first and break that assertion. The same
//     constraint is already recorded at store_integration_test.go:2464.
//   - Soft: the PAP tenant is where classification caps are already written
//     through the front door (TestIntegration_PAPE2E_ClassificationDenial
//     ReachableWithoutSQL), so these proofs reuse an established shape rather
//     than inventing a second one.
//
// # Tool names and rules
//
// Every tool name below is prefixed `journey` and touched by no other proof
// in this package: tool_catalog is keyed per tenant, not per test, so a
// shared name silently couples two tests through the database. The catch-all
// label rule is created and unconditionally deleted for the same reason
// proof 7 and the caps proof in pap_e2e_integration_test.go do it --
// resource_label_rules has a UNIQUE(tenant_id, prefix) constraint, so a ""
// prefix left behind would 409 the next run. Nothing in this package calls
// t.Parallel(), so create-assert-delete inside one test is safe.
package store_test

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/pkg/models"
)

// journeyCatchAll creates the empty-prefix rule these proofs need and
// registers its unconditional removal. Returned so a caller can assert
// against it; ignored by most.
//
// The catch-all is not incidental scaffolding here -- it is load-bearing for
// J1's central claim. "Add a catch-all rule" is the documented fix for an
// unlabelled resource, and J1 asserts that fix cannot rescue a fieldless
// tool. A proof that ran without one would be asserting something much
// weaker (that an unconfigured tenant denies), which nobody doubts.
func journeyCatchAll(t *testing.T, admin, hierarchy, level string) {
	t.Helper()
	journeyRule(t, admin, "", hierarchy, level)
}

// journeyRule creates one label rule and registers its unconditional removal.
// Prefixes are chosen per test and cleaned up because resource_label_rules has
// a UNIQUE(tenant_id, prefix) constraint -- a prefix left behind by a failed
// run 409s the next one.
func journeyRule(t *testing.T, admin, prefix, hierarchy, level string) {
	t.Helper()
	var created models.ResourceLabelRule
	papJSON(t, papAddr, http.MethodPost, "/v1/resource-label-rules", admin, map[string]any{
		"prefix": prefix, "hierarchy": hierarchy, "level": level,
	}, &created)
	if created.ID == uuid.Nil {
		t.Fatalf("POST /v1/resource-label-rules(%q) returned the zero UUID -- nothing was created", prefix)
	}
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
}

// journeyAgent registers a PLATFORM_TRUSTED agent with an unrestricted tool
// list. Both choices exist to remove every axis but the one under test: a
// lower trust tier or a populated allowlist could deny on the agent leg, and
// a proof about classification must not be able to pass for that reason.
func journeyAgent(t *testing.T, admin, name string) models.Agent {
	t.Helper()
	var agent models.Agent
	papJSON(t, papAddr, http.MethodPost, "/v1/agents", admin, map[string]any{
		"name": name, "provider": "anthropic", "model_id": "claude",
		"trust_tier": int(models.TrustTierPlatformTrusted), "enabled": true,
		"allowed_tools": []string{},
	}, &agent)
	if agent.ID == uuid.Nil {
		t.Fatal("POST /v1/agents returned the zero UUID -- nothing was created")
	}
	return agent
}

// ---------------------------------------------------------------------------
// J1 — a classification cap denies every fieldless tool call, permanently
// ---------------------------------------------------------------------------

// TestIntegration_Journey1_AClassificationCapDeniesEveryFieldlessToolCall is
// the live proof of J1, and the strongest form of it available: the cap is
// the most PERMISSIVE one the hierarchy allows, a catch-all label rule is in
// place, the agent is platform-trusted with an unrestricted tool list, and
// the tool is registered at READ_ONLY under a READ_ONLY delegation -- every
// other axis that could deny has been removed. It still denies, and it denies
// for a reason no operator action can clear.
//
// The four assertions, in the order they build:
//
//  1. The FIELDED tool allows. This is what makes the rest a statement about
//     fieldless tools rather than about a broken fixture.
//  2. The FIELDLESS tool denies, with the uncheckable-cap wording -- not the
//     exceeds-cap wording. "We could not evaluate this" must never be
//     recorded as "this was over the line."
//  3. The catch-all rule that fixes an unlabelled FIELDED resource does not
//     fix this one. labelResource returns at internal/pdpgrpc/label.go:85
//     when the extracted id is empty, BEFORE any rule is consulted, so
//     resolution never runs and no rule can ever match.
//  4. Removing the cap and issuing a FRESH delegation allows the same call.
//     This isolates the cap as the sole cause, and incidentally proves caps
//     are copied at issuance rather than read live -- the existing
//     delegation keeps denying.
//
// WHEN THIS FAILS at assertion 2: fieldless tools gained a resource identity
// (fix #1 in docs/validation-journeys.md §5). Update J1 and the §6 scope
// statement -- the "caps and shell access are mutually exclusive" claim is
// no longer true, and it is the load-bearing sentence in §6.
func TestIntegration_Journey1_AClassificationCapDeniesEveryFieldlessToolCall(t *testing.T) {
	const fieldedTool = "journeyFieldedReadTool"
	const fieldlessTool = "journeyFieldlessTool"
	const principal = "journey1-proof@example.com"
	const resourceID = "/tmp/journey1/notes.txt"

	papBlanketPermit(t, "journey1-blanket-permit")
	admin := papAccessToken(t, papAdminUser, papAdminPass)

	// The control: a resource_field, so the PDP can extract an id and the
	// catch-all can label it.
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": fieldedTool, "action_tier": int(models.ActionTierReadOnly),
		"verb": "read", "resource_field": "path",
	}, nil)

	// The subject: the shape Bash, WebFetch, WebSearch and TodoWrite all ship
	// with in deploy/seed/tool-catalog-claude-code.sql -- a fixed tier and NO
	// resource_field. Registered at READ_ONLY so its tier can never be what
	// denies.
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": fieldlessTool, "action_tier": int(models.ActionTierReadOnly),
		"verb": "read",
	}, nil)

	// UNCLASSIFIED is the floor of `nato`, so the fielded resource below is as
	// far under the cap as it is possible to be.
	journeyCatchAll(t, admin, "nato", "UNCLASSIFIED")

	agent := journeyAgent(t, admin, "journey1-proof-agent")

	// TOP-SECRET is the CEILING of `nato`: nothing in the hierarchy outranks
	// it. A denial under this cap therefore cannot mean "the resource was too
	// sensitive" -- it can only mean the cap could not be evaluated at all.
	// That is what makes this a proof about caps existing rather than about
	// this resource's level.
	var view models.AgentCapsView
	papJSON(t, papAddr, http.MethodPut, "/v1/agents/"+agent.ID.String()+"/classification-caps", admin,
		map[string]any{"classification_caps": map[string]string{"nato": "TOP-SECRET"}}, &view)
	if got := view.ClassificationCaps["nato"]; got != "TOP-SECRET" {
		t.Fatalf("PUT classification-caps returned nato=%q, want TOP-SECRET", got)
	}

	capped := journeyDelegation(t, principal, agent.ID, "journey1 capped", fieldedTool, fieldlessTool)

	decide := func(token, tool, rawInput string) *pdpgrpc.DecideResponse {
		return papDecide(t, &pdpgrpc.DecideRequest{
			Token: token, AgentId: agent.ID.String(), Subject: principal,
			Tool: tool, RawInput: rawInput,
		})
	}

	// 1. The fielded tool allows: extraction produces an id, the catch-all
	//    labels it UNCLASSIFIED, and UNCLASSIFIED is under any nato cap.
	fielded := decide(capped.GetToken(), fieldedTool, `{"path":"`+resourceID+`"}`)
	if fielded.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Decide(%s) = %v (%s), want ALLOW -- if the control denies, the fixture is broken "+
			"and every assertion below is meaningless", fieldedTool, fielded.GetEffect(), fielded.GetReason())
	}

	// 2 and 3. The fieldless tool denies, under the same cap, the same
	//    catch-all, the same agent, the same delegation, at the same tier.
	fieldless := decide(capped.GetToken(), fieldlessTool, `{"path":"`+resourceID+`"}`)
	t.Logf("fieldless tool under cap nato=TOP-SECRET with a catch-all rule in place -> effect=%s reason=%q",
		fieldless.GetEffect(), fieldless.GetReason())
	if fieldless.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("Decide(%s) = %v, want DENY. A fieldless tool now satisfies a classification cap -- "+
			"fix #1 from docs/validation-journeys.md §5 has landed. Update J1 and the §6 scope statement",
			fieldlessTool, fieldless.GetEffect())
	}
	if !strings.Contains(fieldless.GetReason(), "cannot be evaluated") {
		t.Errorf("Reason = %q, want the uncheckable-cap wording. An audit trail has to distinguish "+
			"\"we could not check\" from \"we checked and it was over the line\"", fieldless.GetReason())
	}
	if fieldless.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q", fieldless.GetDeniedLeg(), "delegation")
	}
	// The identical raw_input reached both calls. Only the catalog row's
	// resource_field differed, which is the whole finding.
	if fielded.GetEffect() == fieldless.GetEffect() {
		t.Fatal("the fielded and fieldless tools decided identically on identical input; " +
			"this proof can no longer distinguish them")
	}

	// 4. Remove the cap; the SAME call on a FRESH delegation allows.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete,
		"http://"+papAddr+"/v1/agents/"+agent.ID.String()+"/classification-caps", nil)
	if err != nil {
		t.Fatalf("build DELETE classification-caps: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE classification-caps: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("DELETE classification-caps status = %d, want 2xx", resp.StatusCode)
	}

	// The already-issued delegation still carries the cap: caps are copied at
	// issuance, never read live (internal/pdpgrpc/delegation.go's own comment
	// on ClassificationCaps).
	stillDenied := decide(capped.GetToken(), fieldlessTool, `{"path":"`+resourceID+`"}`)
	if stillDenied.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Errorf("the pre-existing delegation stopped denying after the AGENT's caps were removed; "+
			"caps are supposed to be copied at issuance, not read live (effect=%v)", stillDenied.GetEffect())
	}

	uncapped := journeyDelegation(t, principal, agent.ID, "journey1 uncapped", fieldedTool, fieldlessTool)
	allowed := decide(uncapped.GetToken(), fieldlessTool, `{"path":"`+resourceID+`"}`)
	if allowed.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Decide(%s) on an uncapped delegation = %v (%s), want ALLOW -- if this denies, the "+
			"cap was not the only thing denying and J1's diagnosis is wrong",
			fieldlessTool, allowed.GetEffect(), allowed.GetReason())
	}
	t.Log("the same fieldless call allows the moment no cap is configured: the cap is the sole cause, " +
		"and no label rule can satisfy it")
}

// ---------------------------------------------------------------------------
// §4.3 — the dimension that would fix §4.1 is reachable and binds
// ---------------------------------------------------------------------------

// TestIntegration_Journey43_ResourceConstraintsAreEnforcedAndReachable is the
// live proof of §4.3, in two halves that only mean something together:
//
//   - Enforcement works. A delegation carrying a resource constraint denies a
//     request whose resource does not satisfy it, with a reason naming the
//     key. This half is seeded with SQL, exercising the generic exact-match
//     key path directly rather than going through a live CreateDelegation
//     call -- the next test, and the second half of this one, cover that.
//   - A supported path can create one. `PUT /v1/agents/{id}/resource-
//     constraints` (2026-08-28) sets the scope, CreateDelegation copies it
//     onto the root delegation at issuance (internal/pdpgrpc/delegation.go),
//     and GET /v1/delegations reads it straight back.
//
// Either half alone is unremarkable. Together they say the mechanism §4.1
// wanted -- "yes, but only there" -- is now fully implemented, fully
// enforced, AND reachable through the API a real caller uses.
//
// WHEN THIS FAILS at the second half: the write path was removed or broken.
// Update §4.3 and §4.4 -- the "the API cannot express it" sentence is the one
// that changes back.
func TestIntegration_Journey43_ResourceConstraintsAreEnforcedAndReachable(t *testing.T) {
	const tool = "journeyConstraintTool"
	const principal = "journey43-proof@example.com"

	papBlanketPermit(t, "journey43-blanket-permit")
	admin := papAccessToken(t, papAdminUser, papAdminPass)

	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": tool, "action_tier": int(models.ActionTierReadOnly),
		"verb": "read", "resource_field": "path",
	}, nil)

	agent := journeyAgent(t, admin, "journey43-proof-agent")

	t.Run("a constraint that exists is enforced", func(t *testing.T) {
		// Seeded directly, because this shape cannot be created any other
		// way -- which is precisely what the second subtest proves.
		id := uuid.New()
		constrained := seedDelegation(t, &models.Delegation{
			ID: id, TenantID: papTenant, UserID: principal, AgentID: agent.ID,
			ApprovedTools: []string{tool}, MaxActionTier: models.ActionTierReadOnly,
			ClassificationCaps:  map[string]string{},
			ResourceConstraints: map[string]string{"id": "/workspace/allowed.txt"},
			Purpose:             "journey43 constrained", ExpiresAt: time.Now().Add(time.Hour),
			RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agent.ID},
		})
		token := mintToken(t, papPdpClient, constrained.ID)

		matching := papDecide(t, &pdpgrpc.DecideRequest{
			Token: token, AgentId: agent.ID.String(), Subject: principal, Tool: tool,
			RawInput: `{"path":"/workspace/allowed.txt"}`,
		})
		if matching.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Decide(matching resource) = %v (%s), want ALLOW",
				matching.GetEffect(), matching.GetReason())
		}

		other := papDecide(t, &pdpgrpc.DecideRequest{
			Token: token, AgentId: agent.ID.String(), Subject: principal, Tool: tool,
			RawInput: `{"path":"/etc/shadow"}`,
		})
		if other.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Decide(non-matching resource) = %v, want DENY -- a resource constraint that "+
				"does not bind is a security regression, not a documentation update", other.GetEffect())
		}
		if !strings.Contains(other.GetReason(), "resource constraint") {
			t.Errorf("Reason = %q, want it to name the constraint", other.GetReason())
		}
		t.Logf("a scope-limited delegation works exactly as §4.4 wants: %s", other.GetReason())
	})

	t.Run("and a supported path can create one", func(t *testing.T) {
		// The write has to land BEFORE CreateDelegation: a root delegation
		// copies the agent's CURRENT resource_constraints at issuance
		// (internal/pdpgrpc/delegation.go), never reads them live.
		var view models.AgentConstraintsView
		papJSON(t, papAddr, http.MethodPut, "/v1/agents/"+agent.ID.String()+"/resource-constraints", admin,
			map[string]any{"resource_constraints": map[string]string{models.ResourceIDPrefixKey: "/workspace/"}},
			&view)
		if got := view.ResourceConstraints[models.ResourceIDPrefixKey]; got != "/workspace/" {
			t.Fatalf("PUT resource-constraints returned %s=%q, want %q",
				models.ResourceIDPrefixKey, got, "/workspace/")
		}

		created, err := papPdpClient.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
			Subject: principal, AgentId: agent.ID.String(),
			RequestedScope: &pdpgrpc.RequestedScope{
				MaxActionTier: int32(models.ActionTierReadOnly), Tools: []string{tool},
			},
			Purpose: "journey43 via the supported path", TtlSeconds: 3600,
		})
		if err != nil {
			t.Fatalf("CreateDelegation: %v", err)
		}

		var delegations []models.Delegation
		papJSON(t, papAddr, http.MethodGet, "/v1/delegations", admin, nil, &delegations)
		var got *models.Delegation
		for i := range delegations {
			if delegations[i].ID.String() == created.GetDelegationId() {
				got = &delegations[i]
				break
			}
		}
		if got == nil {
			t.Fatalf("GET /v1/delegations did not list %s", created.GetDelegationId())
		}
		if gotPrefix := got.ResourceConstraints[models.ResourceIDPrefixKey]; gotPrefix != "/workspace/" {
			t.Fatalf("resource_constraints[%s] = %q, want %q. A delegation minted through the only "+
				"supported path no longer carries the agent's scope -- fix #2 from "+
				"docs/validation-journeys.md §5 has regressed. Update §4.3 and §4.4",
				models.ResourceIDPrefixKey, gotPrefix, "/workspace/")
		}
		t.Log("a delegation from the supported path carries the scope PUT /v1/agents/{id}/" +
			"resource-constraints set on the agent, copied at issuance")
	})
}

// TestIntegration_Journey43_AScopedDelegationConstrainsEveryPath is the live
// proof that an id_prefix scope, set through the route the previous test
// proves reachable, actually binds -- for a catalogued fielded tool AND for a
// shell command naming several paths at once. It follows
// TestIntegration_Journey1_AShellCommandIsLabelledByEveryPathItNames's
// structure exactly, for the identical reason: a shell call's resource
// identity is a SET, and the decoy subtest is the one that proves the fold
// takes every member rather than the first or the last.
//
// The scope is set on the agent BEFORE CreateDelegation runs, because a root
// delegation copies resource_constraints at issuance and never reads them
// live (internal/pdpgrpc/delegation.go) -- the same ordering requirement the
// previous test's rewritten subtest documents.
//
// WHEN THIS FAILS on the decoy case: the fold stopped requiring every id to
// satisfy the prefix. That is a security regression, not a documentation
// update -- a benign path in a compound command would buy scope for a
// command that also reads outside it.
func TestIntegration_Journey43_AScopedDelegationConstrainsEveryPath(t *testing.T) {
	const readTool = "journeyScopeReadTool"
	const shellTool = "journeyScopeShellTool"
	const principal = "journey43-scope@example.com"
	const prefix = "/workspace/"

	papBlanketPermit(t, "journey43-scope-blanket-permit")
	admin := papAccessToken(t, papAdminUser, papAdminPass)

	// A fielded tool: extraction produces a single id straight from the
	// request, no fold involved.
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": readTool, "action_tier": int(models.ActionTierReadOnly),
		"verb": "read", "resource_field": "path",
	}, nil)

	// Bash's exact catalog shape: a command_field, no fixed tier, no
	// resource_field -- see TestIntegration_Journey1_AShellCommandIsLabelled
	// ByEveryPathItNames's own comment on why this is the shape that matters.
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": shellTool, "verb": "execute", "command_field": "command",
	}, nil)
	// This row has a NULL action_tier, which the migration-boundary proof
	// cannot tolerate anywhere in the table. See the helper's own comment.
	journeyCleanupNullTierTool(t, papTenant, shellTool)

	agent := journeyAgent(t, admin, "journey43-scope-agent")

	// The scope has to land before CreateDelegation: a root delegation copies
	// the agent's CURRENT resource_constraints at issuance, never reads them
	// live.
	var view models.AgentConstraintsView
	papJSON(t, papAddr, http.MethodPut, "/v1/agents/"+agent.ID.String()+"/resource-constraints", admin,
		map[string]any{"resource_constraints": map[string]string{models.ResourceIDPrefixKey: prefix}}, &view)
	if got := view.ResourceConstraints[models.ResourceIDPrefixKey]; got != prefix {
		t.Fatalf("PUT resource-constraints returned %s=%q, want %q", models.ResourceIDPrefixKey, got, prefix)
	}

	// INTERNAL_MODIFY, not READ_ONLY: the decoy case below is a compound
	// command and rates tier 2 (reCompound in internal/authz/tier.go). A
	// READ_ONLY delegation would deny it on the TIER and prove nothing about
	// the constraint.
	delegation := journeyDelegationAtTier(t, principal, agent.ID, "journey43 scoped",
		models.ActionTierInternalModify, readTool, shellTool)

	decide := func(tool, rawInput string) *pdpgrpc.DecideResponse {
		return papDecide(t, &pdpgrpc.DecideRequest{
			Token: delegation.GetToken(), AgentId: agent.ID.String(), Subject: principal,
			Tool: tool, RawInput: rawInput,
		})
	}

	t.Run("a fielded call inside the scope allows", func(t *testing.T) {
		got := decide(readTool, `{"path":"/workspace/a.txt"}`)
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Decide = %v (%s), want ALLOW", got.GetEffect(), got.GetReason())
		}
	})

	t.Run("a fielded call outside the scope denies, naming the id", func(t *testing.T) {
		got := decide(readTool, `{"path":"/etc/shadow"}`)
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Decide = %v, want DENY -- /etc/shadow is outside %s", got.GetEffect(), prefix)
		}
		if !strings.Contains(got.GetReason(), "/etc/shadow") {
			t.Errorf("Reason = %q, want it to name the id outside scope", got.GetReason())
		}
	})

	t.Run("a shell command naming only an in-scope path allows", func(t *testing.T) {
		got := decide(shellTool, `{"command":"cat /workspace/a.txt"}`)
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Decide = %v (%s), want ALLOW -- the single path this command names is inside %s",
				got.GetEffect(), got.GetReason(), prefix)
		}
	})

	t.Run("a decoy path cannot buy scope for the one that is out of it", func(t *testing.T) {
		got := decide(shellTool, `{"command":"cat /workspace/a.txt; cat /etc/shadow"}`)
		t.Logf("decoy command -> effect=%s reason=%q", got.GetEffect(), got.GetReason())
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Decide = %v, want DENY. A benign in-scope path prepended to an out-of-scope one "+
				"just bought scope for a command that still reads outside it -- this is the decoy case "+
				"and it is a SECURITY REGRESSION", got.GetEffect())
		}
		if !strings.Contains(got.GetReason(), "/etc/shadow") {
			t.Errorf("Reason = %q, want it to name the out-of-scope id -- every id must be checked, "+
				"not just the first", got.GetReason())
		}
	})

	t.Run("a traversal segment denies, naming the segment", func(t *testing.T) {
		got := decide(shellTool, `{"command":"cat /workspace/../etc/shadow"}`)
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Decide = %v, want DENY -- a \"..\" segment cannot be checked against a prefix "+
				"without resolving it, and resolving it is not this function's job", got.GetEffect())
		}
		if !strings.Contains(got.GetReason(), "..") {
			t.Errorf("Reason = %q, want it to name the %q segment", got.GetReason(), "..")
		}
	})

	t.Run("a command naming no path denies as unevaluable", func(t *testing.T) {
		got := decide(shellTool, `{"command":"npm test"}`)
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Decide = %v, want DENY -- a command naming no resource has nothing to check "+
				"against a scope, and unevaluable must not read as satisfied", got.GetEffect())
		}
		if !strings.Contains(got.GetReason(), "cannot be evaluated") {
			t.Errorf("Reason = %q, want the uncheckable-constraint wording", got.GetReason())
		}
	})
}

// ---------------------------------------------------------------------------
// J10 — concurrent decisions on one tenant
// ---------------------------------------------------------------------------

// journeyConcurrency is how many Decide calls J10 fires at once. Deliberately
// modest by default: this probe can legitimately FAIL, and a CI run should
// not become flaky on a finding that is already written down. Raise it with
// STRATIUM_IT_JOURNEY_CONCURRENCY to run the real load validation J10 asks
// for -- the number that matters is the level at which collisions START.
const journeyConcurrency = 8

// TestIntegration_Journey10_ConcurrentDecideDoesNotDenyOnAnAuditCollision is
// J10's probe, and it is a REGRESSION GUARD rather than a prediction of
// failure -- the distinction matters for reading a failure correctly.
//
// Every Decide appends to the tenant's hash-linked audit chain, and two
// writers that both read the same chain tail both link to it, whereupon
// UNIQUE(tenant_id, prev_hash) rejects one: store.ErrConcurrentAppend
// (internal/store/audit.go:238) -> gRPC Aborted (internal/pdpgrpc/
// server.go:786) -> a transport error every PEP surface turns into a DENIAL,
// retried by nothing (the blind reissue fires only on an EFFECT_DENY
// *response*). That failure was real, and was measured at "30-70% denials for
// a single tenant under ten concurrent decisions."
//
// It is already fixed. appendAuditTx takes pg_advisory_xact_lock(hashtext(
// tenant_id)) before reading the tail (audit.go:199), held for the
// transaction and released on commit, rollback, or process death. Under that
// lock the collision is unreachable, and this test asserts it stays that way:
// a collision observed here means the lock was bypassed by a new append path
// or removed outright.
//
// What J10 actually needs measuring is the COST of that fix. Every decision
// for a tenant queues behind one lock and one audit write, which bounds a
// tenant's decision throughput -- so this test logs sustained decisions/sec
// alongside the collision count. audit.go:197 names the escape hatch if that
// ceiling ever binds: batch appends behind the lock, never remove it.
func TestIntegration_Journey10_ConcurrentDecideDoesNotDenyOnAnAuditCollision(t *testing.T) {
	const tool = "journeyConcurrencyTool"
	const principal = "journey10-proof@example.com"

	concurrency := journeyConcurrency
	if raw := os.Getenv("STRATIUM_IT_JOURNEY_CONCURRENCY"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			t.Fatalf("STRATIUM_IT_JOURNEY_CONCURRENCY = %q, want a positive integer", raw)
		}
		concurrency = parsed
	}

	papBlanketPermit(t, "journey10-blanket-permit")
	admin := papAccessToken(t, papAdminUser, papAdminPass)
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": tool, "action_tier": int(models.ActionTierReadOnly),
		"verb": "read", "resource_field": "path",
	}, nil)

	agent := journeyAgent(t, admin, "journey10-proof-agent")
	delegation := journeyDelegation(t, principal, agent.ID, "journey10", tool)

	type outcome struct {
		effect pdpgrpc.Effect
		code   codes.Code
		err    error
	}
	results := make([]outcome, concurrency)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release them together; a staggered start proves nothing
			resp, err := papPdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
				Token: delegation.GetToken(), AgentId: agent.ID.String(), Subject: principal,
				Tool: tool, RawInput: `{"path":"/tmp/journey10/` + strconv.Itoa(i) + `.txt"}`,
			})
			if err != nil {
				results[i] = outcome{code: status.Code(err), err: err}
				return
			}
			results[i] = outcome{effect: resp.GetEffect()}
		}(i)
	}
	began := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(began)

	var aborted, otherErrors, decisions int
	for _, r := range results {
		switch {
		case r.err == nil:
			decisions++
		case r.code == codes.Aborted:
			aborted++
			t.Logf("audit-chain collision: %v", r.err)
		default:
			otherErrors++
			t.Logf("unexpected transport error: %v", r.err)
		}
	}
	t.Logf("%d concurrent Decide calls in %s -> %d decisions, %d audit-chain collisions, %d other "+
		"errors (%.1f decisions/sec sustained for this tenant)",
		concurrency, elapsed.Round(time.Millisecond), decisions, aborted, otherErrors,
		float64(concurrency)/elapsed.Seconds())

	if aborted > 0 {
		t.Fatalf("%d of %d concurrent decisions failed with Aborted on the audit chain tail. "+
			"Every one is a legitimate tool call DENIED because another agent decided at the same "+
			"instant. This is supposed to be UNREACHABLE: appendAuditTx serializes appends behind "+
			"pg_advisory_xact_lock (internal/store/audit.go:199), added after this exact failure was "+
			"measured at 30-70%% denials. Either that lock was removed, or a new append path was "+
			"added that does not take it. Do not fix this with a retry -- restore the lock",
			aborted, concurrency)
	}
	if otherErrors > 0 {
		t.Fatalf("%d of %d concurrent decisions failed with a non-Aborted transport error",
			otherErrors, concurrency)
	}
}

// journeyCleanupNullTierTool removes one tool_catalog row by name, and is
// REQUIRED of any test here that seeds a NULL action_tier row.
//
// A NULL action_tier is the one value migrations/000014_tool_catalog_nullable_
// tier's DOWN migration cannot coexist with anywhere in the TABLE -- not merely
// within the seeding tenant's own rows -- and TestEndToEnd's
// chain_verifies_across_the_migration_boundary subtest walks every migration
// down and back up against this same shared database. Leaving one behind fails
// that subtest with `column "action_tier" ... contains null values`, and then
// every tenant_epoch proof after it, because the walk leaves the schema
// mid-flight. Observed, on the run that added the shell proof.
//
// Deliberately narrower than catalog_integration_test.go's own
// cleanupToolCatalogRows, which deletes every row for a tenant: papTenant is
// shared with the pap_e2e proofs and with the other journeys in this file, so
// wiping it wholesale would be a second coupling in place of the first.
//
// context.Background(), not t.Context(): a test's context is already cancelled
// by the time its Cleanup functions run.
func journeyCleanupNullTierTool(t *testing.T, tenant, toolName string) {
	t.Helper()
	t.Cleanup(func() {
		tx, err := testDB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Errorf("cleanup: begin tx: %v", err)
			return
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(context.Background(),
			`SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Errorf("cleanup: set_config app.tenant_id: %v", err)
			return
		}
		if _, err := tx.ExecContext(context.Background(),
			`DELETE FROM tool_catalog WHERE tenant_id = $1 AND tool_name = $2`, tenant, toolName); err != nil {
			t.Errorf("cleanup: delete tool_catalog row %s: %v", toolName, err)
			return
		}
		if err := tx.Commit(); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})
}

// TestIntegration_Journey1_AShellCommandIsLabelledByEveryPathItNames is the
// live proof that J1 is closed for command-field tools, and the proof that it
// was closed SAFELY.
//
// The last case is the whole design. A command naming a benign path and a
// secret one must be denied, or a decoy buys a permissive label while the
// command still reads the secret -- R4's "lying does not pay" broken, and a
// loud denial converted into a silent allow. Extracting only the first path
// would pass every other assertion here and fail that one.
//
// WHEN THIS FAILS on the decoy case: the fold stopped taking the strictest
// label. That is a security regression, not a documentation update.
func TestIntegration_Journey1_AShellCommandIsLabelledByEveryPathItNames(t *testing.T) {
	const tool = "journeyShellTool"
	const principal = "journey1-shell@example.com"
	const benign = "/tmp/journey-shell/ok.txt"
	const secret = "/journey-shell-secret/plans.txt"

	papBlanketPermit(t, "journey1-shell-blanket-permit")
	admin := papAccessToken(t, papAdminUser, papAdminPass)

	// Bash's exact catalog shape: a command_field, no fixed tier, no
	// resource_field. validateToolCatalogFields accepts a command_field-only
	// row precisely so this shape is expressible.
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": tool, "verb": "execute", "command_field": "command",
	}, nil)
	// This row has a NULL action_tier, which the migration-boundary proof
	// cannot tolerate anywhere in the table. See the helper's own comment.
	journeyCleanupNullTierTool(t, papTenant, tool)

	journeyCatchAll(t, admin, "nato", "UNCLASSIFIED")
	journeyRule(t, admin, "/journey-shell-secret/", "nato", "SECRET")

	agent := journeyAgent(t, admin, "journey1-shell-agent")
	var view models.AgentCapsView
	papJSON(t, papAddr, http.MethodPut, "/v1/agents/"+agent.ID.String()+"/classification-caps", admin,
		map[string]any{"classification_caps": map[string]string{"nato": "CONFIDENTIAL"}}, &view)

	// INTERNAL_MODIFY, not READ_ONLY: a compound command rates tier 2, and a
	// tier denial would mask the cap this test is about.
	delegation := journeyDelegationAtTier(t, principal, agent.ID, "journey1 shell",
		models.ActionTierInternalModify, tool)

	decide := func(command string) *pdpgrpc.DecideResponse {
		return papDecide(t, &pdpgrpc.DecideRequest{
			Token: delegation.GetToken(), AgentId: agent.ID.String(), Subject: principal,
			Tool: tool, RawInput: `{"command":"` + command + `"}`,
		})
	}

	t.Run("a command naming only a permitted path allows", func(t *testing.T) {
		got := decide("cat " + benign)
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Decide = %v (%s), want ALLOW -- UNCLASSIFIED is under a CONFIDENTIAL cap. "+
				"Before 2026-08-28 this denied, which was J1", got.GetEffect(), got.GetReason())
		}
	})

	t.Run("a command naming a path above the cap denies", func(t *testing.T) {
		got := decide("cat " + secret)
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Decide = %v, want DENY -- SECRET exceeds a CONFIDENTIAL cap", got.GetEffect())
		}
		if !strings.Contains(got.GetReason(), "exceeds delegation cap") {
			t.Errorf("Reason = %q, want the exceeds-cap wording", got.GetReason())
		}
	})

	t.Run("a decoy path cannot hide the one above the cap", func(t *testing.T) {
		got := decide("cat " + benign + "; cat " + secret)
		t.Logf("decoy command -> effect=%s reason=%q", got.GetEffect(), got.GetReason())
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Decide = %v, want DENY. A benign path prepended to a secret one just bought a "+
				"permissive label while the command still reads the secret. This is R4's "+
				"\"lying does not pay\" broken and it is a SECURITY REGRESSION", got.GetEffect())
		}
		if !strings.Contains(got.GetReason(), "exceeds delegation cap") {
			t.Errorf("Reason = %q, want the exceeds-cap wording -- the strictest path should have won "+
				"the fold, not merely produced an unevaluable label", got.GetReason())
		}
	})

	t.Run("a command naming no path at all still denies", func(t *testing.T) {
		got := decide("npm test")
		if got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Decide = %v, want DENY -- a command naming no resource has nothing to label, "+
				"and this change made caps-plus-shell better, never solved", got.GetEffect())
		}
		if !strings.Contains(got.GetReason(), "cannot be evaluated") {
			t.Errorf("Reason = %q, want the uncheckable-cap wording", got.GetReason())
		}
	})
}

// journeyDelegation issues a root delegation through the real
// CreateDelegation RPC -- the same path session-start and every delegating
// agent use -- rather than seeding one. That matters for J1 specifically:
// the copy of the agent's classification caps onto the delegation happens
// only on this path (internal/pdpgrpc/delegation.go), so a seeded delegation
// would prove nothing about whether an operator's cap actually reaches a
// decision.
func journeyDelegation(
	t *testing.T, principal string, agentID uuid.UUID, purpose string, tools ...string,
) *pdpgrpc.CreateDelegationResponse {
	t.Helper()
	return journeyDelegationAtTier(t, principal, agentID, purpose, models.ActionTierReadOnly, tools...)
}

// journeyDelegationAtTier is journeyDelegation with an explicit ceiling, for
// the shell proof: a compound command rates INTERNAL_MODIFY (reCompound in
// internal/authz/tier.go), so a READ_ONLY delegation would deny it on the TIER
// and prove nothing about the cap.
func journeyDelegationAtTier(
	t *testing.T, principal string, agentID uuid.UUID, purpose string,
	maxTier models.ActionTier, tools ...string,
) *pdpgrpc.CreateDelegationResponse {
	t.Helper()
	created, err := papPdpClient.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
		Subject: principal, AgentId: agentID.String(),
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: int32(maxTier), Tools: tools,
		},
		Purpose: purpose, TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateDelegation(%s): %v", purpose, err)
	}
	if created.GetDelegationId() == "" {
		t.Fatalf("CreateDelegation(%s) returned no delegation_id", purpose)
	}
	return created
}
