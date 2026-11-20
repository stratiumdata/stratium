//go:build integration

package store_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/pkg/models"
)

// TestIntegration_ReportToolUse_RecordsOnlyTheCallThatWasNeverAllowed runs the
// whole path against real services: a Decide that ALLOWs, a report of that
// same call (must leave no trace), and a report of a call nobody decided
// (must leave one audit entry and show up on the delegation). It is the test
// that the audit_chain lookup, the new row's CHECK constraints and both
// database roles' grants actually work together.
func TestIntegration_ReportToolUse_RecordsOnlyTheCallThatWasNeverAllowed(t *testing.T) {
	const tool = "reportToolUseTool"
	const principal = "report-tool-use@example.com"
	const decided = `{"path":"/tmp/report/decided.txt"}`
	const undecided = `{"path":"/tmp/report/undecided.txt"}`

	papBlanketPermit(t, "report-tool-use-blanket-permit")
	admin := papAccessToken(t, papAdminUser, papAdminPass)
	papJSON(t, papAddr, http.MethodPost, "/v1/tool-catalog", admin, map[string]any{
		"tool_name": tool, "action_tier": int(models.ActionTierReadOnly),
		"verb": "read", "resource_field": "path",
	}, nil)
	agent := journeyAgent(t, admin, "report-tool-use-agent")
	delegation := journeyDelegation(t, principal, agent.ID, "report-tool-use", tool)
	token := delegation.GetToken()

	resp, err := papPdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
		Token: token, AgentId: agent.ID.String(), Subject: principal, Tool: tool, RawInput: decided,
	})
	if err != nil || resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Decide = %v, %v; this test needs an ALLOW to match against", resp, err)
	}

	report := func(rawInput string) bool {
		t.Helper()
		r, err := papPdpClient.ReportToolUse(t.Context(), &pdpgrpc.ReportToolUseRequest{
			Token: token, Tool: tool, RawInput: rawInput,
		})
		if err != nil {
			t.Fatalf("ReportToolUse(%s): %v", rawInput, err)
		}
		return r.GetMatched()
	}
	if !report(decided) {
		t.Fatal("the call the PDP allowed was reported as unmatched")
	}
	if report(undecided) {
		t.Fatal("a call the PDP never decided was reported as matched")
	}
	// A second report of the same undecided call is a second entry: the
	// earlier unmatched row must not count as a decision.
	if report(undecided) {
		t.Fatal("an earlier unmatched entry satisfied a later report")
	}

	var listed []struct {
		ID                uuid.UUID `json:"id"`
		UnmatchedToolUses int       `json:"unmatched_tool_uses"`
	}
	papJSON(t, papAddr, http.MethodGet, "/v1/delegations", admin, nil, &listed)
	var found bool
	for _, d := range listed {
		if d.ID.String() == delegation.GetDelegationId() {
			found = true
			if d.UnmatchedToolUses != 2 {
				t.Errorf("unmatched_tool_uses = %d, want 2", d.UnmatchedToolUses)
			}
		}
	}
	if !found {
		t.Fatal("the delegation is missing from GET /v1/delegations")
	}

	var page models.AuditPage
	papJSON(t, papAddr, http.MethodGet,
		"/v1/audit?event_type=unmatched_tool_use&agent_id="+agent.ID.String(), admin, nil, &page)
	if len(page.Entries) != 2 || page.Entries[0].ToolName != tool {
		t.Fatalf("audit entries = %+v, want two for %s", page.Entries, tool)
	}
}
