package pdpgrpc

import (
	"context"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/pkg/models"
)

// A harness hook's own tool name is decided as the canonical tool, and only
// for a caller that names its harness. "apply_patch" is Codex's file edit;
// "Edit" is what a rule names.
func TestDecide_HarnessAlias(t *testing.T) {
	tests := []struct {
		name        string
		harness     string
		catalog     []models.ToolCatalogEntry
		tools       []string // the delegation's approved tools
		constraints map[string]string
		wantEffect  Effect
		wantReason  string // substring of the audit reason; "" means no alias note
	}{
		{
			// The delegation lists the canonical tool, so the alias is all
			// that stands between this call and an allow. It names no
			// resource the PDP can read, so it is refused all the same.
			name:       "an aliased call with no resource identity is refused",
			harness:    "codex",
			tools:      []string{"Edit"},
			wantEffect: Effect_EFFECT_DENY,
			wantReason: `"apply_patch" names no resource the PDP can read [apply_patch decided as Edit]`,
		},
		{
			// The whole point of the harness field: stratium-pep mcp forwards
			// names an MCP server chose and never sets it.
			name:       "no harness means no aliasing, even for a name that has an alias",
			harness:    "",
			tools:      []string{"Edit"},
			wantEffect: Effect_EFFECT_DENY,
		},
		{
			name:       "another harness's alias does not apply",
			harness:    "claude",
			tools:      []string{"Edit"},
			wantEffect: Effect_EFFECT_DENY,
		},
		{
			name:       "a tenant's own row for the name as sent beats the alias",
			harness:    "codex",
			catalog:    []models.ToolCatalogEntry{{ToolName: "apply_patch", ActionTier: tierPtr(models.ActionTierInternalModify)}},
			tools:      []string{"Edit"},
			wantEffect: Effect_EFFECT_DENY,
		},
		{
			name:        "and is refused under a path constraint too",
			harness:     "codex",
			constraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
			wantEffect:  Effect_EFFECT_DENY,
			wantReason:  "[apply_patch decided as Edit]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, req := wellFormedFixture()
			fs.catalog = tt.catalog
			fs.chain[0].ApprovedTools = tt.tools
			fs.chain[0].ResourceConstraints = tt.constraints
			req.Tool = "apply_patch"
			req.RawInput = `{"command":"*** Begin Patch\n*** Update File: /workspace/a.txt\n*** End Patch"}`
			req.Harness = tt.harness
			srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

			resp, err := srv.Decide(context.Background(), req)
			if err != nil {
				t.Fatalf("Decide() error = %v", err)
			}
			if resp.GetDelegationEffect() != tt.wantEffect {
				t.Fatalf("DelegationEffect = %v (%q), want %v",
					resp.GetDelegationEffect(), resp.GetDelegationReason(), tt.wantEffect)
			}
			if len(fs.appended) != 1 {
				t.Fatalf("audit entries = %d, want 1", len(fs.appended))
			}
			row := fs.appended[0]
			// ReportToolUse matches a completed call to its decision by the
			// name the caller sent, so that is the name on the row.
			if row.ToolName != "apply_patch" {
				t.Errorf("audit ToolName = %q, want the name as sent", row.ToolName)
			}
			if got := strings.Contains(row.Reason, "decided as"); got != (tt.wantReason != "") {
				t.Errorf("audit Reason = %q, alias note present = %v, want %v", row.Reason, got, tt.wantReason != "")
			}
			if !strings.Contains(row.Reason, tt.wantReason) {
				t.Errorf("audit Reason = %q, want it to contain %q", row.Reason, tt.wantReason)
			}
		})
	}
}
