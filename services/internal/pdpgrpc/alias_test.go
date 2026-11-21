package pdpgrpc

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/pkg/models"
)

// perFilePolicy allows every call except one on denyID, and records the
// resource id of each call it was asked about.
type perFilePolicy struct {
	denyID string
	asked  []string
}

func (p *perFilePolicy) Evaluate(_ context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	p.asked = append(p.asked, in.Resource["id"])
	if in.Resource["id"] == p.denyID {
		return []authz.PolicyVerdict{{Effect: authz.EffectDeny, Source: "fake", Reason: "not that file"}}, nil
	}
	return []authz.PolicyVerdict{{Effect: authz.EffectAllow, Source: "fake"}}, nil
}

const twoFilePatch = `{"command":"*** Begin Patch\n*** Update File: a.txt\n@@\n-x\n+y\n*** Delete File: /workspace/sub/b.txt\n*** End Patch"}`

// A harness hook's own tool name is decided as the canonical tool, and only
// for a caller that names its harness. "apply_patch" is Codex's file edit;
// "Edit" is what a rule names. The files are the ones the patch text names.
func TestDecide_HarnessAlias(t *testing.T) {
	tests := []struct {
		name        string
		harness     string
		rawInput    string // twoFilePatch when empty
		cwd         string
		catalog     []models.ToolCatalogEntry
		overrides   map[string]models.ActionTier
		tools       []string // the delegation's approved tools; Edit when nil
		constraints map[string]string
		denyID      string // the one file the policy refuses
		wantEffect  Effect
		wantReason  string   // substring of the audit reason; "" means no alias note
		wantAsked   []string // resource ids the policy was asked about, when set
	}{
		{
			name:       "a patch is decided as an Edit of each file it names",
			harness:    "codex",
			cwd:        "/workspace",
			wantEffect: Effect_EFFECT_ALLOW,
			wantReason: "[apply_patch decided as Edit]",
			wantAsked:  []string{"/workspace/a.txt", "/workspace/sub/b.txt"},
		},
		{
			name:       "one file the policy refuses refuses the patch",
			harness:    "codex",
			cwd:        "/workspace",
			denyID:     "/workspace/sub/b.txt",
			wantEffect: Effect_EFFECT_DENY,
			wantReason: "[apply_patch decided as Edit]",
		},
		{
			name:       "and the policy is not asked about the files after it",
			harness:    "codex",
			cwd:        "/workspace",
			denyID:     "/workspace/a.txt",
			wantEffect: Effect_EFFECT_DENY,
			wantReason: "[apply_patch decided as Edit]",
			wantAsked:  []string{"/workspace/a.txt"},
		},
		{
			name:        "every file must be inside a path constraint",
			harness:     "codex",
			cwd:         "/workspace",
			constraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/sub/"},
			wantEffect:  Effect_EFFECT_DENY,
			wantReason:  `resource "/workspace/a.txt" is outside`,
		},
		{
			name:        "and a patch wholly inside one is allowed",
			harness:     "codex",
			cwd:         "/workspace",
			constraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
			wantEffect:  Effect_EFFECT_ALLOW,
			wantReason:  "[apply_patch decided as Edit]",
		},
		{
			name:       "a relative path with no working directory is refused",
			harness:    "codex",
			wantEffect: Effect_EFFECT_DENY,
			wantReason: `"apply_patch" names no resource the PDP can read [apply_patch decided as Edit]`,
		},
		{
			name:       "so is a patch that names no file",
			harness:    "codex",
			cwd:        "/workspace",
			rawInput:   `{"command":"*** Begin Patch\n*** End Patch"}`,
			wantEffect: Effect_EFFECT_DENY,
			wantReason: "names no resource the PDP can read",
		},
		{
			// The delegation's ceiling is INTERNAL_MODIFY, which an Edit fits.
			name:       "a tier override on the name as sent still raises the tier",
			harness:    "codex",
			cwd:        "/workspace",
			overrides:  map[string]models.ActionTier{"apply_patch": models.ActionTierDestructive},
			wantEffect: Effect_EFFECT_DENY,
			wantReason: "[apply_patch decided as Edit]",
		},
		{
			// The whole point of the harness field: stratium-pep mcp forwards
			// names an MCP server chose and never sets it.
			name:       "no harness means no aliasing, even for a name that has an alias",
			harness:    "",
			cwd:        "/workspace",
			wantEffect: Effect_EFFECT_DENY,
		},
		{
			name:       "another harness's alias does not apply",
			harness:    "claude",
			cwd:        "/workspace",
			wantEffect: Effect_EFFECT_DENY,
		},
		{
			name:       "a tenant's own row for the name as sent beats the alias",
			harness:    "codex",
			cwd:        "/workspace",
			catalog:    []models.ToolCatalogEntry{{ToolName: "apply_patch", ActionTier: tierPtr(models.ActionTierInternalModify)}},
			wantEffect: Effect_EFFECT_DENY,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, req := wellFormedFixture()
			fs.catalog = tt.catalog
			fs.overrides = tt.overrides
			fs.chain[0].ApprovedTools = []string{"Edit"}
			if tt.tools != nil {
				fs.chain[0].ApprovedTools = tt.tools
			}
			fs.chain[0].MaxActionTier = models.ActionTierInternalModify
			fs.chain[0].ResourceConstraints = tt.constraints
			req.Tool = "apply_patch"
			req.RawInput = twoFilePatch
			if tt.rawInput != "" {
				req.RawInput = tt.rawInput
			}
			req.Harness = tt.harness
			req.Cwd = tt.cwd
			pol := &perFilePolicy{denyID: tt.denyID}
			srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: pol}), testConfig(), &fakeSigner{})

			resp, err := srv.Decide(context.Background(), req)
			if err != nil {
				t.Fatalf("Decide() error = %v", err)
			}
			if resp.GetEffect() != tt.wantEffect {
				t.Fatalf("Effect = %v (%q), want %v", resp.GetEffect(), resp.GetReason(), tt.wantEffect)
			}
			if tt.wantAsked != nil && !slices.Equal(pol.asked, tt.wantAsked) {
				t.Errorf("policy asked about %q, want %q", pol.asked, tt.wantAsked)
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
