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
	denyID     string
	escalateID string
	asked      []string
}

func (p *perFilePolicy) Evaluate(_ context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	p.asked = append(p.asked, in.Resource["id"])
	if in.Resource["id"] == p.denyID {
		return []authz.PolicyVerdict{{Effect: authz.EffectDeny, Source: "fake", Reason: "not that file"}}, nil
	}
	if in.Resource["id"] == p.escalateID {
		return []authz.PolicyVerdict{{Effect: authz.EffectEscalate, Source: "fake", Reason: "ask first"}}, nil
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
		escalateID  string // the one file the policy wants approval for
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
			name:       "a refusal on a later file beats an escalation on an earlier one",
			harness:    "codex",
			cwd:        "/workspace",
			escalateID: "/workspace/a.txt",
			denyID:     "/workspace/sub/b.txt",
			wantEffect: Effect_EFFECT_DENY,
			wantReason: "[apply_patch decided as Edit]",
			wantAsked:  []string{"/workspace/a.txt", "/workspace/sub/b.txt"},
		},
		{
			name:       "an escalation on one file escalates the patch, whichever file it is",
			harness:    "codex",
			cwd:        "/workspace",
			escalateID: "/workspace/sub/b.txt",
			wantEffect: Effect_EFFECT_ESCALATE,
			wantReason: "[apply_patch decided as Edit]",
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
			// A row with the harness tool's name was written for another tool
			// (an MCP server's, say). It does not take the call away from the
			// alias: the delegation grants Edit, and Edit is what is decided.
			name:       "a tenant's row for the name as sent does not displace the alias",
			harness:    "codex",
			cwd:        "/workspace",
			catalog:    []models.ToolCatalogEntry{{ToolName: "apply_patch", ActionTier: tierPtr(models.ActionTierInternalModify)}},
			wantEffect: Effect_EFFECT_ALLOW,
			wantReason: "[apply_patch decided as Edit]",
		},
		{
			name:       "but a higher tier on that row still raises the tier",
			harness:    "codex",
			cwd:        "/workspace",
			catalog:    []models.ToolCatalogEntry{{ToolName: "apply_patch", ActionTier: tierPtr(models.ActionTierDestructive)}},
			wantEffect: Effect_EFFECT_DENY,
			wantReason: "[apply_patch decided as Edit]",
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
			pol := &perFilePolicy{denyID: tt.denyID, escalateID: tt.escalateID}
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

// OpenCode's file tools send paths relative to the directory it runs in. The
// PDP resolves them, and refuses the call when it cannot.
func TestDecide_OpenCodeFileTools(t *testing.T) {
	tests := []struct {
		name, tool, input, cwd string
		tools                  []string
		constraints            map[string]string
		wantEffect             Effect
		wantAsked              []string
		wantReason             string
	}{
		{name: "a relative path is the file under the working directory",
			tool: "read", input: `{"path":"docs/a.md"}`, cwd: "/workspace", tools: []string{"Read"},
			constraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
			wantEffect:  Effect_EFFECT_ALLOW, wantAsked: []string{"/workspace/docs/a.md"}},
		{name: "and is held to a path constraint as that file",
			tool: "write", input: `{"path":"a.md","content":"x"}`, cwd: "/elsewhere", tools: []string{"Write"},
			constraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
			wantEffect:  Effect_EFFECT_DENY, wantReason: `resource "/elsewhere/a.md" is outside`},
		{name: "a home-relative path is refused",
			tool: "edit", input: `{"path":"~/notes/todo.md","oldString":"a","newString":"b"}`, cwd: "/workspace",
			tools: []string{"Edit"}, wantEffect: Effect_EFFECT_DENY, wantReason: "names no resource the PDP can read"},
		{name: "a relative path with no working directory is refused",
			tool: "read", input: `{"path":"a.md"}`, tools: []string{"Read"},
			wantEffect: Effect_EFFECT_DENY, wantReason: "names no resource the PDP can read"},
		{name: "a patch is read from patchText",
			tool: "patch", input: `{"patchText":"*** Begin Patch\n*** Add File: n.txt\n+hi\n*** End Patch"}`,
			cwd: "/workspace", tools: []string{"Edit"},
			wantEffect: Effect_EFFECT_ALLOW, wantAsked: []string{"/workspace/n.txt"}},
		{name: "a tool that names no file is not held to that rule",
			tool: "glob", input: `{"pattern":"**/*.go"}`, cwd: "/workspace", tools: []string{"Glob"},
			wantEffect: Effect_EFFECT_ALLOW, wantAsked: []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, req := wellFormedFixture()
			fs.chain[0].ApprovedTools = tt.tools
			fs.chain[0].MaxActionTier = models.ActionTierInternalModify
			fs.chain[0].ResourceConstraints = tt.constraints
			req.Tool, req.RawInput, req.Harness, req.Cwd = tt.tool, tt.input, "opencode", tt.cwd
			pol := &perFilePolicy{denyID: "none", escalateID: "none"}
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
			if row := fs.appended[0]; row.ToolName != tt.tool || !strings.Contains(row.Reason, tt.wantReason) {
				t.Errorf("audit ToolName = %q, Reason = %q; want %q and %q", row.ToolName, row.Reason, tt.tool, tt.wantReason)
			}
		})
	}
}

// Cursor's Read is decided under its own name, with the alias's field and not
// the tenant catalog's, and with no rename to note.
func TestDecide_CursorSameNameAlias(t *testing.T) {
	tests := []struct {
		name, input string
		wantEffect  Effect
		wantReason  string
	}{
		{"the path comes from the alias's field", `{"file_path":"a.txt"}`, Effect_EFFECT_ALLOW, ""},
		{"an input without it is refused", `{"target_file":"a.txt"}`, Effect_EFFECT_DENY,
			`"Read" names no resource the PDP can read`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, req := wellFormedFixture()
			wrong := "target_file"
			fs.catalog = []models.ToolCatalogEntry{{ToolName: "Read", Verb: "read", ResourceField: &wrong,
				ActionTier: tierPtr(models.ActionTierReadOnly)}}
			fs.chain[0].ApprovedTools = []string{"Read"}
			fs.chain[0].ResourceConstraints = map[string]string{models.ResourceIDPrefixKey: "/workspace/"}
			req.Tool, req.RawInput, req.Harness, req.Cwd = "Read", tt.input, "cursor", "/workspace"
			pol := &perFilePolicy{denyID: "none", escalateID: "none"}
			srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: pol}), testConfig(), &fakeSigner{})

			resp, err := srv.Decide(context.Background(), req)
			if err != nil {
				t.Fatalf("Decide() error = %v", err)
			}
			if resp.GetEffect() != tt.wantEffect {
				t.Fatalf("Effect = %v (%q), want %v", resp.GetEffect(), resp.GetReason(), tt.wantEffect)
			}
			row := fs.appended[0]
			if row.ToolName != "Read" || strings.Contains(row.Reason, "decided as") || !strings.Contains(row.Reason, tt.wantReason) {
				t.Errorf("audit ToolName = %q, Reason = %q; want Read, no rename note, containing %q", row.ToolName, row.Reason, tt.wantReason)
			}
			if tt.wantEffect == Effect_EFFECT_ALLOW && !slices.Equal(pol.asked, []string{"/workspace/a.txt"}) {
				t.Errorf("policy asked about %q, want the resolved path", pol.asked)
			}
		})
	}
}

// Copilot's apply_patch sends the patch text as its whole input.
func TestDecide_CopilotPatchIsTheWholeInput(t *testing.T) {
	tests := []struct {
		name, input string
		wantEffect  Effect
		wantAsked   []string
	}{
		{"the files are read from the string", `"*** Begin Patch\n*** Update File: /workspace/a.txt\n@@\n-a\n+b\n*** End Patch\n"`,
			Effect_EFFECT_ALLOW, []string{"/workspace/a.txt"}},
		{"a file outside the constraint refuses it", `"*** Begin Patch\n*** Add File: /etc/x\n+a\n*** End Patch\n"`,
			Effect_EFFECT_DENY, nil},
		{"an input that is not a patch string is refused", `{"command":"*** Add File: /workspace/a.txt"}`,
			Effect_EFFECT_DENY, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, req := wellFormedFixture()
			fs.chain[0].ApprovedTools = []string{"Edit"}
			fs.chain[0].MaxActionTier = models.ActionTierInternalModify
			fs.chain[0].ResourceConstraints = map[string]string{models.ResourceIDPrefixKey: "/workspace/"}
			req.Tool, req.RawInput, req.Harness, req.Cwd = "apply_patch", tt.input, "copilot", "/workspace"
			pol := &perFilePolicy{denyID: "none", escalateID: "none"}
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
		})
	}
}
