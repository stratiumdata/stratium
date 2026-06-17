// go/internal/catalog/github/tools.go
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"stratium/internal/catalog"
	"stratium/internal/mcp"
)

const provider = "github"

// Deps are the injected dependencies shared by all GitHub tool handlers.
type Deps struct {
	Auth   catalog.Authorizer
	Creds  catalog.CredentialProvider
	Class  *catalog.Classifier
	Client Client
}

// Handler is the pure orchestration signature for a catalog tool.
type Handler func(ctx context.Context, deps Deps, subjectToken, delegationToken string, args json.RawMessage) (map[string]any, error)

// ToolSpec bundles an MCP tool definition with its action/tier and handler.
type ToolSpec struct {
	Tool    mcp.Tool
	Action  string
	Tier    int
	Handler Handler
}

type readFileArgs struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
	Ref  string `json:"ref"`
}

type searchArgs struct {
	Repo  string `json:"repo"`
	Query string `json:"query"`
}

type createIssueArgs struct {
	Repo  string `json:"repo"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

type deleteBranchArgs struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
}

func strProp(desc string) mcp.PropertySchema {
	return mcp.PropertySchema{Type: "string", Description: desc}
}

// Specs returns the GitHub catalog tools. Tiers: read/search=1, create=2, delete=4.
func Specs() []ToolSpec {
	return []ToolSpec{
		{
			Tool: mcp.Tool{
				Name:        "github_read_file",
				Description: "Read a file's contents from a GitHub repository. Classification-gated by repo.",
				InputSchema: mcp.ToolSchema{Type: "object", Properties: map[string]mcp.PropertySchema{
					"repo": strProp("owner/repo"),
					"path": strProp("file path within the repo"),
					"ref":  strProp("git ref (branch/tag/sha); optional"),
				}, Required: []string{"repo", "path"}},
			},
			Action: "read", Tier: 1, Handler: handleReadFile,
		},
		{
			Tool: mcp.Tool{
				Name:        "github_search_code",
				Description: "Search code within a GitHub repository. Classification-gated by repo.",
				InputSchema: mcp.ToolSchema{Type: "object", Properties: map[string]mcp.PropertySchema{
					"repo":  strProp("owner/repo"),
					"query": strProp("code search query"),
				}, Required: []string{"repo", "query"}},
			},
			Action: "search", Tier: 1, Handler: handleSearchCode,
		},
		{
			Tool: mcp.Tool{
				Name:        "github_create_issue",
				Description: "Create an issue in a GitHub repository. Classification-gated by repo.",
				InputSchema: mcp.ToolSchema{Type: "object", Properties: map[string]mcp.PropertySchema{
					"repo":  strProp("owner/repo"),
					"title": strProp("issue title"),
					"body":  strProp("issue body"),
				}, Required: []string{"repo", "title"}},
			},
			Action: "create", Tier: 2, Handler: handleCreateIssue,
		},
		{
			Tool: mcp.Tool{
				Name:        "github_delete_branch",
				Description: "Delete a branch in a GitHub repository. Destructive; classification-gated by repo.",
				InputSchema: mcp.ToolSchema{Type: "object", Properties: map[string]mcp.PropertySchema{
					"repo":   strProp("owner/repo"),
					"branch": strProp("branch name to delete"),
				}, Required: []string{"repo", "branch"}},
			},
			Action: "delete", Tier: 4, Handler: handleDeleteBranch,
		},
	}
}

// authorize runs the shared classify→ExecuteAction gate. It returns (token, true, nil)
// when the action is authorized and a usable GitHub token was obtained. Otherwise it
// returns a denial result map and ok=false. A non-nil error is an operational failure.
func authorize(ctx context.Context, deps Deps, toolName, action string, tier int, repo, subjectToken, delegationToken string) (string, map[string]any, bool, error) {
	cls, err := deps.Class.Resolve(repo)
	if err != nil {
		if errors.Is(err, catalog.ErrUnclassified) {
			return "", denied(toolName, action, tier, fmt.Sprintf("repository %q classification unknown and no default configured (fail-closed)", repo)), false, nil
		}
		return "", nil, false, fmt.Errorf("classify repo: %w", err)
	}

	dec, err := deps.Auth.Authorize(ctx, catalog.AuthRequest{
		DelegationToken: delegationToken,
		ToolName:        toolName,
		Action:          action,
		ActionTier:      tier,
		ResourceAttributes: map[string]string{
			"resource_id":    repo,
			"classification": cls.Classification,
			"hierarchy":      cls.Hierarchy,
			"provider":       provider,
		},
	})
	if err != nil {
		return "", nil, false, fmt.Errorf("authorize: %w", err)
	}
	if !dec.Authorized {
		return "", denied(toolName, action, tier, dec.Reason), false, nil
	}

	token, err := deps.Creds.GetToken(ctx, subjectToken, provider)
	if err != nil {
		return "", nil, false, fmt.Errorf("github credential: %w", err)
	}
	return token, nil, true, nil
}

func denied(tool, action string, tier int, reason string) map[string]any {
	return map[string]any{
		"authorized": false,
		"tool":       tool,
		"action":     action,
		"tier":       tier,
		"reason":     reason,
		"message":    fmt.Sprintf("DENIED: %s %s (tier %d) — %s", action, tool, tier, reason),
	}
}

func handleReadFile(ctx context.Context, deps Deps, subjectToken, delegationToken string, raw json.RawMessage) (map[string]any, error) {
	var a readFileArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if a.Repo == "" || a.Path == "" {
		return nil, fmt.Errorf("repo and path are required")
	}
	token, deny, ok, err := authorize(ctx, deps, "github_read_file", "read", 1, a.Repo, subjectToken, delegationToken)
	if err != nil {
		return nil, err
	}
	if !ok {
		return deny, nil
	}
	content, err := deps.Client.ReadFile(ctx, token, a.Repo, a.Path, a.Ref)
	if err != nil {
		return nil, err
	}
	return map[string]any{"authorized": true, "tool": "github_read_file", "content": content}, nil
}

func handleSearchCode(ctx context.Context, deps Deps, subjectToken, delegationToken string, raw json.RawMessage) (map[string]any, error) {
	var a searchArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if a.Repo == "" || a.Query == "" {
		return nil, fmt.Errorf("repo and query are required")
	}
	token, deny, ok, err := authorize(ctx, deps, "github_search_code", "search", 1, a.Repo, subjectToken, delegationToken)
	if err != nil {
		return nil, err
	}
	if !ok {
		return deny, nil
	}
	hits, err := deps.Client.SearchCode(ctx, token, a.Repo, a.Query)
	if err != nil {
		return nil, err
	}
	return map[string]any{"authorized": true, "tool": "github_search_code", "hits": hits}, nil
}

func handleCreateIssue(ctx context.Context, deps Deps, subjectToken, delegationToken string, raw json.RawMessage) (map[string]any, error) {
	var a createIssueArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if a.Repo == "" || a.Title == "" {
		return nil, fmt.Errorf("repo and title are required")
	}
	token, deny, ok, err := authorize(ctx, deps, "github_create_issue", "create", 2, a.Repo, subjectToken, delegationToken)
	if err != nil {
		return nil, err
	}
	if !ok {
		return deny, nil
	}
	iss, err := deps.Client.CreateIssue(ctx, token, a.Repo, a.Title, a.Body)
	if err != nil {
		return nil, err
	}
	return map[string]any{"authorized": true, "tool": "github_create_issue", "issue_number": iss.Number, "issue_url": iss.URL}, nil
}

func handleDeleteBranch(ctx context.Context, deps Deps, subjectToken, delegationToken string, raw json.RawMessage) (map[string]any, error) {
	var a deleteBranchArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if a.Repo == "" || a.Branch == "" {
		return nil, fmt.Errorf("repo and branch are required")
	}
	token, deny, ok, err := authorize(ctx, deps, "github_delete_branch", "delete", 4, a.Repo, subjectToken, delegationToken)
	if err != nil {
		return nil, err
	}
	if !ok {
		return deny, nil
	}
	if err := deps.Client.DeleteBranch(ctx, token, a.Repo, a.Branch); err != nil {
		return nil, err
	}
	return map[string]any{"authorized": true, "tool": "github_delete_branch", "deleted_branch": a.Branch}, nil
}
