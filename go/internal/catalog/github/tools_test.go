// go/internal/catalog/github/tools_test.go
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"stratium/internal/catalog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- fakes ---

type fakeAuth struct {
	dec catalog.AuthDecision
	got catalog.AuthRequest
}

func (f *fakeAuth) Authorize(_ context.Context, req catalog.AuthRequest) (catalog.AuthDecision, error) {
	f.got = req
	return f.dec, nil
}

type fakeCreds struct{ token string }

func (f fakeCreds) GetToken(_ context.Context, _ string, _ string) (string, error) {
	return f.token, nil
}

type errCreds struct{}

func (errCreds) GetToken(_ context.Context, _ string, _ string) (string, error) {
	return "", catalog.ErrCredentialUnavailable
}

type fakeGH struct {
	content    string
	readCalled bool
}

func (f *fakeGH) ReadFile(_ context.Context, _, _, _, _ string) (string, error) {
	f.readCalled = true
	return f.content, nil
}
func (f *fakeGH) SearchCode(context.Context, string, string, string) ([]Hit, error) { return nil, nil }
func (f *fakeGH) CreateIssue(context.Context, string, string, string, string) (Issue, error) {
	return Issue{Number: 1, URL: "u"}, nil
}
func (f *fakeGH) DeleteBranch(context.Context, string, string, string) error { return nil }

func specByName(t *testing.T, name string) ToolSpec {
	t.Helper()
	for _, s := range Specs() {
		if s.Tool.Name == name {
			return s
		}
	}
	t.Fatalf("spec %s not found", name)
	return ToolSpec{}
}

func newDeps(auth catalog.Authorizer, gh Client, repos map[string]catalog.Classification, def *catalog.Classification) Deps {
	return Deps{
		Auth:   auth,
		Creds:  fakeCreds{token: "gho_live"},
		Class:  catalog.NewClassifier(repos, def),
		Client: gh,
	}
}

func TestSpecsCoverFourTools(t *testing.T) {
	names := map[string]bool{}
	for _, s := range Specs() {
		names[s.Tool.Name] = true
	}
	for _, want := range []string{"github_read_file", "github_search_code", "github_create_issue", "github_delete_branch"} {
		assert.Truef(t, names[want], "missing tool %s", want)
	}
}

func TestReadFileAllowed(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	gh := &fakeGH{content: "hello"}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "path": "README.md"})
	out, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)

	assert.Equal(t, true, out["authorized"])
	assert.Equal(t, "hello", out["content"])
	assert.True(t, gh.readCalled)
	// classification flowed into the authorize request
	assert.Equal(t, "INTERNAL", auth.got.ResourceAttributes["classification"])
	assert.Equal(t, "github_read_file", auth.got.ToolName)
	assert.Equal(t, 1, auth.got.ActionTier)
}

func TestReadFileDeniedDoesNotCallGitHub(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: false, Reason: "classification CONFIDENTIAL exceeds cap INTERNAL"}}
	gh := &fakeGH{content: "secret"}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/secret": {Classification: "CONFIDENTIAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/secret", "path": "README.md"})
	out, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)

	assert.Equal(t, false, out["authorized"])
	assert.Contains(t, out["reason"], "exceeds cap")
	assert.False(t, gh.readCalled, "GitHub must NOT be called when denied")
}

func TestReadFileUnclassifiedFailsClosed(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}} // even if gateway would allow
	gh := &fakeGH{content: "x"}
	deps := newDeps(auth, gh, nil, nil) // no map, no default → fail closed

	args, _ := json.Marshal(map[string]string{"repo": "acme/unknown", "path": "README.md"})
	out, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)

	assert.Equal(t, false, out["authorized"])
	assert.Contains(t, out["reason"], "classification")
	assert.False(t, gh.readCalled)
}

func TestMissingRequiredArgErrors(t *testing.T) {
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, &fakeGH{}, nil, nil)
	args, _ := json.Marshal(map[string]string{"path": "README.md"}) // no repo
	_, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.Error(t, err)
}

func TestSearchCodeAllowed(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	gh := &fakeGH{}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "query": "func main"})
	out, err := specByName(t, "github_search_code").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, true, out["authorized"])
	assert.Equal(t, "github_search_code", auth.got.ToolName)
	assert.Equal(t, 1, auth.got.ActionTier)
}

func TestSearchCodeDenied(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: false, Reason: "tier exceeds cap"}}
	gh := &fakeGH{}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/secret": {Classification: "CONFIDENTIAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/secret", "query": "password"})
	out, err := specByName(t, "github_search_code").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, false, out["authorized"])
}

func TestSearchCodeMissingArgs(t *testing.T) {
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, &fakeGH{}, nil, nil)
	args, _ := json.Marshal(map[string]string{"repo": "acme/app"}) // no query
	_, err := specByName(t, "github_search_code").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.Error(t, err)
}

func TestCreateIssueAllowed(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	gh := &fakeGH{}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "title": "Bug report", "body": "details"})
	out, err := specByName(t, "github_create_issue").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, true, out["authorized"])
	assert.Equal(t, 1, out["issue_number"])
	assert.Equal(t, "github_create_issue", auth.got.ToolName)
	assert.Equal(t, 2, auth.got.ActionTier)
}

func TestCreateIssueDenied(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: false, Reason: "tool not in approved scope"}}
	gh := &fakeGH{}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "title": "Bug"})
	out, err := specByName(t, "github_create_issue").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, false, out["authorized"])
}

func TestCreateIssueMissingArgs(t *testing.T) {
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, &fakeGH{}, nil, nil)
	args, _ := json.Marshal(map[string]string{"repo": "acme/app"}) // no title
	_, err := specByName(t, "github_create_issue").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.Error(t, err)
}

func TestDeleteBranchAllowed(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	gh := &fakeGH{}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "branch": "feature-x"})
	out, err := specByName(t, "github_delete_branch").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, true, out["authorized"])
	assert.Equal(t, "feature-x", out["deleted_branch"])
	assert.Equal(t, "github_delete_branch", auth.got.ToolName)
	assert.Equal(t, 4, auth.got.ActionTier)
}

func TestDeleteBranchDenied(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: false, Reason: "tier 4 exceeds cap 2"}}
	gh := &fakeGH{}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "branch": "main"})
	out, err := specByName(t, "github_delete_branch").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, false, out["authorized"])
}

func TestDeleteBranchMissingArgs(t *testing.T) {
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, &fakeGH{}, nil, nil)
	args, _ := json.Marshal(map[string]string{"repo": "acme/app"}) // no branch
	_, err := specByName(t, "github_delete_branch").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.Error(t, err)
}

func TestReadFileCredentialErrorReturnsError(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	gh := &fakeGH{content: "x"}
	deps := Deps{Auth: auth, Creds: errCreds{}, Class: catalog.NewClassifier(map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil), Client: gh}
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "path": "README.md"})
	_, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.False(t, gh.readCalled)
}

// --- additional fakes for error-path coverage ---

// errAuth is an Authorizer that always returns an error.
type errAuth struct{ msg string }

func (e errAuth) Authorize(_ context.Context, _ catalog.AuthRequest) (catalog.AuthDecision, error) {
	return catalog.AuthDecision{}, fmt.Errorf("%s", e.msg)
}

// errSearchGH is a Client whose SearchCode always returns an error.
type errSearchGH struct{}

func (errSearchGH) ReadFile(context.Context, string, string, string, string) (string, error) {
	return "", nil
}
func (errSearchGH) SearchCode(context.Context, string, string, string) ([]Hit, error) {
	return nil, fmt.Errorf("search failed")
}
func (errSearchGH) CreateIssue(context.Context, string, string, string, string) (Issue, error) {
	return Issue{}, nil
}
func (errSearchGH) DeleteBranch(context.Context, string, string, string) error { return nil }

// errCreateGH is a Client whose CreateIssue always returns an error.
type errCreateGH struct{}

func (errCreateGH) ReadFile(context.Context, string, string, string, string) (string, error) {
	return "", nil
}
func (errCreateGH) SearchCode(context.Context, string, string, string) ([]Hit, error) {
	return nil, nil
}
func (errCreateGH) CreateIssue(context.Context, string, string, string, string) (Issue, error) {
	return Issue{}, fmt.Errorf("create failed")
}
func (errCreateGH) DeleteBranch(context.Context, string, string, string) error { return nil }

// errDeleteGH is a Client whose DeleteBranch always returns an error.
type errDeleteGH struct{}

func (errDeleteGH) ReadFile(context.Context, string, string, string, string) (string, error) {
	return "", nil
}
func (errDeleteGH) SearchCode(context.Context, string, string, string) ([]Hit, error) {
	return nil, nil
}
func (errDeleteGH) CreateIssue(context.Context, string, string, string, string) (Issue, error) {
	return Issue{}, nil
}
func (errDeleteGH) DeleteBranch(context.Context, string, string, string) error {
	return fmt.Errorf("delete failed")
}

// errReadGH is a Client whose ReadFile always returns an error.
type errReadGH struct{}

func (errReadGH) ReadFile(context.Context, string, string, string, string) (string, error) {
	return "", fmt.Errorf("read failed")
}
func (errReadGH) SearchCode(context.Context, string, string, string) ([]Hit, error) {
	return nil, nil
}
func (errReadGH) CreateIssue(context.Context, string, string, string, string) (Issue, error) {
	return Issue{}, nil
}
func (errReadGH) DeleteBranch(context.Context, string, string, string) error { return nil }

// --- TestValidateRepo ---

func TestValidateRepo(t *testing.T) {
	tests := []struct {
		name    string
		repo    string
		wantErr bool
	}{
		{name: "valid owner/repo", repo: "owner/repo", wantErr: false},
		{name: "valid dotted repo", repo: "owner/repo.js", wantErr: false},
		{name: "missing slash", repo: "ownerrepo", wantErr: true},
		{name: "empty owner", repo: "/repo", wantErr: true},
		{name: "empty repo", repo: "owner/", wantErr: true},
		{name: "whitespace in repo", repo: "owner/re po", wantErr: true},
		{name: "path traversal", repo: "../../etc", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRepo(tc.repo)
			if tc.wantErr {
				assert.Error(t, err, "expected error for %q", tc.repo)
			} else {
				assert.NoError(t, err, "expected no error for %q", tc.repo)
			}
		})
	}
}

// --- TestHandlerRejectsInvalidRepo ---

func TestHandlerRejectsInvalidRepo(t *testing.T) {
	gh := &fakeGH{}
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, gh, nil, nil)

	args, _ := json.Marshal(map[string]string{"repo": "bad", "path": "x"})
	_, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "owner/repo")
	assert.False(t, gh.readCalled, "GitHub must NOT be called when repo is invalid")
}

// --- invalid-repo rejection in all handlers ---

func TestSearchCodeHandlerRejectsInvalidRepo(t *testing.T) {
	gh := &fakeGH{}
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, gh, nil, nil)
	args, _ := json.Marshal(map[string]string{"repo": "bad", "query": "x"})
	_, err := specByName(t, "github_search_code").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.Error(t, err)
}

func TestCreateIssueHandlerRejectsInvalidRepo(t *testing.T) {
	gh := &fakeGH{}
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, gh, nil, nil)
	args, _ := json.Marshal(map[string]string{"repo": "bad", "title": "x"})
	_, err := specByName(t, "github_create_issue").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.Error(t, err)
}

func TestDeleteBranchHandlerRejectsInvalidRepo(t *testing.T) {
	gh := &fakeGH{}
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, gh, nil, nil)
	args, _ := json.Marshal(map[string]string{"repo": "bad", "branch": "x"})
	_, err := specByName(t, "github_delete_branch").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.Error(t, err)
}

// --- invalid JSON argument paths ---

func TestReadFileHandlerBadJSON(t *testing.T) {
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, &fakeGH{}, nil, nil)
	_, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc", "deleg", json.RawMessage(`not-json`))
	require.Error(t, err)
}

func TestSearchCodeHandlerBadJSON(t *testing.T) {
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, &fakeGH{}, nil, nil)
	_, err := specByName(t, "github_search_code").Handler(context.Background(), deps, "kc", "deleg", json.RawMessage(`not-json`))
	require.Error(t, err)
}

func TestCreateIssueHandlerBadJSON(t *testing.T) {
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, &fakeGH{}, nil, nil)
	_, err := specByName(t, "github_create_issue").Handler(context.Background(), deps, "kc", "deleg", json.RawMessage(`not-json`))
	require.Error(t, err)
}

func TestDeleteBranchHandlerBadJSON(t *testing.T) {
	deps := newDeps(&fakeAuth{dec: catalog.AuthDecision{Authorized: true}}, &fakeGH{}, nil, nil)
	_, err := specByName(t, "github_delete_branch").Handler(context.Background(), deps, "kc", "deleg", json.RawMessage(`not-json`))
	require.Error(t, err)
}

// --- authorize error paths ---

func TestReadFileAuthorizeError(t *testing.T) {
	deps := Deps{
		Auth:   errAuth{msg: "gateway down"},
		Creds:  fakeCreds{token: "t"},
		Class:  catalog.NewClassifier(map[string]catalog.Classification{"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"}}, nil),
		Client: &fakeGH{},
	}
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "path": "README.md"})
	_, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorize")
}

func TestSearchCodeAuthorizeError(t *testing.T) {
	deps := Deps{
		Auth:   errAuth{msg: "gateway down"},
		Creds:  fakeCreds{token: "t"},
		Class:  catalog.NewClassifier(map[string]catalog.Classification{"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"}}, nil),
		Client: &fakeGH{},
	}
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "query": "func main"})
	_, err := specByName(t, "github_search_code").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorize")
}

func TestCreateIssueAuthorizeError(t *testing.T) {
	deps := Deps{
		Auth:   errAuth{msg: "gateway down"},
		Creds:  fakeCreds{token: "t"},
		Class:  catalog.NewClassifier(map[string]catalog.Classification{"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"}}, nil),
		Client: &fakeGH{},
	}
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "title": "Bug"})
	_, err := specByName(t, "github_create_issue").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorize")
}

func TestDeleteBranchAuthorizeError(t *testing.T) {
	deps := Deps{
		Auth:   errAuth{msg: "gateway down"},
		Creds:  fakeCreds{token: "t"},
		Class:  catalog.NewClassifier(map[string]catalog.Classification{"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"}}, nil),
		Client: &fakeGH{},
	}
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "branch": "main"})
	_, err := specByName(t, "github_delete_branch").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorize")
}

// --- client error paths ---

func TestReadFileClientError(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	deps := newDeps(auth, errReadGH{}, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "path": "README.md"})
	_, err := specByName(t, "github_read_file").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read failed")
}

func TestSearchCodeClientError(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	deps := newDeps(auth, errSearchGH{}, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "query": "func main"})
	_, err := specByName(t, "github_search_code").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "search failed")
}

func TestCreateIssueClientError(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	deps := newDeps(auth, errCreateGH{}, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "title": "Bug"})
	_, err := specByName(t, "github_create_issue").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create failed")
}

func TestDeleteBranchClientError(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	deps := newDeps(auth, errDeleteGH{}, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)
	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "branch": "main"})
	_, err := specByName(t, "github_delete_branch").Handler(context.Background(), deps, "kc", "deleg", args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
}

// --- allow-path checks verifying returned fields ---

func TestSearchCodeAllowedHits(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	hits := []Hit{{Path: "main.go", Repo: "acme/app"}}
	gh := &hitGH{hits: hits}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "query": "func main"})
	out, err := specByName(t, "github_search_code").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, true, out["authorized"])
	gotHits, ok := out["hits"].([]Hit)
	require.True(t, ok, "hits should be []Hit")
	require.Len(t, gotHits, 1)
	assert.Equal(t, "main.go", gotHits[0].Path)
	assert.True(t, gh.searchCalled)
}

func TestCreateIssueAllowedFields(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	gh := &issueGH{issue: Issue{Number: 99, URL: "https://github.com/acme/app/issues/99"}}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "title": "My issue", "body": "details"})
	out, err := specByName(t, "github_create_issue").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, true, out["authorized"])
	assert.Equal(t, 99, out["issue_number"])
	assert.Equal(t, "https://github.com/acme/app/issues/99", out["issue_url"])
	assert.True(t, gh.createCalled)
}

func TestDeleteBranchAllowedField(t *testing.T) {
	auth := &fakeAuth{dec: catalog.AuthDecision{Authorized: true}}
	gh := &branchGH{}
	deps := newDeps(auth, gh, map[string]catalog.Classification{
		"acme/app": {Classification: "INTERNAL", Hierarchy: "commercial"},
	}, nil)

	args, _ := json.Marshal(map[string]string{"repo": "acme/app", "branch": "feat-xyz"})
	out, err := specByName(t, "github_delete_branch").Handler(context.Background(), deps, "kc-tok", "deleg-tok", args)
	require.NoError(t, err)
	assert.Equal(t, true, out["authorized"])
	assert.Equal(t, "feat-xyz", out["deleted_branch"])
	assert.True(t, gh.deleteCalled)
}

// fakes for allow-path tests with call tracking

type hitGH struct {
	hits         []Hit
	searchCalled bool
}

func (h *hitGH) ReadFile(context.Context, string, string, string, string) (string, error) {
	return "", nil
}
func (h *hitGH) SearchCode(_ context.Context, _, _, _ string) ([]Hit, error) {
	h.searchCalled = true
	return h.hits, nil
}
func (h *hitGH) CreateIssue(context.Context, string, string, string, string) (Issue, error) {
	return Issue{}, nil
}
func (h *hitGH) DeleteBranch(context.Context, string, string, string) error { return nil }

type issueGH struct {
	issue        Issue
	createCalled bool
}

func (g *issueGH) ReadFile(context.Context, string, string, string, string) (string, error) {
	return "", nil
}
func (g *issueGH) SearchCode(context.Context, string, string, string) ([]Hit, error) {
	return nil, nil
}
func (g *issueGH) CreateIssue(_ context.Context, _, _, _, _ string) (Issue, error) {
	g.createCalled = true
	return g.issue, nil
}
func (g *issueGH) DeleteBranch(context.Context, string, string, string) error { return nil }

type branchGH struct {
	deleteCalled bool
}

func (b *branchGH) ReadFile(context.Context, string, string, string, string) (string, error) {
	return "", nil
}
func (b *branchGH) SearchCode(context.Context, string, string, string) ([]Hit, error) {
	return nil, nil
}
func (b *branchGH) CreateIssue(context.Context, string, string, string, string) (Issue, error) {
	return Issue{}, nil
}
func (b *branchGH) DeleteBranch(_ context.Context, _, _, _ string) error {
	b.deleteCalled = true
	return nil
}
