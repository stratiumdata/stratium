// go/internal/catalog/github/tools_test.go
package github

import (
	"context"
	"encoding/json"
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
