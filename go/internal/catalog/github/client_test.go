// go/internal/catalog/github/client_test.go
package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRESTClientReadFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/acme/app/contents/README.md", r.URL.Path)
		assert.Equal(t, "main", r.URL.Query().Get("ref"))
		assert.Equal(t, "Bearer gho_live", r.Header.Get("Authorization"))
		// base64 of "hello"
		_, _ = w.Write([]byte(`{"content":"aGVsbG8=","encoding":"base64"}`))
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, srv.Client())
	content, err := c.ReadFile(context.Background(), "gho_live", "acme/app", "README.md", "main")
	require.NoError(t, err)
	assert.Equal(t, "hello", content)
}

func TestRESTClientCreateIssue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/repos/acme/app/issues", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":42,"html_url":"https://github.com/acme/app/issues/42"}`))
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, srv.Client())
	iss, err := c.CreateIssue(context.Background(), "gho_live", "acme/app", "Bug", "It broke")
	require.NoError(t, err)
	assert.Equal(t, 42, iss.Number)
	assert.Contains(t, iss.URL, "/issues/42")
}

func TestRESTClientDeleteBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/repos/acme/app/git/refs/heads/feature-x", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, srv.Client())
	require.NoError(t, c.DeleteBranch(context.Background(), "gho_live", "acme/app", "feature-x"))
}

func TestRESTClientAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, srv.Client())
	_, err := c.ReadFile(context.Background(), "gho_live", "acme/app", "missing", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestRESTClientSearchCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.URL.RawQuery, "repo:acme/app")
		_, _ = w.Write([]byte(`{"items":[{"path":"main.go","repository":{"full_name":"acme/app"}}]}`))
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, srv.Client())
	hits, err := c.SearchCode(context.Background(), "gho_live", "acme/app", "func+main")
	require.NoError(t, err)
	require.Len(t, hits, 1)
	assert.Equal(t, "main.go", hits[0].Path)
	assert.Equal(t, "acme/app", hits[0].Repo)
}

func TestRESTClientSearchCodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Validation Failed"}`))
	}))
	defer srv.Close()

	c := NewRESTClient(srv.URL, srv.Client())
	_, err := c.SearchCode(context.Background(), "gho_live", "acme/app", "funcmain")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "422")
}

func TestRESTClientNilHTTPClient(t *testing.T) {
	// NewRESTClient with nil http client should use http.DefaultClient (not panic).
	c := NewRESTClient("https://api.github.com", nil)
	assert.NotNil(t, c)
}
