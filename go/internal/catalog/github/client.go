// go/internal/catalog/github/client.go
package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Hit is one code-search result.
type Hit struct {
	Path string `json:"path"`
	Repo string `json:"repository_full_name"`
}

// Issue is a created issue.
type Issue struct {
	Number int    `json:"number"`
	URL    string `json:"html_url"`
}

// Client is the GitHub surface the catalog tools use.
type Client interface {
	ReadFile(ctx context.Context, token, repo, path, ref string) (string, error)
	SearchCode(ctx context.Context, token, repo, query string) ([]Hit, error)
	CreateIssue(ctx context.Context, token, repo, title, body string) (Issue, error)
	DeleteBranch(ctx context.Context, token, repo, branch string) error
}

// RESTClient calls the GitHub REST API (api.github.com or a GHES base URL).
type RESTClient struct {
	baseURL string
	http    *http.Client
}

// NewRESTClient builds a client. baseURL is e.g. "https://api.github.com" or
// "https://ghe.example.com/api/v3".
func NewRESTClient(baseURL string, httpClient *http.Client) *RESTClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &RESTClient{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

func (c *RESTClient) do(ctx context.Context, method, token, path string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, fmt.Errorf("build github request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func apiError(resp *http.Response) error {
	b, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("github API error: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
}

func (c *RESTClient) ReadFile(ctx context.Context, token, repo, path, ref string) (string, error) {
	url := fmt.Sprintf("/repos/%s/contents/%s", repo, path)
	if ref != "" {
		url += "?ref=" + ref
	}
	resp, err := c.do(ctx, http.MethodGet, token, url, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", apiError(resp)
	}
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode contents: %w", err)
	}
	if out.Encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
		if err != nil {
			return "", fmt.Errorf("decode base64 content: %w", err)
		}
		return string(decoded), nil
	}
	return out.Content, nil
}

func (c *RESTClient) SearchCode(ctx context.Context, token, repo, query string) ([]Hit, error) {
	url := fmt.Sprintf("/search/code?q=%s+repo:%s", query, repo)
	resp, err := c.do(ctx, http.MethodGet, token, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	var out struct {
		Items []struct {
			Path       string `json:"path"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode search: %w", err)
	}
	hits := make([]Hit, 0, len(out.Items))
	for _, it := range out.Items {
		hits = append(hits, Hit{Path: it.Path, Repo: it.Repository.FullName})
	}
	return hits, nil
}

func (c *RESTClient) CreateIssue(ctx context.Context, token, repo, title, body string) (Issue, error) {
	payload, _ := json.Marshal(map[string]string{"title": title, "body": body})
	resp, err := c.do(ctx, http.MethodPost, token, fmt.Sprintf("/repos/%s/issues", repo), payload)
	if err != nil {
		return Issue{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return Issue{}, apiError(resp)
	}
	var iss Issue
	if err := json.NewDecoder(resp.Body).Decode(&iss); err != nil {
		return Issue{}, fmt.Errorf("decode issue: %w", err)
	}
	return iss, nil
}

func (c *RESTClient) DeleteBranch(ctx context.Context, token, repo, branch string) error {
	resp, err := c.do(ctx, http.MethodDelete, token, fmt.Sprintf("/repos/%s/git/refs/heads/%s", repo, branch), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return apiError(resp)
	}
	return nil
}
