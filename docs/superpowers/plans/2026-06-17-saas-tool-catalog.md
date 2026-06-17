# SaaS Tool Catalog (Framework + GitHub) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable, classification-aware SaaS-tool-catalog framework for `stratium-mcp` and prove it end-to-end with a GitHub reference tool whose credentials come from Keycloak identity brokering.

**Architecture:** A new pure, unit-tested `stratium/internal/catalog` package holds the reusable pieces — config loader, classification resolver (fail-closed), action-tier guard, an `Authorizer` interface, and `CredentialProvider` implementations (`KeycloakBroker` + `StaticToken`). A `stratium/internal/catalog/github` subpackage holds the GitHub REST client and the four tool handlers as pure orchestration functions (testable with fakes). The existing `stratium/internal/tools` package gains a thin glue file that adapts `Registry`/`gateway.Client` to the catalog interfaces and registers the tools, gated by an opt-in config file. Every tool call routes through the existing Agent Gateway `ExecuteAction` before any GitHub API call.

**Tech Stack:** Go 1.25, `net/http` (no new deps), `encoding/json`, `github.com/stretchr/testify` (already vendored), `github.com/cedar-policy/cedar-go` (already vendored, for the policy template only). Module path is `stratium`.

---

## Design reference (read before starting)

Spec: `docs/superpowers/specs/2026-06-17-saas-tool-catalog-design.md`.

Key existing types you will integrate with (do not re-implement):

- `stratium/internal/mcp` (`go/internal/mcp/types.go`, `server.go`):
  - `mcp.Tool{ Name, Description string; InputSchema mcp.ToolSchema }`
  - `mcp.ToolSchema{ Type string; Properties map[string]mcp.PropertySchema; Required []string }`
  - `mcp.PropertySchema{ Type, Description string; Items *PropertySchema; Enum []string; Default any }`
  - `type mcp.ToolHandler func(args json.RawMessage) (*mcp.ToolCallResult, error)`
  - `func (s *mcp.Server) RegisterTool(tool mcp.Tool, handler mcp.ToolHandler)`
  - `func mcp.SuccessResult(data any) (*mcp.ToolCallResult, error)`
- `stratium/internal/tools` (`go/internal/tools/registry.go`, `actions.go`):
  - `Registry{ gateway *gateway.Client; auth *auth.Provider; logger *log.Logger; session *Session; subAgentCfg *SubAgentConfig }`
  - `Session{ Token *auth.TokenResponse; AgentID, DelegationToken, DelegationID string }`
  - `func (r *Registry) ensureAuth(ctx) error`, `func (r *Registry) accessToken() string`, `func (r *Registry) userID() string`
  - `func (r *Registry) RegisterAll(server *mcp.Server)` — registers tool groups
  - `func parseArgs[T any](args json.RawMessage) (*T, error)`
- The Agent Gateway client call pattern (from `actions.go:110`):
  ```go
  ag "stratium/services/agent-gateway"
  resp, err := r.gateway.ExecuteAction(ctx, r.accessToken(), r.userID(), &ag.ExecuteActionRequest{
      DelegationToken:    token,
      ToolName:           "...",
      Action:             "...",
      ActionTier:         ag.ActionTier(tier), // int32-backed
      ResourceAttributes: map[string]string{...},
  })
  // resp.Authorized bool
  // resp.Decision.{DelegationReason, AgentReason, UserReason, DeniedPrincipal} string
  // resp.Error string
  ```
- `stratium/internal/auth` (`go/internal/auth/oidc.go`): `auth.Provider`, `auth.TokenResponse{ AccessToken, UserID string; ExpiresAt int64 }`. The Keycloak **realm URL** (e.g. `http://localhost:8080/realms/stratium`) is passed to `runMCPMode` as `keycloakURL`; the broker token endpoint is `{keycloakURL}/broker/{alias}/token`.

Run tests from the `go/` directory:
```bash
cd go
go test ./internal/catalog/... -race -v
```

---

## File structure (created / modified)

| File | Responsibility |
|---|---|
| `go/internal/catalog/classifier.go` (create) | `Classification` type; `Classifier` with fail-closed `Resolve`; `ErrUnclassified`. |
| `go/internal/catalog/config.go` (create) | `Config`/`GitHubConfig` + `Load(path)` (JSON file) + defaults + `Classifier()`. |
| `go/internal/catalog/tier.go` (create) | `AssessTier(action)` (mirrors gateway `assessActionTier`) + `GuardTier(action, declared)`. |
| `go/internal/catalog/authorizer.go` (create) | `AuthRequest`, `AuthDecision`, `Authorizer` interface (the gateway seam). |
| `go/internal/catalog/credential.go` (create) | `CredentialProvider` interface; `ErrCredentialUnavailable`; `StaticToken`; `KeycloakBroker`; `parseBrokerToken`. |
| `go/internal/catalog/github/client.go` (create) | GitHub REST `Client` interface + `RESTClient` (ReadFile, SearchCode, CreateIssue, DeleteBranch). |
| `go/internal/catalog/github/tools.go` (create) | `Deps`, `ToolSpec`, `Specs()`, and the 4 pure handler funcs (classify → authorize → creds → API → result map). |
| `go/internal/tools/catalog_github.go` (create) | `gatewayAuthorizer` adapter; `(*Registry).registerCatalogTools`; `(*Registry).SetCatalog`; new `Registry` catalog fields. |
| `go/internal/tools/registry.go` (modify) | Add catalog fields to `Registry`; call `r.registerCatalogTools(server)` in `RegisterAll`. |
| `go/cmd/stratium-mcp/main.go` (modify) | Add `-catalog-config` flag/env; load + wire catalog when enabled. |
| `keycloak/realm-export.json` (modify) | Add GitHub brokered IdP with `storeToken: true`, `storedTokensReadable: true`. |
| `go/internal/catalog/github/policies/github.json` (create) | JSON default policy template. |
| `go/internal/catalog/github/policies/github.cedar` (create) | Cedar default policy template. |
| `demos/catalog-github/seed-catalog-demo.sh` (create) | Demo: register agent, scoped delegation, allowed + denied calls. |
| `demos/catalog-github/README.md` (create) | Demo walkthrough. |

---

## Task 1: Classification resolver (fail-closed)

**Files:**
- Create: `go/internal/catalog/classifier.go`
- Test: `go/internal/catalog/classifier_test.go`

- [ ] **Step 1: Write the failing test**

```go
// go/internal/catalog/classifier_test.go
package catalog

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifierResolve(t *testing.T) {
	repos := map[string]Classification{
		"acme/secret-repo": {Classification: "CONFIDENTIAL", Hierarchy: "commercial"},
	}
	def := &Classification{Classification: "INTERNAL", Hierarchy: "commercial"}

	t.Run("known repo returns mapped classification", func(t *testing.T) {
		c := NewClassifier(repos, def)
		got, err := c.Resolve("acme/secret-repo")
		require.NoError(t, err)
		assert.Equal(t, "CONFIDENTIAL", got.Classification)
		assert.Equal(t, "commercial", got.Hierarchy)
	})

	t.Run("unknown repo falls back to default", func(t *testing.T) {
		c := NewClassifier(repos, def)
		got, err := c.Resolve("acme/other-repo")
		require.NoError(t, err)
		assert.Equal(t, "INTERNAL", got.Classification)
	})

	t.Run("unknown repo with no default fails closed", func(t *testing.T) {
		c := NewClassifier(repos, nil)
		_, err := c.Resolve("acme/other-repo")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnclassified))
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/catalog/ -run TestClassifierResolve -v`
Expected: FAIL — build error, `undefined: Classification`, `NewClassifier`, `ErrUnclassified`.

- [ ] **Step 3: Write minimal implementation**

```go
// go/internal/catalog/classifier.go
package catalog

import "errors"

// ErrUnclassified is returned when a resource has no mapped classification and
// no default is configured. Callers MUST treat this as a denial (fail-closed).
var ErrUnclassified = errors.New("resource classification unknown and no default configured")

// Classification is the resource label evaluated by the policy engine.
type Classification struct {
	Classification string `json:"classification"`
	Hierarchy      string `json:"hierarchy"`
}

// Classifier resolves a resource identifier (e.g. "owner/repo") to a Classification.
type Classifier struct {
	repos   map[string]Classification
	deflt   *Classification
}

// NewClassifier builds a Classifier. A nil deflt means "fail closed on unknown".
func NewClassifier(repos map[string]Classification, deflt *Classification) *Classifier {
	if repos == nil {
		repos = map[string]Classification{}
	}
	return &Classifier{repos: repos, deflt: deflt}
}

// Resolve returns the classification for a resource. It returns ErrUnclassified
// when the resource is unknown and no default is configured — never a permissive
// default.
func (c *Classifier) Resolve(resource string) (Classification, error) {
	if v, ok := c.repos[resource]; ok {
		return v, nil
	}
	if c.deflt != nil {
		return *c.deflt, nil
	}
	return Classification{}, ErrUnclassified
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd go && go test ./internal/catalog/ -run TestClassifierResolve -race -v`
Expected: PASS (3 subtests).

- [ ] **Step 5: Commit**

```bash
cd go && gofmt -w internal/catalog/classifier.go internal/catalog/classifier_test.go
git add go/internal/catalog/classifier.go go/internal/catalog/classifier_test.go
git commit -m "feat(catalog): add fail-closed classification resolver"
```

---

## Task 2: Action-tier guard

**Files:**
- Create: `go/internal/catalog/tier.go`
- Test: `go/internal/catalog/tier_test.go`

- [ ] **Step 1: Write the failing test**

```go
// go/internal/catalog/tier_test.go
package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssessTier(t *testing.T) {
	cases := map[string]int{
		"read": 1, "search": 1, "list": 1,
		"create": 2, "update": 2,
		"send": 3, "publish": 3,
		"delete": 4, "execute": 4,
		"think": 0, "": 0,
	}
	for action, want := range cases {
		assert.Equalf(t, want, AssessTier(action), "AssessTier(%q)", action)
	}
}

func TestGuardTier(t *testing.T) {
	t.Run("declared equals assessed passes", func(t *testing.T) {
		require.NoError(t, GuardTier("delete", 4))
	})
	t.Run("declared above assessed passes", func(t *testing.T) {
		require.NoError(t, GuardTier("read", 2))
	})
	t.Run("declared below assessed fails (anti-spoofing)", func(t *testing.T) {
		require.Error(t, GuardTier("delete", 1))
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/catalog/ -run 'TestAssessTier|TestGuardTier' -v`
Expected: FAIL — `undefined: AssessTier`, `GuardTier`.

- [ ] **Step 3: Write minimal implementation**

```go
// go/internal/catalog/tier.go
package catalog

import "fmt"

// AssessTier mirrors assessActionTier in services/agent-gateway/server.go so the
// catalog can validate a tool's declared tier at registration time. The gateway
// remains the authoritative assessor at call time; this is defense-in-depth.
func AssessTier(action string) int {
	switch action {
	case "read", "get", "list", "query", "search":
		return 1
	case "write", "create", "update", "modify", "patch":
		return 2
	case "send", "email", "notify", "webhook", "publish":
		return 3
	case "delete", "destroy", "drop", "revoke", "transfer", "execute":
		return 4
	default:
		return 0
	}
}

// GuardTier returns an error if a tool declares a tier LOWER than the tier its
// action assesses to. A tool may declare a higher tier than necessary, but never
// a lower one — that would let it slip a sensitive action under a delegation cap.
func GuardTier(action string, declared int) error {
	if assessed := AssessTier(action); declared < assessed {
		return fmt.Errorf("tool declares tier %d but action %q assesses to tier %d", declared, action, assessed)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd go && go test ./internal/catalog/ -run 'TestAssessTier|TestGuardTier' -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd go && gofmt -w internal/catalog/tier.go internal/catalog/tier_test.go
git add go/internal/catalog/tier.go go/internal/catalog/tier_test.go
git commit -m "feat(catalog): add action-tier guard mirroring gateway assessment"
```

---

## Task 3: Authorizer interface (gateway seam)

**Files:**
- Create: `go/internal/catalog/authorizer.go`
- Test: `go/internal/catalog/authorizer_test.go`

This is the small interface that decouples catalog handlers from the concrete `gateway.Client`. The test pins the contract with a fake.

- [ ] **Step 1: Write the failing test**

```go
// go/internal/catalog/authorizer_test.go
package catalog

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAuthorizer struct {
	got      AuthRequest
	decision AuthDecision
	err      error
}

func (f *fakeAuthorizer) Authorize(_ context.Context, req AuthRequest) (AuthDecision, error) {
	f.got = req
	return f.decision, f.err
}

func TestAuthorizerContract(t *testing.T) {
	f := &fakeAuthorizer{decision: AuthDecision{Authorized: true}}
	var a Authorizer = f // compile-time check the fake satisfies the interface

	dec, err := a.Authorize(context.Background(), AuthRequest{
		ToolName:   "github_read_file",
		Action:     "read",
		ActionTier: 1,
	})
	require.NoError(t, err)
	assert.True(t, dec.Authorized)
	assert.Equal(t, "github_read_file", f.got.ToolName)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/catalog/ -run TestAuthorizerContract -v`
Expected: FAIL — `undefined: AuthRequest`, `AuthDecision`, `Authorizer`.

- [ ] **Step 3: Write minimal implementation**

```go
// go/internal/catalog/authorizer.go
package catalog

import "context"

// AuthRequest is a catalog-level authorization request, mapped onto the Agent
// Gateway ExecuteAction call by the adapter in the tools package.
type AuthRequest struct {
	DelegationToken    string
	ToolName           string
	Action             string
	ActionTier         int
	ResourceAttributes map[string]string
}

// AuthDecision is the catalog-level result.
type AuthDecision struct {
	Authorized bool
	Reason     string
}

// Authorizer is the seam to the Agent Gateway. The tools package provides an
// implementation backed by gateway.ExecuteAction; tests provide fakes.
type Authorizer interface {
	Authorize(ctx context.Context, req AuthRequest) (AuthDecision, error)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd go && go test ./internal/catalog/ -run TestAuthorizerContract -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd go && gofmt -w internal/catalog/authorizer.go internal/catalog/authorizer_test.go
git add go/internal/catalog/authorizer.go go/internal/catalog/authorizer_test.go
git commit -m "feat(catalog): add Authorizer interface decoupling tools from gateway"
```

---

## Task 4: Credential providers (StaticToken + KeycloakBroker)

**Files:**
- Create: `go/internal/catalog/credential.go`
- Test: `go/internal/catalog/credential_test.go`

- [ ] **Step 1: Write the failing test**

```go
// go/internal/catalog/credential_test.go
package catalog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticToken(t *testing.T) {
	st := StaticToken{Tokens: map[string]string{"github": "ghp_abc"}}

	tok, err := st.GetToken(context.Background(), "ignored-subject", "github")
	require.NoError(t, err)
	assert.Equal(t, "ghp_abc", tok)

	_, err = st.GetToken(context.Background(), "", "slack")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCredentialUnavailable))
}

func TestKeycloakBrokerGetToken(t *testing.T) {
	t.Run("returns access_token from JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/broker/github/token", r.URL.Path)
			assert.Equal(t, "Bearer kc-access-token", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gho_live","token":"raw","response":{}}`))
		}))
		defer srv.Close()

		b := &KeycloakBroker{RealmURL: srv.URL, HTTP: srv.Client()}
		tok, err := b.GetToken(context.Background(), "kc-access-token", "github")
		require.NoError(t, err)
		assert.Equal(t, "gho_live", tok)
	})

	t.Run("401 maps to ErrCredentialUnavailable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		b := &KeycloakBroker{RealmURL: srv.URL, HTTP: srv.Client()}
		_, err := b.GetToken(context.Background(), "kc-access-token", "github")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrCredentialUnavailable))
	})
}

func TestParseBrokerToken(t *testing.T) {
	t.Run("json access_token preferred", func(t *testing.T) {
		tok, err := parseBrokerToken("application/json", []byte(`{"access_token":"a","token":"b"}`))
		require.NoError(t, err)
		assert.Equal(t, "a", tok)
	})
	t.Run("json token fallback", func(t *testing.T) {
		tok, err := parseBrokerToken("application/json", []byte(`{"token":"b"}`))
		require.NoError(t, err)
		assert.Equal(t, "b", tok)
	})
	t.Run("form-encoded access_token", func(t *testing.T) {
		tok, err := parseBrokerToken("application/x-www-form-urlencoded", []byte(`access_token=c&scope=repo&token_type=bearer`))
		require.NoError(t, err)
		assert.Equal(t, "c", tok)
	})
	t.Run("empty body errors", func(t *testing.T) {
		_, err := parseBrokerToken("application/json", []byte(`{}`))
		require.Error(t, err)
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/catalog/ -run 'TestStaticToken|TestKeycloakBroker|TestParseBrokerToken' -v`
Expected: FAIL — `undefined: StaticToken`, `KeycloakBroker`, `ErrCredentialUnavailable`, `parseBrokerToken`.

- [ ] **Step 3: Write minimal implementation**

```go
// go/internal/catalog/credential.go
package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrCredentialUnavailable signals that no usable token could be obtained for a
// provider (e.g. the user has not linked the account, or the broker rejected the
// request). Handlers surface this as a "link your account" message, distinct from
// an authorization denial.
var ErrCredentialUnavailable = errors.New("credential unavailable")

// CredentialProvider returns a usable third-party access token for a provider.
//
// subjectToken is the caller's Keycloak access token; brokered providers use it
// to authenticate to the /broker/{alias}/token endpoint. Static providers ignore it.
type CredentialProvider interface {
	GetToken(ctx context.Context, subjectToken, provider string) (string, error)
}

// StaticToken serves pre-configured tokens (PATs, bearer tokens). Fallback only.
type StaticToken struct {
	Tokens map[string]string
}

func (s StaticToken) GetToken(_ context.Context, _ string, provider string) (string, error) {
	if t, ok := s.Tokens[provider]; ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: no static token for provider %q", ErrCredentialUnavailable, provider)
}

// KeycloakBroker retrieves a brokered external-IdP token via Keycloak.
// See: GET {RealmURL}/broker/{provider}/token (requires the broker read-token role).
type KeycloakBroker struct {
	RealmURL string // e.g. http://localhost:8080/realms/stratium
	HTTP     *http.Client
}

func (b *KeycloakBroker) GetToken(ctx context.Context, subjectToken, provider string) (string, error) {
	if b.HTTP == nil {
		b.HTTP = http.DefaultClient
	}
	endpoint := strings.TrimRight(b.RealmURL, "/") + "/broker/" + url.PathEscape(provider) + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build broker request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+subjectToken)
	req.Header.Set("Accept", "application/json")

	resp, err := b.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("broker request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return parseBrokerToken(resp.Header.Get("Content-Type"), body)
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return "", fmt.Errorf("%w: provider %q not linked or token not readable (status %d)", ErrCredentialUnavailable, provider, resp.StatusCode)
	default:
		return "", fmt.Errorf("broker returned status %d", resp.StatusCode)
	}
}

// parseBrokerToken extracts a usable access token from a /broker/{alias}/token
// response. Handles both JSON ({"access_token":...} or {"token":...}) and
// form-encoded (access_token=...) bodies, since the shape depends on the IdP.
func parseBrokerToken(contentType string, body []byte) (string, error) {
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return "", fmt.Errorf("parse form broker body: %w", err)
		}
		if t := vals.Get("access_token"); t != "" {
			return t, nil
		}
		return "", fmt.Errorf("%w: no access_token in broker response", ErrCredentialUnavailable)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("parse json broker body: %w", err)
	}
	if parsed.AccessToken != "" {
		return parsed.AccessToken, nil
	}
	if parsed.Token != "" {
		return parsed.Token, nil
	}
	return "", fmt.Errorf("%w: empty broker token response", ErrCredentialUnavailable)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd go && go test ./internal/catalog/ -run 'TestStaticToken|TestKeycloakBroker|TestParseBrokerToken' -race -v`
Expected: PASS (all subtests).

- [ ] **Step 5: Commit**

```bash
cd go && gofmt -w internal/catalog/credential.go internal/catalog/credential_test.go
git add go/internal/catalog/credential.go go/internal/catalog/credential_test.go
git commit -m "feat(catalog): add CredentialProvider with Keycloak broker + static token"
```

---

## Task 5: Config loader

**Files:**
- Create: `go/internal/catalog/config.go`
- Test: `go/internal/catalog/config_test.go`

- [ ] **Step 1: Write the failing test**

```go
// go/internal/catalog/config_test.go
package catalog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
      "enabled": true,
      "providers": ["github"],
      "github": {
        "repo_classifications": {
          "acme/secret-repo": {"classification": "CONFIDENTIAL", "hierarchy": "commercial"}
        },
        "default_classification": {"classification": "INTERNAL", "hierarchy": "commercial"}
      }
    }`), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "github", cfg.GitHub.BrokerAlias)          // default applied
	assert.Equal(t, "https://api.github.com", cfg.GitHub.BaseURL) // default applied

	c := cfg.Classifier()
	got, err := c.Resolve("acme/secret-repo")
	require.NoError(t, err)
	assert.Equal(t, "CONFIDENTIAL", got.Classification)
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/catalog/ -run TestLoadConfig -v`
Expected: FAIL — `undefined: Load`, `cfg.GitHub`, `Classifier()`.

- [ ] **Step 3: Write minimal implementation**

```go
// go/internal/catalog/config.go
package catalog

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the opt-in SaaS catalog configuration, loaded from a JSON file
// (default off). Path comes from the -catalog-config flag / STRATIUM_CATALOG_CONFIG.
type Config struct {
	Enabled   bool         `json:"enabled"`
	Providers []string     `json:"providers"`
	GitHub    GitHubConfig `json:"github"`
}

// GitHubConfig configures the GitHub catalog provider.
type GitHubConfig struct {
	BrokerAlias           string                    `json:"broker_alias"`
	BaseURL               string                    `json:"base_url"`
	DefaultClassification *Classification           `json:"default_classification"`
	RepoClassifications   map[string]Classification `json:"repo_classifications"`
}

// Load reads and validates the catalog config file, applying defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse catalog config: %w", err)
	}
	if cfg.GitHub.BrokerAlias == "" {
		cfg.GitHub.BrokerAlias = "github"
	}
	if cfg.GitHub.BaseURL == "" {
		cfg.GitHub.BaseURL = "https://api.github.com"
	}
	return &cfg, nil
}

// Classifier builds a Classifier from the GitHub repo map + default.
func (c *Config) Classifier() *Classifier {
	return NewClassifier(c.GitHub.RepoClassifications, c.GitHub.DefaultClassification)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd go && go test ./internal/catalog/ -run TestLoadConfig -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd go && gofmt -w internal/catalog/config.go internal/catalog/config_test.go
git add go/internal/catalog/config.go go/internal/catalog/config_test.go
git commit -m "feat(catalog): add JSON config loader with defaults"
```

---

## Task 6: GitHub REST client

**Files:**
- Create: `go/internal/catalog/github/client.go`
- Test: `go/internal/catalog/github/client_test.go`

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/catalog/github/ -run TestRESTClient -v`
Expected: FAIL — `undefined: NewRESTClient`.

- [ ] **Step 3: Write minimal implementation**

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd go && go test ./internal/catalog/github/ -run TestRESTClient -race -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
cd go && gofmt -w internal/catalog/github/client.go internal/catalog/github/client_test.go
git add go/internal/catalog/github/client.go go/internal/catalog/github/client_test.go
git commit -m "feat(catalog/github): add GitHub REST client (read/search/issue/delete)"
```

---

## Task 7: GitHub tool specs + handlers (orchestration)

This is the heart of the framework: the classify → authorize → credential → API → result-map flow, as pure functions testable with fakes.

**Files:**
- Create: `go/internal/catalog/github/tools.go`
- Test: `go/internal/catalog/github/tools_test.go`

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/catalog/github/ -run 'TestSpecs|TestReadFile|TestMissing' -v`
Expected: FAIL — `undefined: ToolSpec`, `Specs`, `Deps`.

- [ ] **Step 3: Write minimal implementation**

```go
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

func strProp(desc string) mcp.PropertySchema { return mcp.PropertySchema{Type: "string", Description: desc} }

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd go && go test ./internal/catalog/github/ -race -v`
Expected: PASS (all client + tools tests).

- [ ] **Step 5: Commit**

```bash
cd go && gofmt -w internal/catalog/github/tools.go internal/catalog/github/tools_test.go
git add go/internal/catalog/github/tools.go go/internal/catalog/github/tools_test.go
git commit -m "feat(catalog/github): add classification-gated tool handlers"
```

---

## Task 8: Wire the catalog into the Registry and main.go

**Files:**
- Create: `go/internal/tools/catalog_github.go`
- Modify: `go/internal/tools/registry.go` (add fields + call in `RegisterAll`)
- Modify: `go/cmd/stratium-mcp/main.go` (add flag + wiring)
- Test: `go/internal/tools/catalog_github_test.go`

- [ ] **Step 1: Write the failing test**

This test verifies the `gatewayAuthorizer` reason-extraction and that `SetCatalog`/registration is gated by `Enabled`. It uses a fake gateway-like decision via the catalog interfaces directly (the adapter logic that maps gateway responses is covered here).

```go
// go/internal/tools/catalog_github_test.go
package tools

import (
	"testing"

	ag "stratium/services/agent-gateway"

	"github.com/stretchr/testify/assert"
)

func TestExtractReason(t *testing.T) {
	t.Run("prefers delegation reason and appends denied principal", func(t *testing.T) {
		resp := &ag.ExecuteActionResponse{
			Authorized: false,
			Decision: &ag.CompoundDecision{
				DelegationReason: "tier exceeds cap",
				DeniedPrincipal:  "delegation",
			},
		}
		assert.Equal(t, "tier exceeds cap (denied by delegation)", extractReason(resp))
	})

	t.Run("falls back to error field", func(t *testing.T) {
		resp := &ag.ExecuteActionResponse{Authorized: false, Error: "boom"}
		assert.Equal(t, "boom", extractReason(resp))
	})
}
```

> NOTE: confirm the exact type names `ag.ExecuteActionResponse` and `ag.CompoundDecision` and their fields (`DelegationReason`, `AgentReason`, `UserReason`, `DeniedPrincipal`) against `go/services/agent-gateway/` — `actions.go:122-137` reads `resp.Decision.DelegationReason` etc., so these exist; adjust the struct-literal field names in the test if the concrete type differs.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/tools/ -run TestExtractReason -v`
Expected: FAIL — `undefined: extractReason`.

- [ ] **Step 3a: Create the glue file**

```go
// go/internal/tools/catalog_github.go
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	ag "stratium/services/agent-gateway"

	"stratium/internal/catalog"
	"stratium/internal/catalog/github"
	"stratium/internal/mcp"
)

// gatewayAuthorizer adapts the Agent Gateway client to catalog.Authorizer.
type gatewayAuthorizer struct{ r *Registry }

func (g gatewayAuthorizer) Authorize(ctx context.Context, req catalog.AuthRequest) (catalog.AuthDecision, error) {
	resp, err := g.r.gateway.ExecuteAction(ctx, g.r.accessToken(), g.r.userID(), &ag.ExecuteActionRequest{
		DelegationToken:    req.DelegationToken,
		ToolName:           req.ToolName,
		Action:             req.Action,
		ActionTier:         ag.ActionTier(req.ActionTier),
		ResourceAttributes: req.ResourceAttributes,
	})
	if err != nil {
		return catalog.AuthDecision{}, fmt.Errorf("execute_action RPC failed: %w", err)
	}
	return catalog.AuthDecision{Authorized: resp.Authorized, Reason: extractReason(resp)}, nil
}

// extractReason mirrors the reason logic in handleExecuteAction (actions.go).
func extractReason(resp *ag.ExecuteActionResponse) string {
	reason := ""
	if resp.Decision != nil {
		switch {
		case resp.Decision.DelegationReason != "":
			reason = resp.Decision.DelegationReason
		case resp.Decision.AgentReason != "":
			reason = resp.Decision.AgentReason
		case resp.Decision.UserReason != "":
			reason = resp.Decision.UserReason
		}
		if resp.Decision.DeniedPrincipal != "" {
			reason = fmt.Sprintf("%s (denied by %s)", reason, resp.Decision.DeniedPrincipal)
		}
	}
	if resp.Error != "" {
		reason = resp.Error
	}
	return reason
}

// SetCatalog enables the SaaS tool catalog with its dependencies. Call before RegisterAll.
func (r *Registry) SetCatalog(cfg *catalog.Config, creds catalog.CredentialProvider, classifier *catalog.Classifier, gh github.Client) {
	r.catalog = cfg
	r.creds = creds
	r.classifier = classifier
	r.gh = gh
}

// registerCatalogTools registers SaaS catalog tools when the catalog is enabled.
func (r *Registry) registerCatalogTools(server *mcp.Server) {
	if r.catalog == nil || !r.catalog.Enabled {
		return
	}
	deps := github.Deps{
		Auth:   gatewayAuthorizer{r},
		Creds:  r.creds,
		Class:  r.classifier,
		Client: r.gh,
	}
	for _, spec := range github.Specs() {
		if err := catalog.GuardTier(spec.Action, spec.Tier); err != nil {
			r.logger.Fatalf("catalog tool %s failed tier guard: %v", spec.Tool.Name, err)
		}
		spec := spec // capture
		server.RegisterTool(spec.Tool, func(args json.RawMessage) (*mcp.ToolCallResult, error) {
			if err := r.ensureAuth(context.Background()); err != nil {
				return nil, err
			}
			out, err := spec.Handler(context.Background(), deps, r.accessToken(), r.session.DelegationToken, args)
			if err != nil {
				return nil, err
			}
			return mcp.SuccessResult(out)
		})
	}
	r.logger.Printf("catalog enabled: registered %d GitHub tools", len(github.Specs()))
}
```

- [ ] **Step 3b: Add catalog fields to the Registry struct**

In `go/internal/tools/registry.go`, modify the `Registry` struct (lines 16-23) to add catalog fields:

```go
// Registry holds tool definitions and the shared dependencies they need.
type Registry struct {
	gateway     *gateway.Client
	auth        *auth.Provider
	logger      *log.Logger
	session     *Session
	subAgentCfg *SubAgentConfig

	// SaaS tool catalog (opt-in; nil/disabled by default)
	catalog    *catalog.Config
	creds      catalog.CredentialProvider
	classifier *catalog.Classifier
	gh         github.Client
}
```

Add the imports to `registry.go` (it currently imports `stratium/internal/auth`, `stratium/internal/gateway`, `stratium/internal/mcp`):

```go
	"stratium/internal/catalog"
	"stratium/internal/catalog/github"
```

- [ ] **Step 3c: Call registerCatalogTools in RegisterAll**

In `go/internal/tools/registry.go`, modify `RegisterAll` (lines 71-76):

```go
// RegisterAll registers all tools on the MCP server.
func (r *Registry) RegisterAll(server *mcp.Server) {
	r.registerAgentTools(server)
	r.registerDelegationTools(server)
	r.registerActionTools(server)
	r.registerSubAgentTools(server)
	r.registerCatalogTools(server)
}
```

- [ ] **Step 4: Run the glue test + build**

Run: `cd go && go test ./internal/tools/ -run TestExtractReason -race -v && go build ./...`
Expected: PASS, and the whole module builds.

- [ ] **Step 5a: Wire main.go**

In `go/cmd/stratium-mcp/main.go`, add the flag (after the `tlsCA` flag, ~line 23):

```go
	catalogCfg := flag.String("catalog-config", envOrDefault("STRATIUM_CATALOG_CONFIG", ""), "Path to SaaS tool catalog config (JSON). Empty = catalog disabled.")
```

Pass it into `runMCPMode` (modify the call at ~line 45 and the signature at ~line 50):

```go
	default:
		runMCPMode(gwClient, logger, *keycloakURL, *clientID, *tokenCache, *gatewayAddr, *catalogCfg)
	}
```

```go
func runMCPMode(gwClient *gateway.Client, logger *log.Logger, keycloakURL, clientID, tokenCache, gatewayAddr, catalogCfgPath string) {
	authProvider := auth.NewProvider(auth.Config{
		KeycloakURL: keycloakURL,
		ClientID:    clientID,
		TokenCache:  tokenCache,
	}, logger)

	server := mcp.NewServer(logger)

	registry := tools.NewRegistry(gwClient, authProvider, logger)

	if catalogCfgPath != "" {
		cfg, err := catalog.Load(catalogCfgPath)
		if err != nil {
			logger.Fatalf("failed to load catalog config: %v", err)
		}
		if cfg.Enabled {
			broker := &catalog.KeycloakBroker{RealmURL: keycloakURL, HTTP: http.DefaultClient}
			ghClient := github.NewRESTClient(cfg.GitHub.BaseURL, http.DefaultClient)
			registry.SetCatalog(cfg, broker, cfg.Classifier(), ghClient)
		}
	}

	registry.RegisterAll(server)

	logger.Printf("stratium-mcp ready (gateway=%s)", gatewayAddr)

	if err := server.Run(); err != nil {
		logger.Fatalf("server error: %v", err)
	}
}
```

Add imports to `main.go` (`net/http`, and the two catalog packages):

```go
	"net/http"

	"stratium/internal/catalog"
	"stratium/internal/catalog/github"
```

> NOTE: the old `logger.Printf("... tools=%d", ..., 14)` hardcoded the tool count; the replacement above drops the hardcoded count since the catalog makes it dynamic.

- [ ] **Step 5b: Build and commit**

Run: `cd go && goimports -w cmd/stratium-mcp/main.go internal/tools/registry.go internal/tools/catalog_github.go && go build ./... && go vet ./internal/... ./cmd/...`
Expected: builds clean, vet clean.

```bash
git add go/internal/tools/catalog_github.go go/internal/tools/catalog_github_test.go go/internal/tools/registry.go go/cmd/stratium-mcp/main.go
git commit -m "feat(catalog): wire catalog tools into stratium-mcp behind opt-in config"
```

---

## Task 9: Keycloak GitHub brokered IdP

**Files:**
- Modify: `keycloak/realm-export.json`

GitHub must be registered as a brokered Identity Provider with token storage so the broker token endpoint returns a usable token.

- [ ] **Step 1: Add the GitHub identity provider**

In `keycloak/realm-export.json`, locate the `"identityProviders"` array (if it does not exist at the realm object's top level, create it as a sibling of `"clients"`). Add this entry:

```json
{
  "alias": "github",
  "providerId": "github",
  "enabled": true,
  "storeToken": true,
  "addReadTokenRoleOnCreate": true,
  "trustEmail": true,
  "firstBrokerLoginFlowAlias": "first broker login",
  "config": {
    "clientId": "${GITHUB_OAUTH_CLIENT_ID}",
    "clientSecret": "${GITHUB_OAUTH_CLIENT_SECRET}",
    "defaultScope": "repo read:org",
    "useJwksUrl": "true"
  }
}
```

- [ ] **Step 2: Validate JSON**

Run: `python3 -c "import json,sys; json.load(open('keycloak/realm-export.json')); print('valid json')"`
Expected: `valid json`

- [ ] **Step 3: Document the OAuth app prerequisite**

Add a short note near the top of `demos/catalog-github/README.md` (created in Task 11) that the operator must:
1. Create a GitHub OAuth App with callback `{KEYCLOAK_URL}/realms/stratium/broker/github/endpoint`.
2. Set `GITHUB_OAUTH_CLIENT_ID` / `GITHUB_OAUTH_CLIENT_SECRET` in the Keycloak environment.
3. Each user links GitHub via the Keycloak Account Console (Account → Linked accounts → GitHub).

> NOTE: `addReadTokenRoleOnCreate: true` corresponds to the "Stored Tokens Readable" switch, granting the `broker` `read-token` role so the catalog can call `/broker/github/token`. The `${...}` placeholders require Keycloak env-var substitution at import; if your import path doesn't expand them, replace with literal values in a local override and keep them out of git.

- [ ] **Step 4: Commit**

```bash
git add keycloak/realm-export.json
git commit -m "feat(keycloak): add GitHub brokered IdP with stored, readable tokens"
```

---

## Task 10: Default policy templates

**Files:**
- Create: `go/internal/catalog/github/policies/github.json`
- Create: `go/internal/catalog/github/policies/github.cedar`

These are shipped reference templates an operator adopts or overrides. They are documentation/artifacts, not loaded by `stratium-mcp` directly.

- [ ] **Step 1: Write the JSON template**

```json
// go/internal/catalog/github/policies/github.json
{
  "name": "github-catalog-default",
  "description": "Default classification-aware policy for the GitHub catalog tools.",
  "rules": [
    {
      "tools": ["github_read_file", "github_search_code"],
      "effect": "allow",
      "conditions": { "max_action_tier": ">=1", "classification": "<=subject_cap" }
    },
    {
      "tools": ["github_create_issue"],
      "effect": "allow",
      "conditions": { "min_trust_tier": 1, "max_action_tier": ">=2", "classification": "<=subject_cap" }
    },
    {
      "tools": ["github_delete_branch"],
      "effect": "allow",
      "conditions": { "min_trust_tier": 2, "max_action_tier": ">=4", "classification": "<=subject_cap" }
    }
  ]
}
```

- [ ] **Step 2: Write the Cedar template**

```
// go/internal/catalog/github/policies/github.cedar
// Default classification-aware policy for the GitHub catalog tools.
// Adopt or override. Subject = agent acting under a delegation.

// Read & search: allowed within the subject's classification cap.
permit(
  principal,
  action in [Action::"github_read_file", Action::"github_search_code"],
  resource
) when {
  resource.classification <= principal.classification_cap
};

// Create issue: requires at least Registered trust tier.
permit(
  principal,
  action == Action::"github_create_issue",
  resource
) when {
  principal.trust_tier >= 1 &&
  resource.classification <= principal.classification_cap
};

// Delete branch (destructive): Certified+ trust tier and explicit tier-4 cap.
permit(
  principal,
  action == Action::"github_delete_branch",
  resource
) when {
  principal.trust_tier >= 2 &&
  principal.max_action_tier >= 4 &&
  resource.classification <= principal.classification_cap
};
```

- [ ] **Step 3: Verify files exist**

Run: `ls go/internal/catalog/github/policies/`
Expected: `github.cedar  github.json`

- [ ] **Step 4: Commit**

```bash
git add go/internal/catalog/github/policies/github.json go/internal/catalog/github/policies/github.cedar
git commit -m "docs(catalog/github): add default JSON + Cedar policy templates"
```

---

## Task 11: Demo

**Files:**
- Create: `demos/catalog-github/seed-catalog-demo.sh`
- Create: `demos/catalog-github/README.md`

The demo mirrors the existing `demos/mcp/seed-demo-data.sh` style and proves the success criteria: an allowed read + a denied (over-cap) read + a denied (out-of-scope/over-tier) delete.

- [ ] **Step 1: Write the demo script**

```bash
# demos/catalog-github/seed-catalog-demo.sh
#!/usr/bin/env bash
# Demo: classification-aware GitHub catalog via Stratium agent authorization.
# Prereqs: stratium-mcp built, Agent Gateway running, GitHub linked in Keycloak,
#          and a catalog config at ~/.stratium/catalog.json (see README).
set -euo pipefail

GW="${STRATIUM_GATEWAY_ADDRESS:-localhost:50054}"
echo "Using Agent Gateway: ${GW}"

cat <<'EOF'
This demo expects a delegation scoped to:
  approved_tools:    ["github_read_file", "github_create_issue"]
  max_action_tier:   2
  classification_cap: { commercial: "INTERNAL" }

Expected outcomes:
  1. github_read_file on an INTERNAL repo  -> ALLOWED
  2. github_read_file on a CONFIDENTIAL repo -> DENIED (classification > cap)
  3. github_delete_branch on any repo      -> DENIED (tool not in scope; tier 4 > cap)
EOF

echo
echo "Run these via your MCP client (Claude Code / Desktop) with stratium-mcp started as:"
echo "  stratium-mcp -catalog-config ~/.stratium/catalog.json"
echo
echo "Sample catalog config (~/.stratium/catalog.json):"
cat <<'EOF'
{
  "enabled": true,
  "providers": ["github"],
  "github": {
    "repo_classifications": {
      "your-org/internal-svc":  { "classification": "INTERNAL",     "hierarchy": "commercial" },
      "your-org/secret-svc":    { "classification": "CONFIDENTIAL", "hierarchy": "commercial" }
    },
    "default_classification": { "classification": "INTERNAL", "hierarchy": "commercial" }
  }
}
EOF
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x demos/catalog-github/seed-catalog-demo.sh && bash demos/catalog-github/seed-catalog-demo.sh`
Expected: prints the demo walkthrough without error.

- [ ] **Step 3: Write the README**

```markdown
<!-- demos/catalog-github/README.md -->
# GitHub Catalog Demo

Demonstrates Stratium's classification-aware GitHub catalog tools, authorized via
the Agent Gateway and credentialed via Keycloak identity brokering.

## Prerequisites

1. **GitHub OAuth App** with callback `{KEYCLOAK_URL}/realms/stratium/broker/github/endpoint`.
2. Keycloak env: `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` (see `keycloak/realm-export.json`).
3. Each user links GitHub: Keycloak Account Console -> Linked accounts -> GitHub.
4. A catalog config file (see `seed-catalog-demo.sh` for a sample) at `~/.stratium/catalog.json`.
5. Start the MCP server with `stratium-mcp -catalog-config ~/.stratium/catalog.json`.

## Tools

| Tool | Tier | Classification gate |
|---|---|---|
| `github_read_file` | 1 | repo classification <= cap |
| `github_search_code` | 1 | repo classification <= cap |
| `github_create_issue` | 2 | repo classification <= cap |
| `github_delete_branch` | 4 | repo classification <= cap; tier <= max_action_tier |

## Walkthrough

Run `bash seed-catalog-demo.sh` for the scoped delegation and expected allow/deny outcomes.
```

- [ ] **Step 4: Commit**

```bash
git add demos/catalog-github/seed-catalog-demo.sh demos/catalog-github/README.md
git commit -m "docs(demos): add GitHub catalog demo and walkthrough"
```

---

## Task 12: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full catalog test suite with race + coverage**

Run:
```bash
cd go && go test ./internal/catalog/... -race -cover
```
Expected: all PASS, coverage reported. Confirm `internal/catalog` and `internal/catalog/github` each report **≥80%** statement coverage.

- [ ] **Step 2: If coverage < 80%, add the missing-path tests**

Inspect uncovered lines:
```bash
cd go && go test ./internal/catalog/... -coverprofile=/tmp/cat.out && go tool cover -func=/tmp/cat.out
```
Add table-driven cases for any uncovered branch (e.g. `SearchCode` allow path, `CreateIssue`/`DeleteBranch` allow + denied paths, `KeycloakBroker` default-status branch). Re-run Step 1 until ≥80%.

- [ ] **Step 3: Vet + build the whole module**

Run:
```bash
cd go && go vet ./... && go build ./...
```
Expected: no output (clean), exit 0.

- [ ] **Step 4: Security scan (if gosec available)**

Run:
```bash
cd go && gosec ./internal/catalog/... 2>/dev/null || echo "gosec not installed — skipping (note in PR)"
```
Expected: no HIGH/MEDIUM findings on the new packages (token never logged; HTTP errors wrapped; no secrets in code).

- [ ] **Step 5: Manual end-to-end smoke (documented, run if a Keycloak + Gateway are available)**

1. Start Keycloak (with GitHub IdP) + Agent Gateway.
2. `stratium-mcp -catalog-config ~/.stratium/catalog.json` (config `enabled: true`).
3. Register an agent and create a delegation scoped to `["github_read_file","github_create_issue"]`, `max_action_tier: 2`, `classification_caps: {"commercial":"INTERNAL"}`.
4. Verify the three success-criteria outcomes (allowed INTERNAL read; denied CONFIDENTIAL read; denied delete_branch) and that audit rows appear with `tool_name` populated.

- [ ] **Step 6: Final commit (if Step 2 added tests)**

```bash
cd go && gofmt -w ./internal/catalog/...
git add go/internal/catalog/
git commit -m "test(catalog): raise coverage to >=80% across catalog packages"
```

---

## Self-review notes (for the implementer)

- **Spec coverage:** framework (Tasks 1–5, 8), GitHub tool tiers 1/2/4 (Tasks 6–7), Keycloak brokering (Tasks 4, 9), classification fail-closed (Tasks 1, 7), opt-in gate (Tasks 5, 8), policy templates (Task 10), error handling distinctions (Tasks 4, 6, 7), testing + demo (Tasks 7, 11, 12). Deferred items (refresh, tier-3 egress, other tools) are intentionally absent per the spec.
- **Type-name verification points (do not skip):** before Task 8, confirm `ag.ExecuteActionResponse` / `ag.CompoundDecision` field names in `go/services/agent-gateway/`; before Task 9, confirm the realm export's top-level shape. Both are flagged inline with `> NOTE`.
- **Provider-agnostic check (optional but recommended):** after Task 8, if `go/services/agent-gateway/cross_provider_test.go` is straightforward to extend, add a case asserting a `github_read_file` `ExecuteAction` authorizes identically for an Anthropic vs OpenAI calling agent — this guards the provider-agnostic token guarantee the catalog relies on.
