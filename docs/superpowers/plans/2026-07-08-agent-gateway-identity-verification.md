# Agent-Gateway Identity Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two CRITICAL auth-bypass findings in the agent-gateway by verifying the incoming OIDC bearer against the Keycloak JWKS and deriving the caller's identity only from verified claims — removing the spoofable `x-user-id` header and the unverified-JWT path.

**Architecture:** A new gateway-local unary interceptor verifies a present bearer via a `TokenVerifier` interface (real impl wraps the existing JWKS-verifying `pkg/auth.AuthService.ValidateToken`; tests inject a fake). It stores the verified identity in the request context; `extractUserID` reads only from that context. `main.go` builds the verifier from the shared `config.OIDCConfig` and fails closed at startup if the issuer is unconfigured.

**Tech Stack:** Go 1.25, gRPC unary interceptors, `github.com/coreos/go-oidc/v3` (via `pkg/auth`, already a dependency), `github.com/stretchr/testify`. Module path `stratium`.

---

## Design reference (read before starting)

Spec: `docs/superpowers/specs/2026-07-08-agent-gateway-identity-verification-design.md`.

Existing types to integrate with (do NOT reimplement):
- `pkg/auth` (`go/pkg/auth/auth.go`):
  - `func NewAuthService(config *config.OIDCConfig) (*AuthService, error)` — builds the JWKS verifier (does OIDC discovery, a network call).
  - `func (a *AuthService) ValidateToken(ctx, tokenString string) (*UserClaims, error)` — real signature/JWKS verification. **Do NOT** use `AuthService.AuthInterceptor()` or `MockValidateToken` — those fall back to unverified parsing and require a token on every RPC.
  - `auth.UserClaims{ Sub, PreferredUsername string; ... }`.
- `config.OIDCConfig` (`go/config/config.go:149`): `Enabled, IssuerURL, ClientID, ClientSecret, RedirectURL, Scopes, AllowInsecureIssuer, SkipClientIDCheck`. Available as `cfg.OIDC`.
- `go/services/agent-gateway/grpc_server.go`: `extractUserID(ctx)` (line 260, to rewrite), `subjectFromBearer` (line 282, to delete). Callers: `CreateDelegation` (line 33), `RegisterAgent` (line 124) — both surface the error as `codes.Unauthenticated`.
- `go/cmd/agent-gateway-server/main.go`: config load (line 54), agent-auth gate (line 60), `unaryInterceptors` slice (lines 135–138), `agent_gateway` already imported.

Package name for `go/services/agent-gateway/*.go` is `agent_gateway`. Run tests from `go/`:
```bash
cd go && go test ./services/agent-gateway/ -race -v
```

---

## File structure

| File | Responsibility |
|---|---|
| `go/services/agent-gateway/auth_interceptor.go` (create) | `TokenVerifier` interface; context helpers (`withIdentity`/`identityFromContext`); `oidcVerifier` + `NewOIDCVerifier` (wraps `pkg/auth`); `IdentityVerificationInterceptor`. |
| `go/services/agent-gateway/auth_interceptor_test.go` (create) | Interceptor + context-helper tests (fake verifier). |
| `go/services/agent-gateway/grpc_server.go` (modify) | Rewrite `extractUserID` to read verified identity from context; delete `subjectFromBearer` + `x-user-id` logic; drop now-unused imports. |
| `go/cmd/agent-gateway-server/main.go` (modify) | Build verifier from `cfg.OIDC`; fail-closed if issuer empty; register the interceptor. |

---

## Task 1: Verifier interface, context helpers, and interceptor

**Files:**
- Create: `go/services/agent-gateway/auth_interceptor.go`
- Test: `go/services/agent-gateway/auth_interceptor_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// go/services/agent-gateway/auth_interceptor_test.go
package agent_gateway

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeVerifier struct {
	identity string
	err      error
	called   bool
}

func (f *fakeVerifier) Verify(_ context.Context, _ string) (string, error) {
	f.called = true
	return f.identity, f.err
}

func TestIdentityContextRoundTrip(t *testing.T) {
	ctx := withIdentity(context.Background(), "alice")
	id, ok := identityFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "alice", id)

	_, ok = identityFromContext(context.Background())
	assert.False(t, ok)

	_, ok = identityFromContext(withIdentity(context.Background(), ""))
	assert.False(t, ok, "empty identity must be treated as absent")
}

func TestInterceptorValidToken(t *testing.T) {
	fv := &fakeVerifier{identity: "alice"}
	var gotIdentity string
	handler := func(ctx context.Context, _ any) (any, error) {
		gotIdentity, _ = identityFromContext(ctx)
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer good.jwt.token"))

	resp, err := IdentityVerificationInterceptor(fv)(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.Equal(t, "alice", gotIdentity)
	assert.True(t, fv.called)
}

func TestInterceptorInvalidTokenRejected(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("bad signature")}
	handlerCalled := false
	handler := func(_ context.Context, _ any) (any, error) {
		handlerCalled = true
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer forged.jwt"))

	_, err := IdentityVerificationInterceptor(fv)(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, handlerCalled, "handler must not run for an invalid token")
}

func TestInterceptorNoTokenPassesThroughWithoutIdentity(t *testing.T) {
	fv := &fakeVerifier{identity: "unused"}
	var hadIdentity bool
	handler := func(ctx context.Context, _ any) (any, error) {
		_, hadIdentity = identityFromContext(ctx)
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs())

	resp, err := IdentityVerificationInterceptor(fv)(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.False(t, hadIdentity)
	assert.False(t, fv.called, "verifier must not be called without a bearer")
}

func TestInterceptorIgnoresXUserID(t *testing.T) {
	fv := &fakeVerifier{}
	var hadIdentity bool
	handler := func(ctx context.Context, _ any) (any, error) {
		_, hadIdentity = identityFromContext(ctx)
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("x-user-id", "admin"))

	_, err := IdentityVerificationInterceptor(fv)(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)
	assert.False(t, hadIdentity, "x-user-id must NOT establish identity")
	assert.False(t, fv.called)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd go && go test ./services/agent-gateway/ -run 'TestIdentity|TestInterceptor' -v`
Expected: FAIL — `undefined: withIdentity`, `identityFromContext`, `IdentityVerificationInterceptor`.

- [ ] **Step 3: Write the implementation**

```go
// go/services/agent-gateway/auth_interceptor.go
package agent_gateway

import (
	"context"
	"strings"

	"stratium/config"
	"stratium/pkg/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenVerifier verifies a raw OIDC bearer token and returns the caller's
// identity (preferred_username, falling back to sub) from VERIFIED claims.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (string, error)
}

// identityCtxKey is the private context key for the verified caller identity.
type identityCtxKey struct{}

func withIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, identity)
}

// identityFromContext returns the verified identity set by the interceptor.
// An empty identity is treated as absent.
func identityFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(identityCtxKey{}).(string)
	return id, ok && id != ""
}

// oidcVerifier is the production TokenVerifier backed by the shared
// JWKS-verifying AuthService. It uses ValidateToken (real signature check) only —
// NOT AuthService.AuthInterceptor/MockValidateToken, which fall back to unverified
// parsing.
type oidcVerifier struct {
	svc *auth.AuthService
}

// NewOIDCVerifier builds a JWKS-backed verifier from the shared OIDC config.
// It performs OIDC discovery (a network call to the issuer); an unreachable issuer
// returns an error, which callers MUST treat as fatal (fail-closed).
func NewOIDCVerifier(oidcCfg *config.OIDCConfig) (TokenVerifier, error) {
	svc, err := auth.NewAuthService(oidcCfg)
	if err != nil {
		return nil, err
	}
	return &oidcVerifier{svc: svc}, nil
}

func (v *oidcVerifier) Verify(ctx context.Context, rawToken string) (string, error) {
	claims, err := v.svc.ValidateToken(ctx, rawToken)
	if err != nil {
		return "", err
	}
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername, nil
	}
	return claims.Sub, nil
}

// IdentityVerificationInterceptor verifies a present bearer token and stores the
// verified identity in the context. A present-but-invalid token is rejected on
// every RPC; an absent token passes through with no identity (handlers that
// require identity reject via extractUserID).
func IdentityVerificationInterceptor(v TokenVerifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if authz := md.Get("authorization"); len(authz) > 0 {
				if raw := stripBearer(authz[0]); raw != "" {
					identity, err := v.Verify(ctx, raw)
					if err != nil {
						return nil, status.Errorf(codes.Unauthenticated, "token verification failed: %v", err)
					}
					ctx = withIdentity(ctx, identity)
				}
			}
		}
		return handler(ctx, req)
	}
}

func stripBearer(header string) string {
	h := strings.TrimSpace(header)
	h = strings.TrimPrefix(h, "Bearer ")
	h = strings.TrimPrefix(h, "bearer ")
	return strings.TrimSpace(h)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd go && go test ./services/agent-gateway/ -run 'TestIdentity|TestInterceptor' -race -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
cd go && goimports -w services/agent-gateway/auth_interceptor.go services/agent-gateway/auth_interceptor_test.go
git add go/services/agent-gateway/auth_interceptor.go go/services/agent-gateway/auth_interceptor_test.go
git commit -m "feat(agent-gateway): add JWKS token-verification interceptor and identity context"
```

---

## Task 2: Rewrite extractUserID to use verified identity; delete the spoofable paths

**Files:**
- Modify: `go/services/agent-gateway/grpc_server.go` (lines 260–306: `extractUserID` + `subjectFromBearer`)
- Test: `go/services/agent-gateway/auth_interceptor_test.go` (append)

- [ ] **Step 1: Write the failing test (append to auth_interceptor_test.go)**

```go
func TestExtractUserIDFromContext(t *testing.T) {
	id, err := extractUserID(withIdentity(context.Background(), "bob"))
	require.NoError(t, err)
	assert.Equal(t, "bob", id)

	_, err = extractUserID(context.Background())
	require.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify current behavior**

Run: `cd go && go test ./services/agent-gateway/ -run TestExtractUserIDFromContext -v`
Expected: FAIL — the current `extractUserID` reads metadata (not the context value), so `extractUserID(withIdentity(...))` returns an error instead of "bob".

- [ ] **Step 3: Rewrite `extractUserID` and delete `subjectFromBearer`**

In `go/services/agent-gateway/grpc_server.go`, replace the entire block from `func extractUserID(` through the end of `func subjectFromBearer(...)` (lines 260–306) with:

```go
// extractUserID returns the verified caller identity established by the
// IdentityVerificationInterceptor. It never trusts client-supplied metadata
// (e.g. x-user-id) or unverified tokens.
func extractUserID(ctx context.Context) (string, error) {
	if id, ok := identityFromContext(ctx); ok {
		return id, nil
	}
	return "", fmt.Errorf("no verified user identity in request context")
}
```

Then fix imports: `subjectFromBearer` was the only user of `strings` and `github.com/golang-jwt/jwt/v5`, and the old `extractUserID` was the only user of `google.golang.org/grpc/metadata`. Remove those three imports.

- [ ] **Step 4: Auto-remove unused imports and run tests**

Run:
```bash
cd go && goimports -w services/agent-gateway/grpc_server.go
go test ./services/agent-gateway/ -race -run 'TestExtractUserIDFromContext|TestInterceptor|TestIdentity' -v
```
Expected: PASS. If `goimports` isn't installed, manually delete the `strings`, `github.com/golang-jwt/jwt/v5`, and `google.golang.org/grpc/metadata` lines from the import block, then `go build ./services/agent-gateway/`.

- [ ] **Step 5: Confirm the whole package builds and the existing test still passes**

Run: `cd go && go build ./services/agent-gateway/ && go test ./services/agent-gateway/ -race`
Expected: build clean; PASS (including the pre-existing `cross_provider_test.go`).

- [ ] **Step 6: Commit**

```bash
git add go/services/agent-gateway/grpc_server.go go/services/agent-gateway/auth_interceptor_test.go
git commit -m "fix(agent-gateway): derive user identity only from verified context; remove x-user-id + unverified JWT"
```

---

## Task 3: Wire the verifier into the gateway server (fail-closed)

**Files:**
- Modify: `go/cmd/agent-gateway-server/main.go`

No unit test (this is process wiring that needs a live issuer); verified by build + the manual smoke in Task 4.

- [ ] **Step 1: Add the fail-closed check + verifier construction**

In `go/cmd/agent-gateway-server/main.go`, immediately AFTER the agent-auth feature check block (the `if !features.ShouldEnableAgentAuth() { ... }` ending at line 65), add:

```go
	// Fail-closed: identity verification requires an OIDC issuer. Without it the
	// gateway would have no way to verify caller identity — refuse to start.
	if cfg.OIDC.IssuerURL == "" {
		logger.Error("Agent Gateway requires OIDC issuer configuration for token verification (set oidc.issuer_url)")
		os.Exit(1)
	}
	tokenVerifier, err := agent_gateway.NewOIDCVerifier(&cfg.OIDC)
	if err != nil {
		logger.Error("Failed to initialize token verifier (is the OIDC issuer reachable?): %v", err)
		os.Exit(1)
	}
```

> NOTE: `err` is already declared in this scope (from `config.Load`), so `tokenVerifier, err := ...` reuses it — that compiles because `tokenVerifier` is new. If the compiler complains that `err` is unused/redeclared, change to two lines: `var vErr error; tokenVerifier, vErr = agent_gateway.NewOIDCVerifier(&cfg.OIDC); if vErr != nil { ... }`.

- [ ] **Step 2: Register the interceptor**

In the same file, change the `unaryInterceptors` slice (lines 135–138) to append the identity interceptor AFTER license + rate-limit:

```go
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		licenseEnforcer.UnaryServerInterceptor(),
		rateLimiter.UnaryServerInterceptor(),
		agent_gateway.IdentityVerificationInterceptor(tokenVerifier),
	}
```

- [ ] **Step 3: Build the whole module**

Run: `cd go && go build ./... && go vet ./cmd/agent-gateway-server/ ./services/agent-gateway/`
Expected: builds clean, vet clean.

> NOTE: `agent_gateway` is already imported in `main.go`; no new import is needed. `NewOIDCVerifier` performs OIDC discovery at startup, so the gateway now requires the Keycloak issuer to be reachable when it boots (document in deployment: gateway `depends_on` Keycloak healthy).

- [ ] **Step 4: Commit**

```bash
git add go/cmd/agent-gateway-server/main.go
git commit -m "feat(agent-gateway): enforce OIDC token verification interceptor; fail closed without issuer"
```

---

## Task 4: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build + vet + race-test the affected packages**

Run:
```bash
cd go
go build ./...
go vet ./services/agent-gateway/... ./cmd/agent-gateway-server/ ./pkg/auth/
go test ./services/agent-gateway/... -race -cover
```
Expected: build clean; vet clean; tests PASS.

- [ ] **Step 2: Confirm the spoofable paths are gone**

Run:
```bash
cd go && grep -rn "ParseUnverified\|x-user-id\|subjectFromBearer" services/agent-gateway/
```
Expected: NO matches (all three removed from the gateway). `internal/gateway/client.go` still sends `x-user-id` — that's harmless (the server ignores it) and out of scope.

- [ ] **Step 3: Full suite stays green**

Run: `cd go && go test ./... 2>&1 | grep -cE '^FAIL'`
Expected: `0`.

- [ ] **Step 4: Manual smoke (documented; run if a Keycloak + gateway are available)**

1. Configure `oidc.issuer_url` (e.g. `http://localhost:8080/realms/stratium`) and `oidc.allow_insecure_issuer: true` for local http; start the gateway. It should log startup (and would `os.Exit(1)` if the issuer were unset/unreachable).
2. Call `CreateDelegation` with a **valid** Keycloak access token as `authorization: Bearer …` → succeeds; the delegation's `user_id` is the token's `preferred_username`/`sub`.
3. Call `CreateDelegation` with `x-user-id: victim` and NO/forged bearer → `Unauthenticated` (identity cannot be spoofed).
4. Call `ExecuteAction` with only a delegation token (no user bearer) → still works (hook path preserved).

---

## Self-review notes (for the implementer)

- **Spec coverage:** JWKS verification + drop x-user-id (Tasks 1–2), verify-if-present/require-where-consumed (interceptor in Task 1 + `extractUserID` in Task 2 + the two callers unchanged), fail-closed startup (Task 3), reuse `pkg/auth` (Task 1), identity claim = `preferred_username`/`sub` from verified claims (Task 1 `oidcVerifier.Verify`), anti-spoofing + no-token + invalid-token tests (Task 1), removal verification (Task 4 Step 2). mTLS remains out of scope per the spec.
- **Access-token audience:** `pkg/auth.NewAuthService` sets the verifier from `config.OIDCConfig` (`SkipClientIDCheck`, `AllowInsecureIssuer`). Ensure the deployment's `oidc.skip_client_id_check` / audience matches how Keycloak issues access-token `aud` (mirror PAP's config). Signature + `iss` + `exp` are always enforced.
- **No test migration needed:** no existing test sets `x-user-id` or drives the gRPC identity path (only `cross_provider_test.go` exists and doesn't touch it).
