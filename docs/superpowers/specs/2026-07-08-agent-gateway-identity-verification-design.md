# Agent-Gateway Identity Verification — Design Spec

- **Date:** 2026-07-08
- **Status:** Approved for implementation planning
- **Severity:** Closes 2 CRITICAL authentication-bypass findings
- **Owner:** Stratium

---

## 1. Context & motivation

A push-time security review flagged two CRITICAL findings in the agent-gateway gRPC server
(`go/services/agent-gateway/grpc_server.go`):

1. **Spoofable identity** — `extractUserID` (line 260) trusts a client-supplied `x-user-id`
   metadata header as the caller's user identity.
2. **Unverified JWT** — the fallback `subjectFromBearer` (line 282) extracts the `sub` claim from
   the bearer token using `jwt.ParseUnverified` — **no signature check**. A developer comment at
   line 280 acknowledges this is a known shortcut ("Swap to jwt.ParseWithClaims + a JWKS-backed
   keyfunc to enforce verification").

The compound authorization decision is `user ∧ agent ∧ delegation`. The delegation token *is*
HMAC-signed and verified in the business logic, but the **user identity that anchors the chain** is
taken from unauthenticated input. Any caller able to reach the gateway can set
`x-user-id: <victim>` (or forge a JWT `sub`) and mint a delegation or register an agent **as another
user** — the user-policy layer is bypassable.

Callers already send a real Keycloak-issued OIDC access token as `authorization: Bearer`
(`go/internal/gateway/client.go` `withAuth`, line 61; token sourced from `~/.stratium/token.json`
via `internal/auth`). So the fix verifies a token that is already arriving and drops the redundant,
spoofable header — **no client-side change required**.

---

## 2. Scope

### In scope
- Verify the incoming OIDC bearer against the Keycloak realm JWKS (signature + `iss` + `exp`;
  audience handled as PAP does for access tokens).
- Derive the caller's user identity **only from verified claims**.
- Remove the `x-user-id` trust and the unverified-JWT path (`subjectFromBearer`) entirely.
- Fail-closed at startup if agent-auth is enabled without an OIDC issuer configured.

### Out of scope (documented follow-ups)
| Deferred | Why |
|---|---|
| Enforcing mTLS (`RequireAndVerifyClientCert`) on the gRPC listener | Deployment-impacting — local/docker gRPC is insecure-by-default today; token verification closes the identity bypass independent of transport. Track separately. |
| Dropping `x-user-id` from the gateway **client** (`withAuth`) | Harmless once the server ignores it; optional cleanup. |
| Sharing one interceptor between PAP and gateway | DRY, but widens blast radius of a security change; not now. |

---

## 3. Key decisions

| # | Decision | Chosen | Rationale |
|---|---|---|---|
| 1 | Scope | JWKS token verification + drop `x-user-id` | Closes the CRITICAL without changing the transport/deployment model. |
| 2 | Enforcement breadth | **Verify-if-present; require where consumed** | A present-but-invalid bearer is rejected on every RPC; identity is *required* only by `CreateDelegation`/`RegisterAgent`. Preserves the check-mode/hook `ExecuteAction` path that authorizes with a delegation-token-only call (no user bearer). |
| 3 | Fail mode | **Fail-closed at startup** | If `AgentGateway.Enabled` and no OIDC issuer configured → gateway refuses to start. No silent-bypass footgun. |
| 4 | Verifier | **Reuse `pkg/auth.AuthService`** behind a `TokenVerifier` interface | Mirrors the vetted PAP/SDK JWKS path; the interface is the test seam. No new crypto. |
| 5 | Identity claim | `preferred_username` (fallback `sub`) from **verified** claims | Same value used today (`internal/auth/oidc.go` `extractUserID`) and that delegations/audit are keyed on — now trustworthy. Avoids a data/semantics migration. |

---

## 4. Architecture & components

### 4.1 New file: `go/services/agent-gateway/auth_interceptor.go`
- **`TokenVerifier` interface** (the testable seam):
  ```go
  type TokenVerifier interface {
      // Verify validates a raw bearer token and returns the caller's identity
      // (preferred_username, fallback sub) from verified claims.
      Verify(ctx context.Context, rawToken string) (identity string, err error)
  }
  ```
- **Real implementation** wrapping `pkg/auth.AuthService`: constructs the JWKS verifier from the
  shared `config.OIDCConfig` (issuer, `AllowInsecureIssuer`, audience/`SkipClientIDCheck` mirrored
  from PAP), calls `ValidateToken`, and returns `preferred_username` (fallback `sub`).
- **`UnaryServerInterceptor(v TokenVerifier) grpc.UnaryServerInterceptor`**:
  - Read `authorization` from incoming metadata.
  - **Present** → strip `Bearer `, `v.Verify(...)`; on error → `status.Error(codes.Unauthenticated, …)`
    (handler never runs); on success → `ctx = context.WithValue(ctx, identityKey, identity)`.
  - **Absent** → call the handler with `ctx` unchanged (no identity).
- **`identityFromContext(ctx) (string, bool)`** helper + an unexported `identityKey` type.

### 4.2 Modify: `go/services/agent-gateway/grpc_server.go`
- `extractUserID(ctx)` reads the verified identity via `identityFromContext`; missing → error
  (surfaced as `codes.Unauthenticated` by the existing call sites at lines 33, 124).
- **Delete** `subjectFromBearer` and the `x-user-id` / `ParseUnverified` logic; drop the now-unused
  `jwt`/`metadata` imports if no longer referenced.

### 4.3 Modify: `go/cmd/agent-gateway-server/main.go`
- Build the `TokenVerifier` from `cfg.OIDC` at startup.
- **Fail-closed check:** if `cfg.AgentGateway.Enabled && cfg.OIDC.IssuerURL == ""` →
  `logger.Fatal("agent-gateway requires OIDC issuer configuration for token verification")`.
- Append the interceptor to the existing chain (after the license + rate-limit interceptors,
  ~lines 135–148).

### 4.4 Config
Reuse the shared `config.OIDCConfig` (`config.go:149–158`: `IssuerURL`, `ClientID`,
`AllowInsecureIssuer`, `SkipClientIDCheck`). No new config struct. The gateway process already loads
the full `Config`, so `cfg.OIDC` is available.

---

## 5. Data flow

```
Client (MCP)  ──gRPC──►  authorization: Bearer <keycloak access token>   (x-user-id ignored)
                              │
                              ▼
              Auth interceptor (auth_interceptor.go)
                bearer present ─► Verify(JWKS sig + iss + exp)
                                    ├─ invalid ─► codes.Unauthenticated  (handler NOT run)
                                    └─ valid   ─► ctx += verified identity
                bearer absent  ─► pass through (no identity)
                              │
                              ▼
              RPC handler (grpc_server.go)
                CreateDelegation / RegisterAgent ─► extractUserID(ctx)
                     identity present ─► proceed
                     identity absent  ─► codes.Unauthenticated
                ExecuteAction / ValidateActionPlan / … ─► use delegation token (HMAC-verified), as today
```

---

## 6. Error handling (fail-closed)

| Condition | Result |
|---|---|
| Bearer present but invalid (bad sig / expired / wrong issuer) | `codes.Unauthenticated` at interceptor, **all** RPCs — never ignored |
| Bearer absent + identity-requiring RPC (`CreateDelegation`, `RegisterAgent`) | `codes.Unauthenticated` at `extractUserID` |
| Bearer absent + delegation-only RPC (`ExecuteAction`, …) | proceeds; delegation token verified in business logic (unchanged) |
| JWKS unreachable / token unverifiable | deny (`Unauthenticated`); go-oidc caches JWKS to absorb transient blips |
| Spoofed `x-user-id` with no/invalid bearer | **no identity** — the header is dead (bug closed) |
| Agent-auth enabled, OIDC issuer unconfigured | **fatal at startup** |

---

## 7. Testing

The `TokenVerifier` interface removes the need for a live Keycloak in unit tests.

- **Interceptor** (fake verifier): valid token → identity in context + handler runs; invalid token →
  `Unauthenticated` + handler **not** called; no `authorization` → handler runs with no identity.
- **`extractUserID`**: context with identity → returns it; without → error.
- **Anti-spoofing regression**: metadata carries `x-user-id` but no/invalid bearer → **no identity**
  (proves the spoofable header no longer grants identity).
- **Migration:** grep gateway tests for `x-user-id`; any that inject it to satisfy
  `CreateDelegation`/`RegisterAgent` are switched to the context-based identity (via the interceptor
  with a fake verifier, or a test helper that seeds `identityKey`).
- **Gate:** whole module builds; `go test ./services/agent-gateway/... -race` passes; `go vet` clean.

---

## 8. Risks & open questions

| Risk | Notes |
|---|---|
| **Access-token audience** | go-oidc's verifier checks `aud == ClientID` by default; Keycloak access tokens carry `aud: account`/resource + `azp: client`. The gateway's OIDC config MUST mirror PAP's handling (confirm PAP's `SkipClientIDCheck`/audience setting and match it). Signature + `iss` + `exp` are the security-critical checks. |
| **Issuer URL vs docker** | In docker-compose the gateway reaches Keycloak by service name, but the token's `iss` may be `http://localhost:8080/...`. Configure the gateway's issuer to match the token `iss` (or use `AllowInsecureIssuer` for local http). Classic Keycloak `frontendUrl` pitfall — call out in deployment docs. |
| **Test migration** | Existing gateway tests that set `x-user-id` will fail until updated to the context-based identity. Bounded and mechanical. |
| **mTLS still not enforced** | This fix does not add transport-level client-cert verification; the gateway should still sit behind mTLS from trusted callers. Tracked as a separate follow-up (§2). |

---

## 9. Success criteria

- A forged/altered bearer (bad signature) or a spoofed `x-user-id` **cannot** establish a user
  identity — `CreateDelegation`/`RegisterAgent` reject with `Unauthenticated`.
- A valid Keycloak access token establishes the caller's identity (`preferred_username`/`sub`),
  and `CreateDelegation`/`RegisterAgent` proceed as before.
- `ExecuteAction` with a delegation token and **no** user bearer still works (hook path preserved).
- The gateway refuses to start when agent-auth is enabled without an OIDC issuer.
- `subjectFromBearer` / `ParseUnverified` / `x-user-id` trust are gone from the codebase.
- Module builds; gateway tests pass (race + vet clean).

---

## 10. Downstream

The `TokenVerifier` seam and the interceptor establish the pattern for the deferred **mTLS
enforcement** follow-up (transport-level peer identity as a second layer) and for any future
service-to-service identity path, without re-touching the handlers.
