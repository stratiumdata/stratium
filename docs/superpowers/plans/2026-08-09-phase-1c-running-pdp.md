# Phase 1c — Thin Vertical Slice: a Running PDP

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Turn the verified decision library into a running binary — gRPC in, tenant-scoped database reads, chain validation, compound decision, tamper-evident audit row, decision out.

**Why now.** `services/cmd/` is empty, so `go build ./...` has never built a binary; it has been a type-check for 54 commits. `migrations.Up` has no caller and 0% coverage. The audit chain's `UNIQUE (tenant_id, prev_hash)` was added in response to a review finding and has never seen a concurrent writer. A thin slice exercises all three and makes the system demonstrable, so Phase 2 fills in a skeleton that works rather than building blind.

**Explicitly not in this slice:** token issuance, escalation, the four policy engines, tier-override loading from the database, mTLS, the PAP, and any PEP. Those are Phases 2–5.

## Global Constraints

- Go 1.25, module path `stratium`, module root `services/`. All `go` commands run from `services/`.
- **The principal leg always denies**, with the reason `principal: no policy engine configured (Phase 2)`. There is no configuration value, build tag, or flag that produces an allow. A bypass added for development is how the predecessor shipped `MockValidateToken` to production and earned a CRITICAL.
- **The tenant is configured at startup, never taken from the request.** The predecessor trusted a client-supplied `x-user-id` header and that was CRITICAL-2. This slice is a single-tenant deployment; per-request tenant identity arrives with OIDC in Phase 2.
- **Every database transaction sets `app.tenant_id` via `SET LOCAL`** before any query. RLS is the isolation boundary; a transaction that forgets it sees zero rows, which is the correct fail-closed default and must not be worked around.
- **A failed audit write denies the action** (spec D3). Not logged-and-continue.
- Strict root `.golangci.yml`. `go test -race ./...` and `golangci-lint run ./...` clean before every commit.
- Conventional commits.

---

## File Structure

| Path | Responsibility |
|---|---|
| `proto/pdp/v1/pdp.proto` | The `Decide` RPC and its messages |
| `services/internal/pdpgrpc/` | Generated code + the server implementation |
| `services/internal/config/config.go` | Environment-backed configuration |
| `services/internal/store/store.go` | Tenant-scoped repository: agent and chain loading |
| `services/internal/store/audit.go` | Hash-linked audit writer |
| `services/internal/policy/policy.go` | `PrincipalPolicy` interface + the deny-with-reason implementation |
| `services/cmd/stratium-pdp/main.go` | Wiring: config → database → migrations → gRPC |
| `deploy/docker/docker-compose.yml` | Postgres + the PDP |
| `services/internal/store/store_integration_test.go` | End-to-end against a real database |

---

### Task 1: Configuration

**Files:** create `services/internal/config/config.go`, `config_test.go`

**Produces:** `type Config struct`, `func Load() (Config, error)`

- [ ] **Step 1: Write the failing test**

Cover: every field populated from environment; a missing `STRATIUM_DATABASE_URL` is an error naming the variable; a missing `STRATIUM_TENANT_ID` is an error; defaults apply for the optional fields; and `MaxDelegationDepth` rejects a value below 1.

- [ ] **Step 2: Run it, confirm it fails on `undefined: Load`**

- [ ] **Step 3: Implement**

```go
// Package config loads the PDP's configuration from the environment.
//
// Required values have no defaults. A PDP that starts with a guessed database
// URL or a guessed tenant is worse than one that refuses to start.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL string        // STRATIUM_DATABASE_URL (required)
	TenantID    string        // STRATIUM_TENANT_ID (required)
	ListenAddr  string        // STRATIUM_LISTEN_ADDR, default ":50051"
	MaxDepth    int           // STRATIUM_MAX_DELEGATION_DEPTH, default 5
	DBTimeout   time.Duration // STRATIUM_DB_TIMEOUT, default 5s
}

func Load() (Config, error) {
	c := Config{
		ListenAddr: envOr("STRATIUM_LISTEN_ADDR", ":50051"),
		MaxDepth:   5,
		DBTimeout:  5 * time.Second,
	}
	var err error

	if c.DatabaseURL = os.Getenv("STRATIUM_DATABASE_URL"); c.DatabaseURL == "" {
		return c, fmt.Errorf("STRATIUM_DATABASE_URL is required")
	}
	// The tenant is configuration, never request input. See the plan's global
	// constraints: the predecessor trusted a client-supplied header and that
	// was a critical authentication bypass.
	if c.TenantID = os.Getenv("STRATIUM_TENANT_ID"); c.TenantID == "" {
		return c, fmt.Errorf("STRATIUM_TENANT_ID is required")
	}
	if v := os.Getenv("STRATIUM_MAX_DELEGATION_DEPTH"); v != "" {
		if c.MaxDepth, err = strconv.Atoi(v); err != nil {
			return c, fmt.Errorf("STRATIUM_MAX_DELEGATION_DEPTH: %w", err)
		}
	}
	if c.MaxDepth < 1 {
		return c, fmt.Errorf("STRATIUM_MAX_DELEGATION_DEPTH must be at least 1, got %d", c.MaxDepth)
	}
	if v := os.Getenv("STRATIUM_DB_TIMEOUT"); v != "" {
		if c.DBTimeout, err = time.ParseDuration(v); err != nil {
			return c, fmt.Errorf("STRATIUM_DB_TIMEOUT: %w", err)
		}
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
```

- [ ] **Step 4: Run tests, confirm pass. Step 5: Commit.**

---

### Task 2: The principal policy seam

**Files:** create `services/internal/policy/policy.go`, `policy_test.go`

**Produces:** `type PrincipalPolicy interface`, `func Unconfigured() PrincipalPolicy`

The seam Phase 2 plugs four engines into. Today it has exactly one implementation and that implementation denies.

- [ ] **Step 1: Write the failing test**

Assert: `Unconfigured().Evaluate(...)` returns `EffectDeny`; the reason names the policy engine as the cause and mentions Phase 2; the reason is non-empty. Add a test asserting the package exports **no** implementation that returns `EffectAllow` — enumerate the package's exported constructors and fail if any produces an allow. That test is the guard against a bypass being added later.

- [ ] **Step 2: Run it, confirm it fails**

- [ ] **Step 3: Implement**

```go
// Package policy is the seam the policy engines plug into in Phase 2.
//
// It has one implementation today and that implementation denies. There is
// deliberately no allow-all variant, not even behind a flag: the predecessor
// carried a development-only auth fallback into production, where any OIDC
// blip silently accepted forged tokens. A bypass outlives the reason it was
// added.
package policy

import (
	"context"

	"stratium/internal/authz"
)

// PrincipalPolicy answers whether the principal may perform this action on this
// resource, independent of which agent is acting.
type PrincipalPolicy interface {
	Evaluate(ctx context.Context, p authz.Principal, action authz.Action, resource map[string]string) authz.LegResult
}

type unconfigured struct{}

// Unconfigured denies every request with a legible reason. It is the only
// implementation in Phase 1c.
func Unconfigured() PrincipalPolicy { return unconfigured{} }

func (unconfigured) Evaluate(context.Context, authz.Principal, authz.Action, map[string]string) authz.LegResult {
	return authz.LegResult{
		Effect: authz.EffectDeny,
		Reason: "principal: no policy engine configured (Phase 2)",
	}
}
```

- [ ] **Step 4: Run tests. Step 5: Commit.**

---

### Task 3: Tenant-scoped store

**Files:** create `services/internal/store/store.go`, `store_test.go`

**Produces:** `func New(db *sql.DB, tenantID string) *Store`, `func (*Store) LoadAgent(ctx, uuid.UUID) (authz.AgentInfo, error)`, `func (*Store) LoadChain(ctx, uuid.UUID) ([]*models.Delegation, error)`, `var ErrNotFound`

Every method runs inside a transaction that sets `app.tenant_id` first. RLS then does the isolation; the Go code does not add `WHERE tenant_id = ?` and must not rely on one.

- [ ] **Step 1: Write the failing test** — unit-level with `sqlmock` or equivalent, asserting that `SET LOCAL app.tenant_id` is issued before any `SELECT` in both methods, and that a missing row returns `ErrNotFound` rather than a zero value.

- [ ] **Step 2: Confirm it fails**

- [ ] **Step 3: Implement.** `LoadChain` walks `parent_delegation_id` from the given delegation up to the root, then reverses so the slice is root-first — the order `authz.ValidateChain` requires. Bound the walk at 64 hops and return an error beyond it, so a cycle introduced by a bad write cannot hang the PDP.

- [ ] **Step 4: Run tests. Step 5: Commit.**

---

### Task 4: Hash-linked audit writer

**Files:** create `services/internal/store/audit.go`, `audit_test.go`

**Produces:** `func (*Store) AppendAudit(ctx, audit.Entry) error`

Reads the tenant's current chain tail, links the new entry via `audit.Link`, computes `Hash()`, and inserts. Returns an error on any failure — the caller denies on error.

- [ ] **Step 1: Write the failing test** covering: the first entry for a tenant links to `ZeroHash`; a subsequent entry links to its predecessor's hash; `entry_hash` is stored as the computed digest; and a unique-violation on `(tenant_id, prev_hash)` surfaces as an error rather than being swallowed.

- [ ] **Step 2: Confirm it fails. Step 3: Implement. Step 4: Confirm pass. Step 5: Commit.**

Note the concurrency shape: `UNIQUE (tenant_id, prev_hash)` means two writers racing on the same tail produce one success and one unique violation. That is the constraint working. Do not add a retry loop in this slice — surface the error, and record in the report that Phase 2 needs a documented strategy (serialized append, advisory lock, or retry).

---

### Task 5: Proto and gRPC server

**Files:** create `proto/pdp/v1/pdp.proto`, `services/internal/pdpgrpc/server.go`, `server_test.go`; add codegen to the Makefile

**Produces:** `DecideRequest`/`DecideResponse` messages, `PDPService`, `func NewServer(...) *Server`

The request carries: `delegation_id`, `agent_id`, `subject`, `tool`, `verb`, `raw_input`, `declared_tier` (optional), and `resource` attributes. **It does not carry a tenant** — that is configuration — **and it does not carry a principal decision.**

The response carries: `effect`, `derived_tier`, per-leg effect and reason, `denied_leg`, `denied_at_depth`, and `reason`.

- [ ] **Step 1: Write the proto.** Comment on `DecideRequest` stating that tenant and principal decision are deliberately absent and why.

- [ ] **Step 2: Add a `make proto` target and generate.**

- [ ] **Step 3: Write the failing server test** — a table over: a well-formed request that reaches a decision; an unknown delegation ID → `NotFound`; an unknown agent → `NotFound`; a malformed UUID → `InvalidArgument`; and an audit-write failure → the RPC fails and **no allow is returned**.

- [ ] **Step 4: Implement `Decide`.** Order: parse and validate inputs → load agent → load chain → build `authz.Request` with the configured tenant and the policy's principal verdict → `authz.Decide` → append audit → return. If the audit append fails, return an error; do not return the decision.

- [ ] **Step 5: Confirm pass. Step 6: Commit.**

---

### Task 6: The binary

**Files:** create `services/cmd/stratium-pdp/main.go`

- [ ] **Step 1: Implement.** Load config; open the database; run `migrations.Up`; construct store, policy, and server; serve gRPC with a health service registered; handle SIGINT/SIGTERM with graceful stop. Log the tenant and listen address at startup, and log plainly that the principal policy is unconfigured so nobody mistakes the resulting denials for a bug.

- [ ] **Step 2: `go build ./...`** — this is the first real `main` package in the repository, so expect it to surface issues the type-check has been hiding. Report anything it finds.

- [ ] **Step 3: Commit.**

---

### Task 7: Compose and the end-to-end proof

**Files:** create `deploy/docker/docker-compose.yml`, `services/internal/store/store_integration_test.go` (build-tagged `integration`); add a `make integration` target

- [ ] **Step 1: Write the compose file** — `postgres:16` with a healthcheck, and the PDP built from a Dockerfile, depending on the database being healthy.

- [ ] **Step 2: Write the integration test** (tag `integration`, skipped by default). Against a real database it must:
  1. run the migrations
  2. seed one agent and a two-hop delegation chain for the configured tenant
  3. call `Decide` over gRPC and assert **DENY** attributed to the principal leg with the unconfigured reason — this is the expected outcome and the point of the slice
  4. assert an audit row was written and that `audit.Verify` passes over the tenant's chain
  5. seed a second tenant's agent and assert the PDP cannot see it — a `NotFound`, proving RLS is doing the isolation rather than a `WHERE` clause
  6. assert that a delegation chain belonging to another tenant is rejected by `ValidateChain`

- [ ] **Step 3: Run it against compose and report the literal output.**

- [ ] **Step 4: Commit.**

---

## What this slice proves

- `go build ./...` builds a binary for the first time.
- `migrations.Up` runs against a real database from a real caller.
- RLS isolates by tenant with no `WHERE tenant_id` in the Go code.
- The audit chain accepts a real writer, links correctly, and verifies.
- `Decide` runs end to end and denies honestly, for a reason a human can read.

## What it deliberately does not prove

An ALLOW. Nothing in this slice can produce one, because the principal leg has no engine. That is the correct state of the system today, and a slice that faked it would be reporting a capability that does not exist.
