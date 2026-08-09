# Agent Authorization — Phase 0 + 1 (Scaffold & Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the new Stratium repository with CI gated on authorization conformance properties, a tenant-scoped schema, a tamper-evident audit chain, and `internal/authz` — the single pure package where every authorization decision is computed.

**Architecture:** Greenfield build in `~/Development/stratium-data` (spec §3.7 G1). A Go workspace at the root with the module under `services/`; `clients/`, `deploy/`, `proto/`, and `docs/` alongside. Domain types are written fresh rather than ported, so tenancy and the new decision vocabulary are structural rather than retrofitted. `internal/authz` is pure — data in, decision out — because three drifting decision engines in the previous system is the specific failure this design exists to prevent.

**Tech Stack:** Go 1.25, PostgreSQL 16, `golang-migrate`, `golangci-lint`, `gitleaks`, GitHub Actions.

## Global Constraints

- Go version is **1.25**. Module path is **`stratium`**. Imports are `stratium/internal/...`, `stratium/pkg/...`.
- The Go module root is **`services/`**. All `go` commands run from `services/`. `make` targets run from the repo root and `cd` for you.
- `internal/authz` is **pure**: no database handles, no network clients, no ambient clock. Time enters through an injected value. Data in, decision out.
- **Policy may only narrow, never widen.** If a mechanism could let a policy author *gain* authority, it is structural Go, not policy.
- **`EffectDeny` must be the zero value of `Effect`.** A leg that is never evaluated must deny, not permit. Do not reorder those constants.
- Every table carries `tenant_id TEXT NOT NULL`.
- Nothing is ported by copy. The old repo at `~/Development/stratium` is **read-only reference material** — read it freely, never modify it.
- Commit after every task. Conventional commits: `<type>: <description>`.
- Spec of record: `docs/superpowers/specs/2026-08-08-agent-authorization-redesign-design.md`. Conformance IDs (C1–C25) refer to its §7.

## Standing action item — not a task in this plan

`~/Development/stratium/deployment/helm/stratium/values-rds.yaml:17,27,41` contains a live RDS password (`[REDACTED-old-RDS-password]`) and hostname, committed since that repo's first commit. Building a new repository does not close that exposure. **Rotate the credential and audit the RDS access logs.** It requires AWS access and is the repository owner's action.

---

## File Structure

Everything below is created new. Nothing is modified in the old repository.

| Path | Responsibility |
|---|---|
| `go.work` | Workspace: `use ./services` |
| `.golangci.yml` | Lint configuration |
| `.github/workflows/ci.yml` | Merge gate: build, test, vet, lint, race, secrets, conformance |
| `Makefile` | Root entry points; each target `cd`s into `services/` |
| `services/go.mod` | `module stratium` |
| `services/pkg/models/tier.go` | `ActionTier`, `AgentTrustTier` and their orderings |
| `services/pkg/models/agent.go` | `Agent` — registry record, tenant-scoped |
| `services/pkg/models/delegation.go` | `Delegation` and `ScopeNarrows` — the child ⊆ parent invariant |
| `services/pkg/classification/classification.go` | Hierarchies, `Index`, `CheckCap` — fail-closed cap enforcement |
| `services/pkg/audit/chain.go` | Hash-chain link computation and verification |
| `services/migrations/migrations.go` | `embed.FS` + `Up(db)` |
| `services/migrations/*.sql` | Versioned schema, tenant-scoped from the first migration |
| `services/internal/authz/types.go` | `Request`, `Result`, `LegResult`, `Effect` |
| `services/internal/authz/tier.go` | Tier derivation, resolution order, override validation |
| `services/internal/authz/agent.go` | Agent leg |
| `services/internal/authz/delegation.go` | Delegation leg |
| `services/internal/authz/compound.go` | Deny-overrides composition |
| `services/internal/authz/conformance_test.go` | C1–C25; unimplemented ones skip with their phase |

**Greenfield simplifications versus the original plan:** tenancy is in the first migration rather than a follow-on `ALTER`; `ScopeNarrows` is written correct rather than fixed; there is no dead code to prune and no dangling imports to chase.

**A Go toolchain quirk that shapes Tasks 1–3.** `go build ./...` treats "matched no packages" as a warning and exits 0; `go vet ./...` and `go test ./...` treat the same condition as a hard error and exit 1. `services/` holds no Go files until Task 4, so Tasks 1–3 verify configuration validity and job wiring rather than a passing gate. Do not add a placeholder `.go` file to make the gate go green — that is masking, and it leaves clutter for whoever writes the first real package. The gate is verified end to end at Task 16 Step 4, once every package exists.

---

# PHASE 0 — Scaffold

### Task 1: Repository scaffold

**Files:**
- Create: `.gitignore`, `Makefile`, `README.md`
- Verify: `go.work`, `services/go.mod`, directory tree

**Interfaces:**
- Consumes: nothing
- Produces: `make build`, `make test`, `make vet` run from the repo root; every later task relies on them

- [ ] **Step 1: Verify the scaffold already in place**

```bash
cd /path/to/stratium-data
cat go.work services/go.mod && find . -type d -not -path "./.git/*" -not -path "./.superpowers/*" | sort
```

(`-not -path "./.git*"` would also exclude `.github` — the glob matches both.)

Expected: `go.work` uses `./services`; `services/go.mod` declares `module stratium` and `go 1.25`; directories `clients`, `deploy/docker`, `deploy/postgres`, `docs/superpowers/{specs,plans}`, `proto`, `services/{cmd,internal,pkg,migrations}`, `.github/workflows` all exist.

- [ ] **Step 2: Write .gitignore**

```gitignore
# Build artifacts
/services/bin/
*.out
!**/testdata/*.out

# Terraform state — resource identifiers, sometimes secrets
*.tfstate
*.tfstate.*
.terraform/

# Local environment
.env
.env.*
!.env.example

# OS / editor
.DS_Store
.idea/
.vscode/

# Node (clients/ui, later phases)
node_modules/
dist/
```

- [ ] **Step 3: Write the Makefile**

```makefile
.DEFAULT_GOAL := help
GO_DIR := services

help: ## Show available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build all binaries
	cd $(GO_DIR) && go build ./...

test: ## Run tests with the race detector
	cd $(GO_DIR) && go test -race ./...

vet: ## Run go vet
	cd $(GO_DIR) && go vet ./...

fmt: ## Format Go code
	cd $(GO_DIR) && go fmt ./...

lint: ## Lint (requires golangci-lint)
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found: https://golangci-lint.run/welcome/install/"; exit 1; }
	cd $(GO_DIR) && golangci-lint run ./...

conformance: ## Run the authorization conformance suite (spec §7)
	cd $(GO_DIR) && go test ./internal/authz/ -run "TestC[0-9]" -v

.PHONY: help build test vet fmt lint conformance
```

- [ ] **Step 4: Write README.md**

```markdown
# Stratium

Multi-tenant authorization platform for AI agents. Decides, per action, whether a
specific agent — acting under a specific person's delegated authority, at a
specific point in a delegation chain — may perform a specific action.

## Layout

- `services/` — the Go module (`module stratium`). PDP, PAP, and PEP.
- `clients/` — Python SDK and admin UI.
- `deploy/` — Docker and Postgres setup.
- `proto/` — service contracts.
- `docs/` — design specs and implementation plans.

## Development

    make build      # compile
    make test       # tests with -race
    make lint       # golangci-lint
    make conformance  # authorization conformance properties

Design of record: `docs/superpowers/specs/2026-08-08-agent-authorization-redesign-design.md`
```

- [ ] **Step 5: Verify the toolchain works**

```bash
cd /path/to/stratium-data && make build && make vet && echo "SCAFFOLD OK"
```

Expected: `SCAFFOLD OK`. No Go files yet, so both are no-ops that prove the workspace resolves.

- [ ] **Step 6: Commit**

```bash
cd /path/to/stratium-data
git add -A
git commit -m "chore: scaffold the Stratium repository

Go workspace with the module under services/ (module stratium), plus
clients/, deploy/, proto/, and docs/. Greenfield per spec §3.7 G1."
```

---

# PHASE 1 — Foundation

### Task 2: Lint configuration

**Files:**
- Create: `.golangci.yml`

**Interfaces:**
- Consumes: `make lint` from Task 1
- Produces: a clean lint baseline; Task 3's CI job runs the same linters

- [ ] **Step 1: Write the configuration**

```yaml
version: "2"

run:
  timeout: 5m
  tests: true

linters:
  enable:
    - errcheck        # an ignored error on a decision path is a security bug
    - govet
    - ineffassign
    - staticcheck
    - unused
    - bodyclose
    - contextcheck
    - errorlint
    - gosec
    - nilerr          # returning nil after a non-nil error is fail-open in disguise
    - rowserrcheck
    - sqlclosecheck

  settings:
    errcheck:
      check-type-assertions: true

  exclusions:
    rules:
      - path: _test\.go
        linters: [gosec, errcheck]

formatters:
  enable:
    - gofmt
    - goimports
  settings:
    goimports:
      local-prefixes: [stratium]
```

There is no exclusion list for pre-existing debt. This repository has none, and adding one now would only invite it.

- [ ] **Step 2: Verify the configuration is valid**

There are no Go files under `services/` until Task 4, so the linter has nothing to analyze yet. What is verifiable now is that the config parses and the linter accepts it:

```bash
cd /path/to/stratium-data/services && golangci-lint config verify
```

Expected: the config validates. If golangci-lint is not installed, install it first — CI runs it regardless.

`make lint` will report "no go files to analyze" until Task 4 adds the first package; that is expected, not a failure of this task. The linter is exercised against real code from Task 4 onward, and the full gate is verified end to end at Task 16 Step 4.

- [ ] **Step 3: Commit**

```bash
git add .golangci.yml
git commit -m "ci: golangci-lint configuration"
```

---

### Task 3: CI pipeline

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Task 2's config
- Produces: the merge gate; Task 16 adds the conformance job to this file

- [ ] **Step 1: Write the workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  GO_VERSION: "1.25"

jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: services/go.sum
      - working-directory: services
        run: go build ./...

  test:
    name: Test (race)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: services/go.sum
      - working-directory: services
        run: go test -race ./...

  vet:
    name: Vet
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: services/go.sum
      - working-directory: services
        run: go vet ./...

  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: services/go.sum
      - uses: golangci/golangci-lint-action@v6
        with:
          version: latest
          working-directory: services

  secrets:
    name: Secret scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      # The gitleaks CLI, not gitleaks-action. The action calls GET /users/{owner}
      # and exits 1 before scanning if the owner is a GitHub Organization and
      # GITLEAKS_LICENSE is unset — the gate would fail on every run of an
      # org-owned repo. The CLI itself is MIT-licensed with no such gate.
      - name: gitleaks
        run: |
          curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
            | tar -xz -C /usr/local/bin gitleaks
          gitleaks git --no-banner --redact --verbose .
        env:
          GITLEAKS_VERSION: "8.24.3"
```

`gitleaks git` scans full history, which is why the checkout sets `fetch-depth: 0`. `--redact` keeps any finding out of the public log. The CLI exits non-zero on a finding, which fails the job — no `--exit-code` flag needed. Pin the version rather than tracking latest, so a new detection rule cannot turn an unrelated PR red.

The race detector runs the full suite. The previous system had a logger data race and TOCTOU races in provider code with nothing gating against them.

- [ ] **Step 2: Validate the YAML parses**

```bash
cd /path/to/stratium-data
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('YAML OK')"
```

Expected: `YAML OK`

- [ ] **Step 3: Verify the job wiring**

The gate cannot pass yet — `services/` holds no Go files until Task 4, and `go vet`/`go test` exit 1 on "no packages" (unlike `go build`, which exits 0). What is verifiable now is that every job names a real target and a real working directory:

```bash
cd /path/to/stratium-data
python3 - <<'PY'
import yaml
wf = yaml.safe_load(open('.github/workflows/ci.yml'))
jobs = wf['jobs']
assert set(jobs) == {'build','test','vet','lint','secrets'}, sorted(jobs)
for name, job in jobs.items():
    for step in job['steps']:
        if 'working-directory' in step:
            assert step['working-directory'] == 'services', (name, step)
        if step.get('uses','').startswith('actions/setup-go'):
            assert step['with']['cache-dependency-path'] == 'services/go.sum', name
print("WIRING OK")
PY
make build
```

Expected: `WIRING OK`, then `make build` exits 0.

The gate runs for real at Task 16 Step 4, once every package exists.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: build, test (race), vet, lint, and secret-scan pipeline"
```

---

### Task 4: Tier types

Written fresh. The old repo's `pkg/models/agent.go` is reference for the tier semantics; do not copy it.

**Files:**
- Create: `services/pkg/models/tier.go`
- Create: `services/pkg/models/tier_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `type ActionTier int` with `ActionTierReasoning`(0), `ActionTierReadOnly`(1), `ActionTierInternalModify`(2), `ActionTierExternalComms`(3), `ActionTierDestructive`(4), and `String()`
  - `type AgentTrustTier int` with `TrustTierUnverified`(0), `TrustTierRegistered`(1), `TrustTierCertified`(2), `TrustTierPlatformTrusted`(3), and `String()`
  - `func ParseActionTier(int) (ActionTier, error)`, `var ErrInvalidTier error`

  Every later task uses these.

- [ ] **Step 1: Write the failing test**

Create `services/pkg/models/tier_test.go`:

```go
package models

import (
	"errors"
	"testing"
)

// Tier values are ordinal — the whole authorization model compares them with
// < and >. A reordering silently changes every ceiling in the system.
func TestActionTier_Ordering(t *testing.T) {
	ordered := []ActionTier{
		ActionTierReasoning,
		ActionTierReadOnly,
		ActionTierInternalModify,
		ActionTierExternalComms,
		ActionTierDestructive,
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Fatalf("action tiers must strictly increase: %v >= %v", ordered[i-1], ordered[i])
		}
	}
	if ActionTierReasoning != 0 {
		t.Fatal("ActionTierReasoning must be 0 — the least-privileged default")
	}
}

func TestAgentTrustTier_Ordering(t *testing.T) {
	ordered := []AgentTrustTier{
		TrustTierUnverified,
		TrustTierRegistered,
		TrustTierCertified,
		TrustTierPlatformTrusted,
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Fatalf("trust tiers must strictly increase: %v >= %v", ordered[i-1], ordered[i])
		}
	}
	if TrustTierUnverified != 0 {
		t.Fatal("TrustTierUnverified must be 0 — an unpopulated agent is untrusted")
	}
}

func TestActionTier_String(t *testing.T) {
	cases := map[ActionTier]string{
		ActionTierReasoning:      "REASONING",
		ActionTierReadOnly:       "READ_ONLY",
		ActionTierInternalModify: "INTERNAL_MODIFY",
		ActionTierExternalComms:  "EXTERNAL_COMMS",
		ActionTierDestructive:    "DESTRUCTIVE",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Errorf("ActionTier(%d).String() = %q, want %q", tier, got, want)
		}
	}
}

// An out-of-range tier must render distinguishably rather than as a valid name,
// so a corrupt value cannot masquerade as READ_ONLY in an audit record.
func TestActionTier_StringOutOfRange(t *testing.T) {
	if got := ActionTier(99).String(); got == "READ_ONLY" || got == "" {
		t.Fatalf("out-of-range tier rendered as %q", got)
	}
}

func TestAgentTrustTier_String(t *testing.T) {
	cases := map[AgentTrustTier]string{
		TrustTierUnverified:      "UNVERIFIED",
		TrustTierRegistered:      "REGISTERED",
		TrustTierCertified:       "CERTIFIED",
		TrustTierPlatformTrusted: "PLATFORM_TRUSTED",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Errorf("AgentTrustTier(%d).String() = %q, want %q", tier, got, want)
		}
	}
}

// Values arriving over the wire must be range-checked, not cast.
func TestParseActionTier(t *testing.T) {
	for i := 0; i <= 4; i++ {
		if _, err := ParseActionTier(i); err != nil {
			t.Errorf("ParseActionTier(%d) should succeed: %v", i, err)
		}
	}
	for _, bad := range []int{-1, 5, 99} {
		if _, err := ParseActionTier(bad); !errors.Is(err, ErrInvalidTier) {
			t.Errorf("ParseActionTier(%d) should reject, got %v", bad, err)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./pkg/models/ 2>&1 | head -5
```

Expected: FAIL — `undefined: ActionTier`

- [ ] **Step 3: Write the implementation**

Create `services/pkg/models/tier.go`:

```go
// Package models holds Stratium's domain types.
//
// Tier values are ordinal and compared with < and >. Their numeric order is
// load-bearing: it defines every ceiling in the authorization model. The zero
// value of each is the least-privileged member, so an unpopulated struct is
// never accidentally privileged.
package models

import (
	"errors"
	"fmt"
)

// ErrInvalidTier indicates a tier value outside the defined range.
var ErrInvalidTier = errors.New("tier value out of range")

// ActionTier is the sensitivity of an attempted action.
type ActionTier int

const (
	ActionTierReasoning      ActionTier = 0 // no side effects
	ActionTierReadOnly       ActionTier = 1 // reads data
	ActionTierInternalModify ActionTier = 2 // mutates internal state
	ActionTierExternalComms  ActionTier = 3 // reaches outside the trust boundary
	ActionTierDestructive    ActionTier = 4 // irreversible or financially binding
)

func (t ActionTier) String() string {
	switch t {
	case ActionTierReasoning:
		return "REASONING"
	case ActionTierReadOnly:
		return "READ_ONLY"
	case ActionTierInternalModify:
		return "INTERNAL_MODIFY"
	case ActionTierExternalComms:
		return "EXTERNAL_COMMS"
	case ActionTierDestructive:
		return "DESTRUCTIVE"
	default:
		return fmt.Sprintf("INVALID_ACTION_TIER(%d)", int(t))
	}
}

// ParseActionTier range-checks a wire value. Casting an untrusted int directly
// to ActionTier would admit values outside the lattice.
func ParseActionTier(v int) (ActionTier, error) {
	if v < int(ActionTierReasoning) || v > int(ActionTierDestructive) {
		return ActionTierReasoning, fmt.Errorf("%w: action tier %d", ErrInvalidTier, v)
	}
	return ActionTier(v), nil
}

// AgentTrustTier is how much an agent is trusted by the platform.
type AgentTrustTier int

const (
	TrustTierUnverified      AgentTrustTier = 0
	TrustTierRegistered      AgentTrustTier = 1
	TrustTierCertified       AgentTrustTier = 2
	TrustTierPlatformTrusted AgentTrustTier = 3
)

func (t AgentTrustTier) String() string {
	switch t {
	case TrustTierUnverified:
		return "UNVERIFIED"
	case TrustTierRegistered:
		return "REGISTERED"
	case TrustTierCertified:
		return "CERTIFIED"
	case TrustTierPlatformTrusted:
		return "PLATFORM_TRUSTED"
	default:
		return fmt.Sprintf("INVALID_TRUST_TIER(%d)", int(t))
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test ./pkg/models/ -v 2>&1 | tail -20
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add services/pkg/models
git commit -m "feat(models): action and trust tier types

Zero value of each is the least-privileged member, so an unpopulated
struct is never accidentally privileged. ParseActionTier range-checks
wire values rather than casting."
```

---

### Task 5: Classification hierarchies

Written fresh. `~/Development/stratium/go/pkg/classification/classification.go` is the reference — its fail-closed rules were carefully reasoned and must be reproduced deliberately, with a test per rule (spec §3.7 G5). Read it, then write this.

**Files:**
- Create: `services/pkg/classification/classification.go`
- Create: `services/pkg/classification/classification_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `var Levels map[string][]string`
  - `func Index(hierarchy, level string) int` — rank, or -1
  - `func CheckCap(caps map[string]string, resourceAttrs map[string]string) (bool, string)`

  Task 6 (`ScopeNarrows`) and Task 13 (delegation leg) both use these.

- [ ] **Step 1: Write the failing test**

Create `services/pkg/classification/classification_test.go`:

```go
package classification

import "testing"

func TestIndex_KnownLevels(t *testing.T) {
	if Index("nato", "UNCLASSIFIED") != 0 {
		t.Error("UNCLASSIFIED must be the lowest NATO level")
	}
	if Index("nato", "TOP-SECRET") != 4 {
		t.Error("TOP-SECRET must be the highest NATO level")
	}
	if Index("nato", "SECRET") <= Index("nato", "CONFIDENTIAL") {
		t.Error("SECRET must outrank CONFIDENTIAL")
	}
}

func TestIndex_CaseInsensitive(t *testing.T) {
	if Index("NATO", "top-secret") != Index("nato", "TOP-SECRET") {
		t.Error("hierarchy and level lookups must be case-insensitive")
	}
}

func TestIndex_UnknownReturnsNegative(t *testing.T) {
	if Index("klingon", "SECRET") != -1 {
		t.Error("unknown hierarchy must return -1")
	}
	if Index("nato", "ULTRA-SECRET") != -1 {
		t.Error("unknown level must return -1")
	}
}

func TestIndex_CommercialHierarchy(t *testing.T) {
	if Index("commercial", "PUBLIC") != 0 {
		t.Error("PUBLIC must be the lowest commercial level")
	}
	if Index("commercial", "HIGHLY-CONFIDENTIAL") <= Index("commercial", "INTERNAL") {
		t.Error("HIGHLY-CONFIDENTIAL must outrank INTERNAL")
	}
}

// --- CheckCap: one test per fail-closed rule ---

// No caps means the delegation places no classification restriction.
func TestCheckCap_NoCapsAllows(t *testing.T) {
	ok, reason := CheckCap(nil, map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("absent caps must allow, got: %s", reason)
	}
}

// A resource that declares no classification is unrestricted by caps.
func TestCheckCap_NoResourceClassificationAllows(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{})
	if !ok {
		t.Fatalf("undeclared resource classification must allow, got: %s", reason)
	}
}

// A classification without a hierarchy is ambiguous and must DENY. Allowing it
// would let a caller bypass every cap by omitting the hierarchy attribute.
func TestCheckCap_ClassificationWithoutHierarchyDenies(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "TOP-SECRET"})
	if ok {
		t.Fatal("classification without a hierarchy must deny as ambiguous")
	}
	if reason == "" {
		t.Fatal("denial must explain itself")
	}
}

// An empty-string hierarchy is the same as an absent one. A caller that always
// populates the keys must not bypass the ambiguity rule with "".
func TestCheckCap_EmptyHierarchyTreatedAsAbsent(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, _ := CheckCap(caps, map[string]string{"classification": "TOP-SECRET", "hierarchy": ""})
	if ok {
		t.Fatal("empty hierarchy with a declared classification must deny")
	}
}

func TestCheckCap_EmptyClassificationTreatedAsAbsent(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("empty classification must be treated as undeclared, got: %s", reason)
	}
}

func TestCheckCap_WithinCapAllows(t *testing.T) {
	caps := map[string]string{"nato": "SECRET"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "CONFIDENTIAL", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("resource below cap must allow, got: %s", reason)
	}
}

func TestCheckCap_AtCapAllows(t *testing.T) {
	caps := map[string]string{"nato": "SECRET"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "SECRET", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("resource at cap must allow, got: %s", reason)
	}
}

func TestCheckCap_AboveCapDenies(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"})
	if ok {
		t.Fatal("resource above cap must deny")
	}
	if reason == "" {
		t.Fatal("denial must explain itself")
	}
}

// A cap on one hierarchy says nothing about another.
func TestCheckCap_NoCapForThisHierarchyAllows(t *testing.T) {
	caps := map[string]string{"commercial": "INTERNAL"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "SECRET", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("cap on a different hierarchy must not restrict, got: %s", reason)
	}
}

// An unknown level must DENY, not compare as equal or fall through.
func TestCheckCap_UnknownResourceLevelDenies(t *testing.T) {
	caps := map[string]string{"nato": "SECRET"}
	ok, _ := CheckCap(caps, map[string]string{"classification": "ULTRA-SECRET", "hierarchy": "nato"})
	if ok {
		t.Fatal("unknown resource level must deny")
	}
}

func TestCheckCap_UnknownCapLevelDenies(t *testing.T) {
	caps := map[string]string{"nato": "MEGA-SECRET"}
	ok, _ := CheckCap(caps, map[string]string{"classification": "SECRET", "hierarchy": "nato"})
	if ok {
		t.Fatal("unknown cap level must deny")
	}
}

func TestCheckCap_CapLookupIsCaseInsensitive(t *testing.T) {
	caps := map[string]string{"nato": "SECRET"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "CONFIDENTIAL", "hierarchy": "NATO"})
	if !ok {
		t.Fatalf("hierarchy lookup must be case-insensitive, got: %s", reason)
	}
}

// Case-insensitivity must hold in BOTH directions. A caps map keyed in any
// casing must be found against a resource declaring any casing. Testing only
// the lowercase-caps direction hides a fail-open: a caps key the lookup cannot
// see falls through to "no cap for this hierarchy", which allows.
func TestCheckCap_CapKeyCasingCannotEvadeTheCap(t *testing.T) {
	for _, capKey := range []string{"nato", "NATO", "Nato", "nAtO"} {
		for _, resourceHierarchy := range []string{"nato", "NATO", "Nato"} {
			t.Run(capKey+"/"+resourceHierarchy, func(t *testing.T) {
				caps := map[string]string{capKey: "CONFIDENTIAL"}
				resource := map[string]string{
					"classification": "TOP-SECRET",
					"hierarchy":      resourceHierarchy,
				}
				if ok, _ := CheckCap(caps, resource); ok {
					t.Fatalf("TOP-SECRET passed a CONFIDENTIAL cap: caps key %q, resource hierarchy %q",
						capKey, resourceHierarchy)
				}
			})
		}
	}
}

// Two keys differing only by case, carrying different caps, is ambiguous.
// Resolving it by picking one would make the ceiling depend on map iteration
// order, so it denies.
func TestCheckCap_ConflictingCaseVariantKeysDeny(t *testing.T) {
	caps := map[string]string{"nato": "TOP-SECRET", "NATO": "UNCLASSIFIED"}
	resource := map[string]string{"classification": "SECRET", "hierarchy": "nato"}
	ok, reason := CheckCap(caps, resource)
	if ok {
		t.Fatal("conflicting case-variant cap keys must deny as ambiguous")
	}
	if reason == "" {
		t.Fatal("an ambiguity denial must explain itself")
	}
}

// Case-variant keys carrying the SAME cap are redundant, not ambiguous, and
// must enforce normally rather than denying.
func TestCheckCap_DuplicateCaseVariantKeysWithSameCapEnforce(t *testing.T) {
	caps := map[string]string{"nato": "SECRET", "NATO": "SECRET"}
	if ok, reason := CheckCap(caps, map[string]string{"classification": "CONFIDENTIAL", "hierarchy": "nato"}); !ok {
		t.Fatalf("identical case-variant caps must enforce, not deny: %s", reason)
	}
	if ok, _ := CheckCap(caps, map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"}); ok {
		t.Fatal("identical case-variant caps must still enforce the cap")
	}
}
```

> `TestCheckCap_UnknownCapLevelDenies` above pins the `capIdx < 0` guard. That guard is currently redundant — `resourceIdx >= 0` is already enforced, so `resourceIdx > -1` denies by arithmetic even without it — but the redundancy depends on guard ordering and on `Index` never returning a sentinel other than `-1`. The test enforces the rule directly so a future change to either cannot silently remove the protection.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./pkg/classification/ 2>&1 | head -5
```

Expected: FAIL — `undefined: Index`

- [ ] **Step 3: Write the implementation**

Create `services/pkg/classification/classification.go`:

```go
// Package classification is the single source for Stratium's classification
// hierarchies and per-hierarchy cap enforcement.
//
// Every rule here fails closed. The recurring attack this defends against is
// bypass-by-omission: a caller that leaves out an attribute, or supplies a
// level nobody recognizes, must be denied rather than slipping through a gap
// in the comparison.
package classification

import (
	"fmt"
	"strings"
)

// Levels are the canonical hierarchies, ordered low to high.
var Levels = map[string][]string{
	"nato": {"UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP-SECRET"},
	"commercial": {
		"PUBLIC", "INTERNAL", "CONFIDENTIAL-COMMERCIAL",
		"RESTRICTED-COMMERCIAL", "HIGHLY-CONFIDENTIAL",
	},
}

// lookupCap finds a hierarchy's cap in a caller-supplied caps map, scanning
// case-insensitively the way Index scans Levels.
//
// A plain map lookup is not enough here. Levels is ours and always lowercase,
// but caps arrives from the caller in whatever casing it chose. Trying only
// `strings.ToLower(h)` and then the verbatim key misses a caps map keyed
// "NATO" against a resource declaring "nato" — the cap is silently invisible
// and CheckCap falls through to "no cap for this hierarchy", which ALLOWS.
// That is a fail-open on the platform's core authorization primitive.
//
// Two keys matching case-insensitively but carrying different levels is
// ambiguous, and ambiguity denies — picking one would make the effective
// ceiling depend on Go's map iteration order.
func lookupCap(caps map[string]string, hierarchy string) (level string, found bool, ambiguous bool) {
	for k, v := range caps {
		if !strings.EqualFold(k, hierarchy) {
			continue
		}
		if found && v != level {
			return "", false, true
		}
		level, found = v, true
	}
	return level, found, false
}

// Index returns a level's rank within its hierarchy, case-insensitively, or -1
// if either the hierarchy or the level is unknown. Callers must treat -1 as a
// denial, never as a comparable value.
func Index(hierarchy, level string) int {
	levels, ok := Levels[strings.ToLower(hierarchy)]
	if !ok {
		return -1
	}
	for i, l := range levels {
		if strings.EqualFold(l, level) {
			return i
		}
	}
	return -1
}

// CheckCap enforces a delegation's per-hierarchy classification caps against
// the resource being accessed.
//
// Rules, each fail-closed:
//   - no caps                                  → allow (no restriction declared)
//   - no resource classification               → allow (nothing to restrict)
//   - classification without a hierarchy       → DENY (ambiguous; the
//     bypass-by-omission case)
//   - no cap for the resource's hierarchy      → allow (this cap says nothing
//     about that hierarchy)
//   - unknown level or unknown cap             → DENY (never compare as equal)
//   - otherwise                                → resource rank ≤ cap rank
func CheckCap(caps map[string]string, resourceAttrs map[string]string) (bool, string) {
	if len(caps) == 0 {
		return true, ""
	}

	// Empty strings are treated as absent. A caller that always populates the
	// keys — building the map from request fields that may be blank — must not
	// be able to sidestep the ambiguity rule by supplying "".
	resourceLevel := resourceAttrs["classification"]
	resourceHierarchy := resourceAttrs["hierarchy"]

	if resourceLevel == "" {
		return true, ""
	}
	if resourceHierarchy == "" {
		return false, "resource classification declared without a hierarchy attribute (ambiguous)"
	}

	capLevel, hasCap, ambiguous := lookupCap(caps, resourceHierarchy)
	if ambiguous {
		return false, fmt.Sprintf(
			"conflicting caps for hierarchy %q (keys differing only by case carry different levels)",
			resourceHierarchy)
	}
	if !hasCap {
		return true, ""
	}

	resourceIdx := Index(resourceHierarchy, resourceLevel)
	if resourceIdx < 0 {
		return false, fmt.Sprintf("unknown classification level %q in hierarchy %q",
			resourceLevel, resourceHierarchy)
	}
	capIdx := Index(resourceHierarchy, capLevel)
	if capIdx < 0 {
		return false, fmt.Sprintf("delegation cap %q is not a known level in hierarchy %q",
			capLevel, resourceHierarchy)
	}

	if resourceIdx > capIdx {
		return false, fmt.Sprintf("resource classification %s exceeds delegation cap %s in hierarchy %q",
			resourceLevel, capLevel, resourceHierarchy)
	}
	return true, ""
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test ./pkg/classification/ -v 2>&1 | tail -25
```

Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add services/pkg/classification
git commit -m "feat(classification): hierarchies and fail-closed cap enforcement

One test per fail-closed rule. The ambiguity rule — a classification
declared without a hierarchy denies — is what prevents bypass by omitting
the hierarchy attribute."
```

---

### Task 6: Agent and Delegation types, with `ScopeNarrows`

The old repo's `ScopeNarrows` checks that a child's cap hierarchy key exists in the parent, then discards both levels without comparing them — so a child could widen `nato: CONFIDENTIAL` to `TOP-SECRET`. Written correctly here from the start.

**Files:**
- Create: `services/pkg/models/agent.go`
- Create: `services/pkg/models/delegation.go`
- Create: `services/pkg/models/delegation_test.go`

**Interfaces:**
- Consumes: `ActionTier`, `AgentTrustTier` (Task 4); `classification.Index` (Task 5)
- Produces:
  - `type Agent struct` with `ID uuid.UUID`, `TenantID string`, `TrustTier AgentTrustTier`, `Enabled bool`, `Suspended bool`, `AllowedTools []string`; method `HasTool(string) bool`
  - `type Delegation struct` with `ID`, `TenantID`, `UserID`, `AgentID`, `ApprovedTools []string`, `MaxActionTier ActionTier`, `ClassificationCaps map[string]string`, `ResourceConstraints map[string]string`, `ExpiresAt time.Time`, `Revoked bool`, `ParentDelegationID *uuid.UUID`, `RootDelegationID uuid.UUID`, `Depth int`, `ChainAgentIDs []uuid.UUID`; methods `HasTool(string) bool`, `IsActive(time.Time) bool`
  - `func ScopeNarrows(parent, child *Delegation) string` — empty string means the child is a valid subset

- [ ] **Step 1: Add the uuid dependency**

```bash
cd /path/to/stratium-data/services && go get github.com/google/uuid@latest
```

- [ ] **Step 2: Write the failing test**

Create `services/pkg/models/delegation_test.go`:

```go
package models

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func parentDelegation() *Delegation {
	return &Delegation{
		MaxActionTier:      ActionTierInternalModify,
		ApprovedTools:      []string{"Read", "Write"},
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"},
		ExpiresAt:          testNow.Add(time.Hour),
	}
}

func validChild() *Delegation {
	return &Delegation{
		MaxActionTier:      ActionTierReadOnly,
		ApprovedTools:      []string{"Read"},
		ClassificationCaps: map[string]string{"nato": "RESTRICTED"},
		ExpiresAt:          testNow.Add(time.Minute),
	}
}

func TestScopeNarrows_ValidChild(t *testing.T) {
	if reason := ScopeNarrows(parentDelegation(), validChild()); reason != "" {
		t.Fatalf("a strictly narrower child must be accepted, got: %s", reason)
	}
}

// An identical child is a valid subset — narrowing is "no wider", not "strictly narrower".
func TestScopeNarrows_IdenticalChildAccepted(t *testing.T) {
	p := parentDelegation()
	c := parentDelegation()
	if reason := ScopeNarrows(p, c); reason != "" {
		t.Fatalf("an identical child must be accepted, got: %s", reason)
	}
}

func TestScopeNarrows_RejectsWiderTier(t *testing.T) {
	c := validChild()
	c.MaxActionTier = ActionTierDestructive
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("child max_action_tier above parent must be rejected")
	}
}

func TestScopeNarrows_RejectsExtraTool(t *testing.T) {
	c := validChild()
	c.ApprovedTools = []string{"Read", "Bash"}
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("child tool outside the parent set must be rejected")
	}
}

// The defect in the previous implementation: cap levels were never compared.
func TestScopeNarrows_RejectsWidenedClassificationCap(t *testing.T) {
	c := validChild()
	c.ClassificationCaps = map[string]string{"nato": "TOP-SECRET"}
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("child widening nato CONFIDENTIAL -> TOP-SECRET must be rejected")
	}
}

func TestScopeNarrows_AcceptsNarrowedClassificationCap(t *testing.T) {
	c := validChild()
	c.ClassificationCaps = map[string]string{"nato": "UNCLASSIFIED"}
	if reason := ScopeNarrows(parentDelegation(), c); reason != "" {
		t.Fatalf("narrowing a cap must be accepted, got: %s", reason)
	}
}

func TestScopeNarrows_RejectsCapForHierarchyParentLacks(t *testing.T) {
	c := validChild()
	c.ClassificationCaps = map[string]string{"nato": "RESTRICTED", "commercial": "PUBLIC"}
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("a cap on a hierarchy the parent does not cap must be rejected")
	}
}

// An unrecognized level must deny rather than compare as equal.
func TestScopeNarrows_RejectsUnknownChildLevel(t *testing.T) {
	c := validChild()
	c.ClassificationCaps = map[string]string{"nato": "ULTRA-MEGA-SECRET"}
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("unknown child cap level must be rejected")
	}
}

func TestScopeNarrows_RejectsUnknownParentLevel(t *testing.T) {
	p := parentDelegation()
	p.ClassificationCaps = map[string]string{"nato": "NOT-A-LEVEL"}
	c := validChild()
	if ScopeNarrows(p, c) == "" {
		t.Fatal("unknown parent cap level must be rejected")
	}
}

func TestScopeNarrows_RejectsLongerExpiry(t *testing.T) {
	c := validChild()
	c.ExpiresAt = testNow.Add(2 * time.Hour)
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("child outliving its parent must be rejected")
	}
}

// Omitting a cap is a widening, not an inheritance. At decision time CheckCap
// treats absent caps as no restriction, so a child that drops the map holds
// unrestricted classification access — the same outcome as widening an entry,
// reached by a different route.
func TestScopeNarrows_RejectsChildOmittingParentCap(t *testing.T) {
	for name, caps := range map[string]map[string]string{
		"nil":   nil,
		"empty": {},
		"other-hierarchy-only": {"commercial": "PUBLIC"},
	} {
		t.Run(name, func(t *testing.T) {
			c := validChild()
			c.ClassificationCaps = caps
			if ScopeNarrows(parentDelegation(), c) == "" {
				t.Fatalf("child with %s caps under a capped parent must be rejected", name)
			}
		})
	}
}

// Resource constraints may only be added. Dropping one, or changing its value,
// widens what the child may reach.
func TestScopeNarrows_RejectsDroppedResourceConstraint(t *testing.T) {
	p := parentDelegation()
	p.ResourceConstraints = map[string]string{"project": "alpha", "region": "us-east"}
	for name, res := range map[string]map[string]string{
		"nil":            nil,
		"empty":          {},
		"partial":        {"project": "alpha"},
		"altered":        {"project": "beta", "region": "us-east"},
		"wildcard":       {"project": "*", "region": "us-east"},
	} {
		t.Run(name, func(t *testing.T) {
			c := validChild()
			c.ResourceConstraints = res
			if ScopeNarrows(p, c) == "" {
				t.Fatalf("child with %s resource constraints must be rejected", name)
			}
		})
	}
}

// Adding a constraint narrows and is permitted.
func TestScopeNarrows_AcceptsAddedResourceConstraint(t *testing.T) {
	p := parentDelegation()
	p.ResourceConstraints = map[string]string{"project": "alpha"}
	c := validChild()
	c.ResourceConstraints = map[string]string{"project": "alpha", "region": "us-east"}
	if reason := ScopeNarrows(p, c); reason != "" {
		t.Fatalf("adding a constraint is narrowing and must be accepted, got: %s", reason)
	}
}

// An empty parent tool list means unrestricted, so any child list is a subset.
func TestScopeNarrows_EmptyParentToolsIsUnrestricted(t *testing.T) {
	p := parentDelegation()
	p.ApprovedTools = nil
	c := validChild()
	c.ApprovedTools = []string{"Anything"}
	if reason := ScopeNarrows(p, c); reason != "" {
		t.Fatalf("unrestricted parent must accept any child tools, got: %s", reason)
	}
}

// A child with no tool restriction under a restricted parent is a widening.
func TestScopeNarrows_RejectsUnrestrictedChildUnderRestrictedParent(t *testing.T) {
	c := validChild()
	c.ApprovedTools = nil
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("an unrestricted child under a restricted parent is a widening")
	}
}

// --- lifecycle ---

func TestDelegation_IsActive(t *testing.T) {
	d := validChild()
	if !d.IsActive(testNow) {
		t.Error("a live delegation must be active")
	}
	d.Revoked = true
	if d.IsActive(testNow) {
		t.Error("a revoked delegation must not be active")
	}
	d.Revoked = false
	if d.IsActive(testNow.Add(time.Hour)) {
		t.Error("an expired delegation must not be active")
	}
}

func TestDelegation_HasTool(t *testing.T) {
	d := &Delegation{ApprovedTools: []string{"Read"}}
	if !d.HasTool("Read") {
		t.Error("an approved tool must be reported present")
	}
	if d.HasTool("Bash") {
		t.Error("an unapproved tool must be reported absent")
	}
	empty := &Delegation{}
	if !empty.HasTool("Anything") {
		t.Error("an empty tool list means unrestricted")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./pkg/models/ 2>&1 | head -5
```

Expected: FAIL — `undefined: Delegation`

- [ ] **Step 4: Write agent.go**

Create `services/pkg/models/agent.go`:

```go
package models

import "github.com/google/uuid"

// Agent is a registered non-person entity that acts on a principal's behalf.
type Agent struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	Name     string `json:"name"     db:"name"`
	Provider string `json:"provider" db:"provider"`
	ModelID  string `json:"model_id" db:"model_id"`

	TrustTier AgentTrustTier `json:"trust_tier" db:"trust_tier"`
	Enabled   bool           `json:"enabled"    db:"enabled"`
	Suspended bool           `json:"suspended"  db:"suspended"`

	AllowedTools []string `json:"allowed_tools" db:"allowed_tools"`
}

// HasTool reports whether a tool is within the agent's allowlist. An empty
// allowlist is unrestricted — the delegation is the real constraint, and this
// matches Delegation.HasTool so the two never disagree.
func (a *Agent) HasTool(tool string) bool {
	if len(a.AllowedTools) == 0 {
		return true
	}
	for _, t := range a.AllowedTools {
		if t == tool {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Write delegation.go**

Create `services/pkg/models/delegation.go`:

```go
package models

import (
	"time"

	"github.com/google/uuid"

	"stratium/pkg/classification"
)

// Delegation is a bounded, time-limited grant of authority from a principal to
// an agent, or from an agent to a sub-agent. It is the ceiling every runtime
// decision is measured against.
type Delegation struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	UserID  string    `json:"user_id"  db:"user_id"`
	AgentID uuid.UUID `json:"agent_id" db:"agent_id"`

	ApprovedTools       []string          `json:"approved_tools"       db:"approved_tools"`
	MaxActionTier       ActionTier        `json:"max_action_tier"      db:"max_action_tier"`
	ClassificationCaps  map[string]string `json:"classification_caps"  db:"classification_caps"`
	ResourceConstraints map[string]string `json:"resource_constraints" db:"resource_constraints"`
	Purpose             string            `json:"purpose"              db:"purpose"`

	ExpiresAt time.Time  `json:"expires_at"           db:"expires_at"`
	CreatedAt time.Time  `json:"created_at"           db:"created_at"`
	Revoked   bool       `json:"revoked"              db:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`

	ParentDelegationID *uuid.UUID  `json:"parent_delegation_id,omitempty" db:"parent_delegation_id"`
	RootDelegationID   uuid.UUID   `json:"root_delegation_id"             db:"root_delegation_id"`
	Depth              int         `json:"depth"                          db:"depth"`
	ChainAgentIDs      []uuid.UUID `json:"chain_agent_ids"                db:"chain_agent_ids"`
}

// IsRoot reports whether this delegation came directly from a principal.
func (d *Delegation) IsRoot() bool { return d.ParentDelegationID == nil }

// IsActive reports whether the delegation is neither revoked nor expired at
// the given instant. Time is a parameter so decisions are deterministic.
func (d *Delegation) IsActive(now time.Time) bool {
	return !d.Revoked && !now.After(d.ExpiresAt)
}

// HasTool reports whether a tool is approved. An empty list is unrestricted,
// matching Agent.HasTool.
func (d *Delegation) HasTool(tool string) bool {
	if len(d.ApprovedTools) == 0 {
		return true
	}
	for _, t := range d.ApprovedTools {
		if t == tool {
			return true
		}
	}
	return false
}

// ScopeNarrows reports whether a child delegation is a valid subset of its
// parent. It returns an empty string when the child is valid, or a description
// of the first widening found.
//
// "Narrows" means no wider — an identical child is valid. Every dimension is
// checked: action tier, tools, classification caps, and expiry. Classification
// caps are compared by rank via classification.Index; an unknown level on
// either side is a rejection, never an equal comparison.
func ScopeNarrows(parent, child *Delegation) string {
	if child.MaxActionTier > parent.MaxActionTier {
		return "child max_action_tier " + child.MaxActionTier.String() +
			" exceeds parent " + parent.MaxActionTier.String()
	}

	// An empty parent list is unrestricted; an empty child list under a
	// restricted parent is a widening, not an inheritance.
	if len(parent.ApprovedTools) > 0 {
		if len(child.ApprovedTools) == 0 {
			return "child has no tool restriction while parent restricts tools"
		}
		allowed := make(map[string]bool, len(parent.ApprovedTools))
		for _, t := range parent.ApprovedTools {
			allowed[t] = true
		}
		for _, t := range child.ApprovedTools {
			if !allowed[t] {
				return "child tool " + t + " not in parent approved_tools"
			}
		}
	}

	// Iterate the PARENT's caps, not the child's. A hierarchy the parent
	// restricts and the child omits is a widening, not an inheritance: at
	// decision time CheckCap treats absent caps as "no restriction", so the
	// child would hold unrestricted access to that hierarchy. This is the same
	// asymmetry enforced above for tools — an empty child side under a
	// restricted parent is a widening.
	for hierarchy, parentCap := range parent.ClassificationCaps {
		childCap, ok := child.ClassificationCaps[hierarchy]
		if !ok {
			return "child does not cap hierarchy " + hierarchy +
				" which parent caps at " + parentCap
		}
		childIdx := classification.Index(hierarchy, childCap)
		if childIdx < 0 {
			return "child cap " + childCap + " is not a known level in hierarchy " + hierarchy
		}
		parentIdx := classification.Index(hierarchy, parentCap)
		if parentIdx < 0 {
			return "parent cap " + parentCap + " is not a known level in hierarchy " + hierarchy
		}
		if childIdx > parentIdx {
			return "child cap " + childCap + " exceeds parent cap " + parentCap +
				" in hierarchy " + hierarchy
		}
	}

	// The child may not introduce a cap on a hierarchy the parent does not cap.
	for hierarchy := range child.ClassificationCaps {
		if _, ok := parent.ClassificationCaps[hierarchy]; !ok {
			return "child caps hierarchy " + hierarchy + " which parent does not cap"
		}
	}

	// Resource constraints may only be added, never dropped or altered. Every
	// constraint the parent sets must appear in the child with an identical
	// value; extra child constraints are further narrowing and permitted.
	// Values are opaque caller-defined strings, so the comparison is exact —
	// it does not try to reason about wildcards or ranges, because every such
	// interpretation is a place a widening could hide.
	for key, parentVal := range parent.ResourceConstraints {
		childVal, ok := child.ResourceConstraints[key]
		if !ok {
			return "child drops parent resource constraint " + key + "=" + parentVal
		}
		if childVal != parentVal {
			return "child resource constraint " + key + "=" + childVal +
				" differs from parent " + key + "=" + parentVal
		}
	}

	if child.ExpiresAt.After(parent.ExpiresAt) {
		return "child expires_at exceeds parent"
	}

	return ""
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /path/to/stratium-data/services && go test ./pkg/models/ -v 2>&1 | tail -30
```

Expected: PASS, all tests including the Task 4 tier tests.

- [ ] **Step 7: Commit**

```bash
git add services/pkg/models services/go.mod services/go.sum
git commit -m "feat(models): Agent, Delegation, and ScopeNarrows

ScopeNarrows compares classification caps by rank. The previous system
checked only that the hierarchy key existed and discarded both levels,
so a child could widen nato CONFIDENTIAL to TOP-SECRET."
```

---

### Task 7: Audit chain

**Files:**
- Create: `services/pkg/audit/chain.go`
- Create: `services/pkg/audit/chain_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `type Entry struct` with `PrevHash [32]byte` and the decision fields
  - `func (e Entry) Hash() [32]byte`
  - `func Verify(entries []Entry) error`
  - `func Link(prev *Entry, e Entry) Entry`
  - `var ErrChainBroken error`, `var ZeroHash [32]byte`

  Task 16's C15 calls `Verify`.

- [ ] **Step 1: Write the failing test**

Create `services/pkg/audit/chain_test.go`:

```go
package audit

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

var auditNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func entry(prev [32]byte, reason string) Entry {
	return Entry{
		PrevHash:   prev,
		TenantID:   "tenant-a",
		OccurredAt: auditNow,
		EventType:  "decision",
		Actor:      "alice@example.com",
		Decision:   "ALLOW",
		Reason:     reason,
	}
}

func TestVerify_IntactChain(t *testing.T) {
	e1 := entry(ZeroHash, "first")
	e2 := entry(e1.Hash(), "second")
	e3 := entry(e2.Hash(), "third")
	if err := Verify([]Entry{e1, e2, e3}); err != nil {
		t.Fatalf("intact chain must verify: %v", err)
	}
}

func TestVerify_EmptyChain(t *testing.T) {
	if err := Verify(nil); err != nil {
		t.Fatalf("an empty chain is vacuously valid: %v", err)
	}
}

func TestVerify_DetectsMutation(t *testing.T) {
	e1 := entry(ZeroHash, "first")
	e2 := entry(e1.Hash(), "second")
	e1.Reason = "tampered"
	if err := Verify([]Entry{e1, e2}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("mutation must break the chain, got: %v", err)
	}
}

func TestVerify_DetectsDeletion(t *testing.T) {
	e1 := entry(ZeroHash, "first")
	e2 := entry(e1.Hash(), "second")
	e3 := entry(e2.Hash(), "third")
	if err := Verify([]Entry{e1, e3}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("deletion must break the chain, got: %v", err)
	}
}

func TestVerify_RejectsNonZeroGenesis(t *testing.T) {
	bogus := [32]byte{1}
	if err := Verify([]Entry{entry(bogus, "first")}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("a non-zero genesis prev_hash must be rejected, got: %v", err)
	}
}

func TestHash_Deterministic(t *testing.T) {
	if entry(ZeroHash, "same").Hash() != entry(ZeroHash, "same").Hash() {
		t.Fatal("identical entries must hash identically")
	}
}

// A field omitted from the serialization can be altered undetected. This test
// fails whenever a field is added to Entry without being added to Hash.
func TestHash_CoversEveryField(t *testing.T) {
	base := entry(ZeroHash, "base")
	// Every field on Entry must appear here. A field present on the struct but
	// absent from this table is a field nothing tests — deleting its write from
	// Hash would pass the whole suite. PrevHash matters most: it is the literal
	// chain link, and without it in the digest the structure stops being a chain.
	someUUID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	mutations := map[string]func(*Entry){
		"PrevHash":         func(e *Entry) { e.PrevHash = [32]byte{7} },
		"TenantID":         func(e *Entry) { e.TenantID = "other" },
		"OccurredAt":       func(e *Entry) { e.OccurredAt = e.OccurredAt.Add(time.Second) },
		"EventType":        func(e *Entry) { e.EventType = "other" },
		"Actor":            func(e *Entry) { e.Actor = "mallory@example.com" },
		"AgentID":          func(e *Entry) { e.AgentID = &someUUID },
		"DelegationID":     func(e *Entry) { e.DelegationID = &someUUID },
		"RootDelegationID": func(e *Entry) { e.RootDelegationID = &someUUID },
		"ChainDepth":       func(e *Entry) { e.ChainDepth = 2 },
		"ToolName":         func(e *Entry) { e.ToolName = "Bash" },
		"Action":           func(e *Entry) { e.Action = "delete" },
		"DeclaredTier":     func(e *Entry) { e.DeclaredTier = 1 },
		"DerivedTier":      func(e *Entry) { e.DerivedTier = 4 },
		"Decision":         func(e *Entry) { e.Decision = "DENY" },
		"DeniedLeg":        func(e *Entry) { e.DeniedLeg = "agent" },
		"DeniedAtDepth":    func(e *Entry) { e.DeniedAtDepth = 3 },
		"Reason":           func(e *Entry) { e.Reason = "other" },
		"InputDigest":      func(e *Entry) { e.InputDigest = [32]byte{9} },
	}

	// Guard against the table silently falling behind the struct.
	if got, want := len(mutations), reflect.TypeOf(Entry{}).NumField(); got != want {
		t.Fatalf("mutation table covers %d fields but Entry has %d — add the missing ones", got, want)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			if m.Hash() == base.Hash() {
				t.Fatalf("field %s is not covered by Hash", name)
			}
		})
	}
}

// Length prefixing prevents field-boundary ambiguity: without it, content can
// shift between fields undetected.
//
// The pair must be ADJACENT in Hash's write order. Actor and Reason are nine
// fields apart, and the fixed-width writes between them act as accidental
// delimiters — a test using that pair passes even with length-prefixing removed
// entirely, which is coverage that isn't there. EventType and Actor are written
// back to back with nothing in between, so they collide the moment prefixes go.
func TestHash_FieldBoundariesUnambiguous(t *testing.T) {
	a := entry(ZeroHash, "same")
	a.EventType, a.Actor = "decisionX", "Y"
	b := entry(ZeroHash, "same")
	b.EventType, b.Actor = "decision", "XY"
	if a.Hash() == b.Hash() {
		t.Fatal("adjacent field boundaries are ambiguous — serialization is not length-prefixed")
	}
}

// Hash is unkeyed, so a forged entry can be linked onto another tenant's real
// entry by anyone who can read it. Verify must reject the mixed chain rather
// than trusting the caller to have filtered by tenant.
func TestVerify_RejectsCrossTenantForgery(t *testing.T) {
	a1 := entry(ZeroHash, "tenant-a first")
	a2 := entry(a1.Hash(), "tenant-a second")

	forged := entry(a2.Hash(), "forged")
	forged.TenantID = "tenant-b"

	if err := Verify([]Entry{a1, a2, forged}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("an entry from another tenant must break the chain, got: %v", err)
	}
}

func TestLink(t *testing.T) {
	e1 := Link(nil, entry([32]byte{}, "first"))
	if e1.PrevHash != ZeroHash {
		t.Fatal("a genesis entry must link to the zero hash")
	}
	e2 := Link(&e1, entry([32]byte{}, "second"))
	if e2.PrevHash != e1.Hash() {
		t.Fatal("Link must set PrevHash from the predecessor")
	}
	if err := Verify([]Entry{e1, e2}); err != nil {
		t.Fatalf("a linked chain must verify: %v", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./pkg/audit/ 2>&1 | head -5
```

Expected: FAIL — `undefined: Entry`

- [ ] **Step 3: Write the implementation**

Create `services/pkg/audit/chain.go`:

```go
// Package audit implements the hash-chained, append-only audit trail.
//
// Each entry commits to its predecessor, so mutation or deletion breaks
// verification. The chain is per tenant: a tenant's first entry links to the
// zero hash.
//
// Raw tool inputs are never stored — only InputDigest. Encrypted plaintext
// storage and crypto-shredding are deferred until per-tenant key management is
// specified (spec §8); writing raw shell commands into an undeletable table
// before then would be worse than not storing them.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrChainBroken indicates the chain does not verify.
var ErrChainBroken = errors.New("audit chain broken")

// ZeroHash is the PrevHash of a tenant's first entry.
var ZeroHash [32]byte

// Entry is one audit record.
//
// Every field must be covered by Hash. A field added here without a
// corresponding line in Hash can be altered undetected —
// TestHash_CoversEveryField guards that.
type Entry struct {
	PrevHash [32]byte

	TenantID   string
	OccurredAt time.Time
	EventType  string
	Actor      string

	AgentID          *uuid.UUID
	DelegationID     *uuid.UUID
	RootDelegationID *uuid.UUID
	ChainDepth       int16

	ToolName     string
	Action       string
	DeclaredTier int16
	DerivedTier  int16

	Decision      string
	DeniedLeg     string
	DeniedAtDepth int16
	Reason        string

	InputDigest [32]byte
}

// Hash computes the entry's digest over a length-prefixed canonical
// serialization. Length prefixes make field boundaries unambiguous.
func (e Entry) Hash() [32]byte {
	h := sha256.New()

	writeBytes := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	writeStr := func(s string) { writeBytes([]byte(s)) }
	writeInt := func(v int64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(v))
		h.Write(n[:])
	}
	writeUUID := func(u *uuid.UUID) {
		if u == nil {
			writeBytes(nil)
			return
		}
		writeBytes(u[:])
	}

	writeBytes(e.PrevHash[:])
	writeStr(e.TenantID)
	writeInt(e.OccurredAt.UTC().UnixNano())
	writeStr(e.EventType)
	writeStr(e.Actor)
	writeUUID(e.AgentID)
	writeUUID(e.DelegationID)
	writeUUID(e.RootDelegationID)
	writeInt(int64(e.ChainDepth))
	writeStr(e.ToolName)
	writeStr(e.Action)
	writeInt(int64(e.DeclaredTier))
	writeInt(int64(e.DerivedTier))
	writeStr(e.Decision)
	writeStr(e.DeniedLeg)
	writeInt(int64(e.DeniedAtDepth))
	writeStr(e.Reason)
	writeBytes(e.InputDigest[:])

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Verify walks a tenant's chain.
//
// Preconditions, both enforced rather than assumed: entries belong to a single
// tenant, and they are ordered by seq ascending. Ordering cannot be checked
// here — Entry carries no ordinal — so a caller that queries audit_chain
// without ORDER BY seq gets ErrChainBroken on intact data. That is a false
// alarm, never a false acceptance.
//
// The tenant check is defence in depth. Hash is unkeyed SHA-256, so anyone can
// compute a valid-looking PrevHash linking a forged entry onto another tenant's
// real one. Row-level security stops an ordinary session from assembling such a
// slice, but an admin, batch, or buggy paging caller could — and this package
// is the auditor-facing proof, so it should not depend on a caller's diligence.
func Verify(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	if entries[0].PrevHash != ZeroHash {
		return fmt.Errorf("%w: first entry does not link to the zero hash", ErrChainBroken)
	}
	tenant := entries[0].TenantID
	for i := 1; i < len(entries); i++ {
		if entries[i].TenantID != tenant {
			return fmt.Errorf("%w: entry %d belongs to tenant %q, chain is for %q",
				ErrChainBroken, i, entries[i].TenantID, tenant)
		}
		if want := entries[i-1].Hash(); entries[i].PrevHash != want {
			return fmt.Errorf("%w: entry %d does not link to entry %d", ErrChainBroken, i, i-1)
		}
	}
	return nil
}

// Link sets PrevHash from the predecessor, returning the entry ready to
// insert. Pass nil for a tenant's first entry.
func Link(prev *Entry, e Entry) Entry {
	if prev == nil {
		e.PrevHash = ZeroHash
		return e
	}
	e.PrevHash = prev.Hash()
	return e
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test -race ./pkg/audit/ -v 2>&1 | tail -25
```

Expected: PASS, all tests and subtests.

- [ ] **Step 5: Commit**

```bash
git add services/pkg/audit
git commit -m "feat(audit): hash-chain link computation and verification (C15)

Length-prefixed serialization makes field boundaries unambiguous.
TestHash_CoversEveryField fails if a field is added to Entry without
being added to Hash."
```

---

### Task 8: Migrations with a tenant-scoped baseline

Greenfield means tenancy is in the first migration, not a follow-on `ALTER`.

**Files:**
- Create: `services/migrations/migrations.go`
- Create: `services/migrations/migrations_test.go`
- Create: `services/migrations/000001_baseline.up.sql`, `000001_baseline.down.sql`

**Interfaces:**
- Consumes: nothing
- Produces: `migrations.FS embed.FS`, `func Up(db *sql.DB) error`; Tasks 9 and 10 add migrations to the same directory

- [ ] **Step 1: Add dependencies**

```bash
cd /path/to/stratium-data/services
go get github.com/golang-migrate/migrate/v4@latest
go get github.com/golang-migrate/migrate/v4/database/postgres@latest
go get github.com/golang-migrate/migrate/v4/source/iofs@latest
```

- [ ] **Step 2: Write the failing test**

Create `services/migrations/migrations_test.go`:

```go
package migrations

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestFSContainsBaseline(t *testing.T) {
	if err := fstest.TestFS(FS, "000001_baseline.up.sql", "000001_baseline.down.sql"); err != nil {
		t.Fatalf("embedded FS is missing the baseline: %v", err)
	}
}

// Every up migration needs a down, or a failed deploy cannot be rolled back.
func TestEveryUpHasADown(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("reading embedded FS: %v", err)
	}
	ups, downs := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".up.sql"):
			ups[strings.TrimSuffix(name, ".up.sql")] = true
		case strings.HasSuffix(name, ".down.sql"):
			downs[strings.TrimSuffix(name, ".down.sql")] = true
		}
	}
	if len(ups) == 0 {
		t.Fatal("no up migrations found")
	}
	for v := range ups {
		if !downs[v] {
			t.Errorf("migration %q has an up but no down", v)
		}
	}
}

// createTable is one parsed CREATE TABLE statement.
type createTable struct {
	Name string
	Body string // exactly the parenthesised column list, nothing after it
}

// parseCreateTables extracts each CREATE TABLE's own column list by matching
// parentheses.
//
// Taking the last ")" in the text between one CREATE TABLE and the next does
// NOT work: a trailing `CREATE INDEX ... ON agents(tenant_id);` gets swallowed
// into the body, so a table that has lost its tenant_id column still appears to
// mention one. Five of six tables in the baseline have exactly that layout, so
// the naive version passes on a schema with no tenancy at all.
func parseCreateTables(sql string) []createTable {
	var out []createTable
	const kw = "CREATE TABLE "
	for i := 0; ; {
		j := strings.Index(sql[i:], kw)
		if j < 0 {
			return out
		}
		start := i + j + len(kw)
		open := strings.Index(sql[start:], "(")
		if open < 0 {
			return out
		}
		open += start

		depth, end := 0, -1
		for k := open; k < len(sql); k++ {
			switch sql[k] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = k
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return out
		}

		name := strings.TrimSpace(sql[start:open])
		name = strings.TrimPrefix(name, "IF NOT EXISTS ")
		out = append(out, createTable{Name: strings.TrimSpace(name), Body: sql[open : end+1]})
		i = end + 1
	}
}

// Tenancy is structural: every table must carry tenant_id from creation.
func TestEveryTableHasTenantID(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("reading embedded FS: %v", err)
	}
	total := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		b, err := FS.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		sql := string(b)
		tables := parseCreateTables(sql)

		// Reconcile per file. The depth counter is character-level, so an
		// unbalanced paren inside a string literal or a comment desyncs it and
		// the parser silently returns fewer tables — possibly none — for the
		// rest of the file. A global "did we parse anything at all" check does
		// not catch that, because another file keeps the total nonzero. Compare
		// against a textual count instead: any disagreement means the parser
		// lost track, and an unparsed table is an unchecked table.
		if want, got := strings.Count(sql, "CREATE TABLE"), len(tables); want != got {
			t.Errorf("%s: found %d occurrences of CREATE TABLE but parsed %d — "+
				"the parser lost sync (unbalanced paren in a literal or comment, "+
				"or an unsupported form such as CREATE TABLE ... AS SELECT)",
				e.Name(), want, got)
			continue
		}

		// Equal counts are not sufficient. A stray paren inside one table's body
		// can overrun its true close and swallow a trailing
		// `CREATE INDEX ... ON t(tenant_id);` — no CREATE TABLE is consumed, so
		// the count still matches, but the swallowed text supplies the substring
		// and a table with no tenant_id column passes. That is the exact bug the
		// paren rewrite closed, resurrected. No parsed body may contain a
		// statement terminator or another statement keyword.
		for _, tbl := range tables {
			if strings.Contains(tbl.Body, ";") || strings.Contains(tbl.Body, "CREATE ") {
				t.Errorf("%s: parsed body for table %q ran past its own closing paren "+
					"and swallowed following statements — the parser lost sync",
					e.Name(), tbl.Name)
			}
		}

		total += len(tables)
		for _, tbl := range tables {
			if !strings.Contains(tbl.Body, "tenant_id") {
				t.Errorf("%s: table %q has no tenant_id column", e.Name(), tbl.Name)
			}
		}
	}
	if total == 0 {
		t.Fatal("parsed no CREATE TABLE statements — the guard is inert")
	}
}

// The reconciliation check must fire when the parser loses sync, rather than
// silently reporting fewer tables.
func TestTenantIDGuardDetectsParserDesync(t *testing.T) {
	desyncing := map[string]string{
		"unbalanced paren in a string literal": `CREATE TABLE a (
    tenant_id TEXT NOT NULL,
    note TEXT DEFAULT 'oops ('
);
CREATE TABLE b (
    id UUID PRIMARY KEY
);`,
		"unbalanced paren in a comment": `CREATE TABLE a (
    tenant_id TEXT NOT NULL, -- see note (
    note TEXT
);
CREATE TABLE b (
    id UUID PRIMARY KEY
);`,
	}
	for name, sql := range desyncing {
		t.Run(name, func(t *testing.T) {
			if want, got := strings.Count(sql, "CREATE TABLE"), len(parseCreateTables(sql)); want == got {
				t.Fatalf("expected the parser to lose sync so the reconciliation "+
					"check can catch it, but it parsed all %d tables", got)
			}
		})
	}
}

// The dangerous desync is the one that keeps the counts equal: a stray paren
// lets a table body swallow a trailing CREATE INDEX naming tenant_id, so a
// table with no such column looks compliant. The body must be rejected for
// containing following statements, not merely counted.
func TestTenantIDGuardCatchesSwallowedStatements(t *testing.T) {
	sql := `CREATE TABLE x (
    id UUID PRIMARY KEY,
    name TEXT DEFAULT 'oops ('
);
CREATE INDEX idx_x_tenant ON x(tenant_id); -- balance )
CREATE TABLE y (
    tenant_id TEXT NOT NULL
);`
	tables := parseCreateTables(sql)
	if strings.Count(sql, "CREATE TABLE") != len(tables) {
		t.Skip("counts already disagree; the count check catches this case")
	}
	swallowed := false
	for _, tbl := range tables {
		if strings.Contains(tbl.Body, ";") || strings.Contains(tbl.Body, "CREATE ") {
			swallowed = true
		}
	}
	if !swallowed {
		t.Fatal("a body that ran past its closing paren was not detected — " +
			"a table with no tenant_id column would pass")
	}
}

// The guard must actually catch a table that lost its tenant_id, including when
// a trailing CREATE INDEX still names the column. This is the case the previous
// substring-based version missed.
func TestTenantIDGuardCatchesMissingColumn(t *testing.T) {
	cases := map[string]string{
		"plain": `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL
);`,
		"trailing index names the column": `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE INDEX idx_thing_tenant ON thing(tenant_id);`,
		"nested parens in a CHECK": `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    tier SMALLINT NOT NULL CHECK (tier BETWEEN 0 AND 4)
);
CREATE INDEX idx_thing_tenant ON thing(tenant_id);`,
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			tables := parseCreateTables(sql)
			if len(tables) != 1 {
				t.Fatalf("expected 1 table, parsed %d", len(tables))
			}
			if strings.Contains(tables[0].Body, "tenant_id") {
				t.Fatalf("parser leaked text outside the column list: %q", tables[0].Body)
			}
		})
	}
}

// A table that legitimately has the column must still be recognised.
func TestTenantIDGuardAcceptsPresentColumn(t *testing.T) {
	sql := `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    tier SMALLINT NOT NULL CHECK (tier BETWEEN 0 AND 4),
    UNIQUE (tenant_id, id)
);
CREATE INDEX idx_thing_tenant ON thing(tenant_id);`
	tables := parseCreateTables(sql)
	if len(tables) != 1 || !strings.Contains(tables[0].Body, "tenant_id") {
		t.Fatalf("parser failed to find a present tenant_id: %+v", tables)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./migrations/ 2>&1 | head -5
```

Expected: FAIL — `undefined: FS`

- [ ] **Step 4: Write the baseline migration**

Create `services/migrations/000001_baseline.up.sql`:

```sql
-- Baseline schema. Tenancy is structural: every table carries tenant_id from
-- creation, because retrofitting isolation into a security product after it
-- holds customer data is significantly harder.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE agents (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     TEXT NOT NULL,
    name          TEXT NOT NULL,
    provider      TEXT NOT NULL,
    model_id      TEXT,
    trust_tier    SMALLINT NOT NULL DEFAULT 0 CHECK (trust_tier BETWEEN 0 AND 3),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    suspended     BOOLEAN NOT NULL DEFAULT false,
    allowed_tools JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_agents_tenant ON agents(tenant_id);

CREATE TABLE delegations (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            TEXT NOT NULL,
    user_id              TEXT NOT NULL,
    -- RESTRICT, not CASCADE. The delegation row is the record of what authority
    -- was granted to whom and when; cascade-deleting an agent silently destroys
    -- that history, including already-revoked grants. pkg/audit records
    -- decisions, not grants, so nothing else preserves it. Agents are retired by
    -- setting enabled=false / suspended=true, which is what those columns exist
    -- for; a hard delete now requires removing the delegations deliberately.
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    approved_tools       JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_action_tier      SMALLINT NOT NULL CHECK (max_action_tier BETWEEN 0 AND 4),
    classification_caps  JSONB NOT NULL DEFAULT '{}'::jsonb,
    resource_constraints JSONB NOT NULL DEFAULT '{}'::jsonb,
    purpose              TEXT,
    expires_at           TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked              BOOLEAN NOT NULL DEFAULT false,
    revoked_at           TIMESTAMPTZ,
    parent_delegation_id UUID REFERENCES delegations(id) ON DELETE CASCADE,
    -- Self-referencing FK: a root delegation points at itself, a child at its
    -- root. Without it a dangling root_delegation_id inserts cleanly, and since
    -- cascade revocation is keyed on this column, such a row would silently
    -- escape a root-keyed revocation sweep. Same backstop reasoning as
    -- tier_overrides' raise-only CHECK.
    root_delegation_id   UUID NOT NULL REFERENCES delegations(id),
    depth                SMALLINT NOT NULL DEFAULT 0 CHECK (depth >= 0),
    chain_agent_ids      JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX idx_delegations_tenant ON delegations(tenant_id);
CREATE INDEX idx_delegations_root   ON delegations(root_delegation_id);
CREATE INDEX idx_delegations_active ON delegations(tenant_id, expires_at) WHERE revoked = false;

CREATE TABLE policies (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      TEXT NOT NULL,
    name           TEXT NOT NULL,
    description    TEXT,
    language       TEXT NOT NULL CHECK (language IN ('json','cedar','rego','xacml')),
    policy_content TEXT NOT NULL,
    effect         TEXT NOT NULL CHECK (effect IN ('allow','deny')),
    version        BIGINT NOT NULL DEFAULT 1,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_policies_tenant_enabled ON policies(tenant_id, enabled);

CREATE TABLE entitlements (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    subject_attributes  JSONB NOT NULL DEFAULT '{}'::jsonb,
    resource_attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    actions             JSONB NOT NULL DEFAULT '[]'::jsonb,
    conditions          JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_entitlements_tenant_enabled ON entitlements(tenant_id, enabled);

-- Raise-only action-tier overrides (spec §4.4). The CHECK is a database-level
-- backstop; application code enforces the same rule against the built-in
-- classifier, which the database cannot see.
CREATE TABLE tier_overrides (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    TEXT NOT NULL,
    tool_or_verb TEXT NOT NULL,
    action_tier  SMALLINT NOT NULL CHECK (action_tier BETWEEN 0 AND 4),
    builtin_tier SMALLINT NOT NULL CHECK (builtin_tier BETWEEN 0 AND 4),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   TEXT NOT NULL,
    CONSTRAINT tier_overrides_raise_only CHECK (action_tier >= builtin_tier),
    UNIQUE (tenant_id, tool_or_verb)
);
CREATE INDEX idx_tier_overrides_tenant ON tier_overrides(tenant_id);

-- Revocation epoch (spec §4.8). Bumped by any revocation, suspension, or
-- policy change; a cached decision carrying a stale epoch is never served.
CREATE TABLE tenant_epoch (
    tenant_id  TEXT PRIMARY KEY,
    epoch      BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

`tenant_epoch`'s primary key *is* `tenant_id`, which satisfies the tenancy test.

Create `services/migrations/000001_baseline.down.sql`:

```sql
DROP TABLE IF EXISTS tenant_epoch;
DROP TABLE IF EXISTS tier_overrides;
DROP TABLE IF EXISTS entitlements;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS delegations;
DROP TABLE IF EXISTS agents;
```

- [ ] **Step 5: Write the runner**

Create `services/migrations/migrations.go`:

```go
// Package migrations embeds the versioned schema and applies it.
//
// Migrations are embedded so a self-hosted operator runs one binary and gets
// the right schema — there is no separate artifact to ship or forget.
package migrations

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed *.sql
var FS embed.FS

// Up applies all pending migrations. Safe on every startup: ErrNoChange is not
// an error condition.
func Up(db *sql.DB) error {
	src, err := iofs.New(FS, ".")
	if err != nil {
		return fmt.Errorf("loading embedded migrations: %w", err)
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("creating postgres migration driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}
```

- [ ] **Step 6: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test ./migrations/ -v
```

Expected: PASS, all three tests.

- [ ] **Step 7: Apply against a real database**

```bash
docker run -d --name strat-mig -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16
sleep 6
docker exec strat-mig psql -U postgres -c "CREATE DATABASE stratium;"
cd /path/to/stratium-data/services/migrations
docker exec -i strat-mig psql -U postgres -d stratium -v ON_ERROR_STOP=1 < 000001_baseline.up.sql
docker exec strat-mig psql -U postgres -d stratium -c "\dt"
```

Expected: six tables — `agents`, `delegations`, `entitlements`, `policies`, `tenant_epoch`, `tier_overrides`.

- [ ] **Step 8: Verify the raise-only CHECK rejects a downgrade**

```bash
docker exec strat-mig psql -U postgres -d stratium -c \
  "INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) VALUES ('t1','Bash',1,4,'test');"
```

Expected: `ERROR: ... violates check constraint "tier_overrides_raise_only"`

- [ ] **Step 9: Verify the down migration**

```bash
docker exec -i strat-mig psql -U postgres -d stratium -v ON_ERROR_STOP=1 < 000001_baseline.down.sql
docker exec strat-mig psql -U postgres -d stratium -c "\dt"
docker rm -f strat-mig
```

Expected: no relations remain.

- [ ] **Step 10: Commit**

```bash
cd /path/to/stratium-data
git add services/migrations services/go.mod services/go.sum
git commit -m "feat: embedded migrations with a tenant-scoped baseline

Tenancy is in the first migration rather than a retrofit. tier_overrides
carries a raise-only CHECK so a direct SQL write cannot lower a tool's
sensitivity below its built-in tier."
```

---

### Task 9: Row-level security

**Files:**
- Create: `services/migrations/000002_rls.up.sql`, `000002_rls.down.sql`

**Interfaces:**
- Consumes: the baseline tables from Task 8
- Produces: connections must `SET LOCAL app.tenant_id`; Task 10's audit table follows the same pattern

- [ ] **Step 1: Write the migration**

Create `services/migrations/000002_rls.up.sql`:

```sql
-- Row-level security. The application sets app.tenant_id per transaction and
-- the database enforces isolation, so a query missing its WHERE clause returns
-- nothing instead of another tenant's data (C18).
--
-- FORCE is required because a table owner otherwise bypasses RLS. The
-- application role must not hold BYPASSRLS.

CREATE OR REPLACE FUNCTION current_tenant() RETURNS TEXT AS $$
    SELECT current_setting('app.tenant_id', true);
$$ LANGUAGE SQL STABLE;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'agents','delegations','policies','entitlements','tier_overrides','tenant_epoch'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) '
            'WITH CHECK (tenant_id = current_tenant())', t);
    END LOOP;
END $$;
```

`current_setting('app.tenant_id', true)` returns NULL when unset, and `tenant_id = NULL` is never true — so a connection that forgets to set the tenant sees nothing. That is the correct fail-closed default.

Create `services/migrations/000002_rls.down.sql`:

```sql
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'agents','delegations','policies','entitlements','tier_overrides','tenant_epoch'
    ] LOOP
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
    END LOOP;
END $$;
DROP FUNCTION IF EXISTS current_tenant();
```

- [ ] **Step 2: Set up a database with an application role**

```bash
docker run -d --name strat-rls -e POSTGRES_PASSWORD=test -p 55433:5432 postgres:16
sleep 6
cd /path/to/stratium-data/services/migrations
docker exec strat-rls psql -U postgres -c "CREATE DATABASE stratium;"
docker exec strat-rls psql -U postgres -d stratium -c "CREATE ROLE app LOGIN PASSWORD 'test';"
docker exec -i strat-rls psql -U postgres -d stratium -v ON_ERROR_STOP=1 < 000001_baseline.up.sql
docker exec -i strat-rls psql -U postgres -d stratium -v ON_ERROR_STOP=1 < 000002_rls.up.sql
docker exec strat-rls psql -U postgres -d stratium -c \
  "GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO app;"
docker exec strat-rls psql -U postgres -d stratium -c \
  "INSERT INTO tenant_epoch (tenant_id) VALUES ('tenant-a'),('tenant-b');"
```

- [ ] **Step 3: Verify a tenant sees only its own rows**

```bash
docker exec strat-rls psql "postgresql://app:test@localhost/stratium" -c \
  "BEGIN; SET LOCAL app.tenant_id='tenant-a'; SELECT tenant_id FROM tenant_epoch; COMMIT;"
```

Expected: exactly one row, `tenant-a`.

- [ ] **Step 4: Verify an unset tenant sees nothing**

```bash
docker exec strat-rls psql "postgresql://app:test@localhost/stratium" -c "SELECT count(*) FROM tenant_epoch;"
```

Expected: `0` — a forgotten `SET LOCAL` leaks nothing.

- [ ] **Step 5: Verify a cross-tenant write is rejected**

```bash
docker exec strat-rls psql "postgresql://app:test@localhost/stratium" -c \
  "BEGIN; SET LOCAL app.tenant_id='tenant-a'; INSERT INTO tenant_epoch (tenant_id) VALUES ('tenant-b'); COMMIT;"
docker rm -f strat-rls
```

Expected: `ERROR: new row violates row-level security policy`

- [ ] **Step 6: Commit**

```bash
cd /path/to/stratium-data
git add services/migrations
git commit -m "feat: row-level security for tenant isolation (C18)

An unset app.tenant_id returns zero rows rather than everything."
```

---

### Task 10: Audit chain table

**Files:**
- Create: `services/migrations/000003_audit_chain.up.sql`, `000003_audit_chain.down.sql`

**Interfaces:**
- Consumes: `current_tenant()` from Task 9; the `Entry` shape from Task 7
- Produces: table `audit_chain`, append-only and tenant-scoped

- [ ] **Step 1: Write the migration**

Create `services/migrations/000003_audit_chain.up.sql`:

```sql
-- Hash-chained, append-only audit (spec §4.9). Each row commits to its
-- predecessor, so any edit or deletion is detectable by re-walking the chain.
--
-- Columns mirror pkg/audit.Entry. Raw tool inputs are NOT stored — only
-- input_digest. Encrypted plaintext and crypto-shredding are deferred until
-- per-tenant key management is specified (spec §8).

CREATE TABLE audit_chain (
    seq        BIGSERIAL PRIMARY KEY,
    tenant_id  TEXT NOT NULL,

    prev_hash  BYTEA NOT NULL,   -- 32 zero bytes for a tenant's first row
    entry_hash BYTEA NOT NULL,   -- SHA-256 over the canonical serialization

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type  TEXT NOT NULL,
    actor       TEXT NOT NULL,

    agent_id           UUID,
    delegation_id      UUID,
    root_delegation_id UUID,
    chain_depth        SMALLINT NOT NULL DEFAULT 0,

    tool_name     TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT '',
    declared_tier SMALLINT NOT NULL DEFAULT 0,
    derived_tier  SMALLINT NOT NULL DEFAULT 0,

    decision        TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY','ESCALATE')),
    denied_leg      TEXT NOT NULL DEFAULT '' CHECK (denied_leg IN ('','principal','agent','delegation')),
    denied_at_depth SMALLINT NOT NULL DEFAULT -1,
    reason          TEXT NOT NULL DEFAULT '',

    input_digest BYTEA,

    CONSTRAINT audit_chain_hash_len CHECK (
        octet_length(prev_hash) = 32 AND octet_length(entry_hash) = 32),
    -- input_digest is also a SHA-256 and must be constrained like its siblings.
    -- Nullable, because an entry need not carry one; but a present value of the
    -- wrong length is a truncated or corrupt digest, not a shorter one.
    CONSTRAINT audit_chain_input_digest_len CHECK (
        input_digest IS NULL OR octet_length(input_digest) = 32)
);

CREATE UNIQUE INDEX audit_chain_tenant_seq   ON audit_chain(tenant_id, seq);
CREATE INDEX audit_chain_tenant_time         ON audit_chain(tenant_id, occurred_at DESC);
CREATE INDEX audit_chain_delegation          ON audit_chain(delegation_id);
CREATE INDEX audit_chain_root                ON audit_chain(root_delegation_id);

-- Append-only, enforced by the database. Rules make UPDATE and DELETE no-ops
-- for every role including the owner, so the application cannot rewrite its
-- own history even if compromised.
CREATE RULE audit_chain_no_update AS ON UPDATE TO audit_chain DO INSTEAD NOTHING;
CREATE RULE audit_chain_no_delete AS ON DELETE TO audit_chain DO INSTEAD NOTHING;

-- Rules do NOT intercept TRUNCATE — only triggers do. Without this, TRUNCATE
-- empties the entire audit trail silently, for any role holding the privilege,
-- and the UPDATE/DELETE rules above give a false sense of immutability.
-- Verified: TRUNCATE as the table owner took the table from 1 row to 0 with no
-- error before this trigger existed.
CREATE OR REPLACE FUNCTION audit_chain_deny_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_chain is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_chain_no_truncate
    BEFORE TRUNCATE ON audit_chain
    FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_deny_truncate();

ALTER TABLE audit_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_chain
    USING (tenant_id = current_tenant())
    WITH CHECK (tenant_id = current_tenant());
```

Create `services/migrations/000003_audit_chain.down.sql`:

```sql
DROP TRIGGER IF EXISTS audit_chain_no_truncate ON audit_chain;
DROP FUNCTION IF EXISTS audit_chain_deny_truncate();
DROP RULE IF EXISTS audit_chain_no_delete ON audit_chain;
DROP RULE IF EXISTS audit_chain_no_update ON audit_chain;
DROP TABLE IF EXISTS audit_chain;
```

- [ ] **Step 2: Verify the tenancy test still passes**

```bash
cd /path/to/stratium-data/services && go test ./migrations/ -v
```

Expected: PASS — `TestEveryTableHasTenantID` now covers `audit_chain` too.

- [ ] **Step 3: Verify UPDATE and DELETE are no-ops**

```bash
docker run -d --name strat-audit -e POSTGRES_PASSWORD=test -p 55434:5432 postgres:16
sleep 6
cd /path/to/stratium-data/services/migrations
docker exec strat-audit psql -U postgres -c "CREATE DATABASE stratium;"
for f in 000001_baseline.up.sql 000002_rls.up.sql 000003_audit_chain.up.sql; do
  docker exec -i strat-audit psql -U postgres -d stratium -v ON_ERROR_STOP=1 < $f
done
docker exec strat-audit psql -U postgres -d stratium -c "
BEGIN;
SET LOCAL app.tenant_id='tenant-a';
INSERT INTO audit_chain (tenant_id, prev_hash, entry_hash, event_type, actor, decision, reason)
VALUES ('tenant-a', repeat('\\000',32)::bytea, sha256('x'::bytea), 'decision', 'alice', 'ALLOW', 'original');
UPDATE audit_chain SET reason='tampered';
DELETE FROM audit_chain;
SELECT reason, count(*) OVER () AS rows FROM audit_chain;
COMMIT;"
docker rm -f strat-audit
```

Expected: one row, `reason = original`, `rows = 1`. Both the UPDATE and the DELETE did nothing.

- [ ] **Step 4: Commit**

```bash
cd /path/to/stratium-data
git add services/migrations
git commit -m "feat: append-only hash-chained audit table (D4, C15)

DO INSTEAD NOTHING rules make UPDATE and DELETE no-ops for every role,
including the table owner."
```

---

### Task 11: Decision types and tier derivation

**Files:**
- Create: `services/internal/authz/types.go`
- Create: `services/internal/authz/tier.go`
- Create: `services/internal/authz/tier_test.go`

**Interfaces:**
- Consumes: `models.ActionTier`, `models.AgentTrustTier`, `models.Delegation`
- Produces:
  - `type Effect int` — `EffectDeny`(0), `EffectAllow`(1), `EffectEscalate`(2), `String()`
  - `type LegResult struct { Effect Effect; Reason string }`
  - `type Action struct { Tool, Verb, RawInput string; DeclaredTier *models.ActionTier }`
  - `type Principal struct { Subject string; Attributes map[string]string }`
  - `type AgentInfo struct { ID uuid.UUID; TrustTier models.AgentTrustTier; Enabled, Suspended bool; AllowedTools []string }`
  - `type Request struct { TenantID string; Principal Principal; Agent AgentInfo; Chain []*models.Delegation; Action Action; Resource map[string]string; Now time.Time; PrincipalDecision LegResult }`
  - `type Result struct { Effect Effect; DerivedTier models.ActionTier; Principal, Agent, Delegation LegResult; DeniedAtDepth int; DeniedLeg, Reason string }`
  - `type TierTable struct { Overrides, Catalog map[string]models.ActionTier; UnknownTier models.ActionTier; DenyUnknown bool }`
  - `func DeriveTier(TierTable, Action) (models.ActionTier, error)`
  - `func BuiltinTier(Action) (models.ActionTier, bool)`
  - `func ValidateOverride(builtin, override models.ActionTier) error`
  - `var ErrUnknownAction, ErrOverrideLowersTier error`

- [ ] **Step 1: Write the failing test**

Create `services/internal/authz/tier_test.go`:

```go
package authz

import (
	"errors"
	"testing"

	"stratium/pkg/models"
)

func tierPtr(t models.ActionTier) *models.ActionTier { return &t }

func TestBuiltinTier_Verbs(t *testing.T) {
	cases := map[string]models.ActionTier{
		"read":     models.ActionTierReadOnly,
		"list":     models.ActionTierReadOnly,
		"write":    models.ActionTierInternalModify,
		"update":   models.ActionTierInternalModify,
		"send":     models.ActionTierExternalComms,
		"publish":  models.ActionTierExternalComms,
		"delete":   models.ActionTierDestructive,
		"transfer": models.ActionTierDestructive,
	}
	for verb, want := range cases {
		t.Run(verb, func(t *testing.T) {
			got, ok := BuiltinTier(Action{Verb: verb})
			if !ok || got != want {
				t.Fatalf("verb %q: got %v (ok=%v), want %v", verb, got, ok, want)
			}
		})
	}
}

// Shell classification runs server-side. In the previous system this lived in
// a bash script on the agent's own machine and the server believed its answer.
func TestBuiltinTier_ShellCommands(t *testing.T) {
	cases := map[string]models.ActionTier{
		"rm -rf /var/data":            models.ActionTierDestructive,
		"dd if=/dev/zero of=/dev/sda": models.ActionTierDestructive,
		"psql -c 'DROP TABLE users'":  models.ActionTierDestructive,
		"terraform destroy":           models.ActionTierDestructive,
		"curl https://evil.example":   models.ActionTierExternalComms,
		"git push origin main":        models.ActionTierExternalComms,
		"cat /etc/hosts":              models.ActionTierReadOnly,
		"ls -la":                      models.ActionTierReadOnly,
		"git status":                  models.ActionTierReadOnly,
		"mkdir build":                 models.ActionTierInternalModify,
	}
	for cmd, want := range cases {
		t.Run(cmd, func(t *testing.T) {
			got, ok := BuiltinTier(Action{Tool: "Bash", RawInput: cmd})
			if !ok || got != want {
				t.Fatalf("command %q: got %v (ok=%v), want %v", cmd, got, ok, want)
			}
		})
	}
}

// An unrecognized command must not land below INTERNAL_MODIFY. Assuming
// read-only is how an unknown internal CLI slips under a low tier cap.
func TestBuiltinTier_UnknownCommandAssumedModifying(t *testing.T) {
	got, ok := BuiltinTier(Action{Tool: "Bash", RawInput: "acmectl deploy --prod"})
	if !ok || got < models.ActionTierInternalModify {
		t.Fatalf("unknown command got %v (ok=%v); must be at least INTERNAL_MODIFY", got, ok)
	}
}

// Raw input beats the verb: the verb attached to a Bash call says nothing
// about what the command actually does.
func TestBuiltinTier_RawInputBeatsVerb(t *testing.T) {
	got, _ := BuiltinTier(Action{Tool: "Bash", Verb: "read", RawInput: "rm -rf /"})
	if got != models.ActionTierDestructive {
		t.Fatalf("raw input must take precedence over the verb, got %v", got)
	}
}

func TestDeriveTier_OverrideBeatsCatalogAndBuiltin(t *testing.T) {
	table := TierTable{
		Overrides: map[string]models.ActionTier{"read": models.ActionTierDestructive},
		Catalog:   map[string]models.ActionTier{"read": models.ActionTierExternalComms},
	}
	got, err := DeriveTier(table, Action{Verb: "read"})
	if err != nil || got != models.ActionTierDestructive {
		t.Fatalf("override must win: got %v, err %v", got, err)
	}
}

func TestDeriveTier_CatalogBeatsBuiltin(t *testing.T) {
	table := TierTable{Catalog: map[string]models.ActionTier{"read": models.ActionTierExternalComms}}
	got, err := DeriveTier(table, Action{Verb: "read"})
	if err != nil || got != models.ActionTierExternalComms {
		t.Fatalf("catalog must beat built-in: got %v, err %v", got, err)
	}
}

func TestDeriveTier_FallsBackToBuiltin(t *testing.T) {
	got, err := DeriveTier(TierTable{}, Action{Verb: "delete"})
	if err != nil || got != models.ActionTierDestructive {
		t.Fatalf("got %v, err %v; want DESTRUCTIVE", got, err)
	}
}

func TestDeriveTier_UnknownDenies(t *testing.T) {
	_, err := DeriveTier(TierTable{DenyUnknown: true}, Action{Verb: "frobnicate"})
	if !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("unknown action with DenyUnknown must error, got %v", err)
	}
}

func TestDeriveTier_UnknownUsesFloor(t *testing.T) {
	table := TierTable{UnknownTier: models.ActionTierInternalModify}
	got, err := DeriveTier(table, Action{Verb: "frobnicate"})
	if err != nil || got != models.ActionTierInternalModify {
		t.Fatalf("got %v, err %v; want the configured floor", got, err)
	}
}

// The declared tier must never influence derivation. (C3)
func TestDeriveTier_IgnoresDeclaredTier(t *testing.T) {
	a := Action{Verb: "delete", DeclaredTier: tierPtr(models.ActionTierReadOnly)}
	got, err := DeriveTier(TierTable{}, a)
	if err != nil || got != models.ActionTierDestructive {
		t.Fatalf("declared tier leaked into derivation: got %v", got)
	}
}

func TestValidateOverride(t *testing.T) {
	if err := ValidateOverride(models.ActionTierReadOnly, models.ActionTierDestructive); err != nil {
		t.Fatalf("raising must be allowed: %v", err)
	}
	if err := ValidateOverride(models.ActionTierExternalComms, models.ActionTierExternalComms); err != nil {
		t.Fatalf("equal must be allowed: %v", err)
	}
	if err := ValidateOverride(models.ActionTierDestructive, models.ActionTierReadOnly); !errors.Is(err, ErrOverrideLowersTier) {
		t.Fatalf("lowering must be rejected, got %v", err)
	}
}

func TestEffect_DenyIsZeroValue(t *testing.T) {
	var e Effect
	if e != EffectDeny {
		t.Fatal("the zero value of Effect must be EffectDeny — an unevaluated leg must deny")
	}
	var leg LegResult
	if leg.Effect != EffectDeny {
		t.Fatal("a zero-value LegResult must deny")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ 2>&1 | head -5
```

Expected: FAIL — `undefined: BuiltinTier`

- [ ] **Step 3: Write types.go**

Create `services/internal/authz/types.go`:

```go
// Package authz is the single place a Stratium authorization decision is
// computed. It is pure: no database handles, no network clients, no ambient
// clock. Callers load the data and pass it in; authz decides.
//
// Every enforcement surface — gRPC proxy, MCP, hooks, Envoy ext-authz —
// reaches this code through the PDP. Nothing else may compute a decision.
// Three parallel implementations drifting apart is the specific failure this
// package exists to prevent.
package authz

import (
	"time"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

// Effect is the outcome of a decision, or of one leg of it.
type Effect int

const (
	// EffectDeny is the zero value deliberately: a leg that is never evaluated
	// must deny rather than silently permit. Do not reorder these.
	EffectDeny Effect = iota
	EffectAllow
	EffectEscalate
)

func (e Effect) String() string {
	switch e {
	case EffectAllow:
		return "ALLOW"
	case EffectEscalate:
		return "ESCALATE"
	default:
		return "DENY"
	}
}

// LegResult is one leg's contribution to the compound decision.
type LegResult struct {
	Effect Effect
	Reason string
}

// Action describes what the agent is attempting.
type Action struct {
	Tool     string // "Bash", "Read", "mcp__stripe__create_refund"
	Verb     string // "read", "write", "delete"
	RawInput string // the actual command or path, used for derivation

	// DeclaredTier is what the caller claims. It never derives the tier — it is
	// only cross-checked against the derived value (C1, C2, C3).
	DeclaredTier *models.ActionTier
}

// Principal is the human on whose behalf the agent acts.
type Principal struct {
	Subject    string
	Attributes map[string]string
}

// AgentInfo is the acting agent's registry record, reduced to what a decision
// needs.
type AgentInfo struct {
	ID           uuid.UUID
	TrustTier    models.AgentTrustTier
	Enabled      bool
	Suspended    bool
	AllowedTools []string
}

// Request is a complete decision input. Chain is ordered root-first, with the
// acting delegation last.
type Request struct {
	TenantID  string
	Principal Principal
	Agent     AgentInfo
	Chain     []*models.Delegation
	Action    Action
	Resource  map[string]string

	// Now is injected so decisions are deterministic and testable.
	Now time.Time

	// PrincipalDecision is the policy engines' verdict, evaluated before this
	// call. Its zero value is EffectDeny, so a caller that forgets to evaluate
	// it denies rather than permitting.
	PrincipalDecision LegResult
}

// Result is the compound decision.
type Result struct {
	Effect      Effect
	DerivedTier models.ActionTier

	Principal  LegResult
	Agent      LegResult
	Delegation LegResult

	// DeniedAtDepth is the chain depth at which a denial occurred, or -1.
	DeniedAtDepth int
	DeniedLeg     string
	Reason        string
}
```

- [ ] **Step 4: Write tier.go**

Create `services/internal/authz/tier.go`:

```go
package authz

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"stratium/pkg/models"
)

var (
	// ErrUnknownAction is returned when an action cannot be classified and the
	// tenant has configured unknown actions to deny.
	ErrUnknownAction = errors.New("action could not be classified")

	// ErrOverrideLowersTier is returned when an override would reduce an
	// action's sensitivity below its built-in tier. Overrides are raise-only.
	ErrOverrideLowersTier = errors.New("tier override may not lower the built-in tier")
)

// TierTable is a tenant's resolved tier configuration, loaded by the caller.
type TierTable struct {
	// Overrides are tenant-authored and raise-only, validated by
	// ValidateOverride at write time and by a database CHECK.
	Overrides map[string]models.ActionTier

	// Catalog holds tiers registered with a tool at registration time.
	Catalog map[string]models.ActionTier

	// UnknownTier is the floor for unclassifiable actions when DenyUnknown is false.
	UnknownTier models.ActionTier

	// DenyUnknown makes an unclassifiable action an error rather than a floor.
	DenyUnknown bool
}

// Shell patterns, most severe first.
var (
	reDestructive = regexp.MustCompile(`(?i)\brm\s+-[a-z]*[rf]|\bmkfs\b|\bdd\s+if=|\bshred\b|` +
		`\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\b|\bdropdb\b|` +
		`\bgit\s+push\s+--force|\bkubectl\s+delete\b|\bterraform\s+destroy\b`)

	reExternal = regexp.MustCompile(`(?i)\b(curl|wget|ssh|scp|rsync|nc|telnet)\b|` +
		`\bgit\s+push\b|\bdocker\s+push\b|\bnpm\s+publish\b|\b(aws|gcloud|az)\s`)

	reReadOnly = regexp.MustCompile(`(?i)^\s*(cat|ls|pwd|head|tail|wc|grep|find|file|stat|` +
		`echo|which|whoami|date|df|du|ps|env|` +
		`git\s+(log|status|diff|show|branch)|docker\s+ps|kubectl\s+get)\b`)
)

var verbTiers = map[string]models.ActionTier{
	"read": models.ActionTierReadOnly, "get": models.ActionTierReadOnly,
	"list": models.ActionTierReadOnly, "query": models.ActionTierReadOnly,
	"search": models.ActionTierReadOnly,

	"write": models.ActionTierInternalModify, "create": models.ActionTierInternalModify,
	"update": models.ActionTierInternalModify, "modify": models.ActionTierInternalModify,
	"patch": models.ActionTierInternalModify,

	"send": models.ActionTierExternalComms, "email": models.ActionTierExternalComms,
	"notify": models.ActionTierExternalComms, "webhook": models.ActionTierExternalComms,
	"publish": models.ActionTierExternalComms,

	"delete": models.ActionTierDestructive, "destroy": models.ActionTierDestructive,
	"drop": models.ActionTierDestructive, "revoke": models.ActionTierDestructive,
	"transfer": models.ActionTierDestructive, "execute": models.ActionTierDestructive,
}

// BuiltinTier classifies an action using the shipped defaults, returning false
// when the action is unrecognized.
//
// Raw input is classified first and takes precedence: the verb attached to a
// shell call says nothing about what the command does.
func BuiltinTier(a Action) (models.ActionTier, bool) {
	if a.RawInput != "" {
		switch {
		case reDestructive.MatchString(a.RawInput):
			return models.ActionTierDestructive, true
		case reExternal.MatchString(a.RawInput):
			return models.ActionTierExternalComms, true
		case reReadOnly.MatchString(a.RawInput):
			return models.ActionTierReadOnly, true
		default:
			// An unrecognized command is assumed to modify. It is not read-only
			// merely because no pattern matched.
			return models.ActionTierInternalModify, true
		}
	}
	if t, ok := verbTiers[strings.ToLower(a.Verb)]; ok {
		return t, true
	}
	return models.ActionTierReasoning, false
}

// DeriveTier resolves an action's sensitivity server-side (spec §4.4):
//
//	1. tenant override  2. catalog entry  3. built-in  4. floor, or deny
//
// The caller's declared tier is never consulted here.
func DeriveTier(t TierTable, a Action) (models.ActionTier, error) {
	keys := lookupKeys(a)
	for _, k := range keys {
		if tier, ok := t.Overrides[k]; ok {
			return tier, nil
		}
	}
	for _, k := range keys {
		if tier, ok := t.Catalog[k]; ok {
			return tier, nil
		}
	}
	if tier, ok := BuiltinTier(a); ok {
		return tier, nil
	}
	if t.DenyUnknown {
		return models.ActionTierReasoning,
			fmt.Errorf("%w: tool=%q verb=%q", ErrUnknownAction, a.Tool, a.Verb)
	}
	return t.UnknownTier, nil
}

// lookupKeys returns candidate keys, most specific first, so a tenant may
// override a whole tool ("Bash") or a single verb ("read").
func lookupKeys(a Action) []string {
	keys := make([]string, 0, 3)
	if a.Tool != "" && a.Verb != "" {
		keys = append(keys, a.Tool+":"+a.Verb)
	}
	if a.Tool != "" {
		keys = append(keys, a.Tool)
	}
	if a.Verb != "" {
		keys = append(keys, strings.ToLower(a.Verb))
	}
	return keys
}

// ValidateOverride enforces the raise-only invariant. Called when an
// administrator writes an override, not on the decision path.
func ValidateOverride(builtin, override models.ActionTier) error {
	if override < builtin {
		return fmt.Errorf("%w: built-in is %s, override is %s",
			ErrOverrideLowersTier, builtin, override)
	}
	return nil
}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -v 2>&1 | tail -20
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add services/internal/authz
git commit -m "feat(authz): decision types and server-side tier derivation (C3, C4)

Shell classification runs server-side. EffectDeny is the zero value so an
unevaluated leg denies."
```

---

### Task 12: Declared-vs-actual cross-check

**Files:**
- Modify: `services/internal/authz/tier.go`
- Modify: `services/internal/authz/tier_test.go`

**Interfaces:**
- Consumes: `DeriveTier` from Task 11
- Produces: `func CheckDeclaredTier(derived models.ActionTier, declared *models.ActionTier) LegResult`

- [ ] **Step 1: Write the failing test**

Append to `services/internal/authz/tier_test.go`:

```go
// Under-declaration is a spoofing attempt. (C1)
func TestCheckDeclaredTier_UnderDeclarationDenies(t *testing.T) {
	got := CheckDeclaredTier(models.ActionTierDestructive, tierPtr(models.ActionTierReadOnly))
	if got.Effect != EffectDeny {
		t.Fatalf("declared below actual must deny, got %v", got.Effect)
	}
	if got.Reason == "" {
		t.Fatal("a denial must carry a reason")
	}
}

// Over-declaration is conservative and permitted. (C2)
func TestCheckDeclaredTier_OverDeclarationAllowed(t *testing.T) {
	got := CheckDeclaredTier(models.ActionTierReadOnly, tierPtr(models.ActionTierDestructive))
	if got.Effect != EffectAllow {
		t.Fatalf("declared above actual must be allowed, got %v: %s", got.Effect, got.Reason)
	}
}

func TestCheckDeclaredTier_ExactMatchAllowed(t *testing.T) {
	if got := CheckDeclaredTier(models.ActionTierExternalComms, tierPtr(models.ActionTierExternalComms)); got.Effect != EffectAllow {
		t.Fatalf("exact match must be allowed, got %v", got.Effect)
	}
}

func TestCheckDeclaredTier_NoDeclarationAllowed(t *testing.T) {
	if got := CheckDeclaredTier(models.ActionTierDestructive, nil); got.Effect != EffectAllow {
		t.Fatalf("absent declaration must be allowed, got %v", got.Effect)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -run TestCheckDeclaredTier 2>&1 | head -5
```

Expected: FAIL — `undefined: CheckDeclaredTier`

- [ ] **Step 3: Write the implementation**

Append to `services/internal/authz/tier.go`:

```go
// CheckDeclaredTier compares the caller's declared tier against the derived one.
//
// Over-declaration is permitted — a conservative client that rounds up is not
// attacking anything. Under-declaration is denied: it is an attempt to slip a
// sensitive action beneath a delegation cap, and it is the hole that made
// every enforcement path in the previous system bypassable (spec §1.1 D1).
func CheckDeclaredTier(derived models.ActionTier, declared *models.ActionTier) LegResult {
	if declared == nil {
		return LegResult{Effect: EffectAllow}
	}
	if *declared < derived {
		return LegResult{
			Effect: EffectDeny,
			Reason: fmt.Sprintf("declared action tier %s is below the derived tier %s (under-declaration)",
				*declared, derived),
		}
	}
	return LegResult{Effect: EffectAllow}
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -v 2>&1 | tail -10
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add services/internal/authz
git commit -m "feat(authz): deny under-declared action tiers (C1, C2)"
```

---

### Task 13: Delegation leg

**Files:**
- Create: `services/internal/authz/delegation.go`
- Create: `services/internal/authz/delegation_test.go`

**Interfaces:**
- Consumes: `models.Delegation`, `classification.CheckCap`, `Action`, `LegResult`
- Produces: `func DelegationLeg(chain []*models.Delegation, a Action, derived models.ActionTier, resource map[string]string, now time.Time, maxDepth int) (LegResult, int)` — leg result plus the denying depth, or -1

- [ ] **Step 1: Write the failing test**

Create `services/internal/authz/delegation_test.go`:

```go
package authz

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

var authzNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func delegation(depth int, maxTier models.ActionTier, tools []string) *models.Delegation {
	return &models.Delegation{
		ID:            uuid.New(),
		Depth:         depth,
		MaxActionTier: maxTier,
		ApprovedTools: tools,
		ExpiresAt:     authzNow.Add(time.Hour),
	}
}

func TestDelegationLeg_AllowsWithinScope(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierInternalModify, []string{"Read"})}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("within scope must allow, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

func TestDelegationLeg_DeniesTierAboveCeiling(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierReadOnly, []string{"Bash"})}
	got, _ := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierDestructive, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("tier above ceiling must deny, got %v", got.Effect)
	}
}

func TestDelegationLeg_DeniesToolNotApproved(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierDestructive, []string{"Read"})}
	got, _ := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("unapproved tool must deny, got %v", got.Effect)
	}
}

// Every hop is checked and the denying depth reported.
func TestDelegationLeg_ReportsDenyingDepth(t *testing.T) {
	chain := []*models.Delegation{
		delegation(0, models.ActionTierDestructive, []string{"Bash"}),
		delegation(1, models.ActionTierDestructive, []string{"Bash"}),
		delegation(2, models.ActionTierReadOnly, []string{"Bash"}),
	}
	got, depth := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierExternalComms, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("must deny, got %v", got.Effect)
	}
	if depth != 2 {
		t.Fatalf("denial should be attributed to depth 2, got %d", depth)
	}
}

func TestDelegationLeg_DeniesExpiredHop(t *testing.T) {
	expired := delegation(1, models.ActionTierDestructive, []string{"Read"})
	expired.ExpiresAt = authzNow.Add(-time.Minute)
	chain := []*models.Delegation{delegation(0, models.ActionTierDestructive, []string{"Read"}), expired}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny || depth != 1 {
		t.Fatalf("expired hop must deny at depth 1, got %v at %d", got.Effect, depth)
	}
}

// A revoked root denies every descendant. (C9)
func TestDelegationLeg_DeniesRevokedRoot(t *testing.T) {
	root := delegation(0, models.ActionTierDestructive, []string{"Read"})
	root.Revoked = true
	chain := []*models.Delegation{root, delegation(1, models.ActionTierReadOnly, []string{"Read"})}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny || depth != 0 {
		t.Fatalf("revoked root must deny at depth 0, got %v at %d", got.Effect, depth)
	}
}

func TestDelegationLeg_DeniesOverMaxDepth(t *testing.T) {
	chain := []*models.Delegation{
		delegation(0, models.ActionTierDestructive, nil),
		delegation(1, models.ActionTierDestructive, nil),
		delegation(2, models.ActionTierDestructive, nil),
	}
	got, _ := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 1)
	if got.Effect != EffectDeny {
		t.Fatalf("chain over max depth must deny, got %v", got.Effect)
	}
}

// No delegation means nothing authorizes the action.
func TestDelegationLeg_DeniesEmptyChain(t *testing.T) {
	got, _ := DelegationLeg(nil, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("empty chain must deny, got %v", got.Effect)
	}
}

func TestDelegationLeg_DeniesClassificationAboveCap(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"}
	resource := map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"}
	got, _ := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("resource above cap must deny, got %v", got.Effect)
	}
}

// The narrowest hop binds, even when it is not the last one.
func TestDelegationLeg_NarrowestHopBinds(t *testing.T) {
	chain := []*models.Delegation{
		delegation(0, models.ActionTierReadOnly, nil),
		delegation(1, models.ActionTierDestructive, nil),
	}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierInternalModify, nil, authzNow, 5)
	if got.Effect != EffectDeny || depth != 0 {
		t.Fatalf("the narrowest hop must bind, got %v at %d", got.Effect, depth)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -run TestDelegationLeg 2>&1 | head -5
```

Expected: FAIL — `undefined: DelegationLeg`

- [ ] **Step 3: Write the implementation**

Create `services/internal/authz/delegation.go`:

```go
package authz

import (
	"fmt"
	"time"

	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// DelegationLeg evaluates every hop in the chain, returning the leg result and
// the depth at which a denial occurred, or -1.
//
// This leg is structural and never policy-configurable. It is the ceiling: if
// policy could raise it, the signed delegation artifact would mean nothing
// (spec §4.3).
//
// derived is the server-computed tier; the caller's declared tier never
// reaches this function.
func DelegationLeg(
	chain []*models.Delegation,
	a Action,
	derived models.ActionTier,
	resource map[string]string,
	now time.Time,
	maxDepth int,
) (LegResult, int) {
	if len(chain) == 0 {
		return LegResult{Effect: EffectDeny, Reason: "no delegation in chain"}, -1
	}
	if len(chain)-1 > maxDepth {
		return LegResult{
			Effect: EffectDeny,
			Reason: fmt.Sprintf("delegation chain depth %d exceeds maximum %d", len(chain)-1, maxDepth),
		}, chain[len(chain)-1].Depth
	}

	for _, d := range chain {
		if d.Revoked {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("delegation %s at depth %d is revoked", d.ID, d.Depth)}, d.Depth
		}
		if !d.IsActive(now) {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("delegation %s at depth %d expired at %s",
					d.ID, d.Depth, d.ExpiresAt.Format(time.RFC3339))}, d.Depth
		}
		if derived > d.MaxActionTier {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("action tier %s exceeds delegation max_action_tier %s at depth %d",
					derived, d.MaxActionTier, d.Depth)}, d.Depth
		}
		if a.Tool != "" && !d.HasTool(a.Tool) {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("tool %q not in delegation approved_tools at depth %d",
					a.Tool, d.Depth)}, d.Depth
		}
		if allowed, reason := classification.CheckCap(d.ClassificationCaps, resource); !allowed {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("%s (depth %d)", reason, d.Depth)}, d.Depth
		}
	}
	return LegResult{Effect: EffectAllow}, -1
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -v 2>&1 | tail -20
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add services/internal/authz
git commit -m "feat(authz): delegation leg — the structural ceiling (C8, C9, C24)"
```

---

### Task 14: Agent leg

**Files:**
- Create: `services/internal/authz/agent.go`
- Create: `services/internal/authz/agent_test.go`

**Interfaces:**
- Consumes: `AgentInfo`, `Action`, `models.ActionTier`, `models.AgentTrustTier`
- Produces:
  - `type TrustTable struct { Required map[models.ActionTier]models.AgentTrustTier }`
  - `func DefaultTrustTable() TrustTable`
  - `func AgentLeg(agent AgentInfo, a Action, derived models.ActionTier, table TrustTable) LegResult`

- [ ] **Step 1: Write the failing test**

Create `services/internal/authz/agent_test.go`:

```go
package authz

import (
	"testing"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

func agentInfo(trust models.AgentTrustTier, tools []string) AgentInfo {
	return AgentInfo{ID: uuid.New(), TrustTier: trust, Enabled: true, AllowedTools: tools}
}

func TestAgentLeg_AllowsSufficientTrust(t *testing.T) {
	a := agentInfo(models.TrustTierCertified, []string{"Bash"})
	if got := AgentLeg(a, Action{Tool: "Bash"}, models.ActionTierExternalComms, DefaultTrustTable()); got.Effect != EffectAllow {
		t.Fatalf("certified agent should perform tier 3, got %v: %s", got.Effect, got.Reason)
	}
}

func TestAgentLeg_DeniesInsufficientTrust(t *testing.T) {
	a := agentInfo(models.TrustTierRegistered, []string{"Bash"})
	if got := AgentLeg(a, Action{Tool: "Bash"}, models.ActionTierDestructive, DefaultTrustTable()); got.Effect != EffectDeny {
		t.Fatalf("registered agent must not perform tier 4, got %v", got.Effect)
	}
}

func TestAgentLeg_DeniesToolNotAllowed(t *testing.T) {
	a := agentInfo(models.TrustTierPlatformTrusted, []string{"Read"})
	if got := AgentLeg(a, Action{Tool: "Bash"}, models.ActionTierReadOnly, DefaultTrustTable()); got.Effect != EffectDeny {
		t.Fatalf("tool outside the allowlist must deny, got %v", got.Effect)
	}
}

// A disabled or suspended agent denies regardless of trust. (C10)
func TestAgentLeg_DeniesDisabledAgent(t *testing.T) {
	a := agentInfo(models.TrustTierPlatformTrusted, nil)
	a.Enabled = false
	if got := AgentLeg(a, Action{Tool: "Read"}, models.ActionTierReadOnly, DefaultTrustTable()); got.Effect != EffectDeny {
		t.Fatalf("disabled agent must deny, got %v", got.Effect)
	}
}

func TestAgentLeg_DeniesSuspendedAgent(t *testing.T) {
	a := agentInfo(models.TrustTierPlatformTrusted, nil)
	a.Suspended = true
	if got := AgentLeg(a, Action{Tool: "Read"}, models.ActionTierReadOnly, DefaultTrustTable()); got.Effect != EffectDeny {
		t.Fatalf("suspended agent must deny, got %v", got.Effect)
	}
}

// An empty allowlist is unrestricted, matching Agent.HasTool and
// Delegation.HasTool. The delegation leg is the real constraint.
func TestAgentLeg_EmptyToolListUnrestricted(t *testing.T) {
	a := agentInfo(models.TrustTierCertified, nil)
	if got := AgentLeg(a, Action{Tool: "anything"}, models.ActionTierReadOnly, DefaultTrustTable()); got.Effect != EffectAllow {
		t.Fatalf("an empty allowlist should not restrict, got %v: %s", got.Effect, got.Reason)
	}
}

// The trust table is data, so a tenant may require more trust than default.
func TestAgentLeg_TenantTableCanRaiseRequirement(t *testing.T) {
	strict := TrustTable{Required: map[models.ActionTier]models.AgentTrustTier{
		models.ActionTierReadOnly: models.TrustTierCertified,
	}}
	a := agentInfo(models.TrustTierRegistered, nil)
	if got := AgentLeg(a, Action{Tool: "Read"}, models.ActionTierReadOnly, strict); got.Effect != EffectDeny {
		t.Fatalf("a stricter tenant table must deny, got %v", got.Effect)
	}
}

// A tier absent from the table demands the highest trust rather than permitting.
func TestAgentLeg_MissingTierEntryFailsClosed(t *testing.T) {
	empty := TrustTable{Required: map[models.ActionTier]models.AgentTrustTier{}}
	a := agentInfo(models.TrustTierCertified, nil)
	if got := AgentLeg(a, Action{Tool: "Read"}, models.ActionTierDestructive, empty); got.Effect != EffectDeny {
		t.Fatalf("a missing table entry must fail closed, got %v", got.Effect)
	}
}

func TestDefaultTrustTable_CoversEveryActionTier(t *testing.T) {
	table := DefaultTrustTable()
	for tier := models.ActionTierReasoning; tier <= models.ActionTierDestructive; tier++ {
		if _, ok := table.Required[tier]; !ok {
			t.Errorf("default trust table has no entry for %s", tier)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -run TestAgentLeg 2>&1 | head -5
```

Expected: FAIL — `undefined: AgentLeg`

- [ ] **Step 3: Write the implementation**

Create `services/internal/authz/agent.go`:

```go
package authz

import (
	"fmt"

	"stratium/pkg/models"
)

// TrustTable maps an action tier to the minimum agent trust tier that may
// perform it. The comparison is structural; the table is data, so a tenant can
// require more trust than the default — never less (spec §4.3).
type TrustTable struct {
	Required map[models.ActionTier]models.AgentTrustTier
}

// DefaultTrustTable is the shipped mapping.
func DefaultTrustTable() TrustTable {
	return TrustTable{Required: map[models.ActionTier]models.AgentTrustTier{
		models.ActionTierReasoning:      models.TrustTierUnverified,
		models.ActionTierReadOnly:       models.TrustTierUnverified,
		models.ActionTierInternalModify: models.TrustTierRegistered,
		models.ActionTierExternalComms:  models.TrustTierCertified,
		models.ActionTierDestructive:    models.TrustTierPlatformTrusted,
	}}
}

// requiredTrust returns the minimum trust for an action tier. A tier absent
// from the table returns the highest requirement — an unmapped tier fails
// closed rather than permitting.
func (t TrustTable) requiredTrust(a models.ActionTier) models.AgentTrustTier {
	if req, ok := t.Required[a]; ok {
		return req
	}
	return models.TrustTierPlatformTrusted
}

// AgentLeg evaluates the acting agent's own authority: enabled, trusted enough
// for this tier, and permitted this tool.
//
// derived is the server-computed tier; the declared value never reaches here.
func AgentLeg(agent AgentInfo, a Action, derived models.ActionTier, table TrustTable) LegResult {
	if !agent.Enabled {
		return LegResult{Effect: EffectDeny, Reason: fmt.Sprintf("agent %s is disabled", agent.ID)}
	}
	if agent.Suspended {
		return LegResult{Effect: EffectDeny, Reason: fmt.Sprintf("agent %s is suspended", agent.ID)}
	}

	if required := table.requiredTrust(derived); agent.TrustTier < required {
		return LegResult{Effect: EffectDeny,
			Reason: fmt.Sprintf("agent trust tier %s insufficient for action tier %s (requires %s)",
				agent.TrustTier, derived, required)}
	}

	if a.Tool != "" && len(agent.AllowedTools) > 0 {
		found := false
		for _, tool := range agent.AllowedTools {
			if tool == a.Tool {
				found = true
				break
			}
		}
		if !found {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("tool %q not in agent allowed_tools", a.Tool)}
		}
	}

	return LegResult{Effect: EffectAllow}
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -v 2>&1 | tail -20
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add services/internal/authz
git commit -m "feat(authz): agent leg with a fail-closed trust table (C10)"
```

---

### Task 15: Compound decision

**Files:**
- Create: `services/internal/authz/compound.go`
- Create: `services/internal/authz/compound_test.go`

**Interfaces:**
- Consumes: `DeriveTier`, `CheckDeclaredTier`, `AgentLeg`, `DelegationLeg`
- Produces: `type Config struct { Tiers TierTable; Trust TrustTable; MaxDepth int }` and `func Decide(req Request, cfg Config) Result` — the PDP's entry point in Phase 2

- [ ] **Step 1: Write the failing test**

Create `services/internal/authz/compound_test.go`:

```go
package authz

import (
	"testing"

	"stratium/pkg/models"
)

func request() Request {
	return Request{
		TenantID:          "tenant-a",
		Principal:         Principal{Subject: "alice@example.com"},
		Agent:             agentInfo(models.TrustTierPlatformTrusted, nil),
		Chain:             []*models.Delegation{delegation(0, models.ActionTierDestructive, nil)},
		Action:            Action{Tool: "Read", Verb: "read"},
		Now:               authzNow,
		PrincipalDecision: LegResult{Effect: EffectAllow},
	}
}

func config() Config {
	return Config{Tiers: TierTable{}, Trust: DefaultTrustTable(), MaxDepth: 5}
}

func TestDecide_AllowsWhenAllLegsAllow(t *testing.T) {
	if got := Decide(request(), config()); got.Effect != EffectAllow {
		t.Fatalf("all legs allow should allow, got %v: %s", got.Effect, got.Reason)
	}
}

// Every leg is evaluated and reported. (C11)
func TestDecide_ReportsAllThreeLegs(t *testing.T) {
	got := Decide(request(), config())
	for name, leg := range map[string]LegResult{
		"principal": got.Principal, "agent": got.Agent, "delegation": got.Delegation,
	} {
		if leg.Effect != EffectAllow {
			t.Errorf("leg %s should be ALLOW, got %v", name, leg.Effect)
		}
	}
}

// A principal decision left at its zero value denies. This is the defect that
// made the previous compound decision silently two-legged. (C11, C13)
func TestDecide_UnevaluatedPrincipalDenies(t *testing.T) {
	req := request()
	req.PrincipalDecision = LegResult{}
	got := Decide(req, config())
	if got.Effect != EffectDeny {
		t.Fatalf("an unevaluated principal leg must deny, got %v", got.Effect)
	}
	if got.DeniedLeg != "principal" {
		t.Fatalf("denial should be attributed to principal, got %q", got.DeniedLeg)
	}
}

// Any single deny overrides. (C12)
func TestDecide_AnyDenyOverrides(t *testing.T) {
	cases := map[string]func(*Request){
		"principal":  func(r *Request) { r.PrincipalDecision = LegResult{Effect: EffectDeny, Reason: "no"} },
		"agent":      func(r *Request) { r.Agent.Enabled = false },
		"delegation": func(r *Request) { r.Chain[0].Revoked = true },
	}
	for leg, mutate := range cases {
		t.Run(leg, func(t *testing.T) {
			req := request()
			mutate(&req)
			got := Decide(req, config())
			if got.Effect != EffectDeny {
				t.Fatalf("%s deny must override, got %v", leg, got.Effect)
			}
			if got.DeniedLeg != leg {
				t.Fatalf("expected denied_leg %q, got %q", leg, got.DeniedLeg)
			}
		})
	}
}

// An allowing policy cannot exceed the delegation ceiling — the legs are
// independent AND terms. (C14)
func TestDecide_PolicyCannotExceedCeiling(t *testing.T) {
	req := request()
	req.PrincipalDecision = LegResult{Effect: EffectAllow, Reason: "policy grants everything"}
	req.Chain = []*models.Delegation{delegation(0, models.ActionTierReadOnly, nil)}
	req.Action = Action{Tool: "Bash", Verb: "delete"}
	got := Decide(req, config())
	if got.Effect != EffectDeny || got.DeniedLeg != "delegation" {
		t.Fatalf("policy must not exceed the ceiling, got %v/%s", got.Effect, got.DeniedLeg)
	}
}

func TestDecide_UnderDeclaredTierDenies(t *testing.T) {
	req := request()
	req.Action = Action{Tool: "Bash", Verb: "delete", DeclaredTier: tierPtr(models.ActionTierReadOnly)}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("under-declaration must deny, got %v", got.Effect)
	}
}

// The derived tier is always reported so audit records what was enforced.
func TestDecide_ReportsDerivedTier(t *testing.T) {
	req := request()
	req.Action = Action{Tool: "Bash", Verb: "delete"}
	if got := Decide(req, config()); got.DerivedTier != models.ActionTierDestructive {
		t.Fatalf("expected DESTRUCTIVE, got %v", got.DerivedTier)
	}
}

func TestDecide_UnknownActionDenies(t *testing.T) {
	req := request()
	req.Action = Action{Tool: "Weird", Verb: "frobnicate"}
	cfg := config()
	cfg.Tiers.DenyUnknown = true
	if got := Decide(req, cfg); got.Effect != EffectDeny {
		t.Fatalf("an unclassifiable action must deny, got %v", got.Effect)
	}
}

func TestDecide_EscalatePropagatesWhenNothingDenies(t *testing.T) {
	req := request()
	req.PrincipalDecision = LegResult{Effect: EffectEscalate, Reason: "approval required"}
	if got := Decide(req, config()); got.Effect != EffectEscalate {
		t.Fatalf("expected ESCALATE, got %v", got.Effect)
	}
}

// Deny-overrides applies to every non-allow, including escalate.
func TestDecide_DenyBeatsEscalate(t *testing.T) {
	req := request()
	req.PrincipalDecision = LegResult{Effect: EffectEscalate, Reason: "approval required"}
	req.Agent.Enabled = false
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("deny must beat escalate, got %v", got.Effect)
	}
}

// A chain denial reports the depth; a non-chain denial leaves it at -1.
func TestDecide_DeniedAtDepth(t *testing.T) {
	req := request()
	req.Chain = []*models.Delegation{
		delegation(0, models.ActionTierDestructive, nil),
		delegation(1, models.ActionTierReadOnly, nil),
	}
	req.Action = Action{Tool: "Bash", Verb: "delete"}
	got := Decide(req, config())
	if got.DeniedAtDepth != 1 {
		t.Fatalf("expected depth 1, got %d", got.DeniedAtDepth)
	}

	req2 := request()
	req2.Agent.Enabled = false
	if got := Decide(req2, config()); got.DeniedAtDepth != -1 {
		t.Fatalf("a non-chain denial must leave depth at -1, got %d", got.DeniedAtDepth)
	}
}

// A denial always carries a reason — an empty one is useless in an audit record.
func TestDecide_DenialAlwaysHasReason(t *testing.T) {
	req := request()
	req.PrincipalDecision = LegResult{Effect: EffectDeny} // no reason supplied
	if got := Decide(req, config()); got.Reason == "" {
		t.Fatal("a denial must always carry a reason")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -run TestDecide 2>&1 | head -5
```

Expected: FAIL — `undefined: Decide`

- [ ] **Step 3: Write the implementation**

Create `services/internal/authz/compound.go`:

```go
package authz

// Config is the tenant's resolved decision configuration, loaded by the caller.
type Config struct {
	Tiers    TierTable
	Trust    TrustTable
	MaxDepth int
}

// Decide computes the compound authorization decision.
//
//	allow = principal ∧ agent ∧ delegation
//
// Each leg is an independent AND term. Because the structural legs are
// separate terms, a policy returning ALLOW can never exceed the delegation
// artifact — the ceiling holds by construction (spec §4.3).
//
// Deny-overrides: any single deny is final. Escalate surfaces only when
// nothing denies.
func Decide(req Request, cfg Config) Result {
	res := Result{DeniedAtDepth: -1}

	// Derive the tier server-side. The declared value is never an input here
	// (spec §4.4, C3).
	derived, err := DeriveTier(cfg.Tiers, req.Action)
	if err != nil {
		res.Effect = EffectDeny
		res.DeniedLeg = "delegation"
		res.Reason = err.Error()
		res.Delegation = LegResult{Effect: EffectDeny, Reason: err.Error()}
		return res
	}
	res.DerivedTier = derived

	// Under-declaration is a spoofing attempt (C1), rejected before any leg is
	// consulted and attributed to the agent — the agent is what lied.
	if check := CheckDeclaredTier(derived, req.Action.DeclaredTier); check.Effect != EffectAllow {
		res.Effect = EffectDeny
		res.DeniedLeg = "agent"
		res.Reason = check.Reason
		res.Agent = check
		return res
	}

	// The principal leg's zero value is EffectDeny, so a caller that forgets to
	// evaluate it denies rather than silently permitting (C11, C13).
	res.Principal = req.PrincipalDecision
	res.Agent = AgentLeg(req.Agent, req.Action, derived, cfg.Trust)
	delegationLeg, deniedDepth := DelegationLeg(
		req.Chain, req.Action, derived, req.Resource, req.Now, cfg.MaxDepth)
	res.Delegation = delegationLeg

	// Deny-overrides, in a fixed order so attribution is deterministic (C12, C13).
	for _, leg := range []struct {
		name   string
		result LegResult
	}{
		{"principal", res.Principal},
		{"agent", res.Agent},
		{"delegation", res.Delegation},
	} {
		if leg.result.Effect == EffectDeny {
			res.Effect = EffectDeny
			res.DeniedLeg = leg.name
			res.Reason = leg.result.Reason
			if res.Reason == "" {
				res.Reason = leg.name + " leg denied"
			}
			if leg.name == "delegation" {
				res.DeniedAtDepth = deniedDepth
			}
			return res
		}
	}

	// Nothing denied. Escalate wins over allow if any leg requests it.
	for _, leg := range []LegResult{res.Principal, res.Agent, res.Delegation} {
		if leg.Effect == EffectEscalate {
			res.Effect = EffectEscalate
			res.Reason = leg.Reason
			return res
		}
	}

	res.Effect = EffectAllow
	return res
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /path/to/stratium-data/services && go test -race ./internal/authz/ -v 2>&1 | tail -25
```

Expected: PASS

- [ ] **Step 5: Check coverage**

```bash
cd /path/to/stratium-data/services && go test -cover ./internal/authz/
```

Expected: coverage above 90%. The package is pure, so anything lower means an untested branch.

- [ ] **Step 6: Commit**

```bash
git add services/internal/authz
git commit -m "feat(authz): compound decision with deny-overrides (C11, C12, C13, C14)

Three independent AND terms. EffectDeny is the zero value, so a leg that
is never evaluated denies."
```

---

### Task 16: Conformance suite and CI gate

**Files:**
- Create: `services/internal/authz/conformance_test.go`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: everything from Tasks 4–15
- Produces: `make conformance` and a required CI job

- [ ] **Step 1: Write the conformance suite**

Create `services/internal/authz/conformance_test.go`:

```go
// Conformance suite for the authorization security properties in
// docs/superpowers/specs/2026-08-08-agent-authorization-redesign-design.md §7.
//
// These are the CI merge gate. Properties whose implementation lands in a later
// phase skip with the phase named — a skip is a visible commitment, not a
// silent gap. Do not delete a property to make the suite pass.
package authz

import (
	"testing"
	"time"

	"stratium/pkg/audit"
	"stratium/pkg/models"
)

func TestC1_UnderDeclaredTierDenies(t *testing.T) {
	req := request()
	req.Action = Action{Tool: "Bash", Verb: "delete", DeclaredTier: tierPtr(models.ActionTierReadOnly)}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C1: under-declaration must deny, got %v", got.Effect)
	}
}

func TestC2_OverDeclaredTierPermitted(t *testing.T) {
	req := request()
	req.Action = Action{Tool: "Read", Verb: "read", DeclaredTier: tierPtr(models.ActionTierDestructive)}
	if got := Decide(req, config()); got.Effect != EffectAllow {
		t.Fatalf("C2: over-declaration must be permitted, got %v: %s", got.Effect, got.Reason)
	}
}

func TestC3_DerivedTierReachesEveryGate(t *testing.T) {
	req := request()
	req.Chain = []*models.Delegation{delegation(0, models.ActionTierReadOnly, nil)}
	req.Action = Action{Tool: "Bash", Verb: "delete", DeclaredTier: tierPtr(models.ActionTierDestructive)}
	got := Decide(req, config())
	if got.Effect != EffectDeny || got.DeniedLeg != "delegation" {
		t.Fatalf("C3: the derived tier must reach the delegation gate, got %v/%s", got.Effect, got.DeniedLeg)
	}
	if got.DerivedTier != models.ActionTierDestructive {
		t.Fatalf("C3: expected derived DESTRUCTIVE, got %v", got.DerivedTier)
	}
}

func TestC4_TierOverrideRaiseOnly(t *testing.T) {
	if err := ValidateOverride(models.ActionTierReadOnly, models.ActionTierDestructive); err != nil {
		t.Fatalf("C4: raising must be allowed: %v", err)
	}
	if err := ValidateOverride(models.ActionTierDestructive, models.ActionTierReadOnly); err == nil {
		t.Fatal("C4: lowering must be rejected")
	}
}

func TestC5_AgentWritableOverrideNotHonored(t *testing.T) {
	t.Skip("Phase 2: requires the PAP override write path")
}

func TestC6_DelegationClampedToPrincipalAuthority(t *testing.T) {
	t.Skip("Phase 2: requires the delegation-creation policy gate")
}

func TestC7_ChildCannotWidenParent(t *testing.T) {
	base := func() *models.Delegation {
		return &models.Delegation{
			MaxActionTier:       models.ActionTierInternalModify,
			ApprovedTools:       []string{"Read"},
			ClassificationCaps:  map[string]string{"nato": "CONFIDENTIAL"},
			ResourceConstraints: map[string]string{"project": "alpha"},
			ExpiresAt:           authzNow.Add(time.Hour),
		}
	}
	// C7 names six dimensions: tools, actions, tier, caps, resources, expiry.
	// Omission counts as widening wherever absence means "unrestricted" at
	// decision time — that is how a child sheds a ceiling without ever
	// appearing to widen one.
	widenings := map[string]func(*models.Delegation){
		"tier":            func(d *models.Delegation) { d.MaxActionTier = models.ActionTierDestructive },
		"tools":           func(d *models.Delegation) { d.ApprovedTools = []string{"Read", "Bash"} },
		"tools-omitted":   func(d *models.Delegation) { d.ApprovedTools = nil },
		"classification":  func(d *models.Delegation) { d.ClassificationCaps = map[string]string{"nato": "TOP-SECRET"} },
		"caps-omitted":    func(d *models.Delegation) { d.ClassificationCaps = nil },
		"resources":       func(d *models.Delegation) { d.ResourceConstraints = map[string]string{"project": "*"} },
		"resources-omitted": func(d *models.Delegation) { d.ResourceConstraints = nil },
		"expiry":          func(d *models.Delegation) { d.ExpiresAt = authzNow.Add(2 * time.Hour) },
	}
	for dim, widen := range widenings {
		t.Run(dim, func(t *testing.T) {
			child := base()
			widen(child)
			if models.ScopeNarrows(base(), child) == "" {
				t.Fatalf("C7: widening %s must be rejected", dim)
			}
		})
	}
}

func TestC8_ChainDepthBounded(t *testing.T) {
	req := request()
	req.Chain = []*models.Delegation{
		delegation(0, models.ActionTierDestructive, nil),
		delegation(1, models.ActionTierDestructive, nil),
		delegation(2, models.ActionTierDestructive, nil),
	}
	cfg := config()
	cfg.MaxDepth = 1
	if got := Decide(req, cfg); got.Effect != EffectDeny {
		t.Fatalf("C8: a chain beyond max depth must deny, got %v", got.Effect)
	}
}

func TestC9_RevokedRootDeniesDescendants(t *testing.T) {
	req := request()
	root := delegation(0, models.ActionTierDestructive, nil)
	root.Revoked = true
	req.Chain = []*models.Delegation{root, delegation(1, models.ActionTierReadOnly, nil)}
	got := Decide(req, config())
	if got.Effect != EffectDeny || got.DeniedAtDepth != 0 {
		t.Fatalf("C9: a revoked root must deny at depth 0, got %v at %d", got.Effect, got.DeniedAtDepth)
	}
}

func TestC10_SuspendedAgentDenied(t *testing.T) {
	req := request()
	req.Agent.Suspended = true
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C10: a suspended agent must deny, got %v", got.Effect)
	}
}

func TestC11_AllThreeLegsEvaluated(t *testing.T) {
	got := Decide(request(), config())
	if got.Principal.Effect != EffectAllow || got.Agent.Effect != EffectAllow || got.Delegation.Effect != EffectAllow {
		t.Fatalf("C11: every leg must be evaluated, got p=%v a=%v d=%v",
			got.Principal.Effect, got.Agent.Effect, got.Delegation.Effect)
	}
	req := request()
	req.PrincipalDecision = LegResult{}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatal("C11: an unevaluated leg must deny")
	}
}

func TestC12_DenyOverridesEverything(t *testing.T) {
	req := request()
	req.Agent.Enabled = false
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C12: any deny must override, got %v", got.Effect)
	}
}

func TestC13_DefaultDeny(t *testing.T) {
	req := request()
	req.PrincipalDecision = LegResult{}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C13: an absent grant must deny, got %v", got.Effect)
	}
}

func TestC14_PolicyCannotExceedCeiling(t *testing.T) {
	req := request()
	req.PrincipalDecision = LegResult{Effect: EffectAllow, Reason: "policy grants everything"}
	req.Chain = []*models.Delegation{delegation(0, models.ActionTierReadOnly, nil)}
	req.Action = Action{Tool: "Bash", Verb: "delete"}
	got := Decide(req, config())
	if got.Effect != EffectDeny || got.DeniedLeg != "delegation" {
		t.Fatalf("C14: policy must not exceed the ceiling, got %v/%s", got.Effect, got.DeniedLeg)
	}
}

func TestC15_AuditChainDetectsMutation(t *testing.T) {
	e1 := audit.Entry{PrevHash: audit.ZeroHash, TenantID: "t", Actor: "alice",
		OccurredAt: authzNow, EventType: "decision", Decision: "ALLOW", Reason: "first"}
	e2 := audit.Entry{PrevHash: e1.Hash(), TenantID: "t", Actor: "alice",
		OccurredAt: authzNow, EventType: "decision", Decision: "ALLOW", Reason: "second"}
	if err := audit.Verify([]audit.Entry{e1, e2}); err != nil {
		t.Fatalf("C15: an intact chain must verify: %v", err)
	}
	e1.Reason = "tampered"
	if err := audit.Verify([]audit.Entry{e1, e2}); err == nil {
		t.Fatal("C15: mutation must be detected")
	}
}

func TestC16_FailedAuditWriteDeniesAction(t *testing.T) {
	t.Skip("Phase 2: requires the PDP audit write path")
}

func TestC17_CryptoShreddingPreservesChain(t *testing.T) {
	t.Skip("Phase 2+: blocked on per-tenant key management (spec §8)")
}

func TestC18_CrossTenantReadImpossible(t *testing.T) {
	t.Skip("Integration: RLS is proven against Postgres in Task 9, not in unit tests")
}

func TestC19_UnreachablePDPDenies(t *testing.T) {
	t.Skip("Phase 3: requires the PEP client")
}

func TestC20_StaleEpochCacheEntryNotServed(t *testing.T) {
	t.Skip("Phase 3: requires the PEP decision cache")
}

func TestC21_EscalationRoutesToRootPrincipal(t *testing.T) {
	t.Skip("Phase 2: requires the approval subsystem")
}

func TestC22_EscalationTimeoutDenies(t *testing.T) {
	t.Skip("Phase 2: requires the approval subsystem")
}

func TestC23_NonBlockingSurfaceDegradesToDeny(t *testing.T) {
	t.Skip("Phase 4: requires the extauthz PEP mode")
}

func TestC24_ExpiredDelegationDenied(t *testing.T) {
	req := request()
	expired := delegation(0, models.ActionTierDestructive, nil)
	expired.ExpiresAt = authzNow.Add(-time.Second)
	req.Chain = []*models.Delegation{expired}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C24: an expired delegation must deny, got %v", got.Effect)
	}
}

func TestC25_MissingDPoPProofDenies(t *testing.T) {
	t.Skip("Phase 2: DPoP verification lives in the PDP transport layer")
}
```

- [ ] **Step 2: Run the conformance suite**

```bash
cd /path/to/stratium-data/services && go test ./internal/authz/ -run "TestC[0-9]" -v 2>&1 | tail -40
```

Expected: C1–C4, C7–C15, and C24 PASS. C5, C6, C16–C23, and C25 SKIP with their phase named. No failures.

- [ ] **Step 3: Add the CI job**

Append to `.github/workflows/ci.yml`:

```yaml
  conformance:
    name: Authorization conformance
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: services/go.sum
      - working-directory: services
        run: go test ./internal/authz/ -run "TestC[0-9]" -v
```

- [ ] **Step 4: Verify the full gate passes**

```bash
cd /path/to/stratium-data
make build && make vet && make test && make lint && make conformance && echo "FULL GATE PASSES"
```

Expected: `FULL GATE PASSES`

- [ ] **Step 5: Commit**

```bash
git add services/internal/authz/conformance_test.go .github/workflows/ci.yml
git commit -m "test: authorization conformance suite as a CI merge gate

15 of 25 properties enforced now; the rest skip with the phase that
implements them named."
```

---

## Self-Review

**Spec coverage.** Spec §6.1's four foundation items map to tasks: CI (2, 3, 16), tenancy schema and migrations (8, 9), audit chain (7, 10), decision core (4, 5, 6, 11–15). §3.7's greenfield amendment is honored — nothing is deleted, the old repo is untouched, layout matches G3, module path matches G4, and G5's "rewrite fresh" is realized in Tasks 4–6 with `classification`'s fail-closed rules reproduced under one test per rule.

**Deliberate deferrals, each recorded where it is deferred:**

- **Crypto-shredding** (spec §4.9) is not built. Per-tenant key management is an open item (spec §8), and writing raw shell commands unencrypted into an undeletable table would be worse than storing only a digest. Task 10 stores `input_digest`; the package doc in Task 7 states why; `TestC17` skips with that reason.
- **`migrations.Up`** is written and unit-tested for its embedded FS, but no binary calls it yet — `cmd/` is Phase 2. Tasks 8–10 apply SQL directly via `psql` to verify schema behavior against a real Postgres.
- **C18** is proven against Postgres in Task 9 Steps 3–5 rather than in the Go suite; the conformance test skips with that noted.

**Type consistency.** `Effect`, `LegResult`, `Action`, `Principal`, `AgentInfo`, `Request`, `Result`, `Config`, `TierTable`, `TrustTable` are each defined once (Tasks 11, 14, 15) and used unchanged thereafter. `DeriveTier`, `BuiltinTier`, `ValidateOverride`, `CheckDeclaredTier`, `AgentLeg`, `DelegationLeg`, `Decide` keep their signatures across every consuming task. Test helpers are defined once each and reused: `tierPtr` (Task 11), `authzNow`/`delegation` (Task 13), `agentInfo` (Task 14), `request`/`config` (Task 15). `models` helpers `testNow`/`parentDelegation`/`validChild` live in Task 6 and belong to a different package, so there is no collision.

**Two invariants an implementer must not "clean up":**

1. **`EffectDeny` is the zero value of `Effect`.** That is what makes an unevaluated leg deny instead of permit — the exact defect that made the previous system's compound decision silently two-legged. `TestEffect_DenyIsZeroValue` guards it. Do not reorder those constants.
2. **`BuiltinTier` returns `INTERNAL_MODIFY` for an unrecognized shell command.** It looks like a fallback that should be `READ_ONLY` or an error. It is neither: assuming read-only is precisely how an unknown internal CLI slips under a low tier cap.
