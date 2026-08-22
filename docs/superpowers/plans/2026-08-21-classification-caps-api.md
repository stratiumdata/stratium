# classification_caps API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a delegation's `classification_caps` settable through the admin plane, so classification enforcement can be turned on without a direct SQL write.

**Architecture:** Caps live on the agent row, like `trust_tier`. A sub-resource at `/v1/agents/{id}/classification-caps` (GET/PUT/DELETE, admin for the writes) reads and writes them, refusing a cap for a hierarchy with no catch-all label rule. Root-delegation issuance copies the agent's caps instead of hardcoding an empty map; child delegations are untouched and still inherit-and-narrow.

**Tech Stack:** Go, PostgreSQL, `golang-migrate`-style numbered migrations, `go-sqlmock` for handler tests, standard `testing`.

**Spec:** `docs/superpowers/specs/2026-08-21-classification-caps-api-design.md`

## Global Constraints

- **Migration numbering** — the next free number is `000020`; the latest on disk is `000019_resource_label_rules`. Every migration has a matching `.down.sql`.
- **Empty map is the OFF switch.** `CheckCap` returns allow when `len(caps) == 0` (`services/pkg/classification/classification.go:130`). Never treat `{}` as "unset but harmless".
- **`allowed_tools: []` means every tool, not no tools.** `store.ErrAllowedToolsRequired` says so verbatim (`services/internal/store/agent.go:47`); the allowlist applies only `if len(agent.AllowedTools) > 0` (`services/internal/authz/agent.go:63`).
- **Error bodies are plain text; success bodies are JSON.** The PAP convention. Never make an error body JSON.
- **`409` vs `400`** — `409` describes what the tenant's state already is; `400` describes something wrong with the request. Stated at `services/cmd/stratium-pap/respond.go:88-98`.
- **Valid hierarchies and levels** come from `classification.Levels` (`map[string][]string`) and `classification.Index(hierarchy, level) int`. Never hardcode level names.
- **Tests run from `services/`:** `cd services && go test ./...`.

---

### Task 1: Migration — add `agents.classification_caps`

**Files:**
- Create: `services/migrations/000020_agent_classification_caps.up.sql`
- Create: `services/migrations/000020_agent_classification_caps.down.sql`
- Test: `services/migrations/migrations_test.go` (existing; it walks every migration)

**Interfaces:**
- Consumes: nothing.
- Produces: column `agents.classification_caps JSONB NOT NULL`, no default after migration.

- [ ] **Step 1: Write the up migration**

```sql
-- 000020_agent_classification_caps.up.sql
--
-- classification_caps on the agent is the template a root delegation's own
-- classification_caps is copied from at issuance. Before this column, issuance
-- hardcoded an empty map (internal/pdpgrpc/delegation.go) and an empty map is
-- CheckCap's allow-everything case, so classification enforcement could not be
-- switched on through any supported interface.
--
-- The DEFAULT exists only to backfill existing rows and is dropped immediately
-- after, matching 000001_baseline.up.sql's refusal to give
-- delegations.approved_tools or delegations.classification_caps a default: an
-- INSERT must state its intent rather than inherit a silent one.
ALTER TABLE agents
    ADD COLUMN classification_caps JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE agents
    ALTER COLUMN classification_caps DROP DEFAULT;
```

- [ ] **Step 2: Write the down migration**

```sql
-- 000020_agent_classification_caps.down.sql
ALTER TABLE agents DROP COLUMN classification_caps;
```

- [ ] **Step 3: Run the migration test to verify up and down both apply**

Run: `cd services && go test ./migrations/ -run TestMigrations -v`
Expected: PASS. If the suite only walks up, also confirm by hand:

```bash
docker compose -f deploy/docker/docker-compose.yml exec -T \
  -e PGPASSWORD=stratium_migrate_local_dev_only postgres \
  psql -h 127.0.0.1 -U stratium_migrate -d stratium -tAc \
  "SELECT column_name, is_nullable, column_default
     FROM information_schema.columns
    WHERE table_name='agents' AND column_name='classification_caps';"
```

Expected: `classification_caps|NO|` — not null, and **no** default.

- [ ] **Step 4: Commit**

```bash
git add services/migrations/000020_agent_classification_caps.*.sql
git commit -m "feat: add agents.classification_caps column"
```

---

### Task 2: Carry the field through `models.Agent` and the agent CRUD

**Files:**
- Modify: `services/pkg/models/agent.go` (add field to `Agent`)
- Modify: `services/internal/store/agent.go` (INSERT, UPDATE, SELECT, scan)
- Test: `services/internal/store/agent_test.go`

**Interfaces:**
- Consumes: the column from Task 1.
- Produces: `models.Agent.ClassificationCaps map[string]string` with JSON tag `classification_caps`, round-tripped by `CreateAgent`, `UpdateAgent`, `GetAgent`, `ListAgents`.

- [ ] **Step 1: Write the failing test**

```go
// services/internal/store/agent_test.go
func TestCreateAgent_RoundTripsClassificationCaps(t *testing.T) {
	s, mock := newStoreFixture(t)
	id, now := uuid.New(), time.Now().UTC().Truncate(time.Second)

	expectWriteAndAudit(mock, "INSERT INTO agents",
		sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(id.String(), now, now))

	got, err := s.CreateAgent(context.Background(), models.Agent{
		Name: "capped", Provider: "anthropic", TrustTier: models.TrustTierCertified,
		Enabled: true, AllowedTools: []string{},
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"},
	}, "operator@example.com", now)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if got.ClassificationCaps["nato"] != "CONFIDENTIAL" {
		t.Errorf("caps = %v, want nato=CONFIDENTIAL", got.ClassificationCaps)
	}
}

// A nil map must persist as {} and not as SQL NULL: the column is NOT NULL, and
// {} is the documented "no cap" value.
func TestCreateAgent_NilCapsPersistsAsEmptyObject(t *testing.T) {
	s, mock := newStoreFixture(t)
	id, now := uuid.New(), time.Now().UTC().Truncate(time.Second)
	expectWriteAndAudit(mock, "INSERT INTO agents",
		sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(id.String(), now, now))

	got, err := s.CreateAgent(context.Background(), models.Agent{
		Name: "uncapped", Provider: "anthropic", TrustTier: models.TrustTierCertified,
		Enabled: true, AllowedTools: []string{}, ClassificationCaps: nil,
	}, "operator@example.com", now)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if got.ClassificationCaps == nil || len(got.ClassificationCaps) != 0 {
		t.Errorf("caps = %v, want an empty non-nil map", got.ClassificationCaps)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services && go test ./internal/store/ -run TestCreateAgent_.*Caps -v`
Expected: FAIL — `unknown field ClassificationCaps in struct literal`.

- [ ] **Step 3: Add the field to the model**

```go
// services/pkg/models/agent.go, after AllowedTools
	// ClassificationCaps is the per-hierarchy ceiling copied onto every ROOT
	// delegation this agent is issued (internal/pdpgrpc/delegation.go). An
	// empty map means no classification enforcement -- classification.CheckCap
	// returns allow for len(caps) == 0 -- so nil and {} are the same thing
	// here and both mean OFF. Children copy their parent's map, never this
	// one, so changing it affects only delegations issued after the change.
	ClassificationCaps map[string]string `json:"classification_caps" db:"classification_caps"`
```

- [ ] **Step 4: Marshal it in the writes and scan it in the reads**

In `CreateAgent` and `UpdateAgent`, alongside the existing `allowedTools` marshal:

```go
	caps := a.ClassificationCaps
	if caps == nil {
		caps = map[string]string{}
	}
	classificationCaps, err := json.Marshal(caps)
	if err != nil {
		return models.Agent{}, fmt.Errorf("store: marshal classification_caps: %w", err)
	}
```

Add `classification_caps` to the INSERT column list and the UPDATE SET list, pass `classificationCaps` in the argument list, and set `a.ClassificationCaps = caps` before returning so the response echoes the normalised value.

In the row scanner (the helper that already unmarshals `allowed_tools`), add:

```go
	if err := json.Unmarshal(classificationCaps, &a.ClassificationCaps); err != nil {
		return fmt.Errorf("store: unmarshal classification_caps: %w", err)
	}
	if a.ClassificationCaps == nil {
		a.ClassificationCaps = map[string]string{}
	}
```

Add `classification_caps` to the SELECT column lists in `GetAgent` and `ListAgents`.

- [ ] **Step 5: Run to verify both pass**

Run: `cd services && go test ./internal/store/ -run TestCreateAgent -v`
Expected: PASS, and every pre-existing `TestCreateAgent*` / `TestUpdateAgent*` still passes.

- [ ] **Step 6: Commit**

```bash
git add services/pkg/models/agent.go services/internal/store/agent.go services/internal/store/agent_test.go
git commit -m "feat: carry classification_caps through the agent CRUD"
```

---

### Task 3: Carry the field to the decision path via `authz.AgentInfo`

**Files:**
- Modify: `services/internal/authz/types.go:127-134` (`AgentInfo`)
- Modify: `services/internal/store/store.go:201-215` (`LoadAgent`) and `loadAgentQuery`
- Test: `services/internal/store/store_test.go`

**Interfaces:**
- Consumes: the column from Task 1.
- Produces: `authz.AgentInfo.ClassificationCaps map[string]string`, populated by `Store.LoadAgent`.

**Why this task exists:** the spec assumed issuance could read `models.Agent`. It cannot — `LoadAgent` returns `authz.AgentInfo`, a deliberately reduced projection (`store.go:201`), and its query selects five columns. The field has to travel through both types.

- [ ] **Step 1: Write the failing test**

```go
// services/internal/store/store_test.go
func TestLoadAgent_CarriesClassificationCaps(t *testing.T) {
	s, mock := newStoreFixture(t)
	id := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT .* FROM agents").WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "trust_tier", "enabled", "suspended", "allowed_tools", "classification_caps"}).
			AddRow(id.String(), int64(3), true, false, []byte(`[]`), []byte(`{"nato":"CONFIDENTIAL"}`)))

	info, err := s.LoadAgent(context.Background(), id)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if info.ClassificationCaps["nato"] != "CONFIDENTIAL" {
		t.Errorf("caps = %v, want nato=CONFIDENTIAL", info.ClassificationCaps)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services && go test ./internal/store/ -run TestLoadAgent_CarriesClassificationCaps -v`
Expected: FAIL — `info.ClassificationCaps undefined`.

- [ ] **Step 3: Add the field and select it**

```go
// services/internal/authz/types.go, in AgentInfo after AllowedTools
	// ClassificationCaps is the template a ROOT delegation's caps are copied
	// from at issuance. It is NOT consulted at decision time -- the decision
	// reads the delegation's own caps (internal/authz/delegation.go) -- so a
	// change here never affects a delegation already issued.
	ClassificationCaps map[string]string
```

In `store.go`, add `classification_caps` to `loadAgentQuery`'s select list and scan it:

```go
	var allowedTools, classificationCaps []byte
	err = tx.QueryRowContext(ctx, loadAgentQuery, id.String()).
		Scan(&info.ID, &trustTier, &info.Enabled, &info.Suspended, &allowedTools, &classificationCaps)
```

and after the existing `allowedTools` unmarshal:

```go
	if err := json.Unmarshal(classificationCaps, &info.ClassificationCaps); err != nil {
		return authz.AgentInfo{}, fmt.Errorf("store: unmarshal classification_caps: %w", err)
	}
	if info.ClassificationCaps == nil {
		info.ClassificationCaps = map[string]string{}
	}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services && go test ./internal/store/ ./internal/authz/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/internal/authz/types.go services/internal/store/store.go services/internal/store/store_test.go
git commit -m "feat: carry classification_caps into authz.AgentInfo"
```

---

### Task 4: Issuance copies the agent's caps onto root delegations

**Files:**
- Modify: `services/internal/pdpgrpc/delegation.go:109` and `:176`
- Test: `services/internal/pdpgrpc/delegation_test.go`

**Interfaces:**
- Consumes: `authz.AgentInfo.ClassificationCaps` from Task 3.
- Produces: root delegations whose `ClassificationCaps` equals the agent's. Child behaviour unchanged.

**Note:** line 109 already calls `s.store.LoadAgent(ctx, agentID)` and **discards the result** — `if _, err := s.store.LoadAgent(...)`. Keep the value rather than adding a read.

- [ ] **Step 1: Write the three failing tests**

```go
// services/internal/pdpgrpc/delegation_test.go
func TestCreateDelegation_RootCopiesAgentCaps(t *testing.T) {
	s := newDelegationFixture(t, authz.AgentInfo{
		ID: agentID, Enabled: true, AllowedTools: []string{},
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"},
	})
	got := mustCreateRootDelegation(t, s)
	if got.ClassificationCaps["nato"] != "CONFIDENTIAL" {
		t.Errorf("root caps = %v, want nato=CONFIDENTIAL", got.ClassificationCaps)
	}
}

// Pins today's behaviour: an agent with no caps must still produce an
// uncapped root, so this change cannot silently start capping existing fleets.
func TestCreateDelegation_RootWithNoAgentCapsStaysUncapped(t *testing.T) {
	s := newDelegationFixture(t, authz.AgentInfo{
		ID: agentID, Enabled: true, AllowedTools: []string{},
		ClassificationCaps: map[string]string{},
	})
	got := mustCreateRootDelegation(t, s)
	if len(got.ClassificationCaps) != 0 {
		t.Errorf("root caps = %v, want empty", got.ClassificationCaps)
	}
}

// A child still copies its PARENT, never the agent row -- the inherit-and-
// narrow rule the chain argument depends on.
func TestCreateDelegation_ChildStillCopiesParentNotAgent(t *testing.T) {
	s := newDelegationFixture(t, authz.AgentInfo{
		ID: agentID, Enabled: true, AllowedTools: []string{},
		ClassificationCaps: map[string]string{"nato": "TOP-SECRET"},
	})
	parent := authz.Delegation{ClassificationCaps: map[string]string{"nato": "RESTRICTED"}}
	got := mustCreateChildDelegation(t, s, parent)
	if got.ClassificationCaps["nato"] != "RESTRICTED" {
		t.Errorf("child caps = %v, want the parent's RESTRICTED, not the agent's TOP-SECRET",
			got.ClassificationCaps)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd services && go test ./internal/pdpgrpc/ -run TestCreateDelegation_.*Cap -v`
Expected: FAIL — the first returns an empty map; the third already passes and must keep passing.

- [ ] **Step 3: Keep the loaded agent and use its caps**

At `delegation.go:109`, change the discard into a binding:

```go
	agent, err := s.store.LoadAgent(ctx, agentID)
	if err != nil {
		// unchanged error handling
	}
```

At `delegation.go:176`, replace the hardcoded empty map:

```go
		// Copied from the agent row, which is the only place an operator can
		// set a ceiling (PUT /v1/agents/{id}/classification-caps). A root has
		// no parent to clamp against, so this is where the ceiling enters the
		// chain; children below copy their parent and can only narrow.
		ClassificationCaps:  copyStringMap(agent.ClassificationCaps),
```

Leave line 197 (`d.ClassificationCaps = copyStringMap(parent.ClassificationCaps)`) untouched.

- [ ] **Step 4: Run to verify all three pass**

Run: `cd services && go test ./internal/pdpgrpc/ -v`
Expected: PASS, including every pre-existing delegation test.

- [ ] **Step 5: Commit**

```bash
git add services/internal/pdpgrpc/delegation.go services/internal/pdpgrpc/delegation_test.go
git commit -m "feat: root delegations inherit the agent's classification caps"
```

---

### Task 5: Store — validation, set, and clear

**Files:**
- Create: `services/internal/store/agent_caps.go`
- Modify: `services/internal/store/agent.go:31-33` (event type constants)
- Modify: `services/internal/store/store.go` (add `ErrNoCatchAllRule`)
- Test: `services/internal/store/agent_caps_test.go`

**Interfaces:**
- Consumes: `models.Agent.ClassificationCaps` (Task 2).
- Produces:
  - `func validateClassificationCaps(caps map[string]string) error`
  - `func (s *Store) SetAgentClassificationCaps(ctx context.Context, id uuid.UUID, caps map[string]string, allowUncovered bool, actor string, now time.Time) (models.AgentCapsView, error)`
  - `func (s *Store) ClearAgentClassificationCaps(ctx context.Context, id uuid.UUID, actor string, now time.Time) error`
  - `var ErrNoCatchAllRule error` (wraps `ErrConflict`)
  - event types `agent_caps_set`, `agent_caps_cleared`

- [ ] **Step 1: Write the failing validation tests**

```go
// services/internal/store/agent_caps_test.go
func TestValidateClassificationCaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		caps    map[string]string
		wantErr bool
	}{
		{"empty is valid and means off", map[string]string{}, false},
		{"nil is valid and means off", nil, false},
		{"known hierarchy and level", map[string]string{"nato": "CONFIDENTIAL"}, false},
		{"commercial hierarchy", map[string]string{"commercial": "INTERNAL"}, false},
		{"unknown hierarchy", map[string]string{"klingon": "SECRET"}, true},
		{"level from the wrong hierarchy", map[string]string{"nato": "INTERNAL"}, true},
		{"empty level", map[string]string{"nato": ""}, true},
		{"empty hierarchy key", map[string]string{"": "SECRET"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClassificationCaps(tc.caps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("err = %v, want it to wrap ErrInvalidRequest", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services && go test ./internal/store/ -run TestValidateClassificationCaps -v`
Expected: FAIL — `undefined: validateClassificationCaps`.

- [ ] **Step 3: Write the validator**

```go
// services/internal/store/agent_caps.go
package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/audit"
	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// ErrNoCatchAllRule is returned when a cap names a hierarchy that has no
// empty-prefix ("") label rule. It wraps ErrConflict, not ErrInvalidRequest:
// the request is well formed, and what is wrong is the tenant's current state
// (respond.go's writeStoreError draws exactly that line).
var ErrNoCatchAllRule = fmt.Errorf("%w: no catch-all label rule", ErrConflict)

// validateClassificationCaps rejects anything classification.CheckCap could not
// act on. Levels come from classification.Levels rather than a local list so
// there is one definition of what a hierarchy contains.
func validateClassificationCaps(caps map[string]string) error {
	for hierarchy, level := range caps {
		levels, ok := classification.Levels[hierarchy]
		if !ok {
			return fmt.Errorf("%w: unknown classification hierarchy %q (known: %s)",
				ErrInvalidRequest, hierarchy, strings.Join(knownHierarchies(), ", "))
		}
		if classification.Index(hierarchy, level) < 0 {
			return fmt.Errorf("%w: %q is not a level in hierarchy %q (levels: %s)",
				ErrInvalidRequest, level, hierarchy, strings.Join(levels, ", "))
		}
	}
	return nil
}

func knownHierarchies() []string {
	out := make([]string, 0, len(classification.Levels))
	for h := range classification.Levels {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
```

Add `"strings"` to the import block.

- [ ] **Step 4: Run to verify validation passes**

Run: `cd services && go test ./internal/store/ -run TestValidateClassificationCaps -v`
Expected: PASS, all eight cases.

- [ ] **Step 5: Write the failing catch-all test**

```go
func TestSetAgentClassificationCaps_RefusesWithoutCatchAll(t *testing.T) {
	s, mock := newStoreFixture(t)
	id, now := uuid.New(), time.Now().UTC()
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"},
	})

	_, err := s.SetAgentClassificationCaps(context.Background(), id,
		map[string]string{"nato": "CONFIDENTIAL"}, false, "operator@example.com", now)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want it to wrap ErrConflict", err)
	}
}

func TestSetAgentClassificationCaps_AllowUncoveredOverrides(t *testing.T) {
	s, mock := newStoreFixture(t)
	id, now := uuid.New(), time.Now().UTC()
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"},
	})
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 0)
	expectWriteAndAudit(mock, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))

	if _, err := s.SetAgentClassificationCaps(context.Background(), id,
		map[string]string{"nato": "CONFIDENTIAL"}, true, "operator@example.com", now); err != nil {
		t.Fatalf("with allowUncovered: %v", err)
	}
}
```

- [ ] **Step 6: Run to verify it fails**

Run: `cd services && go test ./internal/store/ -run TestSetAgentClassificationCaps -v`
Expected: FAIL — `undefined: s.SetAgentClassificationCaps`.

- [ ] **Step 7: Write the setter and clearer**

```go
const (
	eventTypeAgentCapsSet     = "agent_caps_set"
	eventTypeAgentCapsCleared = "agent_caps_cleared"
)

// SetAgentClassificationCaps replaces the agent's caps and returns the view
// callers need to understand what they just did. It refuses a cap for a
// hierarchy with no catch-all rule unless allowUncovered: with a cap set and no
// rule matching, classification.CheckCap denies every resource whose label
// cannot be resolved, so the un-guarded version of this call is a foot-gun that
// looks like a success.
func (s *Store) SetAgentClassificationCaps(
	ctx context.Context, id uuid.UUID, caps map[string]string,
	allowUncovered bool, actor string, now time.Time,
) (models.AgentCapsView, error) {
	if caps == nil {
		caps = map[string]string{}
	}
	if err := validateClassificationCaps(caps); err != nil {
		return models.AgentCapsView{}, err
	}

	catchAll, err := s.catchAllLevels(ctx)
	if err != nil {
		return models.AgentCapsView{}, err
	}
	if !allowUncovered {
		for _, hierarchy := range sortedKeys(caps) {
			if catchAll[hierarchy] == nil {
				return models.AgentCapsView{}, fmt.Errorf(
					"%w for hierarchy %q; a cap without one denies every resource no rule matches. "+
						"POST /v1/resource-label-rules with prefix \"\" first, or pass ?allow_uncovered=true",
					ErrNoCatchAllRule, hierarchy)
			}
		}
	}

	if err := s.writeAgentCaps(ctx, id, caps, eventTypeAgentCapsSet, actor, now); err != nil {
		return models.AgentCapsView{}, err
	}
	return s.agentCapsView(ctx, id, caps, catchAll)
}

// ClearAgentClassificationCaps sets the map back to {}, which turns
// classification enforcement OFF for delegations issued from now on. It is a
// distinct verb precisely so that turning enforcement off cannot happen by
// omitting a field from a request body.
func (s *Store) ClearAgentClassificationCaps(
	ctx context.Context, id uuid.UUID, actor string, now time.Time,
) error {
	return s.writeAgentCaps(ctx, id, map[string]string{}, eventTypeAgentCapsCleared, actor, now)
}
```

`writeAgentCaps` runs `UPDATE agents SET classification_caps = $2, updated_at = $3 WHERE id = $1` inside `beginTenantTx`, returns `ErrNotFound` on no rows, and appends an `audit.Entry` in the same shape `CreateAgent` uses (`agent.go:158-168`) with `EventType` set to the constant passed in and `Reason` set to a compact rendering of the caps.

- [ ] **Step 8: Run to verify both catch-all tests pass**

Run: `cd services && go test ./internal/store/ -run TestSetAgentClassificationCaps -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add services/internal/store/agent_caps.go services/internal/store/agent_caps_test.go services/internal/store/agent.go services/internal/store/store.go
git commit -m "feat: validate and persist agent classification caps"
```

---

### Task 6: Store — the advisory view

**Files:**
- Create: `services/pkg/models/agent_caps.go`
- Modify: `services/internal/store/agent_caps.go` (add `catchAllLevels`, `agentCapsView`, `unsatisfiableTools`)
- Test: `services/internal/store/agent_caps_test.go`

**Interfaces:**
- Consumes: `Store.ListResourceLabelRules`, `Store.ListToolCatalogEntries`, `Store.GetAgent`.
- Produces: `models.AgentCapsView` and `func (s *Store) GetAgentClassificationCaps(ctx context.Context, id uuid.UUID) (models.AgentCapsView, error)`.

- [ ] **Step 1: Write the failing test — the `[]` trap**

```go
// An agent with allowed_tools == [] holds EVERY tool, so the warning must be
// computed against the whole catalog. Computing it against the empty slice
// returns no warnings for exactly the agents with the widest reach.
func TestUnsatisfiableTools_EmptyAllowedToolsMeansEveryTool(t *testing.T) {
	catalog := []models.ToolCatalogEntry{
		{ToolName: "Read", ResourceField: strptr("file_path")},
		{ToolName: "Grep", ResourceField: nil},
		{ToolName: "WebSearch", ResourceField: nil},
	}
	got := unsatisfiableTools([]string{}, catalog)
	want := []string{"Grep", "WebSearch"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unsatisfiableTools([], catalog) = %v, want %v", got, want)
	}
}

func TestUnsatisfiableTools_RestrictedAgentIntersects(t *testing.T) {
	catalog := []models.ToolCatalogEntry{
		{ToolName: "Read", ResourceField: strptr("file_path")},
		{ToolName: "Grep", ResourceField: nil},
		{ToolName: "WebSearch", ResourceField: nil},
	}
	got := unsatisfiableTools([]string{"Read", "Grep"}, catalog)
	want := []string{"Grep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services && go test ./internal/store/ -run TestUnsatisfiableTools -v`
Expected: FAIL — `undefined: unsatisfiableTools`.

- [ ] **Step 3: Write the view type and the helpers**

```go
// services/pkg/models/agent_caps.go
package models

import "github.com/google/uuid"

// AgentCapsView is what the classification-caps routes return. Every field
// beyond ClassificationCaps is advisory: setting a cap has consequences that
// are invisible in the stored value, and this type is where they are stated.
type AgentCapsView struct {
	AgentID            uuid.UUID          `json:"agent_id"`
	ClassificationCaps map[string]string  `json:"classification_caps"`

	// CatchAll gives the level the empty-prefix rule resolves to per capped
	// hierarchy, or nil where there is none -- reachable only via
	// ?allow_uncovered=true, and the state in which every unmatched resource
	// denies.
	CatchAll map[string]*string `json:"catch_all"`

	// UnsatisfiableTools are tools that can never satisfy ANY cap, because they
	// declare no resource_field and so produce no resource to label. Not
	// "denied by this cap" -- denied by any cap at all.
	UnsatisfiableTools []string `json:"unsatisfiable_tools"`

	// LiveDelegations counts the agent's delegations that are neither revoked
	// nor expired. These are the delegations this cap does NOT affect. A
	// warning, not a confirmation.
	LiveDelegations int `json:"live_delegations"`

	// Applies is a fixed human-readable string, always "at next issuance".
	// Present so a reader of the raw response need not infer timing. Not
	// machine-readable; clients must not branch on it.
	Applies string `json:"applies"`
}
```

```go
// services/internal/store/agent_caps.go
func unsatisfiableTools(allowedTools []string, catalog []models.ToolCatalogEntry) []string {
	// allowed_tools == [] means EVERY tool (store.ErrAllowedToolsRequired says
	// so verbatim, and internal/authz/agent.go applies the allowlist only when
	// len > 0), so an empty slice must widen the check, not narrow it to nothing.
	unrestricted := len(allowedTools) == 0
	held := make(map[string]bool, len(allowedTools))
	for _, t := range allowedTools {
		held[t] = true
	}

	var out []string
	for _, e := range catalog {
		if e.ResourceField != nil {
			continue
		}
		if unrestricted || held[e.ToolName] {
			out = append(out, e.ToolName)
		}
	}
	sort.Strings(out)
	return out
}

// catchAllLevels maps each hierarchy to the level its empty-prefix rule
// resolves to, or leaves it absent where no such rule exists.
func (s *Store) catchAllLevels(ctx context.Context) (map[string]*string, error) {
	rules, err := s.ListResourceLabelRules(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]*string{}
	for _, r := range rules {
		if r.Prefix == "" {
			level := r.Level
			out[r.Hierarchy] = &level
		}
	}
	return out, nil
}
```

`agentCapsView` loads the agent (for `AllowedTools`), the catalog, and the live-delegation count, then assembles the struct with `Applies: "at next issuance"`. Restrict `CatchAll` to the hierarchies actually capped, so the response describes this cap rather than the whole tenant.

- [ ] **Step 4: Run to verify both pass**

Run: `cd services && go test ./internal/store/ -run "TestUnsatisfiableTools|TestSetAgentClassificationCaps" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/pkg/models/agent_caps.go services/internal/store/agent_caps.go services/internal/store/agent_caps_test.go
git commit -m "feat: report cap consequences alongside the stored value"
```

---

### Task 7: The three routes

**Files:**
- Create: `services/cmd/stratium-pap/agent_caps.go`
- Modify: `services/cmd/stratium-pap/server.go:218-222` (routeTable)
- Test: `services/cmd/stratium-pap/agent_caps_test.go`
- Test: `services/internal/store/pap_e2e_integration_test.go:296-300` (role matrix table)

**Interfaces:**
- Consumes: `SetAgentClassificationCaps`, `ClearAgentClassificationCaps`, `GetAgentClassificationCaps` (Tasks 5-6).
- Produces: three routes; no further tasks depend on them except the end-to-end test.

- [ ] **Step 1: Write the failing handler tests**

```go
// services/cmd/stratium-pap/agent_caps_test.go
func TestPutAgentCaps_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	expectLabelRules(f.mock, []models.ResourceLabelRule{{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"}})
	expectCatalog(f.mock, nil)
	expectLiveDelegations(f.mock, 0)
	expectWriteAndAudit(f.mock, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))

	body := map[string]any{"classification_caps": map[string]string{"nato": "CONFIDENTIAL"}}
	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+id.String()+"/classification-caps", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[models.AgentCapsView](t, rec)
	if got.ClassificationCaps["nato"] != "CONFIDENTIAL" {
		t.Errorf("caps = %v", got.ClassificationCaps)
	}
	if got.Applies != "at next issuance" {
		t.Errorf("applies = %q", got.Applies)
	}
}

// Editor may rename an agent but must not set its classification ceiling.
func TestPutAgentCaps_EditorForbidden(t *testing.T) {
	f := newTestServerFixture(t)
	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+uuid.New().String()+"/classification-caps",
		f.token(t, "org-editors"),
		map[string]any{"classification_caps": map[string]string{"nato": "CONFIDENTIAL"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// The error body is a bare sentence, not JSON. Asserting this keeps clients
// honest: step 0d of the agent test plan piped curl into json.load and turned
// every failure into the same unreadable traceback.
func TestPutAgentCaps_NoCatchAllIsPlainTextConflict(t *testing.T) {
	f := newTestServerFixture(t)
	expectLabelRules(f.mock, []models.ResourceLabelRule{{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"}})

	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+uuid.New().String()+"/classification-caps", f.token(t, "org-admins"),
		map[string]any{"classification_caps": map[string]string{"nato": "CONFIDENTIAL"}})

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	if strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "{") {
		t.Errorf("body is JSON, want plain text: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "allow_uncovered") {
		t.Errorf("body does not name the override: %s", rec.Body.String())
	}
}

func TestDeleteAgentCaps_ClearsAndReturns204(t *testing.T) {
	f := newTestServerFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	expectWriteAndAudit(f.mock, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))

	rec := doRequest(t, f.server, http.MethodDelete,
		"/v1/agents/"+uuid.New().String()+"/classification-caps", f.token(t, "org-admins"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd services && go test ./cmd/stratium-pap/ -run TestPutAgentCaps -v`
Expected: FAIL with `404` — the routes do not exist.

- [ ] **Step 3: Write the handlers**

```go
// services/cmd/stratium-pap/agent_caps.go
package main

import (
	"net/http"
	"time"
)

// capsRequest is wrapped rather than a bare map so the route can gain a field
// without ambiguity.
type capsRequest struct {
	ClassificationCaps map[string]string `json:"classification_caps"`
}

func getAgentCaps(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	view, err := s.store.GetAgentClassificationCaps(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func putAgentCaps(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req capsRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	allowUncovered := r.URL.Query().Get("allow_uncovered") == "true"
	view, err := s.store.SetAgentClassificationCaps(
		r.Context(), id, req.ClassificationCaps, allowUncovered, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// deleteAgentCaps turns classification enforcement OFF for delegations issued
// from now on. It is a separate verb from PUT so that cannot happen by omitting
// a field from a request body.
func deleteAgentCaps(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.ClearAgentClassificationCaps(r.Context(), id, op.Subject, time.Now()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 4: Register the routes**

In `server.go`'s `routeTable`, after the existing agent routes:

```go
	{Pattern: "GET /v1/agents/{id}/classification-caps", MinRole: RoleViewer, Handler: getAgentCaps},
	{Pattern: "PUT /v1/agents/{id}/classification-caps", MinRole: RoleAdmin, Handler: putAgentCaps},
	{Pattern: "DELETE /v1/agents/{id}/classification-caps", MinRole: RoleAdmin, Handler: deleteAgentCaps},
```

- [ ] **Step 5: Extend the role matrix**

In `services/internal/store/pap_e2e_integration_test.go`, alongside the existing agent rows at `:296-300`:

```go
		{http.MethodGet, "/v1/agents/" + id + "/classification-caps", false},
		{http.MethodPut, "/v1/agents/" + id + "/classification-caps", true},
		{http.MethodDelete, "/v1/agents/" + id + "/classification-caps", true},
```

- [ ] **Step 6: Run to verify all pass**

Run: `cd services && go test ./cmd/stratium-pap/ ./internal/store/ -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add services/cmd/stratium-pap/agent_caps.go services/cmd/stratium-pap/agent_caps_test.go services/cmd/stratium-pap/server.go services/internal/store/pap_e2e_integration_test.go
git commit -m "feat: add the /v1/agents/{id}/classification-caps routes"
```

---

### Task 8: End-to-end — a classification denial with no SQL

**Files:**
- Modify: `services/internal/store/pap_e2e_integration_test.go`
- Modify: `deploy/stratium` (`cmd_verify`, and the `DEMO_TOOLS` note)
- Modify: `docs/architecture.md:370` and its §8 gap list
- Modify: `docs/testing/2026-08-19-resource-labelling-manual-test.md` (Part B's SQL write)

**Interfaces:**
- Consumes: everything above.
- Produces: no new API.

- [ ] **Step 1: Write the failing end-to-end test**

```go
// The denial string at docs/architecture.md:366 has never been reachable
// through a supported interface. This test asserts it now is.
func TestClassificationDenial_ReachableWithoutSQL(t *testing.T) {
	env := newIntegrationEnv(t)

	mustCreateLabelRule(t, env, "", "nato", "UNCLASSIFIED")
	mustCreateLabelRule(t, env, "/secret/", "nato", "SECRET")
	agentID := mustCreateAgent(t, env, []string{})
	mustSetCaps(t, env, agentID, map[string]string{"nato": "CONFIDENTIAL"})

	deleg := mustCreateRootDelegation(t, env, agentID, []string{"Read"})
	if deleg.ClassificationCaps["nato"] != "CONFIDENTIAL" {
		t.Fatalf("delegation caps = %v, want the agent's", deleg.ClassificationCaps)
	}

	allow := mustDecide(t, env, deleg, "Read", "/tmp/notes.txt")
	if !allow.Allowed {
		t.Errorf("UNCLASSIFIED read denied: %s", allow.Reason)
	}

	deny := mustDecide(t, env, deleg, "Read", "/secret/plans.txt")
	if deny.Allowed {
		t.Fatal("SECRET read allowed under a CONFIDENTIAL cap")
	}
	want := `resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)`
	if deny.Reason != want {
		t.Errorf("reason = %q, want %q", deny.Reason, want)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services && go test ./internal/store/ -run TestClassificationDenial_ReachableWithoutSQL -v`
Expected: FAIL before Tasks 1-7 land; PASS after. If it fails after, the fault is in Task 4's issuance copy.

- [ ] **Step 3: Add the fourth assertion to the quickstart**

In `deploy/stratium`'s `cmd_verify`, after the three existing cases, add a classification case and delete the `NOT DEMONSTRATED` block:

```python
    # Classification is now reachable through the API, so verify proves it
    # rather than printing a disclaimer. Requires a catch-all rule and a cap;
    # cmd_up sets both.
    if state.get("caps"):
        rc, reason = hook_probe(state, "Read", f"/secret-{tag}/plans.txt")
        good = rc == 2 and "exceeds delegation cap" in reason
        failures.append(None if good else ("classification", 2, rc))
        print(f"  {'PASS' if good else 'FAIL'}  {'classification':<18} exit={rc} (want 2)  "
              f"SECRET over a CONFIDENTIAL cap")
        print(f"        {reason[:150]}")
```

`cmd_up` gains a step that registers the catch-all and `/secret-*/` rules and calls the new `PUT .../classification-caps`.

- [ ] **Step 4: Run the quickstart end to end**

Run: `deploy/stratium down && deploy/stratium up --harness claude`
Expected: four PASS lines, no `NOT DEMONSTRATED` block.

- [ ] **Step 5: Update the docs that record the gap**

- `docs/architecture.md:370` — replace the "Known gap" blockquote with the route.
- `docs/architecture.md` §8 — delete the `**No route sets classification_caps.**` bullet.
- `docs/testing/2026-08-19-resource-labelling-manual-test.md` — replace Part B's SQL write with the API call, and shrink "the one thing you cannot test".

- [ ] **Step 6: Commit**

```bash
git add services/internal/store/pap_e2e_integration_test.go deploy/stratium docs/
git commit -m "feat: prove classification enforcement without a SQL write"
```

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: surface → 7; storage and issuance → 1, 2, 3, 4; validation steps 1-2 → 5; step 3 → 6; step 4 (audit) → 5; errors → 5 and 7; testing → every task plus 8. The spec's "out of scope" items appear in no task, correctly.

**One task the spec did not anticipate.** Task 3 exists because `Store.LoadAgent` returns `authz.AgentInfo`, not `models.Agent` (`services/internal/store/store.go:201`). The spec said issuance "keeps the returned agent"; that is true, but the returned type is a reduced projection whose query selects five columns, so the field must be added to `AgentInfo` and to `loadAgentQuery` before Task 4 can read it. Without this task, Task 4 does not compile.

**Placeholder scan.** No TBD/TODO. Every code step carries real code. The two places describing rather than showing — `writeAgentCaps`'s body in Task 5 Step 7 and `agentCapsView`'s in Task 6 Step 3 — name the exact query, the transaction helper, the error to return, and the `audit.Entry` shape to copy (`agent.go:158-168`), which is enough to write without a second decision.

**Type consistency.** `ClassificationCaps map[string]string` is spelled identically in `models.Agent` (Task 2), `authz.AgentInfo` (Task 3), and `models.AgentCapsView` (Task 6). `unsatisfiableTools(allowedTools []string, catalog []models.ToolCatalogEntry) []string` is defined in Task 6 Step 3 and called only there. `SetAgentClassificationCaps` has one signature, given in Task 5's Interfaces block and used unchanged in Task 7. `models.ToolCatalogEntry.ResourceField` is `*string` (`services/pkg/models/catalog.go:88`), matching the `!= nil` check.

**Test helpers this plan assumes exist.** `newStoreFixture`, `expectWriteAndAudit`, `newTestServerFixture`, `doJSONRequest`, `doRequest`, `decodeBody[T]`, `assertExpectationsMet`, `f.token(t, group)` are all in use today. Three are new and must be written in the task that first uses them: `expectLabelRules`, `expectCatalog`, `expectLiveDelegations` (Task 5), plus `strptr` (Task 6).
