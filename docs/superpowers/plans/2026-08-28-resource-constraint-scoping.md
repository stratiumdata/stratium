# Resource Constraint Scoping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator scope an agent to a resource subtree — "may do destructive things, but only under `/workspace/`" — by giving `resource_constraints` a write path and prefix semantics.

**Architecture:** A new `id_prefix` constraint key with prefix semantics, evaluated against every resource identity a call resolves to (the catalogued resource field's id, plus one per path a shell command names). Constraints live on the agent row, set only by an operator, copied onto root delegations at issuance and onto children from their parents — mirroring `classification_caps` exactly. Every other constraint key keeps today's exact-match behaviour untouched.

**Tech Stack:** Go 1.25, PostgreSQL with `golang-migrate`, gRPC, `net/http` for the PAP.

**Spec:** [`docs/superpowers/specs/2026-08-28-resource-constraint-scoping-design.md`](../specs/2026-08-28-resource-constraint-scoping-design.md)

## Global Constraints

- **Use `make`, not `go build` directly.** The admin UI is embedded into `stratium-pap` with `//go:embed dist`; on a fresh checkout every Go command that compiles `cmd/stratium-pap` fails with `pattern dist: no matching files found` until `make ui` has run. `go test ./internal/...` and `./pkg/...` are unaffected.
- **Every ambiguity denies.** An unevaluable constraint is a denial, never a pass. Reasons must distinguish "could not check" from "checked and it failed".
- **Never assume a resource id is a filesystem path.** It may be an S3 key, an API route, or a document id. Reject on a `..` segment; never call `path.Clean`.
- **`internal/authz` is pure**: no database handle, no network client, no ambient clock. Time is a parameter.
- **The comparison stays a bare `strings.HasPrefix`.** Write-time validation guarantees the trailing `/`, so no boundary logic belongs on the decision path.
- **`pkg/models` may not import `internal/authz`** — the dependency runs the other way. Shared constants live in `models`.
- Run `gofmt -w` on every file you touch. `make lint` runs `golangci-lint`.
- Commit messages: `<type>: <description>`, types `feat|fix|refactor|docs|test|chore|perf|ci`.

---

### Task 1: Prefix matching primitives

Pure functions with no callers yet. Everything that decides whether one resource id is inside a scope lives here.

**Files:**
- Create: `services/internal/authz/constraints.go`
- Create: `services/internal/authz/constraints_test.go`
- Modify: `services/pkg/models/delegation.go` (add one exported constant)

**Interfaces:**
- Consumes: nothing.
- Produces: `models.ResourceIDPrefixKey` (string constant `"id_prefix"`); `authz.satisfiesIDPrefix(ids []string, prefix string) (bool, string)`; `authz.hasDotDotSegment(id string) bool`.

The constant lives in `pkg/models`, not `internal/authz`, because `ScopeNarrows` (Task 3) needs it and `models` cannot import `authz` — the dependency runs the other way.

- [ ] **Step 1: Add the shared key constant**

In `services/pkg/models/delegation.go`, directly above `func ScopeNarrows`:

```go
// ResourceIDPrefixKey is the one resource-constraint key with PREFIX
// semantics: its value is matched against every resource identity a call
// resolved to, and every one of them must be under it. Every other key keeps
// exact-match semantics (internal/authz's checkResourceConstraints), for the
// reason that function's own comment gives — an opaque caller-defined string
// has no ordering to narrow along, so interpreting one is a place a widening
// can hide.
//
// It lives here rather than in internal/authz because ScopeNarrows below
// needs it too, and pkg/models cannot import internal/authz — the dependency
// runs the other way.
const ResourceIDPrefixKey = "id_prefix"
```

- [ ] **Step 2: Write the failing tests**

Create `services/internal/authz/constraints_test.go`:

```go
package authz

import "testing"

func TestHasDotDotSegment(t *testing.T) {
	cases := map[string]bool{
		"/workspace/src/main.go":   false,
		"/workspace/../etc/shadow": true,
		"/workspace/a/../b.txt":    true,
		"../etc/shadow":            true,
		"..":                       true,
		// A segment, not a substring: these are ordinary names.
		"/workspace/..hidden/x": false,
		"/workspace/a..b.txt":   false,
		"":                      false,
	}
	for id, want := range cases {
		if got := hasDotDotSegment(id); got != want {
			t.Errorf("hasDotDotSegment(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestSatisfiesIDPrefix(t *testing.T) {
	const prefix = "/workspace/"

	t.Run("every id under the prefix satisfies", func(t *testing.T) {
		ok, reason := satisfiesIDPrefix([]string{"/workspace/a.txt", "/workspace/src/b.go"}, prefix)
		if !ok {
			t.Fatalf("satisfiesIDPrefix denied (%s), want satisfied", reason)
		}
	})

	t.Run("one id outside denies and names it", func(t *testing.T) {
		ok, reason := satisfiesIDPrefix([]string{"/workspace/a.txt", "/etc/shadow"}, prefix)
		if ok {
			t.Fatal("satisfiesIDPrefix allowed a set containing an id outside the prefix")
		}
		if !contains(reason, "/etc/shadow") {
			t.Errorf("reason = %q, want it to name the offending id", reason)
		}
	})

	// The safety property: a decoy inside the prefix adds an obligation, it
	// never relieves one. Order must not matter either.
	t.Run("a decoy cannot rescue an id outside the prefix", func(t *testing.T) {
		for _, ids := range [][]string{
			{"/workspace/ok.txt", "/etc/shadow"},
			{"/etc/shadow", "/workspace/ok.txt"},
		} {
			if ok, _ := satisfiesIDPrefix(ids, prefix); ok {
				t.Fatalf("satisfiesIDPrefix(%v) allowed; a decoy just bought access outside the scope", ids)
			}
		}
	})

	t.Run("a traversal segment denies even under the prefix", func(t *testing.T) {
		ok, reason := satisfiesIDPrefix([]string{"/workspace/../etc/shadow"}, prefix)
		if ok {
			t.Fatal("satisfiesIDPrefix allowed a traversal escape; HasPrefix alone does not stop this")
		}
		if !contains(reason, "..") {
			t.Errorf("reason = %q, want it to name the traversal segment", reason)
		}
	})

	t.Run("no ids at all denies as unevaluable", func(t *testing.T) {
		ok, reason := satisfiesIDPrefix(nil, prefix)
		if ok {
			t.Fatal("satisfiesIDPrefix allowed an empty id set; unevaluable must not read as satisfied")
		}
		if !contains(reason, "cannot be evaluated") {
			t.Errorf("reason = %q, want the uncheckable wording, distinct from an outside-the-scope denial", reason)
		}
	})
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
```

If `contains`/`indexOf` already exist in package `authz`, delete them from this file and use the existing ones — a redeclaration is a compile error.

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd services && go test ./internal/authz/ -run 'TestHasDotDotSegment|TestSatisfiesIDPrefix'
```

Expected: FAIL, `undefined: hasDotDotSegment`, `undefined: satisfiesIDPrefix`.

- [ ] **Step 4: Write the implementation**

Create `services/internal/authz/constraints.go`:

```go
package authz

import (
	"fmt"
	"strings"

	"stratium/pkg/models"
)

// satisfiesIDPrefix reports whether EVERY resource identity in ids is inside
// prefix, and why not when one is not.
//
// Every one, not any one, and that is the whole safety argument. A shell
// command names several paths (ShellResourceIDs); requiring only one of them
// to be in scope would let a benign path buy access for a dangerous one, the
// same decoy that strictest-wins labelling exists to defeat. Requiring all of
// them means an extra path adds an obligation rather than relieving one, so
// there is nothing an attacker can ADD to a command to widen it.
//
// The prefix comparison is a bare strings.HasPrefix with no boundary logic,
// which is safe only because write-time validation guarantees the prefix ends
// in "/" (internal/store's validateResourceConstraints). Without that,
// "/workspace" would admit "/workspace-evil/secrets.txt". If you are tempted
// to add boundary handling here, fix the validation instead: one rule in one
// place beats two half-rules.
func satisfiesIDPrefix(ids []string, prefix string) (bool, string) {
	if len(ids) == 0 {
		// Distinct from an outside-the-scope denial, deliberately. An
		// operator's audit trail has to tell "we could not check" apart from
		// "we checked and it was outside", the same distinction CheckCap
		// draws for an unlabelled resource.
		return false, "request identifies no resource; the delegation's " +
			models.ResourceIDPrefixKey + " constraint cannot be evaluated and therefore denies"
	}
	for _, id := range ids {
		// Checked before the prefix test, not after: "/workspace/../etc/shadow"
		// PASSES HasPrefix, so a prefix-first order would allow the escape.
		// Rejected on the segment rather than resolved, because nothing here
		// may assume the id is a filesystem path — it may be an S3 key, an
		// API route, or a document id, and path.Clean would be inventing a
		// meaning the tenant never gave it.
		if hasDotDotSegment(id) {
			return false, fmt.Sprintf(
				"resource %q contains a %q segment and cannot be checked against %s %q",
				id, "..", models.ResourceIDPrefixKey, prefix)
		}
		if !strings.HasPrefix(id, prefix) {
			return false, fmt.Sprintf("resource %q is outside delegation %s %q",
				id, models.ResourceIDPrefixKey, prefix)
		}
	}
	return true, ""
}

// hasDotDotSegment reports whether id contains a ".." PATH SEGMENT.
//
// A segment, not a substring: "/workspace/..hidden/x" and "/a/b..c.txt" are
// ordinary names and must not be refused. Splitting on "/" is the whole test.
func hasDotDotSegment(id string) bool {
	for _, segment := range strings.Split(id, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd services && gofmt -w internal/authz/constraints.go internal/authz/constraints_test.go pkg/models/delegation.go
go test ./internal/authz/ ./pkg/models/
```

Expected: PASS for both packages.

- [ ] **Step 6: Commit**

```bash
git add services/internal/authz/constraints.go services/internal/authz/constraints_test.go services/pkg/models/delegation.go
git commit -m "feat: prefix matching primitives for resource constraints"
```

---

### Task 2: Enforce prefix constraints on the decision path

Wires Task 1's primitives into the delegation leg. After this task the enforcement works end to end in memory; nothing can yet SET a constraint, so no live behaviour changes.

**Files:**
- Modify: `services/internal/authz/delegation.go` (`checkResourceConstraints`, `DelegationLeg`)
- Modify: `services/internal/authz/types.go` (add `Request.ResourceIDs`)
- Modify: `services/internal/authz/compound.go:66-67` (the `DelegationLeg` call)
- Test: `services/internal/authz/delegation_test.go` (extend)

**Interfaces:**
- Consumes: `satisfiesIDPrefix`, `models.ResourceIDPrefixKey` from Task 1.
- Produces: `authz.Request.ResourceIDs []string`; `checkResourceConstraints(constraints, resource map[string]string, ids []string) (bool, string)`; `DelegationLeg(chain []*models.Delegation, a Action, derived models.ActionTier, resource map[string]string, resourceIDs []string, now time.Time, maxDepth int) (LegResult, int)`.

- [ ] **Step 1: Write the failing tests**

Append to `services/internal/authz/delegation_test.go`:

```go
func TestCheckResourceConstraints_IDPrefix(t *testing.T) {
	constraints := map[string]string{models.ResourceIDPrefixKey: "/workspace/"}

	t.Run("every id inside satisfies", func(t *testing.T) {
		ok, reason := checkResourceConstraints(constraints, map[string]string{},
			[]string{"/workspace/a.txt", "/workspace/b.txt"})
		if !ok {
			t.Fatalf("denied (%s), want satisfied", reason)
		}
	})

	t.Run("one id outside denies", func(t *testing.T) {
		ok, _ := checkResourceConstraints(constraints, map[string]string{},
			[]string{"/workspace/a.txt", "/etc/shadow"})
		if ok {
			t.Fatal("allowed a set containing an id outside the prefix")
		}
	})

	t.Run("no ids denies", func(t *testing.T) {
		ok, _ := checkResourceConstraints(constraints, map[string]string{}, nil)
		if ok {
			t.Fatal("allowed with no resource identified; unevaluable must deny")
		}
	})
}

// The existing exact-match behaviour must be bit-for-bit unchanged, including
// its deny-if-absent rule. A prefix key is an addition, not a replacement.
func TestCheckResourceConstraints_ExactKeysAreUnchanged(t *testing.T) {
	constraints := map[string]string{"tenant": "acme"}

	if ok, _ := checkResourceConstraints(constraints, map[string]string{"tenant": "acme"}, nil); !ok {
		t.Error("an exact key matching its value should satisfy")
	}
	if ok, _ := checkResourceConstraints(constraints, map[string]string{"tenant": "other"}, nil); ok {
		t.Error("an exact key with a different value must deny")
	}
	if ok, reason := checkResourceConstraints(constraints, map[string]string{}, nil); ok {
		t.Errorf("an exact key absent from the request must deny, got satisfied (%s)", reason)
	}
}

// Both key kinds in one constraint set: both must hold.
func TestCheckResourceConstraints_PrefixAndExactTogether(t *testing.T) {
	constraints := map[string]string{
		models.ResourceIDPrefixKey: "/workspace/",
		"tenant":                   "acme",
	}
	resource := map[string]string{"tenant": "acme"}

	if ok, reason := checkResourceConstraints(constraints, resource, []string{"/workspace/a.txt"}); !ok {
		t.Fatalf("denied (%s), want satisfied — both constraints hold", reason)
	}
	if ok, _ := checkResourceConstraints(constraints, map[string]string{"tenant": "other"},
		[]string{"/workspace/a.txt"}); ok {
		t.Error("the exact key failed but the call was allowed")
	}
	if ok, _ := checkResourceConstraints(constraints, resource, []string{"/etc/shadow"}); ok {
		t.Error("the prefix failed but the call was allowed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd services && go test ./internal/authz/ -run TestCheckResourceConstraints
```

Expected: FAIL — `too many arguments in call to checkResourceConstraints`.

- [ ] **Step 3: Add the field to Request**

In `services/internal/authz/types.go`, inside `type Request struct`, directly after the `Resource map[string]string` field:

```go
	// ResourceIDs are every identity this call resolved to: the catalogued
	// resource field's own id, plus one per path a command_field tool's
	// command names (ShellResourceIDs). The delegation leg's id_prefix
	// constraint is evaluated against every member — see
	// satisfiesIDPrefix for why every, not any.
	//
	// Separate from Resource rather than a key inside it: Resource is a map
	// of single-valued attributes the policy engines also read, and R1
	// strips two of its keys unconditionally. A multi-valued identity does
	// not fit that shape and must not be smuggled into it.
	ResourceIDs []string
```

- [ ] **Step 4: Add the prefix branch to checkResourceConstraints**

In `services/internal/authz/delegation.go`, change the signature and add the branch as the first thing inside the loop:

```go
func checkResourceConstraints(constraints, resource map[string]string, ids []string) (bool, string) {
	for key, want := range constraints {
		// The one key with prefix semantics. Checked against the resolved
		// identities rather than resource[key], because a shell call has
		// several identities and no "id" attribute at all — writing one
		// would let a decoy satisfy this while another path did the work.
		if key == models.ResourceIDPrefixKey {
			if ok, reason := satisfiesIDPrefix(ids, want); !ok {
				return false, reason
			}
			continue
		}
		got, ok := resource[key]
		if !ok {
			return false, fmt.Sprintf("resource constraint %q is required but absent from the request", key)
		}
		if got != want {
			return false, fmt.Sprintf("resource constraint %s=%q does not match request value %q", key, want, got)
		}
	}
	return true, ""
}
```

- [ ] **Step 5: Thread the ids through DelegationLeg**

In the same file, add `resourceIDs []string` to `DelegationLeg`'s parameters, directly after `resource map[string]string`:

```go
func DelegationLeg(
	chain []*models.Delegation,
	a Action,
	derived models.ActionTier,
	resource map[string]string,
	resourceIDs []string,
	now time.Time,
	maxDepth int,
) (LegResult, int) {
```

and update its one call to `checkResourceConstraints`:

```go
		if allowed, reason := checkResourceConstraints(d.ResourceConstraints, resource, resourceIDs); !allowed {
```

In `services/internal/authz/compound.go`, update the call at line 66:

```go
	delegationLeg, deniedDepth := DelegationLeg(
		req.Chain, req.Action, derived, req.Resource, req.ResourceIDs, req.Now, cfg.MaxDepth)
```

- [ ] **Step 6: Run the whole authz package**

```bash
cd services && gofmt -w internal/authz/ && go test ./internal/authz/
```

Expected: PASS. Existing `DelegationLeg` callers in tests will need `nil` added as the new argument — do that mechanically; a test that passed no ids before is asserting exact-match behaviour, which `nil` preserves exactly.

- [ ] **Step 7: Run the conformance suite**

```bash
cd .. && make conformance
```

Expected: `25/25 conformance properties executed.`

- [ ] **Step 8: Commit**

```bash
git add services/internal/authz/
git commit -m "feat: enforce id_prefix resource constraints against every resolved identity"
```

---

### Task 3: Narrowing rule for prefixes

A child delegation may go deeper into a scope, never shallower.

**Files:**
- Modify: `services/pkg/models/delegation.go` (`ScopeNarrows`, the resource-constraint loops)
- Test: `services/pkg/models/delegation_test.go` (extend)

**Interfaces:**
- Consumes: `models.ResourceIDPrefixKey` from Task 1.
- Produces: no new symbols; `ScopeNarrows` gains a case.

- [ ] **Step 1: Write the failing tests**

Append to `services/pkg/models/delegation_test.go`:

```go
func TestScopeNarrows_IDPrefix(t *testing.T) {
	newDelegation := func(prefix string) *Delegation {
		d := &Delegation{
			ApprovedTools: []string{"Read"}, MaxActionTier: ActionTierReadOnly,
			ClassificationCaps:  map[string]string{},
			ResourceConstraints: map[string]string{},
			ExpiresAt:           time.Now().Add(time.Hour),
		}
		if prefix != "" {
			d.ResourceConstraints[ResourceIDPrefixKey] = prefix
		}
		return d
	}

	cases := []struct {
		name         string
		parent,child string
		wantValid    bool
	}{
		{"deeper narrows", "/workspace/", "/workspace/src/", true},
		{"equal is valid", "/workspace/", "/workspace/", true},
		{"shallower widens", "/workspace/src/", "/workspace/", false},
		{"root widens", "/workspace/", "/", false},
		{"a sibling is not a subtree", "/workspace/", "/other/", false},
		// The boundary trap, at narrowing time as well as matching time.
		{"a longer sibling is not a subtree", "/workspace/", "/workspace-evil/", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := ScopeNarrows(newDelegation(tc.parent), newDelegation(tc.child))
			if tc.wantValid && reason != "" {
				t.Fatalf("ScopeNarrows(%q -> %q) = %q, want valid", tc.parent, tc.child, reason)
			}
			if !tc.wantValid && reason == "" {
				t.Fatalf("ScopeNarrows(%q -> %q) accepted a widening", tc.parent, tc.child)
			}
		})
	}

	// §4.3.1 is unchanged: introduce and drop are both still refused.
	t.Run("a child may not introduce a prefix its parent leaves open", func(t *testing.T) {
		if ScopeNarrows(newDelegation(""), newDelegation("/workspace/")) == "" {
			t.Fatal("accepted a child introducing a constraint its parent lacks")
		}
	})
	t.Run("a child may not drop its parent's prefix", func(t *testing.T) {
		if ScopeNarrows(newDelegation("/workspace/"), newDelegation("")) == "" {
			t.Fatal("accepted a child dropping its parent's constraint — an absent constraint " +
				"is unrestricted at decision time, so this would be a promotion")
		}
	})
}
```

Note `"/workspace-evil/"` fails `HasPrefix(child, parent)` because parent ends in `/` — the trailing-slash rule closes the boundary trap in both directions with no extra logic.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd services && go test ./pkg/models/ -run TestScopeNarrows_IDPrefix
```

Expected: FAIL on `deeper narrows` — the existing exact comparison rejects it.

- [ ] **Step 3: Add the prefix case**

In `services/pkg/models/delegation.go`, in the loop over `parent.ResourceConstraints`, replace the value comparison with:

```go
	for key, parentVal := range parent.ResourceConstraints {
		childVal, ok := child.ResourceConstraints[key]
		if !ok {
			return "child drops parent resource constraint " + key + "=" + parentVal
		}
		// ResourceIDPrefixKey narrows by containment, not equality: a child
		// may go DEEPER into its parent's subtree, never shallower and never
		// sideways. HasPrefix is the whole test, and it is sufficient only
		// because a stored prefix always ends in "/" (validated at write
		// time) — without that, parent "/workspace" would accept child
		// "/workspace-evil/" as a narrowing.
		if key == ResourceIDPrefixKey {
			if !strings.HasPrefix(childVal, parentVal) {
				return "child resource constraint " + key + "=" + childVal +
					" is not within parent " + key + "=" + parentVal
			}
			continue
		}
		if childVal != parentVal {
			return "child resource constraint " + key + "=" + childVal +
				" differs from parent " + key + "=" + parentVal
		}
	}
```

Add `"strings"` to the file's imports if it is not already there.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd services && gofmt -w pkg/models/ && go test ./pkg/models/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/pkg/models/
git commit -m "feat: narrow id_prefix resource constraints by containment"
```

---

### Task 4: Storage and the admin write path

The column, the store methods, and the write-time validation that makes Task 1's bare `HasPrefix` safe.

**Files:**
- Create: `services/migrations/000021_agent_resource_constraints.up.sql`
- Create: `services/migrations/000021_agent_resource_constraints.down.sql`
- Create: `services/pkg/models/agent_constraints.go`
- Create: `services/internal/store/agent_constraints.go`
- Create: `services/internal/store/agent_constraints_test.go`
- Modify: `services/pkg/models/agent.go` (add `ResourceConstraints`)
- Modify: `services/internal/store/agent.go` (`getAgentQuery`, `listAgentsQuery`, and the scan)

**Interfaces:**
- Consumes: `models.ResourceIDPrefixKey` from Task 1.
- Produces: `models.AgentConstraintsView`; `store.SetAgentResourceConstraints(ctx, id uuid.UUID, constraints map[string]string, actor string, now time.Time) (models.AgentConstraintsView, error)`; `store.ClearAgentResourceConstraints(ctx, id uuid.UUID, actor string, now time.Time) error`; `store.GetAgentResourceConstraints(ctx, id uuid.UUID) (models.AgentConstraintsView, error)`; `store.ErrInvalidResourceConstraint`.

- [ ] **Step 1: Write the migration**

Create `services/migrations/000021_agent_resource_constraints.up.sql`:

```sql
-- 000021_agent_resource_constraints.up.sql
--
-- resource_constraints on the agent is the template a root delegation's own
-- resource_constraints is copied from at issuance. Before this column,
-- issuance hardcoded an empty map (internal/pdpgrpc/delegation.go) and an
-- empty map is checkResourceConstraints' unrestricted case, so scope
-- enforcement could not be switched on through any supported interface --
-- exactly the shape 000020 fixed for classification_caps.
--
-- The DEFAULT exists only to backfill existing rows and is dropped
-- immediately after, matching 000020 and 000001_baseline's refusal to give
-- delegations.approved_tools a default: an INSERT must state its intent
-- rather than inherit a silent one.
ALTER TABLE agents
    ADD COLUMN resource_constraints JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE agents
    ALTER COLUMN resource_constraints DROP DEFAULT;
```

Create `services/migrations/000021_agent_resource_constraints.down.sql`:

```sql
-- 000021_agent_resource_constraints.down.sql
ALTER TABLE agents DROP COLUMN resource_constraints;
```

- [ ] **Step 2: Add the model field and the view**

In `services/pkg/models/agent.go`, after `ClassificationCaps`:

```go
	// ResourceConstraints is the scope copied onto every ROOT delegation at
	// issuance, the same way ClassificationCaps above is. It is NOT consulted
	// at decision time -- the decision reads the delegation's own constraints
	// -- so a change here never affects a delegation already issued.
	ResourceConstraints map[string]string `json:"resource_constraints" db:"resource_constraints"`
```

Create `services/pkg/models/agent_constraints.go`:

```go
package models

import "github.com/google/uuid"

// AgentConstraintsView is what the resource-constraints routes return: the
// scope itself plus the two warnings an operator needs to read it correctly.
// Deliberately the same shape as AgentCapsView, which carries the same two
// warnings for the same reasons.
type AgentConstraintsView struct {
	AgentID             uuid.UUID         `json:"agent_id"`
	ResourceConstraints map[string]string `json:"resource_constraints"`

	// UnsatisfiableTools are tools that can satisfy NO constraint, because
	// they resolve no resource identity at all -- a catalogued tool with
	// neither a resource_field nor a command_field. Not "denied by this
	// scope": denied by any scope whatsoever. Same computation and same
	// caveats as AgentCapsView.UnsatisfiableTools, including that an
	// UNRESTRICTED agent's uncatalogued tools cannot be enumerated.
	UnsatisfiableTools []string `json:"unsatisfiable_tools"`

	// LiveDelegations counts the agent's delegations that are neither revoked
	// nor expired -- the ones this write does NOT affect, because constraints
	// are copied at issuance. A warning, not a confirmation.
	LiveDelegations int `json:"live_delegations"`
}
```

- [ ] **Step 3: Write the failing validation tests**

Create `services/internal/store/agent_constraints_test.go`:

```go
package store

import (
	"strings"
	"testing"

	"stratium/pkg/models"
)

// Write-time validation is what lets the decision path use a bare
// strings.HasPrefix with no boundary logic. If these rules move or weaken,
// internal/authz.satisfiesIDPrefix becomes unsafe.
func TestValidateResourceConstraints(t *testing.T) {
	cases := []struct {
		name        string
		constraints map[string]string
		wantErr     string
	}{
		{"a well-formed prefix", map[string]string{models.ResourceIDPrefixKey: "/workspace/"}, ""},
		{"no constraints at all", map[string]string{}, ""},
		{"an opaque exact key is accepted", map[string]string{"tenant": "acme"}, ""},

		{
			"a prefix without a trailing slash",
			map[string]string{models.ResourceIDPrefixKey: "/workspace"},
			"must end with",
		},
		{
			"an empty prefix",
			map[string]string{models.ResourceIDPrefixKey: ""},
			"must not be empty",
		},
		{
			"a prefix containing a traversal segment",
			map[string]string{models.ResourceIDPrefixKey: "/workspace/../"},
			"..",
		},
		{"an empty key", map[string]string{"": "x"}, "must not be empty"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResourceConstraints(tc.constraints)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateResourceConstraints(%v) = %v, want nil", tc.constraints, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateResourceConstraints(%v) = nil, want an error naming %q",
					tc.constraints, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// A trailing-slash rejection must be actionable: the operator's next move is
// to add the slash, and the message should say so.
func TestValidateResourceConstraints_TrailingSlashErrorExplainsWhy(t *testing.T) {
	err := validateResourceConstraints(map[string]string{models.ResourceIDPrefixKey: "/workspace"})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "/workspace/") {
		t.Errorf("error = %q, want it to show the corrected form", err)
	}
}
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
cd services && go test ./internal/store/ -run TestValidateResourceConstraints
```

Expected: FAIL, `undefined: validateResourceConstraints`.

- [ ] **Step 5: Write the store layer**

Create `services/internal/store/agent_constraints.go`. Model every method on its `agent_caps.go` counterpart — read that file first and follow its transaction, RLS, and audit shape exactly.

```go
// agent_constraints.go is the write path for an agent's resource_constraints,
// the scope copied onto every root delegation at issuance. It mirrors
// agent_caps.go method for method; read that file first.
package store

import (
	"fmt"
	"strings"

	"stratium/pkg/models"
)

// ErrInvalidResourceConstraint wraps ErrInvalidRequest so the PAP maps it to
// 400 through writeStoreError without a special case.
var ErrInvalidResourceConstraint = fmt.Errorf("%w: invalid resource constraint", ErrInvalidRequest)

// validateResourceConstraints enforces the two rules that let the decision
// path compare with a bare strings.HasPrefix (internal/authz.satisfiesIDPrefix):
// a prefix is non-empty and ends with "/".
//
// The trailing slash is not cosmetic. Without it "/workspace" admits
// "/workspace-evil/secrets.txt", and the same trap reappears in ScopeNarrows,
// where parent "/workspace" would accept child "/workspace-evil/" as a
// narrowing. Enforcing it once here closes both.
//
// A prefix containing ".." is refused for the same reason an id containing one
// is: it cannot be compared without resolving it, and nothing here may assume
// the value is a filesystem path.
func validateResourceConstraints(constraints map[string]string) error {
	for key, value := range constraints {
		if key == "" {
			return fmt.Errorf("%w: a constraint key must not be empty", ErrInvalidResourceConstraint)
		}
		if key != models.ResourceIDPrefixKey {
			// Opaque caller-defined attribute with exact-match semantics.
			// Nothing to validate: any string is a legitimate value.
			continue
		}
		if value == "" {
			return fmt.Errorf("%w: %s must not be empty; use DELETE to remove the scope",
				ErrInvalidResourceConstraint, models.ResourceIDPrefixKey)
		}
		if strings.Contains(value, "..") {
			return fmt.Errorf("%w: %s %q must not contain %q",
				ErrInvalidResourceConstraint, models.ResourceIDPrefixKey, value, "..")
		}
		if !strings.HasSuffix(value, "/") {
			return fmt.Errorf("%w: %s %q must end with %q (did you mean %q?) — without it the "+
				"prefix also matches siblings such as %q",
				ErrInvalidResourceConstraint, models.ResourceIDPrefixKey, value, "/",
				value+"/", value+"-other/secrets")
		}
	}
	return nil
}
```

Then add the three methods by mirroring `SetAgentClassificationCaps`, `ClearAgentClassificationCaps`, and `GetAgentClassificationCaps` from `agent_caps.go`. Read those three in full first; their exact transaction and audit shape is the contract, not a detail. Each of your methods must:

1. Open a transaction and `SELECT set_config('app.tenant_id', $1, true)` **before** any query — the Go code never adds a `WHERE tenant_id` clause, because RLS is the tenant boundary and a second implementation of it is worse than none.
2. Call `validateResourceConstraints` before the write, so an invalid prefix never reaches the column.
3. `UPDATE agents SET resource_constraints = $1 WHERE id = $2` and treat zero rows affected as `ErrNotFound`.
4. Append an audit entry inside the same transaction, exactly as the caps methods do — a configuration write that is not recorded did not happen.
5. Return `models.AgentConstraintsView` built from the freshly written value.

The tenant epoch bump is a database trigger and needs no Go code; do not write one.

There is no `allow_uncovered` analogue — that parameter exists for catch-all label rules and has no meaning here, so `SetAgentResourceConstraints` takes no such flag.

Reuse `countLiveDelegations` and `unsatisfiableTools` from `agent_caps.go` unchanged. Do NOT copy them: a second copy of `unsatisfiableTools` is exactly the drift the shared-helper note in the spec warns about.

- [ ] **Step 6: Add the column to the agent reads**

In `services/internal/store/agent.go`, add `resource_constraints` to both `getAgentQuery` and `listAgentsQuery`, after `classification_caps`, and scan it into `a.ResourceConstraints` with the same `json.Unmarshal` plus nil-to-empty-map treatment `classification_caps` already gets at lines 113-118.

- [ ] **Step 7: Run the store package**

```bash
cd services && gofmt -w internal/store/ pkg/models/ && go test ./internal/store/ ./pkg/models/
```

Expected: PASS.

- [ ] **Step 8: Verify the migration applies and rolls back**

```bash
cd .. && make integration 2>&1 | grep -E "chain_verifies_across_the_migration_boundary|^ok|FAIL"
```

Expected: the migration-boundary subtest PASSES. It walks every migration down and back up; a malformed `000021` fails here and nowhere else.

- [ ] **Step 9: Commit**

```bash
git add services/migrations/000021_* services/internal/store/ services/pkg/models/
git commit -m "feat: store agent resource constraints with write-time prefix validation"
```

---

### Task 5: PAP routes

**Files:**
- Create: `services/cmd/stratium-pap/agent_constraints.go`
- Create: `services/cmd/stratium-pap/agent_constraints_test.go`
- Modify: `services/cmd/stratium-pap/server.go:231-233` (route table)

**Interfaces:**
- Consumes: the three store methods from Task 4.
- Produces: `getAgentConstraints`, `putAgentConstraints`, `deleteAgentConstraints` handlers.

- [ ] **Step 1: Register the routes**

In `services/cmd/stratium-pap/server.go`, directly below the three `classification-caps` entries:

```go
	// resource-constraints is gated exactly as classification-caps is, and for
	// the same reason: it is a security ceiling, so a writer must hold
	// RoleAdmin rather than the blanket editor role the CRUD routes use.
	{Pattern: "GET /v1/agents/{id}/resource-constraints", MinRole: RoleViewer, Handler: getAgentConstraints},
	{Pattern: "PUT /v1/agents/{id}/resource-constraints", MinRole: RoleAdmin, Handler: putAgentConstraints},
	{Pattern: "DELETE /v1/agents/{id}/resource-constraints", MinRole: RoleAdmin, Handler: deleteAgentConstraints},
```

- [ ] **Step 2: Write the handlers**

Create `services/cmd/stratium-pap/agent_constraints.go`, mirroring `agent_caps.go` exactly:

```go
// agent_constraints.go implements the three /v1/agents/{id}/resource-constraints
// routes routeTable (server.go) registers -- the same thin decode/call/respond
// shape agent_caps.go uses. All validation lives in internal/store's
// validateResourceConstraints, not duplicated here.
package main

import (
	"net/http"
	"time"
)

// constraintsRequest is wrapped rather than a bare map so the route can gain a
// field without ambiguity, matching capsRequest.
type constraintsRequest struct {
	ResourceConstraints map[string]string `json:"resource_constraints"`
}

func getAgentConstraints(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	view, err := s.store.GetAgentResourceConstraints(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func putAgentConstraints(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req constraintsRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	view, err := s.store.SetAgentResourceConstraints(
		r.Context(), id, req.ResourceConstraints, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// deleteAgentConstraints turns scope enforcement OFF for delegations issued
// from now on. A separate verb from PUT so that cannot happen by omitting a
// field from a request body -- the same reasoning deleteAgentCaps documents.
func deleteAgentConstraints(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.ClearAgentResourceConstraints(r.Context(), id, op.Subject, time.Now()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 3: Write handler tests**

Create `services/cmd/stratium-pap/agent_constraints_test.go`, modelled on `agent_caps_test.go`: a `PUT` with a valid prefix returns `200` and the view; a `PUT` with `/workspace` (no trailing slash) returns `400`; a `GET` returns the stored value; a `DELETE` returns `204`; a caller below `RoleAdmin` gets `403` on `PUT` and `DELETE`; and an unknown agent id gets `404` (which is also what another tenant's agent returns — indistinguishable, by design). Follow `agent_caps_test.go`'s fake-store pattern rather than inventing one.

- [ ] **Step 4: Run the tests**

```bash
cd services && gofmt -w cmd/stratium-pap/ && cd .. && make ui >/dev/null && cd services && go test ./cmd/stratium-pap/
```

Expected: PASS. `make ui` is required before any command that compiles `cmd/stratium-pap`.

- [ ] **Step 5: Commit**

```bash
git add services/cmd/stratium-pap/
git commit -m "feat: admin routes for agent resource constraints"
```

---

### Task 6: Copy constraints at issuance, and feed the identities in

The last wiring. After this the feature works end to end.

**Files:**
- Modify: `services/internal/pdpgrpc/delegation.go:182` (root copy) and `:200-206` (child copy)
- Modify: `services/internal/pdpgrpc/server.go` (pass `ResourceIDs` into the `authz.Request`)
- Test: `services/internal/pdpgrpc/delegation_test.go` (extend)

**Interfaces:**
- Consumes: `models.Agent.ResourceConstraints` (Task 4), `authz.Request.ResourceIDs` (Task 2).
- Produces: no new symbols.

- [ ] **Step 1: Write the failing test**

Find the existing test asserting the same property for `ClassificationCaps` and reuse its fixture — it already builds a store fake with an agent, which is the fiddly part:

```bash
cd services && grep -n "ClassificationCaps" internal/pdpgrpc/delegation_test.go
```

With that fixture in hand, the new test asserts exactly this:

```go
// The scope reaches a delegation ONLY through this copy. Without it the agent
// column is settable and inert -- the state docs/validation-journeys.md §4.3
// describes, and the state this task ends.
func TestCreateDelegation_CopiesAgentResourceConstraintsOntoARoot(t *testing.T) {
	// fixture: an agent whose ResourceConstraints is
	//   map[string]string{models.ResourceIDPrefixKey: "/workspace/"}
	// plus a policy permitting the requested tool at the requested tier,
	// without which Clamp rejects the call before any copy happens.

	resp, err := server.CreateDelegation(ctx, &CreateDelegationRequest{
		Subject: "alice@example.com", AgentId: agentID.String(),
		RequestedScope: &RequestedScope{
			MaxActionTier: int32(models.ActionTierReadOnly), Tools: []string{"Read"},
		},
		Purpose: "constraint copy", TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateDelegation: %v", err)
	}

	created := // read the persisted delegation back through the file's own fixture
	if got := created.ResourceConstraints[models.ResourceIDPrefixKey]; got != "/workspace/" {
		t.Fatalf("root delegation %s = %q, want %q -- the agent's scope did not reach the delegation",
			models.ResourceIDPrefixKey, got, "/workspace/")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd services && go test ./internal/pdpgrpc/ -run CreateDelegation
```

Expected: FAIL — the root's constraints are the hardcoded empty map.

- [ ] **Step 3: Copy from the agent onto a root**

In `services/internal/pdpgrpc/delegation.go`, replace line 182:

```go
		ResourceConstraints: map[string]string{},
```

with:

```go
		// Copied from the agent row, the only place an operator can set a
		// scope (PUT /v1/agents/{id}/resource-constraints). A root has no
		// parent to clamp against, so this is where the scope enters the
		// chain; children below copy their parent and can only narrow.
		// Exactly the path ClassificationCaps above takes.
		ResourceConstraints: copyStringMap(agent.ResourceConstraints),
```

The child branch below already copies `parent.ResourceConstraints` unchanged — leave it alone. An identical child always narrows (`ScopeNarrows` treats equal as valid), so copying is always accepted.

- [ ] **Step 4: Pass the identities into the decision**

In `services/internal/pdpgrpc/server.go`, find where the `authz.Request` is built and add the `resourceIDs` slice already computed for labelling:

```go
		ResourceIDs: resourceIDs,
```

`resourceIDs` is in scope: it is built a few lines above for `labelResource`. Do not recompute it — one derivation, two consumers.

- [ ] **Step 5: Run the tests**

```bash
cd services && gofmt -w internal/pdpgrpc/ && go test ./internal/pdpgrpc/ ./internal/...
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add services/internal/pdpgrpc/
git commit -m "feat: copy agent resource constraints onto root delegations"
```

---

### Task 7: Live proof, journey inversion, and documentation

**Files:**
- Modify: `services/internal/store/journeys_integration_test.go`
- Modify: `docs/validation-journeys.md`, `docs/default-posture.md`, `docs/concepts.md`, `docs/user-guide.md`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing further.

- [ ] **Step 1: Invert the journey assertion**

`TestIntegration_Journey43_ResourceConstraintsAreEnforcedButUnreachable`'s second subtest, `but_no_supported_path_can_create_one`, asserts a delegation from `CreateDelegation` carries no constraints. That is now false by design — its `WHEN THIS FAILS` marker names this work. Rename the test to `TestIntegration_Journey43_ResourceConstraintsAreEnforcedAndReachable` and rewrite that subtest to: `PUT` a scope on the agent, call `CreateDelegation`, read the delegation back through `GET /v1/delegations`, and assert `resource_constraints` carries the prefix.

- [ ] **Step 2: Add the live scope proof**

Add `TestIntegration_Journey43_AScopedDelegationConstrainsEveryPath` to the same file, on the PAP tenant, following `TestIntegration_Journey1_AShellCommandIsLabelledByEveryPathItNames`'s structure exactly — including `journeyCleanupNullTierTool` for the `command_field` row, without which the migration-boundary proof fails. Subtests:

| Command or call | Expected |
|---|---|
| `Read` inside `/workspace/` | ALLOW |
| `Read` outside | DENY, naming the id |
| `cat /workspace/a.txt` | ALLOW |
| `cat /workspace/a.txt; cat /etc/shadow` | DENY — the decoy case, the one that matters |
| `cat /workspace/../etc/shadow` | DENY, naming the `..` segment |
| `npm test` | DENY as unevaluable |

- [ ] **Step 3: Run the full suite**

```bash
cd /path/to/stratium-data && make integration
```

Expected: every test passes. Check `make: *** Error` is absent from the output — `make integration`'s exit code is the one that matters, so do not wrap it in anything that masks it.

- [ ] **Step 4: Update the documentation**

- `docs/validation-journeys.md`: mark fix #2 done in §5; rewrite §4.3 — the mechanism is now reachable; update §4.4's one-sentence version, which is the passage this whole change exists to make true; update the harness table with the new test names.
- `docs/default-posture.md`: add resource constraints to §1's table and give them a short section beside §4's cap guidance, including that setting one denies tools resolving no identity.
- `docs/concepts.md` §7: the delegation chain's resource-constraint dimension now narrows by containment.
- `docs/user-guide.md` §5.5: document the three routes in the agent CRUD section.

- [ ] **Step 5: Commit**

```bash
git add services/internal/store/journeys_integration_test.go docs/
git commit -m "docs: record resource constraint scoping and prove it live"
```

---

## Open questions for the implementer to raise, not decide

- **Should `unsatisfiable_tools` be a refusal rather than a warning**, on this route and on `classification-caps`? Both are advisory today, and both let an operator silently disable an agent's whole toolkit. Flagged in the spec's Risks; out of scope for this plan.
- **Should the two views share one computation?** `unsatisfiableTools` is reused unchanged by Task 4. If a future change makes the two definitions diverge, split them deliberately rather than by drift.
