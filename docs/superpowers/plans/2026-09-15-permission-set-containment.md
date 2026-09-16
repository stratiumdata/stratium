# Permission-Set Containment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Stratium one engine that answers "is this set of permissions contained in that one?", and point the four places that need that answer at it.

**Architecture:** A new `services/pkg/permset` package holds a `Set` type (the six dimensions that bound a delegation), an explicit dimension registry, `Contains` (exact, blocking) and `Union` (over-approximating, advisory). `models.ScopeNarrows` moves into it wholesale — its existing test suite is the acceptance criterion for the move. Three consumers then hang off the engine: a containment endpoint, an effective-permissions endpoint, and a recorded verdict on agent-grant writes.

**Tech Stack:** Go 1.25.0, module `stratium`, stdlib only. Postgres via `lib/pq`. No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-09-15-permission-set-containment-design.md`](../specs/2026-09-15-permission-set-containment-design.md)

## Global Constraints

- **No new dependencies.** `services/go.mod` must be byte-identical at the end of this plan. If a task seems to need a library, it is the wrong task.
- **Run every Go command from `services/`.** The module root is `services/`, not the repository root.
- **`make ui` once before any task that compiles `cmd/stratium-pap`** (Tasks 5, 6, 7). The admin UI is `//go:embed`ed and `dist/` is git-ignored, so bare `go test ./cmd/stratium-pap/` fails with `pattern dist: no matching files found` until the UI is built. Tasks 1–4 and 8 do not touch that package and need no UI build.
- **Reason strings are operator-facing and must be preserved verbatim.** `store.CreateDelegation` wraps them into an error an operator reads. Changing the wording is a user-visible change with no gain.
- **Tests run with the race detector**, matching `make test`: `go test -race ./...`.
- **Commit format:** conventional commits (`feat:`, `fix:`, `refactor:`, `test:`). End every commit message with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- **Work on a branch.** `main` has unrelated uncommitted changes; do not commit on top of them.

---

### Task 1: The `Set` type, the dimension registry, and the completeness test

This task builds no comparison logic. Its entire deliverable is the vocabulary plus the test that makes gap 5 structurally impossible — a reviewer should be able to accept or reject the registry's shape without judging any containment rule.

**Files:**
- Create: `services/pkg/permset/permset.go`
- Create: `services/pkg/permset/registry.go`
- Test: `services/pkg/permset/registry_test.go`

**Interfaces:**
- Consumes: `models.Delegation`, `models.ActionTier` from `stratium/pkg/models`.
- Produces: `permset.Set` (struct, fields `Tools []string`, `MaxTier models.ActionTier`, `EscalateAt *models.ActionTier`, `ClassificationCaps map[string]string`, `ResourceConstraints map[string]string`, `ExpiresAt time.Time`); package-private `dimensions map[string]string` and `notDimensions map[string]string`.

- [ ] **Step 1: Write the failing test**

Create `services/pkg/permset/registry_test.go`:

```go
package permset

import (
	"reflect"
	"testing"

	"stratium/pkg/models"
)

// TestEveryDelegationFieldIsClassified is the whole of gap 5. A field added
// to models.Delegation must be classified as a permission dimension or
// explicitly excluded with a reason. A field in neither fails the build,
// which is what turns "someone remembered to add an if" into "the compiler
// asked a question".
//
// See docs/superpowers/specs/2026-09-15-permission-set-containment-design.md.
// WHEN THIS FAILS: you added a field to models.Delegation. Decide whether it
// bounds what its holder may do. If it does, add it to dimensions and add a
// containment rule AND a union rule for it. If it does not, add it to
// notDimensions with a falsifiable reason -- "enforced per hop at
// authz/delegation.go" is falsifiable; "not relevant" is not.
func TestEveryDelegationFieldIsClassified(t *testing.T) {
	dt := reflect.TypeOf(models.Delegation{})
	for i := range dt.NumField() {
		name := dt.Field(i).Name
		_, isDimension := dimensions[name]
		reason, isExcluded := notDimensions[name]

		switch {
		case isDimension && isExcluded:
			t.Errorf("field %s is both a dimension and excluded; pick one", name)
		case !isDimension && !isExcluded:
			t.Errorf("field %s is classified neither as a permission dimension "+
				"(dimensions, registry.go) nor as excluded (notDimensions). "+
				"Read this test's doc comment before adding it to either.", name)
		case isExcluded && reason == "":
			t.Errorf("field %s is excluded with an empty reason; the reason is "+
				"the part that makes the exclusion reviewable", name)
		}
	}
}

// TestDimensionsAreDelegationFields is the mirror: a registry entry naming a
// field that no longer exists is a stale rule, and a stale rule reads as
// coverage it no longer provides.
func TestDimensionsAreDelegationFields(t *testing.T) {
	dt := reflect.TypeOf(models.Delegation{})
	for _, registry := range []map[string]string{dimensions, notDimensions} {
		for name := range registry {
			if _, ok := dt.FieldByName(name); !ok {
				t.Errorf("registry names %q, which models.Delegation does not have", name)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services && go test ./pkg/permset/ -run TestEveryDelegationFieldIsClassified -v`
Expected: FAIL — the package does not exist (`no Go files in .../pkg/permset`).

- [ ] **Step 3: Write the minimal implementation**

Create `services/pkg/permset/permset.go`:

```go
// Package permset answers one question: is this set of permissions contained
// in that one?
//
// It exists because Stratium had four separate needs for that answer --
// attenuating a child delegation, reviewing a config change, bounding a
// group of sibling agents, and guarding a trust table -- and answered only
// the first, by hand, in a function that fails open on any dimension nobody
// remembered to add (registry.go's own test).
//
// Two operations, with deliberately different precision contracts:
//
//	Contains  EXACT.  It blocks a write; it must be right in both directions.
//	Union     May over-approximate UPWARD. It only ever feeds an advisory
//	          report, where widening makes the report noisier, never blinder.
//
// That asymmetry is load-bearing, not a convenience -- see union.go's
// resource-constraint rule, which is sound only under it. A new BLOCKING
// caller of Union is a design change, not a refactor.
package permset

import (
	"time"

	"stratium/pkg/models"
)

// Set is a permission grant reduced to the dimensions that bound what its
// holder may do. It is the common denominator of four shapes that are
// unrelated types today: a delegation's grant, an agent's registered grant,
// a principal's ceiling, and a computed union.
//
// Agent trust tier is deliberately NOT here. It belongs to the agent leg,
// and folding it in would conflate two conjuncts the architecture keeps
// separate (allow = principal AND agent AND delegation).
type Set struct {
	// Tools is the approved tool list. EMPTY MEANS UNRESTRICTED, matching
	// models.Delegation.HasTool and models.Agent.HasTool. That convention is
	// why an empty child list under a restricted parent is a widening rather
	// than an inheritance.
	Tools []string

	MaxTier models.ActionTier

	// EscalateAt is nil when this grant never escalates. Lower is NARROWER:
	// a lower threshold escalates sooner.
	EscalateAt *models.ActionTier

	ClassificationCaps  map[string]string // hierarchy -> level
	ResourceConstraints map[string]string // models.ResourceIDPrefixKey, today

	ExpiresAt time.Time
}

// FromDelegation reduces a delegation to its permission set. Every field it
// reads is named in dimensions (registry.go), and the test there is what
// keeps those two lists honest with each other.
func FromDelegation(d *models.Delegation) Set {
	return Set{
		Tools:               d.ApprovedTools,
		MaxTier:             d.MaxActionTier,
		EscalateAt:          d.EscalateAt,
		ClassificationCaps:  d.ClassificationCaps,
		ResourceConstraints: d.ResourceConstraints,
		ExpiresAt:           d.ExpiresAt,
	}
}
```

Create `services/pkg/permset/registry.go`:

```go
package permset

// dimensions names every models.Delegation field that bounds what its holder
// may do, mapped to the wire name its reason strings use. Every entry here
// must have a rule in contains.go AND a rule in union.go.
var dimensions = map[string]string{
	"ApprovedTools":       "approved_tools",
	"MaxActionTier":       "max_action_tier",
	"EscalateAt":          "escalate_at",
	"ClassificationCaps":  "classification_caps",
	"ResourceConstraints": "resource_constraints",
	"ExpiresAt":           "expires_at",
}

// notDimensions names every models.Delegation field that is deliberately not
// a permission dimension, with the reason. The reason is the load-bearing
// half: a bare list degrades into a place to silence registry_test.go, and
// "enforced per hop at authz/delegation.go" is falsifiable in review in a
// way that "not relevant" is not.
var notDimensions = map[string]string{
	"ID":        "identity",
	"TenantID":  "identity; the tenant boundary is RLS, not a comparison",
	"UserID":    "identity of the granting principal",
	"Purpose":   "human-readable; carries no authority",
	"CreatedAt": "metadata",

	// Not "identity": a child delegating to a DIFFERENT agent is the entire
	// point of a chain. AgentLeg (internal/authz/agent.go) bounds the acting
	// agent independently, on every decision.
	"AgentID": "acting agent; bounded by AgentLeg, not by containment",

	// Authorization-bearing, but enforced per hop at decision time.
	// DelegationLeg walks every hop and checks each of these independently,
	// so a containment rule here would be a second, divergent implementation
	// of a check that already holds -- which is worse than none, because when
	// two implementations disagree the wrong one can silently win.
	"Revoked":       "enforced per hop: internal/authz/delegation.go",
	"RevokedAt":     "enforced per hop: internal/authz/delegation.go",
	"Depth":         "bounded per request by maxDepth: internal/authz/delegation.go",
	"ChainAgentIDs": "enforced per hop: internal/authz/delegation.go",

	"ParentDelegationID": "chain structure, not a grant",
	"RootDelegationID":   "chain structure, not a grant",
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services && go test -race ./pkg/permset/ -v`
Expected: PASS, both tests.

- [ ] **Step 5: Prove the guard actually fires**

A guard test that has never been seen to fail is not known to work. Temporarily add a field to `models.Delegation`:

```go
// TEMPORARY -- delete after observing the failure.
ScratchField string `json:"-"`
```

Run: `cd services && go test ./pkg/permset/ -run TestEveryDelegationFieldIsClassified`
Expected: FAIL with `field ScratchField is classified neither as a permission dimension ...`

Then **delete the temporary field** and re-run:
Run: `cd services && go test -race ./pkg/permset/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd services
git add pkg/permset/permset.go pkg/permset/registry.go pkg/permset/registry_test.go
git commit -m "feat: add permset.Set and a dimension registry that fails closed

A field added to models.Delegation must now be classified as a permission
dimension or explicitly excluded with a reason; a field in neither fails the
build. Closes the fail-open half of gap 5 before any comparison logic exists
to depend on it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `Contains`, frozen against `ScopeNarrows`'s current behaviour

`ScopeNarrows` is the single check standing between a child delegation and its parent's ceiling. A subtle difference in a reimplementation is a silent widening at the most load-bearing check in the system. So this task writes the expected reason strings down as literals **captured from the existing implementation** before writing any new logic, and those literals become the permanent regression suite.

**Files:**
- Create: `services/pkg/permset/contains.go`
- Test: `services/pkg/permset/contains_test.go`

**Interfaces:**
- Consumes: `permset.Set`, `permset.FromDelegation` (Task 1); `classification.Index` from `stratium/pkg/classification`; `models.ResourceIDPrefixKey`.
- Produces: `func Contains(outer, inner Set) string` — empty string means contained; otherwise a reason naming the first violated dimension.

- [ ] **Step 1: Capture the current reason strings**

Do not transcribe these from the source by eye. Generate them, so the literals in the test are what the code actually produces today.

Create a throwaway file `services/pkg/models/zz_capture_test.go`:

```go
package models

import (
	"fmt"
	"testing"
	"time"
)

func TestZZCapture(t *testing.T) {
	base := func() *Delegation {
		esc := ActionTierExternalComms
		return &Delegation{
			ApprovedTools:       []string{"Read", "Write"},
			MaxActionTier:       ActionTierExternalComms,
			EscalateAt:          &esc,
			ClassificationCaps:  map[string]string{"nato": "SECRET"},
			ResourceConstraints: map[string]string{ResourceIDPrefixKey: "/workspace/"},
			ExpiresAt:           time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		}
	}
	mut := map[string]func(p, c *Delegation){
		"valid_identical":       func(p, c *Delegation) {},
		"tier_wider":            func(p, c *Delegation) { c.MaxActionTier = ActionTierDestructive },
		"escalate_introduced":   func(p, c *Delegation) { p.EscalateAt = nil },
		"escalate_dropped":      func(p, c *Delegation) { c.EscalateAt = nil },
		"escalate_raised":       func(p, c *Delegation) { e := ActionTierDestructive; c.EscalateAt = &e; c.MaxActionTier = ActionTierDestructive; p.MaxActionTier = ActionTierDestructive },
		"escalate_lowered":      func(p, c *Delegation) { e := ActionTierReadOnly; c.EscalateAt = &e },
		"tools_unrestricted":    func(p, c *Delegation) { c.ApprovedTools = nil },
		"tools_extra":           func(p, c *Delegation) { c.ApprovedTools = []string{"Read", "Bash"} },
		"caps_omitted":          func(p, c *Delegation) { c.ClassificationCaps = map[string]string{} },
		"caps_child_unknown":    func(p, c *Delegation) { c.ClassificationCaps = map[string]string{"nato": "BOGUS"} },
		"caps_parent_unknown":   func(p, c *Delegation) { p.ClassificationCaps = map[string]string{"nato": "BOGUS"} },
		"caps_widened":          func(p, c *Delegation) { p.ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"} },
		"caps_introduced":       func(p, c *Delegation) { c.ClassificationCaps["acme"] = "SECRET" },
		"rc_dropped":            func(p, c *Delegation) { c.ResourceConstraints = map[string]string{} },
		"rc_sideways":           func(p, c *Delegation) { c.ResourceConstraints[ResourceIDPrefixKey] = "/workspace-evil/" },
		"rc_deeper":             func(p, c *Delegation) { c.ResourceConstraints[ResourceIDPrefixKey] = "/workspace/sub/" },
		"rc_other_key_differs":  func(p, c *Delegation) { p.ResourceConstraints["env"] = "prod"; c.ResourceConstraints["env"] = "dev" },
		"rc_introduced":         func(p, c *Delegation) { c.ResourceConstraints["env"] = "dev" },
		"expiry_longer":         func(p, c *Delegation) { c.ExpiresAt = p.ExpiresAt.Add(time.Hour) },
	}
	for name, f := range mut {
		p, c := base(), base()
		f(p, c)
		fmt.Printf("%q: %q,\n", name, ScopeNarrows(p, c))
	}
}
```

Run: `cd services && go test ./pkg/models/ -run TestZZCapture -v 2>&1 | grep '": "'`

Copy the printed lines. Then **delete `services/pkg/models/zz_capture_test.go`** — it is scaffolding and must not be committed.

- [ ] **Step 2: Write the failing test**

Create `services/pkg/permset/contains_test.go`. Paste the captured literals into `want`, replacing the placeholder values below with the exact strings Step 1 printed:

```go
package permset

import (
	"testing"
	"time"

	"stratium/pkg/models"
)

func baseSet() Set {
	esc := models.ActionTierExternalComms
	return Set{
		Tools:               []string{"Read", "Write"},
		MaxTier:             models.ActionTierExternalComms,
		EscalateAt:          &esc,
		ClassificationCaps:  map[string]string{"nato": "SECRET"},
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
		ExpiresAt:           time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
	}
}

// TestContains_FrozenReasons pins Contains to the reason strings
// models.ScopeNarrows produced on 2026-09-15, captured mechanically rather
// than transcribed. These strings reach an operator through
// store.CreateDelegation's wrapped error, so they are API.
//
// WHEN THIS FAILS: you changed a containment rule or a reason string. Both
// are user-visible. Neither is a refactor.
func TestContains_FrozenReasons(t *testing.T) {
	cases := []struct {
		name string
		mut  func(outer, inner *Set)
		want string // <- paste each captured value here
	}{
		{"valid_identical", func(o, i *Set) {}, ""},
		{"tier_wider", func(o, i *Set) { i.MaxTier = models.ActionTierDestructive },
			"child max_action_tier DESTRUCTIVE exceeds parent EXTERNAL_COMMS"},
		{"escalate_introduced", func(o, i *Set) { o.EscalateAt = nil },
			"child introduces escalate_at EXTERNAL_COMMS which parent leaves unset"},
		{"escalate_dropped", func(o, i *Set) { i.EscalateAt = nil },
			"child drops parent escalate_at EXTERNAL_COMMS"},
		{"escalate_lowered", func(o, i *Set) { e := models.ActionTierReadOnly; i.EscalateAt = &e }, ""},
		{"tools_unrestricted", func(o, i *Set) { i.Tools = nil },
			"child has no tool restriction while parent restricts tools"},
		{"tools_extra", func(o, i *Set) { i.Tools = []string{"Read", "Bash"} },
			"child tool Bash not in parent approved_tools"},
		{"caps_omitted", func(o, i *Set) { i.ClassificationCaps = map[string]string{} },
			"child does not cap hierarchy nato which parent caps at SECRET"},
		{"caps_introduced", func(o, i *Set) { i.ClassificationCaps["acme"] = "SECRET" },
			"child caps hierarchy acme which parent does not cap"},
		{"rc_dropped", func(o, i *Set) { i.ResourceConstraints = map[string]string{} },
			"child drops parent resource constraint id_prefix=/workspace/"},
		{"rc_sideways", func(o, i *Set) { i.ResourceConstraints[models.ResourceIDPrefixKey] = "/workspace-evil/" },
			"child resource constraint id_prefix=/workspace-evil/ is not within parent id_prefix=/workspace/"},
		{"rc_deeper", func(o, i *Set) { i.ResourceConstraints[models.ResourceIDPrefixKey] = "/workspace/sub/" }, ""},
		{"rc_introduced", func(o, i *Set) { i.ResourceConstraints["env"] = "dev" },
			"child constrains resource key env which parent does not constrain"},
		{"expiry_longer", func(o, i *Set) { i.ExpiresAt = i.ExpiresAt.Add(time.Hour) },
			"child expires_at exceeds parent"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outer, inner := baseSet(), baseSet()
			tc.mut(&outer, &inner)
			if got := Contains(outer, inner); got != tc.want {
				t.Errorf("Contains() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestContains_EscalateAtPresenceIsAsymmetric is called out separately
// because it is the rule most likely to be "fixed" by a future reader.
// Introducing escalate_at genuinely NARROWS and is rejected anyway, so that
// a child's shape is derivable from its parent's fixed set of dimensions
// rather than from which hop first introduced one (spec section 4.3.1).
func TestContains_EscalateAtPresenceIsAsymmetric(t *testing.T) {
	read := models.ActionTierReadOnly

	introduced, in := baseSet(), baseSet()
	introduced.EscalateAt = nil
	if Contains(introduced, in) == "" {
		t.Error("a child introducing escalate_at must be rejected")
	}

	o, dropped := baseSet(), baseSet()
	dropped.EscalateAt = nil
	if Contains(o, dropped) == "" {
		t.Error("a child dropping escalate_at must be rejected")
	}

	o2, lowered := baseSet(), baseSet()
	lowered.EscalateAt = &read
	if reason := Contains(o2, lowered); reason != "" {
		t.Errorf("a child lowering escalate_at narrows and must be accepted: %s", reason)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd services && go test ./pkg/permset/ -run TestContains -v`
Expected: FAIL to compile — `undefined: Contains`.

- [ ] **Step 4: Write the implementation**

Create `services/pkg/permset/contains.go`. This is a move of `models.ScopeNarrows`'s body onto `Set`, not a rewrite — copy the logic and every reason string exactly, including the comments explaining why the rules are stricter than ordering requires:

```go
package permset

import (
	"strings"

	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// Contains reports whether inner is a valid subset of outer, returning the
// empty string when it is and a reason naming the first violated dimension
// when it is not. The empty-means-valid convention is models.ScopeNarrows's,
// whose behaviour this reproduces exactly -- including the two rules that are
// NOT lattice containment:
//
//   - EscalateAt presence must MATCH. A child may neither introduce the field
//     where the parent leaves it unset nor drop it where the parent sets it.
//     Dropping is a widening. Introducing narrows, and is rejected anyway.
//   - ResourceConstraints may not be INTRODUCED either, by the same rule and
//     for the same reason.
//
// Both are stricter than pointwise ordering requires, both are deliberate
// (spec section 4.3.1), and a clean lattice would quietly permit what they
// forbid. Do not "fix" either without reading contains_test.go's
// EscalateAtPresenceIsAsymmetric case first.
func Contains(outer, inner Set) string {
	if inner.MaxTier > outer.MaxTier {
		return "child max_action_tier " + inner.MaxTier.String() +
			" exceeds parent " + outer.MaxTier.String()
	}

	// EscalateAt narrows in the opposite direction from a first guess: a
	// LOWER threshold escalates sooner, so lowering it narrows and raising it
	// widens. Every branch guards both pointers explicitly rather than
	// relying on the preceding cases having excluded one being nil, so this
	// stays safe if the cases are ever reordered.
	switch {
	case outer.EscalateAt == nil && inner.EscalateAt != nil:
		return "child introduces escalate_at " + inner.EscalateAt.String() +
			" which parent leaves unset"
	case outer.EscalateAt != nil && inner.EscalateAt == nil:
		return "child drops parent escalate_at " + outer.EscalateAt.String()
	case outer.EscalateAt != nil && inner.EscalateAt != nil && *inner.EscalateAt > *outer.EscalateAt:
		return "child escalate_at " + inner.EscalateAt.String() +
			" exceeds parent " + outer.EscalateAt.String()
	}

	// An empty outer list is unrestricted; an empty inner list under a
	// restricted outer is a widening, not an inheritance.
	if len(outer.Tools) > 0 {
		if len(inner.Tools) == 0 {
			return "child has no tool restriction while parent restricts tools"
		}
		allowed := make(map[string]bool, len(outer.Tools))
		for _, t := range outer.Tools {
			allowed[t] = true
		}
		for _, t := range inner.Tools {
			if !allowed[t] {
				return "child tool " + t + " not in parent approved_tools"
			}
		}
	}

	// Iterate the OUTER's caps. A hierarchy outer restricts and inner omits
	// is a widening: CheckCap treats absent caps as "no restriction", so
	// inner would hold unrestricted access to that hierarchy.
	for hierarchy, outerCap := range outer.ClassificationCaps {
		innerCap, ok := inner.ClassificationCaps[hierarchy]
		if !ok {
			return "child does not cap hierarchy " + hierarchy +
				" which parent caps at " + outerCap
		}
		innerIdx := classification.Index(hierarchy, innerCap)
		if innerIdx < 0 {
			return "child cap " + innerCap + " is not a known level in hierarchy " + hierarchy
		}
		outerIdx := classification.Index(hierarchy, outerCap)
		if outerIdx < 0 {
			return "parent cap " + outerCap + " is not a known level in hierarchy " + hierarchy
		}
		if innerIdx > outerIdx {
			return "child cap " + innerCap + " exceeds parent cap " + outerCap +
				" in hierarchy " + hierarchy
		}
	}
	for hierarchy := range inner.ClassificationCaps {
		if _, ok := outer.ClassificationCaps[hierarchy]; !ok {
			return "child caps hierarchy " + hierarchy + " which parent does not cap"
		}
	}

	// Values are opaque caller-defined strings, so the comparison is exact --
	// it does not reason about wildcards or ranges, because every such
	// interpretation is a place a widening could hide. ResourceIDPrefixKey is
	// the one exception: it has prefix semantics, so it narrows by
	// containment. HasPrefix is sufficient ONLY because a stored prefix
	// always ends in "/" (validated at write time) -- without that, parent
	// "/workspace" would accept child "/workspace-evil/" as a narrowing.
	for key, outerVal := range outer.ResourceConstraints {
		innerVal, ok := inner.ResourceConstraints[key]
		if !ok {
			return "child drops parent resource constraint " + key + "=" + outerVal
		}
		if key == models.ResourceIDPrefixKey {
			if !strings.HasPrefix(innerVal, outerVal) {
				return "child resource constraint " + key + "=" + innerVal +
					" is not within parent " + key + "=" + outerVal
			}
			continue
		}
		if innerVal != outerVal {
			return "child resource constraint " + key + "=" + innerVal +
				" differs from parent " + key + "=" + outerVal
		}
	}
	for key := range inner.ResourceConstraints {
		if _, ok := outer.ResourceConstraints[key]; !ok {
			return "child constrains resource key " + key + " which parent does not constrain"
		}
	}

	if inner.ExpiresAt.After(outer.ExpiresAt) {
		return "child expires_at exceeds parent"
	}

	return ""
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd services && go test -race ./pkg/permset/ -v`
Expected: PASS, all cases. Any mismatch between a captured literal and `Contains`'s output is a real behaviour difference — fix `Contains`, never the literal.

- [ ] **Step 6: Confirm the capture scaffolding is gone**

Run: `cd services && git status --short pkg/models/`
Expected: no `zz_capture_test.go`. If it is there, delete it.

- [ ] **Step 7: Commit**

```bash
cd services
git add pkg/permset/contains.go pkg/permset/contains_test.go
git commit -m "feat: add permset.Contains, frozen against ScopeNarrows

Reason strings captured mechanically from the current implementation rather
than transcribed, and pinned as literals: they reach operators through
CreateDelegation's wrapped error, so they are API. The escalate_at presence
asymmetry gets its own named test because it is the rule most likely to be
mistaken for a bug and 'fixed'.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Move `ScopeNarrows` into `permset` and delete the original

`pkg/models` cannot import `pkg/permset` — `permset` imports `models` for `ActionTier`, and Go rejects the cycle. So the function moves rather than adapting in place. Every call site changes only its package qualifier.

**Files:**
- Modify: `services/pkg/permset/contains.go` (append the `ScopeNarrows` wrapper)
- Modify: `services/pkg/models/delegation.go` (delete `ScopeNarrows`, lines 91–230, and any import it alone used)
- Move: `services/pkg/models/delegation_test.go` → `services/pkg/permset/scopenarrows_test.go`
- Create: `services/pkg/models/delegation_test.go` (the two tests that are not about `ScopeNarrows`)
- Modify: `services/internal/store/delegation.go` (line 120 call, line 67 doc comment)
- Modify: `services/internal/authz/conformance_test.go` (line 254)
- Modify: `services/internal/authz/journeys_test.go` (lines 431, 441, 450, 462, 475)

**Interfaces:**
- Consumes: `permset.Contains`, `permset.FromDelegation` (Tasks 1–2).
- Produces: `func ScopeNarrows(parent, child *models.Delegation) string` in package `permset`. `models.ScopeNarrows` no longer exists.

- [ ] **Step 1: Add the wrapper**

Append to `services/pkg/permset/contains.go`:

```go
// ScopeNarrows reports whether a child delegation is a valid subset of its
// parent, returning the empty string when it is and the reason when it is
// not. It is Contains over the two delegations' permission sets, and exists
// under this name because store.CreateDelegation wraps its return into an
// operator-facing error.
//
// It lives here rather than in pkg/models because permset imports models for
// ActionTier, so models cannot import permset back. Giving permset bare int
// tiers was the alternative and was rejected: the reason strings above name
// tiers by symbol (EXTERNAL_COMMS, not 3), and preserving them verbatim is a
// requirement of the design this package implements.
func ScopeNarrows(parent, child *models.Delegation) string {
	return Contains(FromDelegation(parent), FromDelegation(child))
}
```

- [ ] **Step 2: Move the test file, contents unmodified**

```bash
cd services
git mv pkg/models/delegation_test.go pkg/permset/scopenarrows_test.go
```

Then in `pkg/permset/scopenarrows_test.go` make **only** these mechanical changes:
1. `package models` → `package permset`
2. Add `"stratium/pkg/models"` to the import block.
3. In the two fixtures at the top (`parentDelegation()`, `validChild()`) and in any other constructor, qualify the model types: `*Delegation` → `*models.Delegation`, `ActionTier…` → `models.ActionTier…`, `ResourceIDPrefixKey` → `models.ResourceIDPrefixKey`.
4. Cut `TestDelegation_IsActive` and `TestDelegation_HasTool` out — they move back in Step 3.

**No assertion, no expected string, and no fixture value changes.** This file is the acceptance criterion for the move; editing an assertion to make it pass defeats the entire task.

- [ ] **Step 3: Restore the two non-ScopeNarrows tests**

Create `services/pkg/models/delegation_test.go` containing exactly the `TestDelegation_IsActive` and `TestDelegation_HasTool` functions cut in Step 2, with `package models` and whatever imports they need.

- [ ] **Step 4: Delete the original and fix the call sites**

In `services/pkg/models/delegation.go`, delete `ScopeNarrows` and its doc comment (the block beginning at the `// ScopeNarrows reports whether...` comment above line 107 and ending at its closing brace). Leave `ResourceIDPrefixKey` and every other declaration alone.

Update the five call sites:

```bash
cd services
# production
sed -i '' 's/models\.ScopeNarrows(/permset.ScopeNarrows(/g' internal/store/delegation.go
# tests
sed -i '' 's/models\.ScopeNarrows(/permset.ScopeNarrows(/g' internal/authz/conformance_test.go internal/authz/journeys_test.go
```

Add `"stratium/pkg/permset"` to the import block of each of those three files. Update the prose reference at `internal/store/delegation.go:67` from `models.ScopeNarrows(parent, d)` to `permset.ScopeNarrows(parent, d)`.

- [ ] **Step 5: Let the compiler find the unused imports**

Run: `cd services && go build ./...`
Expected: errors naming any import in `pkg/models/delegation.go` that only `ScopeNarrows` used (likely `strings` and `stratium/pkg/classification`). Remove exactly those, then re-run until clean.

- [ ] **Step 6: Run the full suite**

Run: `cd services && go test -race ./pkg/... ./internal/...`
Expected: PASS. Every moved `TestScopeNarrows_*` test passes unmodified, which is the whole point of this task.

Run: `cd services && grep -rn 'models\.ScopeNarrows' . --include='*.go'`
Expected: no output.

- [ ] **Step 7: Commit**

```bash
cd services
git add -A pkg/models pkg/permset internal/store/delegation.go internal/authz
git commit -m "refactor: move ScopeNarrows into permset, unchanged

pkg/models cannot import permset (permset needs models.ActionTier, and Go
rejects the cycle), so the function moves rather than adapting in place. Its
test suite moves with it, contents unmodified except the package line and
model-type qualifiers -- that suite is the acceptance criterion for the move.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `Union`

**Files:**
- Create: `services/pkg/permset/union.go`
- Test: `services/pkg/permset/union_test.go`

**Interfaces:**
- Consumes: `permset.Set` (Task 1).
- Produces: `func Union(sets ...Set) (Set, []string)` — the joined set, plus one reason string per dimension that had to be widened beyond an exact join.

- [ ] **Step 1: Write the failing test**

Create `services/pkg/permset/union_test.go`:

```go
package permset

import (
	"slices"
	"strings"
	"testing"
	"time"

	"stratium/pkg/models"
)

func TestUnion_TakesTheWeakestOfEachDimension(t *testing.T) {
	read, ext := models.ActionTierReadOnly, models.ActionTierExternalComms
	early := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	a := Set{
		Tools: []string{"Read"}, MaxTier: models.ActionTierReadOnly, EscalateAt: &read,
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"},
		ExpiresAt:          early,
	}
	b := Set{
		Tools: []string{"Bash"}, MaxTier: models.ActionTierDestructive, EscalateAt: &ext,
		ClassificationCaps: map[string]string{"nato": "SECRET"},
		ExpiresAt:          early.Add(time.Hour),
	}

	got, reasons := Union(a, b)

	if got.MaxTier != models.ActionTierDestructive {
		t.Errorf("MaxTier = %s, want DESTRUCTIVE", got.MaxTier)
	}
	if got.EscalateAt == nil || *got.EscalateAt != ext {
		t.Errorf("EscalateAt = %v, want EXTERNAL_COMMS (the weaker threshold)", got.EscalateAt)
	}
	want := []string{"Bash", "Read"}
	sorted := slices.Clone(got.Tools)
	slices.Sort(sorted)
	if !slices.Equal(sorted, want) {
		t.Errorf("Tools = %v, want %v", sorted, want)
	}
	if got.ClassificationCaps["nato"] != "SECRET" {
		t.Errorf("cap = %s, want SECRET", got.ClassificationCaps["nato"])
	}
	if !got.ExpiresAt.Equal(early.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v, want the later", got.ExpiresAt)
	}
	if len(reasons) != 0 {
		t.Errorf("no dimension needed widening here, got reasons %v", reasons)
	}
}

// An unrestricted tool list and a nil EscalateAt are each the weakest
// possible value of their dimension, so each absorbs everything else.
func TestUnion_WeakestValuesAbsorb(t *testing.T) {
	read := models.ActionTierReadOnly
	restricted := Set{Tools: []string{"Read"}, EscalateAt: &read}
	unrestricted := Set{Tools: nil, EscalateAt: nil}

	got, _ := Union(restricted, unrestricted)
	if len(got.Tools) != 0 {
		t.Errorf("Tools = %v, want empty (unrestricted absorbs)", got.Tools)
	}
	if got.EscalateAt != nil {
		t.Errorf("EscalateAt = %v, want nil (never-escalates absorbs)", got.EscalateAt)
	}
}

// A hierarchy only one member caps is UNCAPPED in the union: the other
// member's holder has unrestricted access to it.
func TestUnion_HierarchyCappedByOnlyOneMemberBecomesUncapped(t *testing.T) {
	a := Set{ClassificationCaps: map[string]string{"nato": "SECRET"}}
	b := Set{ClassificationCaps: map[string]string{}}

	got, reasons := Union(a, b)
	if _, capped := got.ClassificationCaps["nato"]; capped {
		t.Error("a hierarchy only one member caps must be uncapped in the union")
	}
	if len(reasons) == 0 {
		t.Error("dropping a cap is a widening and must be named in reasons")
	}
}

// The one honest imprecision. The union of two differing prefixes is not a
// prefix, and Set holds one string -- so it widens to unconstrained and says
// so. Sound ONLY because Union is advisory (see permset.go's package doc).
func TestUnion_DifferingPrefixesWidenToUnconstrainedAndSayWhich(t *testing.T) {
	a := Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"}}
	b := Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/tmp/"}}

	got, reasons := Union(a, b)
	if _, constrained := got.ResourceConstraints[models.ResourceIDPrefixKey]; constrained {
		t.Error("differing prefixes must widen to unconstrained")
	}
	var named bool
	for _, r := range reasons {
		if strings.Contains(r, "/workspace/") && strings.Contains(r, "/tmp/") {
			named = true
		}
	}
	if !named {
		t.Errorf("the reason must name both prefixes that disagreed; got %v", reasons)
	}
}

// Identical constraint values survive the union exactly.
func TestUnion_AgreeingConstraintsSurvive(t *testing.T) {
	a := Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"}}
	got, reasons := Union(a, a)
	if got.ResourceConstraints[models.ResourceIDPrefixKey] != "/workspace/" {
		t.Errorf("agreeing constraints must survive, got %v", got.ResourceConstraints)
	}
	if len(reasons) != 0 {
		t.Errorf("nothing widened, got %v", reasons)
	}
}

func TestUnion_NoSetsIsTheEmptyGrant(t *testing.T) {
	got, reasons := Union()
	if len(got.Tools) != 0 || got.MaxTier != models.ActionTierReasoning || len(reasons) != 0 {
		t.Errorf("Union() of nothing must be the zero Set, got %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services && go test ./pkg/permset/ -run TestUnion -v`
Expected: FAIL to compile — `undefined: Union`.

- [ ] **Step 3: Write the implementation**

Create `services/pkg/permset/union.go`:

```go
package permset

import (
	"maps"
	"slices"

	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// Union returns the weakest Set containing every input: the permissions a
// holder of all of them would jointly have. The second return is one reason
// per dimension that had to be widened BEYOND an exact join, so an advisory
// report can say where it lost precision instead of quietly losing it.
//
// Union may over-approximate upward; Contains may not. See permset.go's
// package doc -- the resource-constraint rule below is sound only under that
// asymmetry, and a blocking caller of Union is a design change.
func Union(sets ...Set) (Set, []string) {
	if len(sets) == 0 {
		return Set{}, nil
	}

	out := Set{
		ClassificationCaps:  map[string]string{},
		ResourceConstraints: map[string]string{},
	}
	var reasons []string

	// Tools: an empty list is unrestricted, which is the weakest possible
	// value, so it absorbs.
	unrestricted := false
	seen := map[string]bool{}
	for _, s := range sets {
		if len(s.Tools) == 0 {
			unrestricted = true
		}
		for _, t := range s.Tools {
			seen[t] = true
		}
	}
	if !unrestricted {
		out.Tools = slices.Sorted(maps.Keys(seen))
	}

	// MaxTier: the highest ceiling. ExpiresAt: the latest.
	for _, s := range sets {
		if s.MaxTier > out.MaxTier {
			out.MaxTier = s.MaxTier
		}
		if s.ExpiresAt.After(out.ExpiresAt) {
			out.ExpiresAt = s.ExpiresAt
		}
	}

	// EscalateAt: nil never escalates, which is weakest, so it absorbs;
	// otherwise the highest threshold escalates latest.
	neverEscalates := false
	var highest *models.ActionTier
	for _, s := range sets {
		if s.EscalateAt == nil {
			neverEscalates = true
			continue
		}
		if highest == nil || *s.EscalateAt > *highest {
			v := *s.EscalateAt
			highest = &v
		}
	}
	if !neverEscalates {
		out.EscalateAt = highest
	}

	// Caps: a hierarchy any member leaves uncapped is UNCAPPED in the union,
	// because that member's holder reaches it without restriction. Otherwise
	// the highest level wins.
	capped := map[string]bool{}
	for _, s := range sets {
		for h := range s.ClassificationCaps {
			capped[h] = true
		}
	}
	for h := range capped {
		best, all := "", true
		for _, s := range sets {
			lvl, ok := s.ClassificationCaps[h]
			if !ok {
				all = false
				break
			}
			if best == "" || classificationIndexAtLeast(h, lvl, best) {
				best = lvl
			}
		}
		if !all {
			reasons = append(reasons,
				"hierarchy "+h+" is capped by some members and not others, so the union is uncapped for it")
			continue
		}
		out.ClassificationCaps[h] = best
	}

	// Resource constraints. Values agree -> the value survives. Values
	// disagree -> unconstrained, named. A key only some members carry ->
	// unconstrained, named.
	//
	// ponytail: the union of "/workspace/" and "/tmp/" is not a prefix and
	// Set holds one string, so it widens to unconstrained. Upgrade path is a
	// prefix-set field on Set, worth taking only if this proves noisy in a
	// real report.
	keys := map[string]bool{}
	for _, s := range sets {
		for k := range s.ResourceConstraints {
			keys[k] = true
		}
	}
	for k := range keys {
		var val string
		agree, present := true, true
		for _, s := range sets {
			v, ok := s.ResourceConstraints[k]
			if !ok {
				present = false
				break
			}
			if val == "" {
				val = v
			} else if v != val {
				agree = false
				reasons = append(reasons,
					"resource constraint "+k+" differs across members ("+val+" vs "+v+
						"), so the union is unconstrained for it")
				break
			}
		}
		if !present {
			reasons = append(reasons,
				"resource constraint "+k+" is set by some members and not others, so the union is unconstrained for it")
			continue
		}
		if agree {
			out.ResourceConstraints[k] = val
		}
	}

	return out, reasons
}
```

Add the two small helpers this uses at the bottom of `union.go`:

```go
// classificationIndexAtLeast reports whether lvl ranks at or above best in
// hierarchy h. An unrankable level sorts as weakest here rather than
// denying: Union is advisory and must not fail, and a level neither side can
// rank cannot contribute a ceiling either way.
func classificationIndexAtLeast(h, lvl, best string) bool {
	return classification.Index(h, lvl) > classification.Index(h, best)
}

```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services && go test -race ./pkg/permset/ -v`
Expected: PASS, all `TestUnion_*` cases plus every earlier test.

- [ ] **Step 5: Commit**

```bash
cd services
git add pkg/permset/union.go pkg/permset/union_test.go
git commit -m "feat: add permset.Union for advisory group analysis

Takes the weakest value of each dimension. Where a dimension cannot represent
a join exactly -- two differing id_prefix values -- it widens to unconstrained
and names what disagreed, which is sound only because Union is advisory. A
blocking caller would need the prefix-set upgrade first.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `GET /v1/principals/{id}/effective`

Makes gap 6 visible. Today the union of a principal's live root delegations is not merely unchecked — it cannot be seen.

**Files:**
- Create: `services/cmd/stratium-pap/principals.go`
- Modify: `services/cmd/stratium-pap/server.go` (add one row to `routeTable`, near the `/v1/delegations` rows around line 257)
- Test: `services/cmd/stratium-pap/principals_test.go`

**Interfaces:**
- Consumes: `permset.Union`, `permset.FromDelegation` (Tasks 1, 4); `store.ListDelegations(ctx) ([]models.Delegation, error)`; `models.Delegation.IsRoot()`, `.IsActive(now)`.
- Produces: HTTP route `GET /v1/principals/{id}/effective` at `RoleViewer`, returning `effectiveResponse`.

- [ ] **Step 1: Build the UI once so the package compiles**

Run: `cd /path/to/stratium-data && make ui`
Expected: completes, `services/cmd/stratium-pap/dist/index.html` exists.

- [ ] **Step 2: Write the failing test**

Create `services/cmd/stratium-pap/principals_test.go`. Follow the existing handler-test style in this package for server construction:

```go
package main

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

// TestEffective_UnionsOnlyLiveRootDelegations pins the three filters that
// make the answer honest: revoked, expired, and non-root delegations do not
// contribute. A revoked delegation grants nothing, so counting it would
// overstate a principal's reach and train operators to ignore the report.
func TestEffective_UnionsOnlyLiveRootDelegations(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	child := uuidFor(t, "11111111-1111-1111-1111-111111111111")

	all := []models.Delegation{
		{UserID: "alice", MaxActionTier: models.ActionTierReadOnly,
			ApprovedTools: []string{"Read"}, ExpiresAt: now.Add(time.Hour)},
		{UserID: "alice", MaxActionTier: models.ActionTierExternalComms,
			ApprovedTools: []string{"Bash"}, ExpiresAt: now.Add(time.Hour)},
		{UserID: "alice", MaxActionTier: models.ActionTierDestructive,
			ApprovedTools: []string{"Delete"}, ExpiresAt: now.Add(time.Hour), Revoked: true},
		{UserID: "alice", MaxActionTier: models.ActionTierDestructive,
			ApprovedTools: []string{"Nuke"}, ExpiresAt: now.Add(-time.Hour)},
		{UserID: "alice", MaxActionTier: models.ActionTierDestructive,
			ApprovedTools: []string{"Sub"}, ExpiresAt: now.Add(time.Hour),
			ParentDelegationID: &child},
		{UserID: "bob", MaxActionTier: models.ActionTierDestructive,
			ApprovedTools: []string{"Other"}, ExpiresAt: now.Add(time.Hour)},
	}

	got := effectiveFor(all, "alice", now)

	if got.Union.MaxTier != models.ActionTierExternalComms {
		t.Errorf("MaxTier = %s, want EXTERNAL_COMMS (revoked, expired, child and "+
			"other-principal rows must not contribute)", got.Union.MaxTier)
	}
	if got.DelegationsCounted != 2 {
		t.Errorf("DelegationsCounted = %d, want 2", got.DelegationsCounted)
	}
}

// A principal with no live delegations must return an empty grant, not an
// error and not an unrestricted one -- an empty tool list means UNRESTRICTED
// everywhere else in this system, so the count is what disambiguates.
func TestEffective_NoLiveDelegationsReturnsEmptyGrantAndZeroCount(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	got := effectiveFor(nil, "nobody", now)
	if got.DelegationsCounted != 0 {
		t.Errorf("DelegationsCounted = %d, want 0", got.DelegationsCounted)
	}
	if got.Union.MaxTier != models.ActionTierReasoning {
		t.Errorf("MaxTier = %s, want REASONING", got.Union.MaxTier)
	}
}

func TestEffective_RouteIsRegisteredAtViewer(t *testing.T) {
	var found bool
	for _, rt := range routeTable {
		if rt.Pattern == "GET /v1/principals/{id}/effective" {
			found = true
			if rt.MinRole != RoleViewer {
				t.Errorf("MinRole = %v, want RoleViewer", rt.MinRole)
			}
		}
	}
	if !found {
		t.Error("GET /v1/principals/{id}/effective is not in routeTable")
	}
}

func uuidFor(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	return id
}
```

If `cmd/stratium-pap` already defines a `uuidFor` helper, use that one instead
of adding a second.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd services && go test ./cmd/stratium-pap/ -run TestEffective -v`
Expected: FAIL to compile — `undefined: effectiveFor`.

- [ ] **Step 4: Write the implementation**

Create `services/cmd/stratium-pap/principals.go`:

```go
// principals.go implements GET /v1/principals/{id}/effective: the union of
// every live root delegation a principal holds.
//
// It answers the horizontal question the delegation leg does not. That leg
// enforces child <= parent at every hop, exhaustively; nothing compares
// SIBLINGS. Two live root delegations -- one reaching /secret, one reaching
// EXTERNAL_COMMS -- are individually in bounds and jointly an exfiltration
// path, and until this route existed that union could not even be seen.
//
// It REPORTS and does not enforce. There is no principal ceiling to check
// the union against; adding one is a follow-up whose whole implementation is
// one permset.Contains call against the value this route already returns.
package main

import (
	"net/http"
	"time"

	"stratium/pkg/models"
	"stratium/pkg/permset"
)

type effectiveResponse struct {
	PrincipalID string      `json:"principal_id"`
	Union       permset.Set `json:"union"`

	// DelegationsCounted disambiguates the empty grant. An empty Tools list
	// means UNRESTRICTED everywhere else in this system, so a zero-value
	// Set and a genuinely unrestricted one are the same JSON; the count is
	// what tells them apart.
	DelegationsCounted int `json:"delegations_counted"`

	// Imprecision names every dimension Union had to widen beyond an exact
	// join. Returned rather than logged because a report that silently lost
	// precision is worse than no report.
	Imprecision []string `json:"imprecision"`
}

// effectiveFor is the pure core, separated from the handler so the filters
// are testable without a database.
func effectiveFor(all []models.Delegation, principalID string, now time.Time) effectiveResponse {
	var sets []permset.Set
	for i := range all {
		d := &all[i]
		if d.UserID != principalID || !d.IsRoot() || !d.IsActive(now) {
			continue
		}
		sets = append(sets, permset.FromDelegation(d))
	}
	union, imprecision := permset.Union(sets...)
	if imprecision == nil {
		imprecision = []string{}
	}
	return effectiveResponse{
		PrincipalID:        principalID,
		Union:              union,
		DelegationsCounted: len(sets),
		Imprecision:        imprecision,
	}
}

func getPrincipalEffective(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	// Not pathID: a principal id is the OIDC subject string, not a uuid.
	principalID := r.PathValue("id")
	if principalID == "" {
		http.Error(w, "principal id is required", http.StatusBadRequest)
		return
	}
	all, err := s.store.ListDelegations(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, effectiveFor(all, principalID, time.Now().UTC()))
}
```

In `services/cmd/stratium-pap/server.go`, add to `routeTable` immediately after the `/v1/delegations` rows:

```go
	{Pattern: "GET /v1/principals/{id}/effective", MinRole: RoleViewer, Handler: getPrincipalEffective},
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd services && go test -race ./cmd/stratium-pap/ -run TestEffective -v`
Expected: PASS, all three tests.

- [ ] **Step 6: Run the package's full suite**

Run: `cd services && go test -race ./cmd/stratium-pap/`
Expected: PASS. `server_test.go` inspects `routeTable` directly, so a malformed row fails here.

- [ ] **Step 7: Commit**

```bash
cd services
git add cmd/stratium-pap/principals.go cmd/stratium-pap/principals_test.go cmd/stratium-pap/server.go
git commit -m "feat: add GET /v1/principals/{id}/effective

The union of a principal's live root delegations. Answers the horizontal
question the delegation leg does not: siblings are individually in bounds and
jointly unbounded. Reports rather than enforces -- there is no ceiling to
check against yet, and adding one is one Contains call against this value.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `POST /v1/containment`

**Files:**
- Create: `services/cmd/stratium-pap/containment.go`
- Modify: `services/cmd/stratium-pap/server.go` (one `routeTable` row)
- Test: `services/cmd/stratium-pap/containment_test.go`

**Interfaces:**
- Consumes: `permset.Set`, `permset.Contains` (Tasks 1–2).
- Produces: HTTP route `POST /v1/containment` at `RoleViewer`, request `containmentRequest{Baseline, Candidate permset.Set}`, response `containmentResponse{Contained bool, Reason string}`.

- [ ] **Step 1: Write the failing test**

Create `services/cmd/stratium-pap/containment_test.go`:

```go
package main

import (
	"testing"
	"time"

	"stratium/pkg/models"
	"stratium/pkg/permset"
)

func TestContainment_ReportsContainedAndNot(t *testing.T) {
	at := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	baseline := permset.Set{
		Tools: []string{"Read", "Write"}, MaxTier: models.ActionTierExternalComms, ExpiresAt: at,
	}
	narrower := permset.Set{
		Tools: []string{"Read"}, MaxTier: models.ActionTierReadOnly, ExpiresAt: at,
	}
	wider := permset.Set{
		Tools: []string{"Read", "Bash"}, MaxTier: models.ActionTierExternalComms, ExpiresAt: at,
	}

	if got := containmentOf(baseline, narrower); !got.Contained || got.Reason != "" {
		t.Errorf("narrower candidate must be contained, got %+v", got)
	}
	got := containmentOf(baseline, wider)
	if got.Contained {
		t.Error("a candidate adding a tool must not be contained")
	}
	if got.Reason != "child tool Bash not in parent approved_tools" {
		t.Errorf("Reason = %q, want the tool reason verbatim", got.Reason)
	}
}

func TestContainment_RouteIsRegisteredAtViewer(t *testing.T) {
	var found bool
	for _, rt := range routeTable {
		if rt.Pattern == "POST /v1/containment" {
			found = true
			if rt.MinRole != RoleViewer {
				t.Errorf("MinRole = %v, want RoleViewer: this endpoint reads, it does not write", rt.MinRole)
			}
		}
	}
	if !found {
		t.Error("POST /v1/containment is not in routeTable")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services && go test ./cmd/stratium-pap/ -run TestContainment -v`
Expected: FAIL to compile — `undefined: containmentOf`.

- [ ] **Step 3: Write the implementation**

Create `services/cmd/stratium-pap/containment.go`:

```go
// containment.go implements POST /v1/containment: does this candidate
// permission set allow anything the baseline does not?
//
// It is the universal query this system did not have. Every other question
// the PAP can ask is a POINT query -- POST /v1/policies/test evaluates one
// sample input, policy.Probe asks about one tier and tool with no resource --
// and neither answers "what did this change widen?"
//
// POST, not GET, because the sets go in the body: they are structured values,
// not identifiers. It writes nothing, which is why it is RoleViewer.
package main

import (
	"net/http"

	"stratium/pkg/permset"
)

type containmentRequest struct {
	Baseline  permset.Set `json:"baseline"`
	Candidate permset.Set `json:"candidate"`
}

type containmentResponse struct {
	Contained bool `json:"contained"`

	// Reason is the counterexample in the only form this engine produces: the
	// first dimension on which the candidate exceeds the baseline, named the
	// same way an operator would see it in a refused delegation.
	Reason string `json:"reason"`
}

func containmentOf(baseline, candidate permset.Set) containmentResponse {
	reason := permset.Contains(baseline, candidate)
	return containmentResponse{Contained: reason == "", Reason: reason}
}

func checkContainment(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	var req containmentRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, containmentOf(req.Baseline, req.Candidate))
}
```

In `services/cmd/stratium-pap/server.go`, add to `routeTable` after the `/v1/policies/test` row:

```go
	{Pattern: "POST /v1/containment", MinRole: RoleViewer, Handler: checkContainment},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services && go test -race ./cmd/stratium-pap/ -run TestContainment -v`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
cd services
git add cmd/stratium-pap/containment.go cmd/stratium-pap/containment_test.go cmd/stratium-pap/server.go
git commit -m "feat: add POST /v1/containment

The universal query this system did not have. Every other PAP question is a
point query; this one answers 'does the candidate allow anything the baseline
forbids' and returns the first exceeding dimension as the counterexample.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Record a containment verdict on agent-grant writes

The three endpoints that change an agent's grant set the template copied onto every root delegation issued afterwards. Nothing today compares the new template to the old one. Per spec decision 3 the write still lands; the verdict is recorded.

**Files:**
- Modify: `services/internal/store/agent_constraints.go` (in `writeAgentConstraints`, around lines 148–192)
- Modify: `services/internal/store/agent_caps.go` (in `writeAgentCaps`, around lines 269–330)
- Create: `services/internal/store/containment_audit.go`
- Test: `services/internal/store/containment_audit_test.go`

**Interfaces:**
- Consumes: `permset.Set`, `permset.Contains` (Tasks 1–2); `audit.Entry`; the package-private `appendAuditTx`.
- Produces: `const eventTypeContainment = "containment"`; `func containmentReason(before, after permset.Set) string`.

- [ ] **Step 1: Write the failing test**

Create `services/internal/store/containment_audit_test.go`:

```go
package store

import (
	"testing"

	"stratium/pkg/models"
	"stratium/pkg/permset"
)

// TestContainmentReason_NamesAWideningAndStaysSilentOnANarrowing is the whole
// contract: the verdict is recorded only when a write WIDENS. A narrowing
// write that logged a verdict would train operators to ignore the event type.
func TestContainmentReason_NamesAWideningAndStaysSilentOnANarrowing(t *testing.T) {
	before := permset.Set{ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"}}
	wider := permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET"}}
	narrower := permset.Set{ClassificationCaps: map[string]string{"nato": "UNCLASSIFIED"}}

	if reason := containmentReason(before, wider); reason == "" {
		t.Error("raising a cap widens the grant and must produce a reason")
	}
	if reason := containmentReason(before, narrower); reason != "" {
		t.Errorf("lowering a cap narrows; want no reason, got %q", reason)
	}
	if reason := containmentReason(before, before); reason != "" {
		t.Errorf("an unchanged grant must produce no reason, got %q", reason)
	}
}

// Clearing a constraint is the widening most likely to be made by accident,
// because the API for it is a DELETE that looks like tidying up.
func TestContainmentReason_ClearingAConstraintIsAWidening(t *testing.T) {
	before := permset.Set{
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
	}
	after := permset.Set{ResourceConstraints: map[string]string{}}

	if reason := containmentReason(before, after); reason == "" {
		t.Error("clearing id_prefix widens the grant and must produce a reason")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services && go test ./internal/store/ -run TestContainmentReason -v`
Expected: FAIL to compile — `undefined: containmentReason`.

- [ ] **Step 3: Write the implementation**

Create `services/internal/store/containment_audit.go`:

```go
// containment_audit.go records what an agent-grant write widened.
//
// The three endpoints that change an agent's grant -- PUT /v1/agents/{id},
// and the caps and resource-constraints routes -- set the template copied
// onto every ROOT delegation issued afterwards
// (internal/pdpgrpc/delegation.go). Until this file, nothing compared the new
// template to the old one, so widening an agent's scope was both unchecked
// and invisible.
//
// The write still lands. Blocking here would need a break-glass and would
// stall a tenant's first grant, which has no baseline to be contained in;
// recording the verdict in the one log the system can prove was not edited
// afterwards is the trade this design took.
//
// Only the AGENT grant is covered, not all six epoch-bumping tables. The
// other four -- policies, tool_catalog, tier_overrides, resource_label_rules
// -- change the classification FUNCTION (what tier an action derives, what
// label a resource resolves to), not a permission set, so containment does
// not typecheck against them. See the design doc's consumer section.
package store

import "stratium/pkg/permset"

const eventTypeContainment = "containment"

// containmentReason returns the reason the new grant is not contained in the
// old one, or the empty string when the write narrows or leaves it unchanged.
//
// Argument order reads backwards on purpose: Contains(outer, inner) asks
// whether inner fits inside outer, so the BEFORE value is the outer one. A
// write is a widening exactly when the after value does not fit inside it.
func containmentReason(before, after permset.Set) string {
	return permset.Contains(before, after)
}
```

In `services/internal/store/agent_constraints.go`, inside `writeAgentConstraints`, load the agent's current constraints before the `UPDATE` and append a second audit entry after the existing one when the write widens:

```go
	// Captured BEFORE the UPDATE below, inside the same transaction, so the
	// comparison cannot race another writer.
	beforeSet := permset.Set{ResourceConstraints: currentConstraints}
	afterSet := permset.Set{ResourceConstraints: constraints}

	// ... existing UPDATE and audit.Entry append ...

	if reason := containmentReason(beforeSet, afterSet); reason != "" {
		widened := audit.Entry{
			TenantID:      s.tenantID,
			OccurredAt:    updatedAt,
			EventType:     eventTypeContainment,
			Actor:         actor,
			AgentID:       &id,
			Decision:      "ALLOW",
			DeniedAtDepth: noDenial,
			Reason:        "agent grant widened: " + reason,
		}
		if err := s.appendAuditTx(ctx, tx, widened); err != nil {
			return err
		}
	}
```

Read `currentConstraints` with the same `SELECT ... FOR UPDATE`-style pattern the surrounding code uses to load an agent row inside a transaction; if no such helper exists in this file, add a query mirroring `updateAgentConstraintsQuery` that selects `resource_constraints` for the id.

Apply the identical shape in `services/internal/store/agent_caps.go`'s `writeAgentCaps`, with `permset.Set{ClassificationCaps: ...}` on both sides.

Add `"stratium/pkg/permset"` to both files' imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services && go test -race ./internal/store/ -run TestContainmentReason -v`
Expected: PASS, both tests.

- [ ] **Step 5: Run the store package's full suite**

Run: `cd services && go test -race ./internal/store/`
Expected: PASS. Existing audit tests that count rows for a caps or constraints write may now see a second row on a widening write — if one fails, confirm the extra row is the containment entry and update that test's expectation, naming this task in the comment.

- [ ] **Step 6: Commit**

```bash
cd services
git add internal/store/containment_audit.go internal/store/containment_audit_test.go internal/store/agent_constraints.go internal/store/agent_caps.go
git commit -m "feat: record a containment verdict when an agent grant widens

The three agent-grant endpoints set the template copied onto every root
delegation issued afterwards, and nothing compared the new template to the
old. The write still lands; the verdict joins the hash-chained audit log.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Pin `DefaultTrustTable` as the only construction site

`internal/authz/agent.go:12-19` records that a tenant-supplied `TrustTable` could require LESS trust than the default, with no validation to stop it. Only `DefaultTrustTable()` is wired today, so the hazard is latent. This guard makes it stay latent until someone reads the note.

No `ValidateTrustTable` — it would have no caller, and scaffolding for a load path nobody has asked for is the thing this codebase's own rules forbid.

**Files:**
- Test: `services/internal/authz/trusttable_guard_test.go` (create)

**Interfaces:**
- Consumes: nothing. This task adds no production code.

- [ ] **Step 1: Write the test**

Create `services/internal/authz/trusttable_guard_test.go`:

```go
package authz

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultTrustTableIsTheOnlyConstructionSite guards the gap this package's
// own doc comment records: TrustTable is per-tenant data with no raise-only
// validation, so "nothing today stops a tenant-supplied table from requiring
// LESS trust than DefaultTrustTable" (agent.go). Only DefaultTrustTable() is
// wired, which is the only reason that gap is latent rather than live.
//
// WHEN THIS FAILS: you are building a TrustTable somewhere new -- most likely
// a tenant-configurable load path. Read agent.go's TrustTable doc comment
// first. A load path needs write-time raise-only validation analogous to
// ValidateOverride BEFORE it lands, or it silently makes a security floor
// lowerable by the tenant it constrains.
func TestDefaultTrustTableIsTheOnlyConstructionSite(t *testing.T) {
	// Path SUFFIX, not basename: pkg/models/agent.go also basenames to
	// "agent.go", and matching on the basename would silently permit a second
	// construction site there.
	const allowedPath = "internal/authz/agent.go"

	root := ".."
	fset := token.NewFileSet()
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // not this test's business
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			var name string
			switch t := lit.Type.(type) {
			case *ast.Ident:
				name = t.Name
			case *ast.SelectorExpr:
				name = t.Sel.Name
			}
			if name == "TrustTable" && !strings.HasSuffix(filepath.ToSlash(path), allowedPath) {
				offenders = append(offenders, fset.Position(lit.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("TrustTable is constructed outside %s at:\n  %s\n\n"+
			"Read this test's doc comment before adding an exception.",
			allowedPath, strings.Join(offenders, "\n  "))
	}
}
```

- [ ] **Step 2: Run the test**

Run: `cd services && go test ./internal/authz/ -run TestDefaultTrustTableIsTheOnlyConstructionSite -v`
Expected: PASS. If it fails, the offender list is real — either the walk root is wrong or a second construction site already exists; investigate before adjusting the test.

- [ ] **Step 3: Prove the guard fires**

Temporarily add to any non-test file under `services/internal/`:

```go
var zzScratch = authz.TrustTable{} // TEMPORARY -- delete after observing the failure
```

Run: `cd services && go test ./internal/authz/ -run TestDefaultTrustTableIsTheOnlyConstructionSite`
Expected: FAIL, naming that file and line.

Delete the temporary line and re-run:
Expected: PASS.

- [ ] **Step 4: Update the TODO in `agent.go`**

Replace the existing `// TODO(phase-2):` line with:

```go
// TODO(phase-2): decide per spec section 8. If raise-only is confirmed, add
// write-time validation analogous to ValidateOverride. Until then
// TestDefaultTrustTableIsTheOnlyConstructionSite (trusttable_guard_test.go)
// keeps the gap latent by failing the build on a second construction site.
```

- [ ] **Step 5: Commit**

```bash
cd services
git add internal/authz/trusttable_guard_test.go internal/authz/agent.go
git commit -m "test: pin DefaultTrustTable as the only TrustTable construction site

TrustTable is per-tenant data with no raise-only validation; only the
hardcoded default being wired is what keeps that latent. A second
construction site now fails the build and points at the note explaining why
a load path needs validation first.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Final verification

- [ ] **Run the whole suite**

Run: `cd /path/to/stratium-data && make test`
Expected: PASS, including the admin UI's lint and tests.

- [ ] **Run the conformance suite**

Run: `cd /path/to/stratium-data && make conformance`
Expected: PASS. This is the authorization property suite and it exercises `ScopeNarrows` through `internal/authz/conformance_test.go`.

- [ ] **Confirm no dependency drift**

Run: `cd services && git diff --stat go.mod go.sum`
Expected: no output. A change here means a task took a wrong turn.

- [ ] **Confirm the old symbol is gone**

Run: `cd services && grep -rn 'models\.ScopeNarrows' . --include='*.go'`
Expected: no output.

---

## Notes for the executor

- **Task 2 Step 1 is not optional.** Transcribing reason strings by eye is exactly how a behaviour-preserving extraction stops preserving behaviour. Generate them.
- **Tasks 1 Step 5 and 8 Step 3 deliberately break the build, then fix it.** A guard test nobody has watched fail is not known to work. Do not skip them, and do not commit the temporary field or variable.
- **If an existing test needs its expectation changed, stop and say why.** In Tasks 1–6 no existing test should need editing. Task 7 Step 5 names the single expected exception (an audit row count). Anything else is a signal the extraction changed behaviour.
