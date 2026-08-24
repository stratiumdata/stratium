# PAP Admin Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `clients/ui` from a read-only viewer into a full CRUD admin console for every resource the PAP exposes.

**Architecture:** The React app embedded in `stratium-pap` gains a body-carrying request helper, form primitives beside the existing table primitives, and a per-resource edit panel that replaces the table in place. Two small Go changes make the server's refusals informative enough for the UI's no-client-side-gating rule to be humane. No new npm dependencies, no router, no dialog library.

**Tech Stack:** React 19 + TypeScript, Vite, vitest + @testing-library/react, Tailwind via `cn()`, class-variance-authority. Go 1.x for the two server changes. `make ui`, `make ui-test`, `make test`.

**Spec:** `docs/superpowers/specs/2026-08-23-pap-admin-console-design.md`

## Global Constraints

- **No new npm dependencies.** `clients/ui` depends on `react` and `react-dom` and must still depend on exactly those. No CodeMirror, no Radix, no router.
- **N14 — the UI never decides what an operator may do.** No button is hidden, greyed, disabled, or pre-flighted based on a role. Every action renders for every signed-in operator; the server refuses or does not, and its own words are displayed.
- **`PUT` is a full replace on every resource.** A form holds every editable field and sends all of them.
- **Server-owned fields are never rendered as inputs.** Policy: `id`, `version`, `created_at`, `updated_at`. Agent: `id`, `created_at`, `updated_at`, `classification_caps`. TierOverride: `id`, `tenant_id`, `builtin_tier`, `created_at`, `created_by`. ResourceLabelRule: `id`, `tenant_id`.
- **A label rule's `prefix` may be the empty string** and must never be marked required. `""` is the tenant-wide catch-all; `migrations/000019` deliberately omits a `length(prefix) > 0` CHECK.
- **Tool catalog `action_tier` is `number | null`, and `null` is not `0`.**
- **There is no `DELETE /v1/tool-catalog/{id}`.** Offer no delete on that screen.
- **`classification_caps` is never sent on the agent body.** `store.UpdateAgent` ignores it. Caps go only to `PUT`/`DELETE /v1/agents/{id}/classification-caps`.
- **Policy `effect` is operator-choosable only for `cedar` and `json`.** For `rego` and `xacml` the store refuses any value other than `"deny"` (`multiValuedLanguageEffect`, `ErrEffectNotDeclarable`).
- **Files stay under 800 lines**, per the project's coding-style rules; 200-400 is typical.
- **Tests assert payloads, not call counts.** `expect(spy).toHaveBeenCalledWith(id, {every: 'field'})`, never a bare `toHaveBeenCalled()`.
- **A second click in the same test needs the first render flushed.** On this branch's pinned React 19 + RTL 16, a raw `element.click()` does not force React to flush a pending state update before returning, so `getByRole(...).click()` immediately after another click can run against the pre-update tree. Use `fireEvent.click`, or `await screen.findByRole(...)` between the two. A single click with an `await screen.find*` after it is fine, which is why the existing tests never hit this.
- **Drive inputs with `fireEvent.change`, never `el.value = x` plus `dispatchEvent`.** React installs its own value setter and its tracker sees no change, so the raw form silently does not fire `onChange` on a controlled input.
- **Every existing test must still pass.** `make test` runs `ui`, `ui-test`, then the Go suite with `-race`.
- **A UI task is not green until `npm run build` passes.** `npm run test` is `vitest run` and does NOT typecheck; only `build` (`tsc -b && vite build`) does, and CI reaches it through `make ui`. `tsconfig.app.json` sets `noUncheckedIndexedAccess: true`, so indexing a mock's `calls[0]` yields `T | undefined` and must be narrowed. The full gate for every UI task is `npm run lint && npm run test && npm run build`. Building is safe: `dist/` is gitignored and never dirties the tree.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `clients/ui/src/crud.ts` | `useList` (moved here) plus `useEditor` and the stale-write guard |
| `clients/ui/src/screens/index.ts` | Re-exports every screen; the only import site `App.tsx` needs |
| `clients/ui/src/screens/policies.tsx` | Policies list, editor, Validate, Test |
| `clients/ui/src/screens/agents.tsx` | Agents list, editor, classification-caps panel |
| `clients/ui/src/screens/tier-overrides.tsx` | Tier overrides list + editor |
| `clients/ui/src/screens/tool-catalog.tsx` | Tool catalog list + editor (no delete) |
| `clients/ui/src/screens/label-rules.tsx` | Resource label rules list + editor (new resource) |
| `clients/ui/src/screens/approvals.tsx` | Approvals list + approve/deny |
| `clients/ui/src/screens/delegations.tsx` | Delegations list + revoke (unchanged behaviour) |
| `clients/ui/src/screens/*.test.tsx` | One test file per screen |
| `services/cmd/stratium-pap/languages.go` | `GET /v1/policy-languages` handler |
| `services/cmd/stratium-pap/languages_test.go` | Its test |

**Modified:**

| File | Change |
|---|---|
| `clients/ui/src/api.ts` | Body-carrying `request()`, all write methods, `ResourceLabelRule` and `AgentCaps` types, `policyLanguages()` |
| `clients/ui/src/ui.tsx` | Form primitives; correct the false `ErrorBanner` comment |
| `clients/ui/src/display.ts` | Export `declaresEffect(language)` from the existing `DECLARED_EFFECT_LANGUAGES` set |
| `clients/ui/src/App.tsx` | Import from `./screens`; add the Label rules entry to `SCREENS` |
| `services/cmd/stratium-pap/server.go` | Informative 403 messages; one `routeTable` entry |

**Deleted:**

| File | Why |
|---|---|
| `clients/ui/src/screens.tsx` | Split into `screens/`; its 373 lines plus CRUD for seven resources would exceed the 800-line ceiling |
| `clients/ui/src/screens.test.tsx` | Split into `screens/*.test.tsx` alongside what each covers |

---

### Task 1: Informative 403s

The UI renders every button for every operator (N14) and reports the server's refusal. Today both role-refusal paths write the bare word `forbidden`, so a Viewer who presses Delete learns nothing. `ui.tsx`'s `ErrorBanner` comment already claims otherwise; this task makes the claim true.

**Files:**
- Modify: `services/cmd/stratium-pap/server.go:355-363`
- Modify: `clients/ui/src/ui.tsx` (the `ErrorBanner` doc comment)
- Test: `services/cmd/stratium-pap/server_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: two 403 body strings later tasks assert against — `your token carries no recognised role claim` and `this action requires role <min>; your token carries <role>`.

- [ ] **Step 1: Write the failing test**

Append to `services/cmd/stratium-pap/server_test.go`. Copy the fixture idiom from `approvals_test.go`'s `TestViewer_CanListButCannotDecide` — `newTestServerFixture`, `tokenWithClaims`, `doRequest` are all in this package already.

```go
// A 403 that says only "forbidden" is useless to the admin console, which
// renders every action for every operator (N14) and relies on the refusal to
// explain itself. Both role paths must name what happened.
func TestForbidden_NamesTheRequiredRoleAndTheOperatorsOwn(t *testing.T) {
	f := newTestServerFixture(t)
	tok := f.tokenWithClaims(t, "org-viewers", map[string]any{"email": "v@example.com", "email_verified": true})

	rec := doRequest(t, f.server, http.MethodDelete, "/v1/policies/"+uuid.New().String(), tok)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	body := strings.TrimSpace(rec.Body.String())
	if !strings.Contains(body, "requires role admin") {
		t.Errorf("body = %q, want it to name the required role", body)
	}
	if !strings.Contains(body, "viewer") {
		t.Errorf("body = %q, want it to name the operator's own role", body)
	}
}

// The other 403 path: the token authenticated, but no claim value maps to any
// role. That is a different fix for the operator than "you need a higher
// role", so it must not produce the same sentence.
func TestForbidden_UnmappedClaimSaysSo(t *testing.T) {
	f := newTestServerFixture(t)
	tok := f.tokenWithClaims(t, "no-such-group", map[string]any{"email": "v@example.com", "email_verified": true})

	rec := doRequest(t, f.server, http.MethodGet, "/v1/policies", tok)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	body := strings.TrimSpace(rec.Body.String())
	if !strings.Contains(body, "no recognised role claim") {
		t.Errorf("body = %q, want it to name the missing claim mapping", body)
	}
	if strings.Contains(body, "requires role") {
		t.Errorf("body = %q, must not be confused with the role-floor refusal", body)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd services && go test ./cmd/stratium-pap/ -run 'TestForbidden_' -v
```

Expected: FAIL — both bodies are `forbidden`.

- [ ] **Step 3: Implement**

In `services/cmd/stratium-pap/server.go`, replace the two `http.Error(w, "forbidden", …)` calls at lines 357 and 361:

```go
		role, err := resolveRole(claims, s.roleClaim, s.roles)
		if err != nil {
			// Distinct from the role-floor refusal below: the operator's fix
			// is a claim mapping, not a higher role. The admin console shows
			// this text verbatim (N14), so it has to name the actual problem.
			http.Error(w, "your token carries no recognised role claim", http.StatusForbidden)
			return
		}
		if !role.meets(min) {
			// Naming the floor discloses nothing -- routeTable's MinRole is
			// published in docs/user-guide.md -- and without it a console that
			// renders every action for every operator (N14) refuses without
			// explaining.
			http.Error(w, fmt.Sprintf("this action requires role %s; your token carries %s", min, role),
				http.StatusForbidden)
			return
		}
```

`Role` is a `string` type (`role.go:19`), so `%s` renders it directly. Confirm `fmt` is imported in `server.go`; add it if not.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd services && go test ./cmd/stratium-pap/ -run 'TestForbidden_' -v
```

Expected: PASS.

- [ ] **Step 5: Correct the false comment in `ui.tsx`**

The `ErrorBanner` doc comment currently asserts the 403 already names the floor. It describes this task's outcome, not the code that preceded it. Replace that sentence:

```tsx
/** An error banner. Always shows the server's own words.
 *
 *  The PAP has two 403s and they say different things: a role floor names the
 *  role required and the role this token carries, while an unrecognised role
 *  claim names neither and says so (services/cmd/stratium-pap/server.go).
 *  Paraphrasing either would lose the one detail that tells an operator which
 *  of the two they are looking at, and they have different fixes — a claim
 *  mapping, or a higher role. N14: the server decides, this screen reports. */
```

- [ ] **Step 6: Run the whole suite and commit**

```bash
cd services && go test -race ./cmd/stratium-pap/
cd .. && git add services/cmd/stratium-pap/server.go services/cmd/stratium-pap/server_test.go clients/ui/src/ui.tsx
git commit -m "fix(pap): say why a 403 refused, not just that it did

Both role paths wrote the bare word forbidden. Under N14 the admin console
renders every action for every operator and relies on the refusal to explain
itself, so a viewer pressing Delete learned nothing at all.

The two paths now say different things, because they have different fixes: an
unmapped claim needs a claim mapping, a role floor needs a higher role.

ui.tsx's ErrorBanner comment already claimed the 403 named the floor. It
described an intention; it now describes the code."
```

---

### Task 2: `GET /v1/policy-languages`

The policy editor needs the languages this build can actually evaluate. Hardcoding them in TypeScript is "a second thing to keep in step" — the failure `uiConfig.IdPEndpoints` is deliberately not served to avoid — and its symptom is silent: a language the registry lacks would still be offered, and policies authored in it evaluate to an honest deny (D10) that nothing in the UI predicts.

**Files:**
- Create: `services/cmd/stratium-pap/languages.go`
- Create: `services/cmd/stratium-pap/languages_test.go`
- Modify: `services/cmd/stratium-pap/server.go` (one `routeTable` entry)

**Interfaces:**
- Consumes: `policy.Registry` (a `map[string]PolicyEngine`), already on `Server` as `s.registry`.
- Produces: `GET /v1/policy-languages` → `200 {"languages":["cedar","json","rego","xacml"]}`, sorted. Task 4 consumes it as `api.policyLanguages(): Promise<string[]>`.

- [ ] **Step 1: Write the failing test**

Create `services/cmd/stratium-pap/languages_test.go`.

**`newTestServerFixture` wires an empty `policy.Registry{}` on purpose**
(`server_test.go:55`), so a fixture-based test cannot assert the four real
languages — it would see none. Sorting is therefore tested by calling the
handler directly against a `Server` built with a known registry. `Registry` is
`map[string]PolicyEngine` and this handler reads only its keys, so `nil` values
are sufficient and no fake engine is needed.

```go
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"stratium/internal/policy"
)

// Sorting is the property under test, so the handler is called directly with a
// registry this test controls. nil engines are fine: listPolicyLanguages reads
// keys and never calls one.
func TestPolicyLanguages_ReturnsTheRegistrysKeysSorted(t *testing.T) {
	s := &Server{registry: policy.Registry{"xacml": nil, "cedar": nil, "rego": nil, "json": nil}}
	rec := httptest.NewRecorder()

	listPolicyLanguages(s, rec, httptest.NewRequest(http.MethodGet, "/v1/policy-languages", nil), Operator{})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got struct {
		Languages []string `json:"languages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"cedar", "json", "rego", "xacml"}
	if len(got.Languages) != len(want) {
		t.Fatalf("languages = %v, want %v", got.Languages, want)
	}
	for i, w := range want {
		if got.Languages[i] != w {
			t.Errorf("languages[%d] = %q, want %q -- output must be sorted, because Go randomises map iteration and a selector that reorders itself per request is a bug", i, got.Languages[i], w)
		}
	}
}

// An empty registry must serialise as [] and never as null. `var xs []string`
// marshals to null, which would make the console's languages.map(...) throw
// rather than render an empty selector -- a build with no engines registered
// should produce an empty list, not a broken screen.
func TestPolicyLanguages_EmptyRegistryIsAnEmptyArrayNotNull(t *testing.T) {
	s := &Server{registry: policy.Registry{}}
	rec := httptest.NewRecorder()

	listPolicyLanguages(s, rec, httptest.NewRequest(http.MethodGet, "/v1/policy-languages", nil), Operator{})

	if body := rec.Body.String(); !strings.Contains(body, `"languages":[]`) {
		t.Errorf("body = %s, want an empty ARRAY -- null would break the caller", body)
	}
}

// The route is wired at RoleViewer, like every other read on this table. The
// fixture's registry is empty by design, so this asserts reachability and the
// role floor, not the contents.
func TestPolicyLanguages_ViewerMayRead(t *testing.T) {
	f := newTestServerFixture(t)
	tok := f.tokenWithClaims(t, "org-viewers", map[string]any{"email": "v@example.com", "email_verified": true})
	if rec := doRequest(t, f.server, http.MethodGet, "/v1/policy-languages", tok); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
```

Add `"strings"` to the import block. Confirm the module path prefix on the
`policy` import matches what other files in this package use.

- [ ] **Step 2: Run it to verify it fails**

```bash
cd services && go test ./cmd/stratium-pap/ -run 'TestPolicyLanguages_' -v
```

Expected: FAIL — `listPolicyLanguages` is undefined, so the package does not compile.

- [ ] **Step 3: Implement the handler**

Create `services/cmd/stratium-pap/languages.go`:

```go
package main

import (
	"net/http"
	"sort"
)

// listPolicyLanguages answers GET /v1/policy-languages with the languages this
// build can actually evaluate -- s.registry's own keys, not a list maintained
// beside it.
//
// The admin console's language selector reads this. A constant in the
// TypeScript would be a second copy of a value the browser can obtain
// first-hand, which is the reasoning uiConfig.IdPEndpoints already applies to
// the IdP's endpoints (ui.go). The failure a constant produces is silent:
// offer a language nothing is registered for and policies authored in it
// evaluate to Multi's honest deny (D10), with nothing in the UI to predict it.
//
// Sorted so the response is stable -- Go randomises map iteration, and an
// order that changes per request would make the selector reorder itself.
//
// Note this is the REGISTRY, which is not the only authority: policies.language
// carries its own CHECK (migrations/000001_baseline.up.sql) fixing the set the
// database will store. The two agree today. Where they could not, the registry
// is the right one to advertise: a language the database accepts but no engine
// evaluates is worse than one this console never offers.
func listPolicyLanguages(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	languages := make([]string, 0, len(s.registry))
	for name := range s.registry {
		languages = append(languages, name)
	}
	sort.Strings(languages)

	writeJSON(w, http.StatusOK, map[string][]string{"languages": languages})
}
```

- [ ] **Step 4: Register the route**

In `services/cmd/stratium-pap/server.go`'s `routeTable`, immediately after the `POST /v1/policies/test` entry:

```go
	{Pattern: "GET /v1/policy-languages", MinRole: RoleViewer, Handler: listPolicyLanguages},
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd services && go test ./cmd/stratium-pap/ -run 'TestPolicyLanguages_' -v
cd services && go test -race ./cmd/stratium-pap/
```

Expected: PASS, and the existing suite still green.

- [ ] **Step 6: Commit**

```bash
git add services/cmd/stratium-pap/languages.go services/cmd/stratium-pap/languages_test.go services/cmd/stratium-pap/server.go
git commit -m "feat(pap): serve the registered policy languages

The admin console's language selector needs the set this build can evaluate.
Deriving it from s.registry means adding an engine changes the response with
no second edit; a constant in the TypeScript would be a second thing to keep
in step, and its failure mode is silent -- offer a language nothing is
registered for and its policies evaluate to Multi's honest deny with nothing
in the UI to predict it.

Sorted, because Go randomises map iteration and a selector that reorders
itself per request is a bug report waiting to happen."
```

---

### Task 3: Split `screens.tsx` into `screens/`

A pure move. `screens.tsx` is 373 lines for six read-only tables; adding CRUD for seven resources to one file would pass the 800-line ceiling in the project's coding-style rules. Doing the move on its own keeps the behaviour-changing diffs that follow small enough to review.

**No behaviour changes in this task.** A reviewer should be able to confirm that by the tests passing untouched.

**Files:**
- Create: `clients/ui/src/crud.ts`, `clients/ui/src/screens/index.ts`, and `screens/{policies,agents,tier-overrides,tool-catalog,approvals,delegations}.tsx`
- Create: `clients/ui/src/screens/{policies,delegations}.test.tsx`
- Delete: `clients/ui/src/screens.tsx`, `clients/ui/src/screens.test.tsx`
- Modify: `clients/ui/src/App.tsx` (the import line only)

**Interfaces:**
- Produces: `useList<T>(load: () => Promise<T[]>): { rows: T[] | null; error: string | null; reload: () => void }` from `./crud`, and `Loading()` from `./crud`. Every screen component keeps its current exported name: `PoliciesScreen`, `AgentsScreen`, `TierOverridesScreen`, `ToolCatalogScreen`, `ApprovalsScreen`, `DelegationsScreen`.

- [ ] **Step 1: Move `useList` and `Loading` into `crud.ts`**

Create `clients/ui/src/crud.ts` and move both verbatim from `screens.tsx`, keeping `useList`'s doc comment exactly as written — it explains the `rows === null` versus `[]` distinction and the generation counter, both of which every screen depends on.

```ts
// crud.ts holds the data-loading hooks every screen shares. Split out of
// screens.tsx when those screens grew editors: the loading behaviour is the
// one part that genuinely is identical across all seven, and it is the part
// most easily broken by a well-meaning edit to one screen.

import { useCallback, useEffect, useState } from 'react'

import { describeError } from './api'

interface ListState<T> {
  rows: T[] | null
  error: string | null
}

// ... useList exactly as it stands in screens.tsx, doc comment included ...

export function Loading() {
  return <p className="text-sm text-muted-foreground">Loading…</p>
}
```

`Loading` returns JSX, so `crud.ts` must be named `crud.tsx`. Use `crud.tsx`.

- [ ] **Step 2: Move each screen into its own file**

One file per screen under `clients/ui/src/screens/`, each importing `useList` and `Loading` from `../crud`. The component bodies are unchanged — copy them, do not retype them.

`screens.tsx`'s header comment argues for one file: *"each is the same shape — fetch a list, render a table — and splitting them would trade six imports for six near-identical twelve-line files."* That reasoning expires with this task, so it does not travel to the new files. Put this at the top of `screens/index.ts` instead:

```ts
// screens/ holds one file per admin screen. This was a single screens.tsx
// while every screen was a list and a table; each now carries an editor,
// its own field rules, and its own tests, and the shapes stopped being
// near-identical. index.ts exists so App.tsx has one import site.

export { PoliciesScreen } from './policies'
export { AgentsScreen } from './agents'
export { TierOverridesScreen } from './tier-overrides'
export { ToolCatalogScreen } from './tool-catalog'
export { ApprovalsScreen } from './approvals'
export { DelegationsScreen } from './delegations'
```

Six exports, not seven: `LabelRulesScreen` is created in Task 7 and adds its own line there. Exporting it here would not compile.

- [ ] **Step 3: Split the tests to match**

`screens.test.tsx` covers `PoliciesScreen` and `DelegationsScreen`. Move each describe block, with its factory function and its comments, into `screens/policies.test.tsx` and `screens/delegations.test.tsx`. Imports become `./policies` and `./delegations`; `./api` becomes `../api`.

- [ ] **Step 4: Update `App.tsx`**

One line — the import moves from `./screens` (the file) to `./screens` (the directory's `index.ts`). The path text is unchanged; confirm Vite resolves it and the `SCREENS` array still compiles.

- [ ] **Step 5: Verify nothing changed**

```bash
cd clients/ui && npm run lint && npm run test
```

Expected: every existing test passes, unmodified except for import paths. If a test needed a behaviour change to pass, the move was not a pure move — revert and redo it.

- [ ] **Step 6: Commit**

```bash
git add -A clients/ui/src
git commit -m "refactor(ui): one file per admin screen

Pure move, no behaviour change: every test passes with only its import path
edited. screens.tsx was 373 lines for six read-only tables and argued in its
own header for staying one file, because the screens were near-identical.

Each is about to grow an editor, its own field rules, and its own tests, so
that argument expires here rather than at the 800-line ceiling.

useList and Loading move to crud.tsx: shared by all seven, and the part most
easily broken by a well-meaning edit to one screen."
```

---

### Task 4: The write transport

`api.ts`'s `request()` takes no body, which is why nothing in this application can create anything. This task adds the body, the write methods for every resource, the two missing types, and the language reader from Task 2.

**Plan ruling — the spec's stale-write guard cannot key on `updated_at`.** The spec says to compare `updated_at` before saving. Only `Policy` and `Agent` have one: `ResourceLabelRule` is `{id, tenant_id, prefix, hierarchy, level}`, `TierOverride` has `created_at` but no update timestamp, and `ToolCatalogEntry` has no timestamps at all. The guard therefore compares the **whole re-fetched object** against the snapshot the form was seeded with. This works for all five, needs no new server field, and is implemented in Task 6.

**Files:**
- Modify: `clients/ui/src/api.ts`
- Test: `clients/ui/src/api.test.ts` (create)

**Interfaces:**
- Consumes: `GET /v1/policy-languages` from Task 2.
- Produces: everything below. Later tasks call these exact names.

```ts
export interface ResourceLabelRule { id: string; tenant_id: string; prefix: string; hierarchy: string; level: string }
export type ClassificationCaps = Record<string, string>
export interface PolicyTestVerdict { effect: string; reason: string; source?: string; policy_id?: string }

api.policyLanguages(): Promise<string[]>
api.policy(id): Promise<Policy>
api.createPolicy(p: Policy): Promise<Policy>
api.updatePolicy(id: string, p: Policy): Promise<Policy>
api.deletePolicy(id: string): Promise<void>
api.validatePolicy(language: string, text: string): Promise<void>
api.testPolicy(req: unknown): Promise<PolicyTestVerdict>
api.agent(id): Promise<Agent>
api.createAgent(a: Agent): Promise<Agent>
api.updateAgent(id: string, a: Agent): Promise<Agent>
api.deleteAgent(id: string): Promise<void>
api.agentCaps(id: string): Promise<ClassificationCaps>
api.putAgentCaps(id: string, caps: ClassificationCaps): Promise<ClassificationCaps>
api.deleteAgentCaps(id: string): Promise<void>
api.tierOverride(id): Promise<TierOverride>
api.createTierOverride(t: TierOverride): Promise<TierOverride>
api.updateTierOverride(id: string, t: TierOverride): Promise<TierOverride>
api.deleteTierOverride(id: string): Promise<void>
api.toolCatalogEntry(id): Promise<ToolCatalogEntry>
api.createToolCatalogEntry(e: ToolCatalogEntry): Promise<ToolCatalogEntry>
api.updateToolCatalogEntry(id: string, e: ToolCatalogEntry): Promise<ToolCatalogEntry>
api.resourceLabelRules(): Promise<ResourceLabelRule[]>
api.resourceLabelRule(id): Promise<ResourceLabelRule>
api.createResourceLabelRule(r: ResourceLabelRule): Promise<ResourceLabelRule>
api.updateResourceLabelRule(id: string, r: ResourceLabelRule): Promise<ResourceLabelRule>
api.deleteResourceLabelRule(id: string): Promise<void>
api.approveApproval(id: string): Promise<Approval>
api.denyApproval(id: string): Promise<Approval>
```

There is deliberately no `deleteToolCatalogEntry`: the PAP exposes no such route.

- [ ] **Step 1: Write the failing transport test**

Create `clients/ui/src/api.test.ts`. This is the one test in the suite that spies on `fetch` rather than on `api` — it exists to prove the body reaches the wire at all, which no `api`-level spy can show.

```ts
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from './api'

// vi.mock, not vi.spyOn: api.ts binds authHeader at import time, so replacing
// the property on the module namespace afterwards does not affect the caller.
vi.mock('./auth', () => ({
  authHeader: () => ({ Authorization: 'Bearer t' }),
  onUnauthorized: () => {},
}))

function okJSON(value: unknown) {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  }))
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('request', () => {
  it('serialises the body and declares its content type', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({ id: 'r1' }))

    await api.createResourceLabelRule({
      id: '', tenant_id: '', prefix: '/secret-', hierarchy: 'nato', level: 'SECRET',
    })

    expect(f).toHaveBeenCalledTimes(1)
    const [path, init] = f.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/v1/resource-label-rules')
    expect(init.method).toBe('POST')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
    // The whole body, not merely "a body": a form that drops a field is the
    // failure this suite exists to catch.
    expect(JSON.parse(init.body as string)).toEqual({
      id: '', tenant_id: '', prefix: '/secret-', hierarchy: 'nato', level: 'SECRET',
    })
  })

  it('sends no body and no content type on a GET', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON([]))

    await api.resourceLabelRules()

    const [, init] = f.mock.calls[0] as [string, RequestInit]
    expect(init.body).toBeUndefined()
    expect((init.headers as Record<string, string>)['Content-Type']).toBeUndefined()
  })

  it('carries an empty prefix to the wire rather than dropping it', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({ id: 'r2' }))

    await api.createResourceLabelRule({
      id: '', tenant_id: '', prefix: '', hierarchy: 'nato', level: 'PUBLIC',
    })

    // "" is R7's tenant-wide catch-all. A helper that pruned empty strings
    // would silently turn the catch-all into a rule matching nothing.
    expect(JSON.parse((f.mock.calls[0][1] as RequestInit).body as string).prefix).toBe('')
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd clients/ui && npm run test -- api.test.ts
```

Expected: FAIL — `api.createResourceLabelRule` does not exist.

- [ ] **Step 3: Add the body to `request`**

In `clients/ui/src/api.ts`, replace the `request` function:

```ts
/** The PAP client's single request path. `body` is omitted, not null, on a
 *  read: sending `Content-Type: application/json` with no body invites a 400
 *  from a strict decoder, and several routes here are POSTs that genuinely
 *  carry nothing (approve, deny, revoke). */
async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const header = authHeader()
  if (!header) throw new APIError(401, 'not signed in')

  const headers: Record<string, string> = { ...header, Accept: 'application/json' }
  const init: RequestInit = { method, headers }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }

  const res = await fetch(path, init)
  if (res.status === 401) {
    // The token is dead. Drop it rather than retry with it.
    onUnauthorized()
    throw new APIError(401, 'your session has expired — sign in again')
  }
  if (!res.ok) {
    const body = (await res.text()).trim()
    throw new APIError(res.status, body || `${method} ${path} failed with ${res.status}`)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}
```

- [ ] **Step 4: Add the types**

```ts
/** models.ResourceLabelRule.
 *
 *  `prefix` may legitimately be the EMPTY STRING: "" is a prefix of every
 *  resource id, which makes such a row the tenant's catch-all (R7) and the
 *  answer to "a cap was enabled and now everything denies". Nothing in this
 *  client may treat it as a missing required field — migrations/000019
 *  deliberately omits the length(prefix) > 0 CHECK. */
export interface ResourceLabelRule {
  id: string
  tenant_id: string
  prefix: string
  hierarchy: string
  level: string
}

/** The classification-caps sub-resource: hierarchy -> level.
 *
 *  An EMPTY map is the off switch — CheckCap returns allow for len(caps) == 0.
 *  Any entry at all makes an unlabelled resource DENY (R2). The two states are
 *  not "unset" and "set to nothing"; they are "off" and "on". */
export type ClassificationCaps = Record<string, string>

/** One leg of POST /v1/policies/test's answer. */
export interface PolicyTestVerdict {
  effect: string
  reason: string
  source?: string
  policy_id?: string
}
```

- [ ] **Step 5: Add the write methods**

Extend the exported `api` object. Keep the existing seven entries; add:

```ts
  policyLanguages: () =>
    request<{ languages: string[] }>('GET', '/v1/policy-languages').then((r) => r.languages),

  policy: (id: string) => request<Policy>('GET', `/v1/policies/${encodeURIComponent(id)}`),
  createPolicy: (p: Policy) => request<Policy>('POST', '/v1/policies', p),
  updatePolicy: (id: string, p: Policy) =>
    request<Policy>('PUT', `/v1/policies/${encodeURIComponent(id)}`, p),
  deletePolicy: (id: string) => request<void>('DELETE', `/v1/policies/${encodeURIComponent(id)}`),

  // validate answers 200 {valid:true} or a 400 carrying the engine's own
  // message. The 400 is the useful case, and APIError already carries its
  // body, so this returns void and lets the rejection speak.
  validatePolicy: (language: string, text: string) =>
    request<void>('POST', '/v1/policies/validate', { language, text }),
  testPolicy: (req: unknown) => request<PolicyTestVerdict>('POST', '/v1/policies/test', req),

  agent: (id: string) => request<Agent>('GET', `/v1/agents/${encodeURIComponent(id)}`),
  createAgent: (a: Agent) => request<Agent>('POST', '/v1/agents', a),
  updateAgent: (id: string, a: Agent) =>
    request<Agent>('PUT', `/v1/agents/${encodeURIComponent(id)}`, a),
  deleteAgent: (id: string) => request<void>('DELETE', `/v1/agents/${encodeURIComponent(id)}`),

  // The caps sub-resource is a separate route at a separate role floor
  // (RoleAdmin, where the agent body is RoleEditor). store.UpdateAgent ignores
  // classification_caps on input, so this is the ONLY way to write one.
  agentCaps: (id: string) =>
    request<ClassificationCaps>('GET', `/v1/agents/${encodeURIComponent(id)}/classification-caps`),
  putAgentCaps: (id: string, caps: ClassificationCaps) =>
    request<ClassificationCaps>('PUT', `/v1/agents/${encodeURIComponent(id)}/classification-caps`, caps),
  deleteAgentCaps: (id: string) =>
    request<void>('DELETE', `/v1/agents/${encodeURIComponent(id)}/classification-caps`),

  tierOverride: (id: string) =>
    request<TierOverride>('GET', `/v1/tier-overrides/${encodeURIComponent(id)}`),
  createTierOverride: (t: TierOverride) => request<TierOverride>('POST', '/v1/tier-overrides', t),
  updateTierOverride: (id: string, t: TierOverride) =>
    request<TierOverride>('PUT', `/v1/tier-overrides/${encodeURIComponent(id)}`, t),
  deleteTierOverride: (id: string) =>
    request<void>('DELETE', `/v1/tier-overrides/${encodeURIComponent(id)}`),

  toolCatalogEntry: (id: string) =>
    request<ToolCatalogEntry>('GET', `/v1/tool-catalog/${encodeURIComponent(id)}`),
  createToolCatalogEntry: (e: ToolCatalogEntry) =>
    request<ToolCatalogEntry>('POST', '/v1/tool-catalog', e),
  updateToolCatalogEntry: (id: string, e: ToolCatalogEntry) =>
    request<ToolCatalogEntry>('PUT', `/v1/tool-catalog/${encodeURIComponent(id)}`, e),
  // No delete: the PAP exposes no DELETE /v1/tool-catalog/{id}.

  resourceLabelRules: () => request<ResourceLabelRule[]>('GET', '/v1/resource-label-rules'),
  resourceLabelRule: (id: string) =>
    request<ResourceLabelRule>('GET', `/v1/resource-label-rules/${encodeURIComponent(id)}`),
  createResourceLabelRule: (r: ResourceLabelRule) =>
    request<ResourceLabelRule>('POST', '/v1/resource-label-rules', r),
  updateResourceLabelRule: (id: string, r: ResourceLabelRule) =>
    request<ResourceLabelRule>('PUT', `/v1/resource-label-rules/${encodeURIComponent(id)}`, r),
  deleteResourceLabelRule: (id: string) =>
    request<void>('DELETE', `/v1/resource-label-rules/${encodeURIComponent(id)}`),

  approveApproval: (id: string) =>
    request<Approval>('POST', `/v1/approvals/${encodeURIComponent(id)}/approve`),
  denyApproval: (id: string) =>
    request<Approval>('POST', `/v1/approvals/${encodeURIComponent(id)}/deny`),
```

- [ ] **Step 6: Run the tests and commit**

```bash
cd clients/ui && npm run lint && npm run test
cd ../.. && git add clients/ui/src/api.ts clients/ui/src/api.test.ts
git commit -m "feat(ui): give the PAP client a body

request() took (method, path) and nothing else, which is why this application
could read six resources and write none of them: not a missing screen, a
missing parameter.

Adds every write route the PAP exposes, and deliberately not one it does not
-- there is no deleteToolCatalogEntry because there is no DELETE
/v1/tool-catalog/{id}.

The transport test spies on fetch rather than on api, because an api-level
spy cannot show that the body reached the wire, and asserts the whole
serialised object: a form that drops a field is the failure it exists to
catch. One case covers prefix: '' specifically, since a helper that pruned
empty strings would turn R7's tenant-wide catch-all into a rule matching
nothing."
```

---

### Task 5: Form primitives

`ui.tsx` holds the presentational primitives, written in shadcn's shape without Radix because six read-only tables needed no interaction state. Editors need inputs. Same conventions: `cn()`-merged `className`, `cva` for variants, plain semantic HTML.

**Files:**
- Modify: `clients/ui/src/ui.tsx`
- Test: `clients/ui/src/ui.test.tsx` (create)

**Interfaces:**
- Produces:
```tsx
<Panel title={string} onClose={() => void}>{children}</Panel>
<Field label={string} hint?={ReactNode} htmlFor?={string}>{children}</Field>
<TextInput {...InputHTMLAttributes} />
<NumberInput {...InputHTMLAttributes} />
<Textarea {...TextareaHTMLAttributes} />
<Checkbox label={string} checked={boolean} onChange={(e) => void} />
<Select value={string} onChange={(e) => void} options={string[]} />
<StringListInput value={string[]} onChange={(next: string[]) => void} placeholder?={string} />
<ConfirmRow prompt={ReactNode} confirmLabel={string} onConfirm={() => void} onCancel={() => void} />
```

- [ ] **Step 1: Write the failing tests**

Create `clients/ui/src/ui.test.tsx`:

```tsx
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ConfirmRow, StringListInput } from './ui'

describe('StringListInput', () => {
  // allowed_tools is a []string and an EMPTY list means unrestricted, for both
  // Agent and Delegation (models.Agent.HasTool). A control that cannot express
  // the empty list cannot express "unrestricted".
  it('emits an empty array when every entry is cleared', () => {
    const onChange = vi.fn()
    render(<StringListInput value={['Read']} onChange={onChange} />)

    fireEvent.change(screen.getByDisplayValue('Read'), { target: { value: '' } })

    expect(onChange).toHaveBeenCalledWith([])
  })

  it('splits on newlines and trims, dropping blank lines but not order', () => {
    const onChange = vi.fn()
    render(<StringListInput value={[]} onChange={onChange} />)

    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'Read\n  Grep  \n\nGlob' } })

    expect(onChange).toHaveBeenCalledWith(['Read', 'Grep', 'Glob'])
  })
})

describe('ConfirmRow', () => {
  // Never window.confirm: it blocks the event loop and cannot carry the
  // resource-specific warning some deletions need.
  it('calls onConfirm only when the confirm control is pressed', () => {
    const onConfirm = vi.fn()
    const onCancel = vi.fn()
    render(
      <ConfirmRow prompt="Delete this rule?" confirmLabel="Delete" onConfirm={onConfirm} onCancel={onCancel} />,
    )

    screen.getByRole('button', { name: 'Cancel' }).click()
    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(onConfirm).not.toHaveBeenCalled()

    screen.getByRole('button', { name: 'Delete' }).click()
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd clients/ui && npm run test -- ui.test.tsx
```

Expected: FAIL — neither component exists.

- [ ] **Step 3: Implement the primitives**

Append to `clients/ui/src/ui.tsx`:

```tsx
/** The editor shell. Replaces the table in place rather than floating over it:
 *  a dialog would mean adding Radix, and this file's own header explains why
 *  that dependency has not been earned. */
export function Panel({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <Card className="p-4">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-base font-semibold">{title}</h3>
        <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
      </div>
      {children}
    </Card>
  )
}

/** A labelled control with optional explanatory text. The hint is not
 *  decoration: several fields here mean something an operator cannot guess
 *  from the label — an empty prefix, a null action tier — and the alternative
 *  to saying so is a support ticket. */
export function Field({ label, hint, htmlFor, children }: {
  label: string; hint?: ReactNode; htmlFor?: string; children: ReactNode
}) {
  return (
    <div className="mb-3">
      <label htmlFor={htmlFor} className="mb-1 block text-sm font-medium">{label}</label>
      {children}
      {hint ? <p className="mt-1 text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  )
}

const inputClass =
  'w-full rounded-md border border-border bg-background px-3 py-2 text-sm ' +
  'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary'

export function TextInput({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input type="text" className={cn(inputClass, className)} {...props} />
}

export function NumberInput({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input type="number" className={cn(inputClass, className)} {...props} />
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn(inputClass, 'font-mono min-h-40', className)} {...props} />
}

export function Checkbox({ label, ...props }: { label: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="mb-3 flex items-center gap-2 text-sm">
      <input type="checkbox" className="size-4 rounded border-border" {...props} />
      {label}
    </label>
  )
}

export function Select({ options, className, ...props }: { options: string[] } & SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn(inputClass, className)} {...props}>
      {options.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  )
}

/** A []string as one line per entry. Newline-separated rather than chips
 *  because the values are tool names an operator pastes from a catalog, and
 *  because an empty textarea is an unambiguous empty list — which for
 *  allowed_tools means UNRESTRICTED, not "none". */
export function StringListInput({ value, onChange, placeholder }: {
  value: string[]; onChange: (next: string[]) => void; placeholder?: string
}) {
  return (
    <textarea
      className={cn(inputClass, 'font-mono min-h-24')}
      placeholder={placeholder}
      value={value.join('\n')}
      onChange={(e) => onChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
    />
  )
}

/** An inline destructive confirmation. Never window.confirm: it blocks the
 *  event loop, it cannot be styled, and it cannot carry the resource-specific
 *  warning some deletions need (removing the catch-all label rule, for one). */
export function ConfirmRow({ prompt, confirmLabel, onConfirm, onCancel }: {
  prompt: ReactNode; confirmLabel: string; onConfirm: () => void; onCancel: () => void
}) {
  return (
    <div role="alertdialog" className="flex flex-wrap items-center gap-3 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
      <span className="text-destructive">{prompt}</span>
      <span className="ml-auto flex gap-2">
        <Button variant="ghost" size="sm" onClick={onCancel}>Cancel</Button>
        <Button variant="destructive" size="sm" onClick={onConfirm}>{confirmLabel}</Button>
      </span>
    </div>
  )
}
```

Extend the existing type import at the top of the file to cover the new ones:

```tsx
import type {
  ButtonHTMLAttributes, HTMLAttributes, InputHTMLAttributes, ReactNode,
  SelectHTMLAttributes, TdHTMLAttributes, TextareaHTMLAttributes,
} from 'react'
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd clients/ui && npm run lint && npm run test -- ui.test.tsx
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add clients/ui/src/ui.tsx clients/ui/src/ui.test.tsx
git commit -m "feat(ui): form primitives, same shape as the table primitives

ui.tsx held Button, Badge, Card and a table because six read-only screens
needed nothing else, and said a dialog would be the point at which Radix
earns its place. The editors these primitives serve replace the table in
place instead, so it still has not.

StringListInput is newline-separated rather than chips because an empty
textarea is an unambiguous empty list, and for allowed_tools an empty list
means unrestricted -- a control that cannot express it cannot express the
default.

ConfirmRow exists because window.confirm blocks the event loop and cannot
carry a resource-specific warning; deleting the catch-all label rule needs
one."
```

---

### Task 6: `useEditor` and the stale-write guard

Every editing screen needs the same four things: hold a draft, seed it from a fresh `GET` rather than the list row, refuse to clobber a concurrent edit, and surface the server's own refusal. That is `useEditor`.

**Files:**
- Modify: `clients/ui/src/crud.tsx`
- Test: `clients/ui/src/crud.test.tsx` (create)

**Interfaces:**
- Consumes: `describeError` from `./api`.
- Produces:
```ts
interface Editor<T> {
  draft: T | null
  editingID: string | null
  error: string | null
  busy: boolean
  create: (blank: T) => void
  edit: (id: string) => void
  patch: (fields: Partial<T>) => void
  save: () => void
  close: () => void
}
function useEditor<T>(res: {
  get: (id: string) => Promise<T>
  create: (value: T) => Promise<T>
  update: (id: string, value: T) => Promise<T>
  onSaved: () => void
}): Editor<T>
```

- [ ] **Step 1: Write the failing tests**

Create `clients/ui/src/crud.test.tsx`:

```tsx
import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { useEditor } from './crud'

interface Row { id: string; name: string }

function harness(over: Partial<Parameters<typeof useEditor<Row>>[0]> = {}) {
  const res = {
    get: vi.fn(async (id: string) => ({ id, name: 'stored' })),
    create: vi.fn(async (v: Row) => v),
    update: vi.fn(async (_id: string, v: Row) => v),
    onSaved: vi.fn(),
    ...over,
  }
  return { res, hook: renderHook(() => useEditor<Row>(res)) }
}

describe('useEditor', () => {
  // The list row may be stale, and PUT is a full replace: seeding the form
  // from the row would write back whatever the list happened to hold.
  it('seeds the draft from a fresh GET, not from the caller', async () => {
    const { res, hook } = harness()
    act(() => hook.result.current.edit('r1'))
    await waitFor(() => expect(hook.result.current.draft).toEqual({ id: 'r1', name: 'stored' }))
    expect(res.get).toHaveBeenCalledWith('r1')
  })

  it('sends the whole draft on save, not the patched fields', async () => {
    const { res, hook } = harness()
    act(() => hook.result.current.edit('r1'))
    await waitFor(() => expect(hook.result.current.draft).not.toBeNull())

    act(() => hook.result.current.patch({ name: 'edited' }))
    await act(async () => hook.result.current.save())

    expect(res.update).toHaveBeenCalledWith('r1', { id: 'r1', name: 'edited' })
    expect(res.onSaved).toHaveBeenCalledTimes(1)
  })

  // Two operators, one resource, no If-Match on the API. Without this the
  // second save silently discards the first.
  it('refuses to save when the stored object moved under the edit', async () => {
    let stored: Row = { id: 'r1', name: 'stored' }
    const { res, hook } = harness({ get: vi.fn(async () => stored) })

    act(() => hook.result.current.edit('r1'))
    await waitFor(() => expect(hook.result.current.draft).not.toBeNull())

    stored = { id: 'r1', name: 'somebody else got here first' }
    act(() => hook.result.current.patch({ name: 'mine' }))
    await act(async () => hook.result.current.save())

    expect(res.update).not.toHaveBeenCalled()
    expect(hook.result.current.error).toMatch(/changed while you were editing/)
  })

  it('reports the server refusal verbatim rather than swallowing it', async () => {
    const { hook } = harness({
      update: vi.fn(async () => { throw new Error('this action requires role admin; your token carries viewer') }),
    })
    act(() => hook.result.current.edit('r1'))
    await waitFor(() => expect(hook.result.current.draft).not.toBeNull())

    await act(async () => hook.result.current.save())
    expect(hook.result.current.error).toContain('requires role admin')
  })

  it('creates without a guard read, since there is nothing yet to clobber', async () => {
    const { res, hook } = harness()
    act(() => hook.result.current.create({ id: '', name: 'new' }))
    await act(async () => hook.result.current.save())

    expect(res.create).toHaveBeenCalledWith({ id: '', name: 'new' })
    expect(res.get).not.toHaveBeenCalled()
  })
})
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd clients/ui && npm run test -- crud.test.tsx
```

Expected: FAIL — `useEditor` is not exported.

- [ ] **Step 3: Implement `useEditor`**

Append to `clients/ui/src/crud.tsx`:

```tsx
export interface Editor<T> {
  draft: T | null
  editingID: string | null
  error: string | null
  busy: boolean
  create: (blank: T) => void
  edit: (id: string) => void
  patch: (fields: Partial<T>) => void
  save: () => void
  close: () => void
}

/**
 * Holds one resource's draft.
 *
 * Two properties matter and neither is obvious:
 *
 * 1. `edit` seeds from a fresh GET, never from the list row handed in. Every
 *    PUT on this API is a full replace, so a draft seeded from a stale row
 *    writes that row's staleness back over whatever is stored.
 *
 * 2. `save` re-reads before an update and refuses if the stored object moved.
 *    The PAP has no If-Match and Version is server-owned, so the only
 *    alternative is silently discarding a colleague's edit. The comparison is
 *    a whole-object one rather than a timestamp: ResourceLabelRule,
 *    TierOverride and ToolCatalogEntry carry no updated_at to compare. Both
 *    sides are server JSON parsed the same way, so key order matches and
 *    JSON.stringify is a sound comparison here.
 *
 * The guard narrows the window; it does not close it. Two saves inside one
 * round-trip still race, and closing that needs If-Match in the API.
 */
export function useEditor<T>(res: {
  get: (id: string) => Promise<T>
  create: (value: T) => Promise<T>
  update: (id: string, value: T) => Promise<T>
  onSaved: () => void
}): Editor<T> {
  const [draft, setDraft] = useState<T | null>(null)
  const [snapshot, setSnapshot] = useState<T | null>(null)
  const [editingID, setEditingID] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const close = useCallback(() => {
    setDraft(null); setSnapshot(null); setEditingID(null); setError(null)
  }, [])

  const create = useCallback((blank: T) => {
    setDraft(blank); setSnapshot(null); setEditingID(null); setError(null)
  }, [])

  const edit = useCallback((id: string) => {
    setError(null); setBusy(true); setEditingID(id)
    res.get(id).then(
      (fresh) => { setDraft(fresh); setSnapshot(fresh); setBusy(false) },
      (err: unknown) => { setError(describeError(err)); setBusy(false) },
    )
  }, [res])

  const patch = useCallback((fields: Partial<T>) => {
    setDraft((d) => (d === null ? d : { ...d, ...fields }))
  }, [])

  // Split deliberately: runSave is async, `save` is not.
  //
  // Editor<T>.save is declared `() => void` and must genuinely be one. Seven
  // screens call it straight from an onClick, and a handler that returns a
  // Promise trips @typescript-eslint/no-misused-promises at every one of those
  // call sites -- seven suppressions instead of this one wrapper. There is
  // also nothing to await: every branch below reports through `error` and this
  // never rejects.
  const runSave = useCallback(async () => {
    if (draft === null) return
    setBusy(true); setError(null)
    try {
      if (editingID === null) {
        await res.create(draft)
      } else {
        const fresh = await res.get(editingID)
        if (JSON.stringify(fresh) !== JSON.stringify(snapshot)) {
          setError('this changed while you were editing — close and reopen to see the current version')
          return
        }
        await res.update(editingID, draft)
      }
      res.onSaved()
      setDraft(null); setSnapshot(null); setEditingID(null)
    } catch (err: unknown) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }, [draft, editingID, res, snapshot])

  const save = useCallback(() => {
    void runSave()
  }, [runSave])

  return { draft, editingID, error, busy, create, edit, patch, save, close }
}
```

`res` is an object literal at every call site, so it is a new reference each render. Wrap it in `useMemo` in the screens, or the `edit` callback churns. Each screen task below does so.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd clients/ui && npm run lint && npm run test -- crud.test.tsx
```

Expected: PASS, all five.

- [ ] **Step 5: Commit**

```bash
git add clients/ui/src/crud.tsx clients/ui/src/crud.test.tsx
git commit -m "feat(ui): useEditor, with a guard against clobbering a concurrent edit

Every PUT on this API is a full replace, so a draft seeded from a list row
writes that row's staleness back. useEditor seeds from a fresh GET instead.

Before an update it re-reads and refuses if the stored object moved: the PAP
has no If-Match and Version is server-owned, so the alternative is silently
discarding a colleague's edit to a policy. The comparison is whole-object,
not a timestamp -- ResourceLabelRule, TierOverride and ToolCatalogEntry carry
no updated_at.

The guard narrows the window, it does not close it. Closing it needs If-Match
in the API."
```

---

### Task 7: Resource label rules

A new screen for a resource with no UI at all today, and the first full vertical slice through Tasks 4-6. It is deliberately first: it is the smallest complete CRUD surface, and it carries the single most consequential field rule in the console.

**Files:**
- Create: `clients/ui/src/screens/label-rules.tsx`
- Create: `clients/ui/src/screens/label-rules.test.tsx`
- Modify: `clients/ui/src/screens/index.ts` (add the export)
- Modify: `clients/ui/src/App.tsx` (add the `SCREENS` entry)

**Interfaces:**
- Consumes: `useList`, `useEditor` from `../crud`; `api.resourceLabelRules`, `.resourceLabelRule`, `.createResourceLabelRule`, `.updateResourceLabelRule`, `.deleteResourceLabelRule`, and `type ResourceLabelRule` from `../api`; `Panel`, `Field`, `TextInput`, `ConfirmRow` and the table primitives from `../ui`.
- Produces: `export function LabelRulesScreen()`.

- [ ] **Step 1: Write the failing tests**

Create `clients/ui/src/screens/label-rules.test.tsx`:

```tsx
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type ResourceLabelRule } from '../api'
import { LabelRulesScreen } from './label-rules'

afterEach(() => { vi.restoreAllMocks() })

function rule(over: Partial<ResourceLabelRule> = {}): ResourceLabelRule {
  return {
    id: '33333333-3333-3333-3333-333333333333',
    tenant_id: 'acme',
    prefix: '/secret-',
    hierarchy: 'nato',
    level: 'SECRET',
    ...over,
  }
}

describe('LabelRulesScreen', () => {
  it('says so when the tenant has no rules, rather than showing an empty table', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([])
    render(<LabelRulesScreen />)
    expect(await screen.findByText('No resource label rules.')).toBeInTheDocument()
  })

  // "" is a prefix of every resource id: R7's tenant-wide catch-all, and the
  // documented cure for "a cap was enabled and now everything denies". A blank
  // cell would read as a missing value.
  it('renders an empty prefix as the catch-all rather than as blank', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([rule({ prefix: '', level: 'PUBLIC' })])
    render(<LabelRulesScreen />)
    expect(await screen.findByText(/matches every resource/i)).toBeInTheDocument()
  })

  // The rule this screen exists to protect. migrations/000019 deliberately
  // omits a length(prefix) > 0 CHECK; a required-field validator here would
  // re-add in the browser the constraint the schema author refused to add.
  it('saves a rule whose prefix is empty', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([])
    const create = vi.spyOn(api, 'createResourceLabelRule').mockResolvedValue(rule({ prefix: '' }))

    render(<LabelRulesScreen />)
    await screen.findByText('No resource label rules.')
    screen.getByRole('button', { name: 'New rule' }).click()

    fireEvent.change(await screen.findByLabelText('Hierarchy'), { target: { value: 'nato' } })
    fireEvent.change(screen.getByLabelText('Level'), { target: { value: 'PUBLIC' } })

    screen.getByRole('button', { name: 'Save' }).click()

    // Every field, and prefix present as "" rather than absent.
    await waitFor(() => expect(create).toHaveBeenCalledWith({
      id: '', tenant_id: '', prefix: '', hierarchy: 'nato', level: 'PUBLIC',
    }))
  })

  it('warns that deleting the catch-all makes unlabelled resources deny', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([rule({ prefix: '' })])
    render(<LabelRulesScreen />)

    ;(await screen.findByRole('button', { name: 'Delete' })).click()
    expect(await screen.findByText(/unlabelled resources will deny/i)).toBeInTheDocument()
  })

  // N14: the button is not conditioned on a role, and the refusal is shown.
  it('offers delete to every operator and surfaces the server refusal', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([rule()])
    vi.spyOn(api, 'deleteResourceLabelRule').mockRejectedValue(
      new APIError(403, 'this action requires role admin; your token carries editor'),
    )

    render(<LabelRulesScreen />)
    ;(await screen.findByRole('button', { name: 'Delete' })).click()
    screen.getByRole('button', { name: 'Delete rule' }).click()

    expect(await screen.findByRole('alert')).toHaveTextContent('requires role admin')
  })
})
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd clients/ui && npm run test -- label-rules
```

Expected: FAIL — the module does not exist.

- [ ] **Step 3: Implement the screen**

Create `clients/ui/src/screens/label-rules.tsx`:

```tsx
// label-rules.tsx administers resource_label_rules: the table that decides
// what classification a resource carries, and therefore which requests a
// classification cap refuses.
//
// One field on this screen behaves unlike every other field in the console.
// See PREFIX_HINT.

import { useCallback, useMemo, useState } from 'react'

import { api, type ResourceLabelRule } from '../api'
import { Loading, useEditor, useList } from '../crud'
import {
  Button, ConfirmRow, EmptyRow, ErrorBanner, Field, Panel, ScreenHeader,
  TCell, THead, TRow, Table, TextInput,
} from '../ui'

/** An empty prefix is a prefix of every resource id, which makes the row the
 *  tenant's catch-all (R7) — the documented answer to "a cap was enabled and
 *  now everything denies". It is NOT a missing value, it is not invalid, and
 *  nothing here may require it: migrations/000019 deliberately omits the
 *  length(prefix) > 0 CHECK, and re-adding it in the browser would remove the
 *  one tenant-wide unblock from the screen most likely to be open when it is
 *  needed. */
const PREFIX_HINT = 'Leave empty to match every resource — this tenant’s catch-all.'

const BLANK: ResourceLabelRule = { id: '', tenant_id: '', prefix: '', hierarchy: '', level: '' }

export function LabelRulesScreen() {
  const { rows, error, reload } = useList<ResourceLabelRule>(api.resourceLabelRules)
  const [confirming, setConfirming] = useState<ResourceLabelRule | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  const res = useMemo(() => ({
    get: api.resourceLabelRule,
    create: api.createResourceLabelRule,
    update: api.updateResourceLabelRule,
    onSaved: reload,
  }), [reload])
  const editor = useEditor<ResourceLabelRule>(res)

  const remove = useCallback((r: ResourceLabelRule) => {
    api.deleteResourceLabelRule(r.id).then(
      () => { setConfirming(null); setActionError(null); reload() },
      (err: unknown) => { setConfirming(null); setActionError(describeErrorText(err)) },
    )
  }, [reload])

  if (editor.draft !== null) {
    return (
      <Panel title={editor.editingID === null ? 'New resource label rule' : 'Edit resource label rule'} onClose={editor.close}>
        {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}

        <Field label="Prefix" htmlFor="prefix" hint={PREFIX_HINT}>
          <TextInput
            id="prefix"
            value={editor.draft.prefix}
            onChange={(e) => editor.patch({ prefix: e.target.value })}
          />
        </Field>
        <Field label="Hierarchy" htmlFor="hierarchy" hint="Stored verbatim; never case-folded on the way in.">
          <TextInput
            id="hierarchy"
            value={editor.draft.hierarchy}
            onChange={(e) => editor.patch({ hierarchy: e.target.value })}
          />
        </Field>
        <Field label="Level" htmlFor="level" hint="Stored verbatim; never case-folded on the way in.">
          <TextInput
            id="level"
            value={editor.draft.level}
            onChange={(e) => editor.patch({ level: e.target.value })}
          />
        </Field>

        <div className="mt-4 flex gap-2">
          <Button onClick={editor.save} disabled={editor.busy}>Save</Button>
          <Button variant="outline" onClick={editor.close}>Cancel</Button>
        </div>
      </Panel>
    )
  }

  return (
    <section>
      <ScreenHeader title="Resource label rules">
        The longest matching prefix decides a resource&apos;s classification, and an
        unlabelled resource denies under any configured cap. A rule with an empty prefix
        matches everything and is this tenant&apos;s catch-all.
      </ScreenHeader>

      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {actionError ? <ErrorBanner>{actionError}</ErrorBanner> : null}
      {confirming ? (
        <div className="mb-4">
          <ConfirmRow
            prompt={confirming.prefix === ''
              ? 'Delete the catch-all? With no rule matching everything, unlabelled resources will deny under any configured cap.'
              : `Delete the rule for ${confirming.prefix}?`}
            confirmLabel="Delete rule"
            onConfirm={() => remove(confirming)}
            onCancel={() => setConfirming(null)}
          />
        </div>
      ) : null}

      <div className="mb-3">
        <Button onClick={() => editor.create(BLANK)}>New rule</Button>
      </div>

      {rows === null ? <Loading /> : (
        <Table>
          <THead columns={['Prefix', 'Hierarchy', 'Level', '']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={4}>No resource label rules.</EmptyRow> : rows.map((r) => (
              <TRow key={r.id}>
                <TCell className="font-mono">
                  {r.prefix === ''
                    ? <span className="text-muted-foreground">(empty) — matches every resource</span>
                    : r.prefix}
                </TCell>
                <TCell>{r.hierarchy}</TCell>
                <TCell>{r.level}</TCell>
                <TCell className="text-right">
                  <Button variant="ghost" size="sm" onClick={() => editor.edit(r.id)}>Edit</Button>
                  <Button variant="ghost" size="sm" onClick={() => setConfirming(r)}>Delete</Button>
                </TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
```

Import `describeError` from `../api` and use it directly rather than the placeholder name above:

```tsx
import { api, describeError, type ResourceLabelRule } from '../api'
```

and call `describeError(err)` in `remove`.

- [ ] **Step 4: Register the screen**

`clients/ui/src/screens/index.ts` — add:

```ts
export { LabelRulesScreen } from './label-rules'
```

`clients/ui/src/App.tsx` — add to the `SCREENS` array, after `tool-catalog`:

```tsx
  { id: 'label-rules', label: 'Label rules', Screen: LabelRulesScreen },
```

and add `LabelRulesScreen` to the import from `./screens`.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd clients/ui && npm run lint && npm run test
```

Expected: PASS, and every earlier test still green.

- [ ] **Step 6: Commit**

```bash
git add clients/ui/src/screens/label-rules.tsx clients/ui/src/screens/label-rules.test.tsx clients/ui/src/screens/index.ts clients/ui/src/App.tsx
git commit -m "feat(ui): administer resource label rules

The table that decides what classification a resource carries had no screen
at all, so the rules behind every denial in the product could only be written
with curl or psql.

The prefix field does not behave like any other field in this console: empty
is legal and meaningful. It is R7's tenant-wide catch-all and the documented
cure for 'a cap was enabled and now everything denies'. migrations/000019
deliberately omits a length(prefix) > 0 CHECK, so marking it required here
would re-add in the browser the constraint the schema author refused -- and
would remove the one tenant-wide unblock from the screen most likely to be
open when someone needs it. Deleting that row warns accordingly."
```

---

### Task 7b: Correct three wire shapes in `api.ts`

Task 4's review cross-checked every client method's **path and verb** against
`routeTable` and found all 35 correct. It did not check **body field names**,
and three are wrong. All three are in merged code.

| Method | Sends / expects | The server actually uses |
|---|---|---|
| `validatePolicy` | `{language, text}` | `validatePolicyRequest.Text` is tagged **`json:"policy_content"`** (validate.go:42) |
| `putAgentCaps` | a bare map | `capsRequest` is **`{"classification_caps": {...}}`** (agent_caps.go:16) |
| `agentCaps` | returns `Record<string,string>` | returns **`models.AgentCapsView`** — `{agent_id, classification_caps, catch_all}` |

The second is the dangerous one. Sending a bare map leaves `capsRequest.ClassificationCaps` nil, so an operator setting a cap would **clear every cap on that agent** — a silent widening of a security ceiling, reported as success.

**Files:** Modify `clients/ui/src/api.ts`, `clients/ui/src/api.test.ts`.

- [ ] **Step 1: Write the failing tests**

```ts
  it('sends the policy source as policy_content, the field the server reads', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({ valid: true }))
    await api.validatePolicy('cedar', 'permit(principal, action, resource);')
    const body = JSON.parse((f.mock.calls[0]?.[1] as RequestInit).body as string)
    // validatePolicyRequest.Text is tagged json:"policy_content". Sending
    // "text" leaves it empty and validates an EMPTY policy instead.
    expect(body).toEqual({ language: 'cedar', policy_content: 'permit(principal, action, resource);' })
  })

  it('wraps caps in the envelope the server decodes', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({ agent_id: 'a', classification_caps: {}, catch_all: {} }))
    await api.putAgentCaps('a1', { nato: 'SECRET' })
    const body = JSON.parse((f.mock.calls[0]?.[1] as RequestInit).body as string)
    // capsRequest is {"classification_caps": {...}}. A bare map decodes to nil
    // and CLEARS every cap -- widening a ceiling while reporting success.
    expect(body).toEqual({ classification_caps: { nato: 'SECRET' } })
  })
```

- [ ] **Step 2: Run them, confirm both FAIL**

- [ ] **Step 3: Fix the three methods**

```ts
export interface AgentCapsView {
  agent_id: string
  classification_caps: ClassificationCaps
  /** Per hierarchy, the level the tenant's catch-all label rule assigns, or
   *  null where no catch-all exists for it. Read-only context: it is what an
   *  unlabelled resource resolves to, which is what makes a cap bite. */
  catch_all: Record<string, string | null>
}

  validatePolicy: (language: string, policyContent: string) =>
    request<void>('POST', '/v1/policies/validate', { language, policy_content: policyContent }),

  agentCaps: (id: string) =>
    request<AgentCapsView>('GET', `/v1/agents/${encodeURIComponent(id)}/classification-caps`),
  putAgentCaps: (id: string, caps: ClassificationCaps) =>
    request<AgentCapsView>('PUT', `/v1/agents/${encodeURIComponent(id)}/classification-caps`,
      { classification_caps: caps }),
```

- [ ] **Step 4: Run the gate, commit**

```bash
cd clients/ui && npm run lint && npm run test && npm run build
git commit -m "fix(ui): three client bodies the server never reads

Task 4's review checked every method's path and verb against routeTable and
found all 35 right. It did not check body FIELD NAMES.

- validatePolicy sent {text}; validatePolicyRequest.Text is tagged
  json:\"policy_content\", so the server validated an empty policy.
- putAgentCaps sent a bare map; capsRequest is {\"classification_caps\": ...},
  so a nil map decoded and an operator SETTING a cap would have CLEARED every
  cap on that agent -- widening a security ceiling and reporting success.
- agentCaps typed the response as a bare map; it is AgentCapsView, carrying
  agent_id and catch_all alongside."
```

---

### Task 8: Approvals — approve and deny

The escalation feature's premise is a human deciding, and `STRATIUM_PEP_APPROVAL_TIMEOUT` exists to hold a tool call open while they do. This screen lists pending approvals and offers no way to decide one, so that human reaches for `curl` while an agent blocks.

**Files:**
- Modify: `clients/ui/src/screens/approvals.tsx`
- Create: `clients/ui/src/screens/approvals.test.tsx`

**Interfaces:**
- Consumes: `api.approveApproval(id)`, `api.denyApproval(id)`, `useList` — all existing.
- Produces: no new exports; `ApprovalsScreen` keeps its name.

- [ ] **Step 1: Write the failing tests**

Create `clients/ui/src/screens/approvals.test.tsx`:

```tsx
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type Approval } from '../api'
import { ApprovalsScreen } from './approvals'

afterEach(() => { vi.restoreAllMocks() })

function approval(over: Partial<Approval> = {}): Approval {
  return {
    id: '44444444-4444-4444-4444-444444444444',
    agent_id: '55555555-5555-5555-5555-555555555555',
    delegation_id: '66666666-6666-6666-6666-666666666666',
    root_delegation_id: '66666666-6666-6666-6666-666666666666',
    subject: 'agent@example.com',
    root_principal: 'operator@example.com',
    tool_name: 'Bash',
    action: 'rm -rf /tmp/x',
    derived_tier: 4,
    input_digest: 'a'.repeat(64),
    status: 'pending',
    requested_at: '2026-08-23T10:00:00Z',
    expires_at: '2026-08-23T10:02:00Z',
    ...over,
  }
}

describe('ApprovalsScreen', () => {
  it('offers approve and deny on a pending approval', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([approval()])
    const approve = vi.spyOn(api, 'approveApproval').mockResolvedValue(approval({ status: 'approved' }))

    render(<ApprovalsScreen />)
    ;(await screen.findByRole('button', { name: 'Approve' })).click()

    await waitFor(() => expect(approve).toHaveBeenCalledWith('44444444-4444-4444-4444-444444444444'))
  })

  // An expired approval keeps status 'pending' -- the schema's CHECK has only
  // pending/approved/denied -- but models.Approval.Verify refuses it at
  // CONSUMPTION ("approval %s expired at %s"). So DecideApproval would happily
  // return 200 while the agent's call stays refused: the operator believes
  // they unblocked something and nothing happened.
  it('offers neither on an approval that has expired, and says why', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([
      approval({ status: 'pending', expires_at: '2020-01-01T00:00:00Z' }),
    ])
    render(<ApprovalsScreen />)

    expect(await screen.findByText(/expired/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument()
  })

  it('offers neither on an approval that is already decided', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([approval({ status: 'approved', approved_by: 'op@example.com' })])
    render(<ApprovalsScreen />)

    await screen.findByText('approved')
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument()
  })

  // N7: the approver is fixed to the chain's ROOT PRINCIPAL, and a role is
  // necessary but never sufficient. respond.go's message carries only the
  // approval id -- deliberately not the operator identity or the root
  // principal -- so this screen shows what it was given and invents nothing.
  it('shows the N7 refusal verbatim without reconstructing who was expected', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([approval()])
    vi.spyOn(api, 'approveApproval').mockRejectedValue(
      new APIError(403, 'approver is not the root principal of approval 44444444-4444-4444-4444-444444444444'),
    )

    render(<ApprovalsScreen />)
    ;(await screen.findByRole('button', { name: 'Approve' })).click()

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('approver is not the root principal')
    // The server withholds both identities on purpose; the screen must not
    // fill the gap from the row it happens to be rendering.
    expect(alert).not.toHaveTextContent('operator@example.com')
  })
})
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd clients/ui && npm run test -- approvals
```

Expected: FAIL — no Approve button exists.

- [ ] **Step 3: Implement**

In `clients/ui/src/screens/approvals.tsx`, add an actions column. Keep every existing column and the existing `ScreenHeader` text.

```tsx
  const [actionError, setActionError] = useState<string | null>(null)

  const decide = useCallback((id: string, how: 'approve' | 'deny') => {
    const call = how === 'approve' ? api.approveApproval : api.denyApproval
    call(id).then(
      () => { setActionError(null); reload() },
      (err: unknown) => setActionError(describeError(err)),
    )
  }, [reload])
```

and in the row, offered unconditionally to every signed-in operator (N14) but only where there is something to decide:

```tsx
                <TCell className="text-right">
                  {a.status === 'pending' ? (
                    <>
                      <Button variant="ghost" size="sm" onClick={() => decide(a.id, 'approve')}>Approve</Button>
                      <Button variant="ghost" size="sm" onClick={() => decide(a.id, 'deny')}>Deny</Button>
                    </>
                  ) : null}
                </TCell>
```

Render `actionError` through `ErrorBanner` above the table. Add `''` to the `THead` columns array for the new column.

Decidability is `status === 'pending' && new Date(a.expires_at) > new Date()`. Put it in one named helper so the row's badge and the buttons cannot disagree:

```tsx
// An approval is decidable only while it is pending AND unexpired. Expiry is
// not a status: the schema's CHECK holds only pending/approved/denied, so an
// expired request still reads 'pending'. models.Approval.Verify refuses it at
// consumption ("approval %s expired at %s"), which means DecideApproval would
// return 200 on one while the agent's call stays refused -- the operator
// believing they unblocked something that never moved.
function decidable(a: Approval): boolean {
  return a.status === 'pending' && new Date(a.expires_at).getTime() > Date.now()
}
```

Render an expired-but-pending row with a `Badge tone="warn"` reading `expired`, so the absent buttons have a visible reason.

Neither test is an authorization decision — both are "there is nothing here to decide", the same reasoning `DelegationsScreen` already uses to withhold Revoke from an already-revoked delegation. N14 governs whether the UI second-guesses a *role*; it does not oblige a screen to offer an action that cannot take effect.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd clients/ui && npm run lint && npm run test
```

- [ ] **Step 5: Commit**

```bash
git add clients/ui/src/screens/approvals.tsx clients/ui/src/screens/approvals.test.tsx
git commit -m "feat(ui): decide an approval from the console

The escalation path holds a tool call open for a human to decide -- that is
what APPROVAL_TIMEOUT is for -- and the screen listing those approvals had no
button, so the human reached for curl while an agent blocked.

Buttons appear only where status is pending, which is not an authorization
decision but 'there is nothing here to decide', the same reasoning that
withholds Revoke from an already-revoked delegation.

N7's refusal is shown verbatim. respond.go carries only the approval id in
that message, withholding both the operator identity and the root principal
on purpose, so the screen does not fill the gap from the row it is rendering."
```

---

### Task 9: Tier overrides and tool catalog

Two small screens of the same shape, done together. Both are `Editor` to write; tier overrides are `Admin` to delete and the tool catalog has no delete at all.

**Files:**
- Modify: `clients/ui/src/screens/tier-overrides.tsx`, `clients/ui/src/screens/tool-catalog.tsx`
- Create: `clients/ui/src/screens/tier-overrides.test.tsx`, `clients/ui/src/screens/tool-catalog.test.tsx`

**Interfaces:**
- Consumes: `useEditor`, and the eight `api` methods added in Task 4 for these two resources.
- Produces: no new exports.

- [ ] **Step 1: Write the failing tests**

`clients/ui/src/screens/tier-overrides.test.tsx`:

```tsx
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, type TierOverride } from '../api'
import { TierOverridesScreen } from './tier-overrides'

afterEach(() => { vi.restoreAllMocks() })

function override(over: Partial<TierOverride> = {}): TierOverride {
  return {
    id: '77777777-7777-7777-7777-777777777777',
    tool_or_verb: 'Bash',
    action_tier: 4,
    builtin_tier: 2,
    created_at: '2026-08-23T10:00:00Z',
    created_by: 'operator@example.com',
    ...over,
  }
}

describe('TierOverridesScreen', () => {
  // The store ignores ID, TenantID, BuiltinTier, CreatedAt and CreatedBy on
  // input and sets them authoritatively -- BuiltinTier specifically must never
  // be operator-supplied. An input for one would accept a value that is
  // discarded without complaint.
  it('offers no input for the server-owned fields', async () => {
    vi.spyOn(api, 'tierOverrides').mockResolvedValue([override()])
    vi.spyOn(api, 'tierOverride').mockResolvedValue(override())

    render(<TierOverridesScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    await screen.findByLabelText('Tool or verb')
    expect(screen.queryByLabelText('Builtin tier')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Created by')).not.toBeInTheDocument()
  })

  it('shows the builtin tier beside the override, so the operator sees what is being overridden', async () => {
    vi.spyOn(api, 'tierOverrides').mockResolvedValue([override({ action_tier: 4, builtin_tier: 2 })])
    render(<TierOverridesScreen />)
    // actionTier() renders the names, not the numbers.
    expect(await screen.findByText('DESTRUCTIVE')).toBeInTheDocument()
    expect(screen.getByText('INTERNAL_MODIFY')).toBeInTheDocument()
  })

  it('sends every editable field on save', async () => {
    vi.spyOn(api, 'tierOverrides').mockResolvedValue([])
    const create = vi.spyOn(api, 'createTierOverride').mockResolvedValue(override())

    render(<TierOverridesScreen />)
    await screen.findByText('No tier overrides.')
    screen.getByRole('button', { name: 'New override' }).click()

    fireEvent.change(await screen.findByLabelText('Tool or verb'), { target: { value: 'Write' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ tool_or_verb: 'Write', action_tier: 0 }),
    ))
  })
})
```

`clients/ui/src/screens/tool-catalog.test.tsx`:

```tsx
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, type ToolCatalogEntry } from '../api'
import { ToolCatalogScreen } from './tool-catalog'

afterEach(() => { vi.restoreAllMocks() })

function entry(over: Partial<ToolCatalogEntry> = {}): ToolCatalogEntry {
  return {
    id: '88888888-8888-8888-8888-888888888888',
    tool_name: 'Read',
    action_tier: 1,
    verb: 'read',
    resource_field: 'file_path',
    ...over,
  }
}

describe('ToolCatalogScreen', () => {
  // The PAP exposes no DELETE /v1/tool-catalog/{id}. A button here would 404.
  it('offers no delete, because the API has none', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([entry()])
    render(<ToolCatalogScreen />)
    await screen.findByText('Read')
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
  })

  // null and 0 are different: null means "derive the tier", 0 means REASONING.
  // A numeric input defaulting to zero would silently pin every new tool to
  // the lowest tier.
  it('sends action_tier as null when the tier is derived, never as 0', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([])
    const create = vi.spyOn(api, 'createToolCatalogEntry').mockResolvedValue(entry())

    render(<ToolCatalogScreen />)
    await screen.findByText('No tool catalog entries.')
    screen.getByRole('button', { name: 'New entry' }).click()

    fireEvent.change(await screen.findByLabelText('Tool name'), { target: { value: 'Glob' } })
    // "Derive the tier" is checked by default.
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ tool_name: 'Glob', action_tier: null }),
    ))
  })

  // "" is not "unset" for these two: they are *string with omitempty in Go, so
  // "" arrives as a non-nil pointer to the empty string and satisfies both the
  // store's `ActionTier == nil && CommandField == nil` guard and the database's
  // tool_catalog_tier_or_command_field CHECK. The row stored then means "derive
  // the tier from the field named empty-string" -- an invalid entry that both
  // guards were written to prevent.
  it('omits an empty command_field rather than sending an empty string', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([])
    const create = vi.spyOn(api, 'createToolCatalogEntry').mockResolvedValue(entry())

    render(<ToolCatalogScreen />)
    await screen.findByText('No tool catalog entries.')
    screen.getByRole('button', { name: 'New entry' }).click()

    fireEvent.change(await screen.findByLabelText('Tool name'), { target: { value: 'Glob' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalled())
    const sent = create.mock.calls[0]?.[0] as Record<string, unknown>
    expect('command_field' in sent && sent.command_field === '').toBe(false)
    expect('resource_field' in sent && sent.resource_field === '').toBe(false)
  })

  it('sends a number once the tier is set explicitly', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([])
    const create = vi.spyOn(api, 'createToolCatalogEntry').mockResolvedValue(entry())

    render(<ToolCatalogScreen />)
    await screen.findByText('No tool catalog entries.')
    screen.getByRole('button', { name: 'New entry' }).click()

    ;(await screen.findByLabelText('Derive the tier from the command')).click()
    fireEvent.change(screen.getByLabelText('Action tier'), { target: { value: '3' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ action_tier: 3 }),
    ))
  })
})
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd clients/ui && npm run test -- tier-overrides tool-catalog
```

Expected: FAIL — no editors exist.

- [ ] **Step 3: Implement the tier overrides editor**

In `tier-overrides.tsx`, wire `useEditor` exactly as `label-rules.tsx` does, with:

```tsx
const BLANK: TierOverride = {
  id: '', tool_or_verb: '', action_tier: 0, builtin_tier: 0, created_at: '', created_by: '',
}

const res = useMemo(() => ({
  get: api.tierOverride,
  create: api.createTierOverride,
  update: api.updateTierOverride,
  onSaved: reload,
}), [reload])
```

Two fields, and only two:

```tsx
<Field label="Tool or verb" htmlFor="tool_or_verb">
  <TextInput id="tool_or_verb" value={editor.draft.tool_or_verb}
    onChange={(e) => editor.patch({ tool_or_verb: e.target.value })} />
</Field>
<Field label="Action tier" htmlFor="action_tier"
  hint={`Overrides the builtin tier, which the server computes and this form cannot set.`}>
  <NumberInput id="action_tier" min={0} max={4} value={editor.draft.action_tier}
    onChange={(e) => editor.patch({ action_tier: Number(e.target.value) })} />
</Field>
```

The list gains a `Builtin` column rendered with the existing `actionTier()` formatter, plus Edit and Delete buttons and a `ConfirmRow`, following `label-rules.tsx`'s delete flow.

- [ ] **Step 4: Implement the tool catalog editor**

In `tool-catalog.tsx`:

```tsx
// resource_field and command_field are *string with omitempty in Go. Sending
// "" is NOT the same as omitting them: it produces a non-nil pointer to the
// empty string, which defeats BOTH guards on this table --
// store.CreateToolCatalogEntry refuses only `ActionTier == nil &&
// CommandField == nil` (internal/store/catalog.go), and the database's
// tool_catalog_tier_or_command_field CHECK tests `IS NOT NULL`. An empty
// string passes each, and the row it stores means "derive the tier from the
// field named empty-string". They stay absent until an operator types one.
const BLANK: ToolCatalogEntry = { id: '', tool_name: '', action_tier: null, verb: '' }

/** '' means "not set" for the two optional field names, and must be omitted
 *  from the payload rather than sent. See BLANK. */
const orUndefined = (v: string) => (v === '' ? undefined : v)
```

The tier control is a checkbox plus a conditional input, because `null` and `0` are different values with different meanings:

```tsx
<Checkbox
  label="Derive the tier from the command"
  checked={editor.draft.action_tier === null}
  onChange={(e) => editor.patch({ action_tier: e.target.checked ? null : 0 })}
/>
{editor.draft.action_tier !== null ? (
  <Field label="Action tier" htmlFor="action_tier">
    <NumberInput id="action_tier" min={0} max={4} value={editor.draft.action_tier}
      onChange={(e) => editor.patch({ action_tier: Number(e.target.value) })} />
  </Field>
) : null}
```

`tool_name` and `verb` are plain `TextInput`s. `resource_field` and `command_field` are `TextInput`s whose `onChange` passes through `orUndefined`, so clearing one omits it instead of sending `""`:

```tsx
<Field label="Command field" htmlFor="command_field"
  hint="Required when the tier is derived: it names the argument holding the command to classify.">
  <TextInput id="command_field" value={editor.draft.command_field ?? ''}
    onChange={(e) => editor.patch({ command_field: orUndefined(e.target.value) })} />
</Field>
```

The form does not itself refuse "derive the tier" with no command field. Once `""` is omitted rather than sent, the store's own guard catches it and answers with its own message, which the panel shows — the server stays the authority. The hint above says so up front so the operator is not surprised by it.

**No delete button and no `ConfirmRow`** — the API has no such route.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd clients/ui && npm run lint && npm run test
```

- [ ] **Step 6: Commit**

```bash
git add clients/ui/src/screens/tier-overrides.tsx clients/ui/src/screens/tier-overrides.test.tsx clients/ui/src/screens/tool-catalog.tsx clients/ui/src/screens/tool-catalog.test.tsx
git commit -m "feat(ui): edit tier overrides and the tool catalog

Tier overrides expose two fields and no more. The store ignores ID, TenantID,
BuiltinTier, CreatedAt and CreatedBy on input and sets them authoritatively --
BuiltinTier specifically must never be operator-supplied -- so an input for
any of them would accept a value that is discarded without complaint. The
builtin tier is shown beside the override instead, so the operator can see
what is being overridden.

The tool catalog's action_tier is a checkbox plus a conditional number,
because null and 0 are different: null means derive the tier, 0 means
REASONING. A plain numeric input defaulting to zero would silently pin every
new tool to the lowest tier.

No delete on the tool catalog: the PAP exposes no such route, and a button
would 404."
```

---

### Task 10: Agents, and classification caps

The agent form is ordinary. The caps control is not: it writes a different route at a different role floor, and putting it on the agent body instead would produce a field that saves without error and changes nothing.

**Files:**
- Modify: `clients/ui/src/screens/agents.tsx`
- Create: `clients/ui/src/screens/agents.test.tsx`

**Interfaces:**
- Consumes: `api.agent`, `.createAgent`, `.updateAgent`, `.deleteAgent`, `.agentCaps`, `.putAgentCaps`, `.deleteAgentCaps`, `type ClassificationCaps`.
- Produces: no new exports.

- [ ] **Step 1: Write the failing tests**

Create `clients/ui/src/screens/agents.test.tsx`:

```tsx
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, type Agent } from '../api'
import { AgentsScreen } from './agents'

afterEach(() => { vi.restoreAllMocks() })

function agent(over: Partial<Agent> = {}): Agent {
  return {
    id: '99999999-9999-9999-9999-999999999999',
    name: 'claude-code',
    provider: 'anthropic',
    model_id: 'claude-opus-5',
    trust_tier: 2,
    enabled: true,
    suspended: false,
    allowed_tools: ['Read', 'Grep'],
    created_at: '2026-08-23T10:00:00Z',
    updated_at: '2026-08-23T10:00:00Z',
    ...over,
  }
}

describe('AgentsScreen', () => {
  // store.UpdateAgent passes eight parameters and classification_caps is not
  // one of them: it is read back via RETURNING and never written. A field for
  // it on this form would accept input, save without error, and change
  // nothing -- an operator believing they had tightened a security ceiling
  // that never moved.
  it('offers no caps field on the agent form itself', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({})

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    await screen.findByLabelText('Name')
    expect(screen.queryByLabelText('Classification caps')).not.toBeInTheDocument()
  })

  it('does not send classification_caps in the agent body', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({})
    const update = vi.spyOn(api, 'updateAgent').mockResolvedValue(agent())

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'renamed' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(update).toHaveBeenCalled())
    const [, body] = update.mock.calls[0]
    expect(body).not.toHaveProperty('classification_caps')
    // ...and it is a full replace, so everything else IS there.
    expect(body).toMatchObject({
      name: 'renamed', provider: 'anthropic', model_id: 'claude-opus-5',
      trust_tier: 2, enabled: true, suspended: false, allowed_tools: ['Read', 'Grep'],
    })
  })

  it('writes caps through the sub-resource route', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({ nato: 'CONFIDENTIAL' })
    const putCaps = vi.spyOn(api, 'putAgentCaps').mockResolvedValue({ nato: 'SECRET' })

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    fireEvent.change(await screen.findByDisplayValue('CONFIDENTIAL'), { target: { value: 'SECRET' } })
    screen.getByRole('button', { name: 'Save caps' }).click()

    await waitFor(() => expect(putCaps).toHaveBeenCalledWith(
      '99999999-9999-9999-9999-999999999999', { nato: 'SECRET' },
    ))
  })

  // An empty map is the off switch; any entry makes unlabelled resources deny.
  // "no caps" and "caps set to nothing" are the same wire value and must read
  // the same on screen.
  // live_delegations is "the delegations this cap does NOT affect. A warning,
  // not a confirmation." Caps are copied onto a delegation at issuance, so an
  // operator lowering a ceiling during an incident must not believe they have
  // stopped something that is still running under the old cap.
  it('warns that live delegations keep the previous cap until reissued', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({
      agent_id: agent().id, classification_caps: { nato: 'SECRET' }, catch_all: { nato: 'PUBLIC' },
      unsatisfiable_tools: [], live_delegations: 3, applies: 'at next issuance',
    })

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    expect(await screen.findByText(/3/)).toBeInTheDocument()
    expect(screen.getByText(/at next issuance/i)).toBeInTheDocument()
  })

  // For an unrestricted agent the list covers CATALOGUED tools only -- there is
  // no finite set to scan. An empty list must not read as "everything is fine".
  it('does not claim an unrestricted agent has no unsatisfiable tools', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent({ allowed_tools: [] })])
    vi.spyOn(api, 'agent').mockResolvedValue(agent({ allowed_tools: [] }))
    vi.spyOn(api, 'agentCaps').mockResolvedValue({
      agent_id: agent().id, classification_caps: { nato: 'SECRET' }, catch_all: { nato: 'PUBLIC' },
      unsatisfiable_tools: [], live_delegations: 0, applies: 'at next issuance',
    })

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    expect(await screen.findByText(/uncatalogued tools cannot be listed/i)).toBeInTheDocument()
  })

  // The refusal is an acknowledgement gate. It must be shown in the server's
  // own words, and overriding it must be a separate deliberate act.
  it('offers an explicit override only after the server refuses an uncovered hierarchy', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({
      agent_id: agent().id, classification_caps: {}, catch_all: {},
      unsatisfiable_tools: [], live_delegations: 0, applies: 'at next issuance',
    })
    const put = vi.spyOn(api, 'putAgentCaps').mockRejectedValue(
      new APIError(400, 'hierarchy "nato" has no catch-all rule: POST /v1/resource-label-rules with prefix "" first, or pass ?allow_uncovered=true'),
    )

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    fireEvent.change(await screen.findByLabelText('Hierarchy'), { target: { value: 'nato' } })
    fireEvent.change(screen.getByLabelText('Level'), { target: { value: 'SECRET' } })
    screen.getByRole('button', { name: 'Add' }).click()
    ;(await screen.findByRole('button', { name: 'Save caps' })).click()

    expect(await screen.findByRole('alert')).toHaveTextContent('no catch-all rule')
    // Not sent with the override on the first attempt.
    expect(put).toHaveBeenCalledWith(agent().id, { nato: 'SECRET' }, false)

    ;(await screen.findByRole('button', { name: 'Apply anyway (uncovered)' })).click()
    await waitFor(() => expect(put).toHaveBeenLastCalledWith(agent().id, { nato: 'SECRET' }, true))
  })

  it('says an empty cap set means no ceiling is enforced', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({})

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    expect(await screen.findByText(/no classification ceiling is enforced/i)).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd clients/ui && npm run test -- agents
```

- [ ] **Step 3: Implement the agent form**

`useEditor` as in Task 7, with:

```tsx
const BLANK: Agent = {
  id: '', name: '', provider: '', model_id: '', trust_tier: 0,
  enabled: true, suspended: false, allowed_tools: [], created_at: '', updated_at: '',
}
```

Fields: `name`, `provider`, `model_id` as `TextInput`; `trust_tier` as `NumberInput` (0-3); `enabled` and `suspended` as `Checkbox`; `allowed_tools` as `StringListInput` with the hint *"One per line. Empty means unrestricted."*

**No caps field.** The draft is seeded from `api.agent(id)`, whose response includes `classification_caps` — strip it before sending so the body cannot carry a value the server ignores:

```tsx
// classification_caps is returned by GET and IGNORED by PUT (store.UpdateAgent
// passes eight parameters and caps is not among them). Sending it back would
// put a field on the wire that silently does nothing; caps are written through
// their own route below.
const res = useMemo(() => ({
  get: api.agent,
  create: api.createAgent,
  update: (id: string, a: Agent) => {
    const { classification_caps: _ignored, ...body } = a as Agent & { classification_caps?: unknown }
    return api.updateAgent(id, body as Agent)
  },
  onSaved: reload,
}), [reload])
```

- [ ] **Step 4: Implement the caps panel**

A separate section inside the same `Panel`, below the agent form's Save, loaded independently when an existing agent is opened:

```tsx
function CapsSection({ agentID }: { agentID: string }) {
  const [caps, setCaps] = useState<ClassificationCaps | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    api.agentCaps(agentID).then(
      (c) => { if (live) setCaps(c ?? {}) },
      (err: unknown) => { if (live) setError(describeError(err)) },
    )
    return () => { live = false }
  }, [agentID])

  if (caps === null) return error ? <ErrorBanner>{error}</ErrorBanner> : <Loading />

  const entries = Object.entries(caps)
  return (
    <section className="mt-6 border-t border-border pt-4">
      <h4 className="mb-1 text-sm font-semibold">Classification caps</h4>
      <p className="mb-3 text-xs text-muted-foreground">
        The per-hierarchy ceiling copied onto every root delegation for this agent.
        An empty set is the off switch — with none set, no classification ceiling is
        enforced. Set any cap and a resource with no label DENIES.
      </p>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}

      {entries.length === 0
        ? <p className="mb-3 text-sm text-muted-foreground">None — no classification ceiling is enforced for this agent.</p>
        : entries.map(([hierarchy, level]) => (
          <div key={hierarchy} className="mb-2 flex items-center gap-2">
            <span className="w-32 font-mono text-sm">{hierarchy}</span>
            <TextInput
              value={level}
              onChange={(e) => setCaps({ ...caps, [hierarchy]: e.target.value })}
            />
            <Button variant="ghost" size="sm" onClick={() => {
              const next = { ...caps }; delete next[hierarchy]; setCaps(next)
            }}>Remove</Button>
          </div>
        ))}

      <NewCapRow onAdd={(h, l) => setCaps({ ...caps, [h]: l })} />

      <div className="mt-3 flex gap-2">
        <Button onClick={() => api.putAgentCaps(agentID, caps).then(
          (saved) => { setCaps(saved ?? {}); setError(null) },
          (err: unknown) => setError(describeError(err)),
        )}>Save caps</Button>
        <Button variant="destructive" onClick={() => api.deleteAgentCaps(agentID).then(
          () => { setCaps({}); setError(null) },
          (err: unknown) => setError(describeError(err)),
        )}>Clear all caps</Button>
      </div>
    </section>
  )
}
```

`NewCapRow` is a two-`TextInput` row (hierarchy, level) with an Add button, holding its own local state and calling `onAdd` then clearing itself.

#### The caps panel is mostly the server's advisories, not the map

`AgentCapsView`'s own doc comment states the design: *"Every field beyond
ClassificationCaps is advisory: setting a cap has consequences that are
invisible in the stored value, and this type is where they are stated."* The
server computes those consequences precisely so a console can show them. A
panel that renders only `classification_caps` throws away the whole point.

First extend the type in `api.ts` — Task 7b added three of its fields, these
are the rest:

```ts
export interface AgentCapsView {
  agent_id: string
  classification_caps: ClassificationCaps
  catch_all: Record<string, string | null>
  unsatisfiable_tools: string[]
  live_delegations: number
  /** Fixed human-readable string, always "at next issuance". Display only —
   *  its own doc comment says clients must not branch on it. */
  applies: string
}
```

Render all four advisories:

**1. `live_delegations` — the one that matters most.** These are the agent's
delegations that are neither revoked nor expired, and the field's doc calls
them *"the delegations this cap does NOT affect. A warning, not a
confirmation."* Caps are copied onto a delegation at issuance, so tightening a
ceiling changes nothing already in flight. An operator lowering a cap during an
incident would otherwise believe they had stopped something that is still
running. Pair it with `applies`:

> Saved. This takes effect **at next issuance** — N live delegations already
> carry the previous cap and are unaffected. Revoke them on the Delegations
> screen to apply this now.

**2. `unsatisfiable_tools`, phrased carefully.** These are tools that can never
satisfy *any* cap, because they produce no resource to classify — not "denied
by this cap", denied by every cap. **The list is not exhaustive for an
unrestricted agent.** Its doc is explicit: for `allowed_tools == []` there is no
finite list to scan, so an empty result means only that every *catalogued* tool
is satisfiable. Word it to match, or the empty state becomes a false assurance:

- restricted agent: `These tools can never satisfy any cap: …`
- unrestricted agent (`allowed_tools` empty): `Of the catalogued tools, these can never satisfy any cap: … Uncatalogued tools cannot be listed for an unrestricted agent.`

**3. `catch_all`** — per capped hierarchy, the level the empty-prefix rule
resolves to, or `null` where there is none. Show it beside each cap: it is what
an unlabelled resource resolves to, and therefore what decides whether the cap
bites.

**4. The uncovered-hierarchy refusal, and its override.** Capping a hierarchy
with no catch-all rule is **refused by default** (`internal/store/agent_caps.go`),
with a message naming the two ways forward: create a `prefix: ""` label rule, or
pass `?allow_uncovered=true`. So `putAgentCaps` needs the flag:

```ts
  putAgentCaps: (id: string, caps: ClassificationCaps, allowUncovered = false) =>
    request<AgentCapsView>('PUT',
      `/v1/agents/${encodeURIComponent(id)}/classification-caps` +
        (allowUncovered ? '?allow_uncovered=true' : ''),
      { classification_caps: caps }),
```

Do not send the flag by default and do not pre-empt the refusal client-side.
Save normally; when the server refuses, show its message verbatim and offer one
explicit control — `Apply anyway (uncovered)` — that retries with the flag.
The refusal is an acknowledgement gate, and acknowledging it has to be a
separate deliberate act, not a checkbox someone leaves ticked.

Render `<CapsSection agentID={editor.editingID} />` only when `editor.editingID !== null` — an agent that does not exist yet has no sub-resource.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd clients/ui && npm run lint && npm run test
```

- [ ] **Step 6: Commit**

```bash
git add clients/ui/src/screens/agents.tsx clients/ui/src/screens/agents.test.tsx
git commit -m "feat(ui): edit agents, and set classification caps separately

The caps control is not on the agent form and does not travel in the agent
body. store.UpdateAgent passes eight parameters -- name, provider, model_id,
trust_tier, enabled, suspended, allowed_tools, id -- and classification_caps
is not among them: it is read back via RETURNING and never written. A field
for it here would accept input, save without error, and change nothing, which
is an operator believing they had tightened a security ceiling that never
moved.

GET returns the column, so the update path strips it before sending rather
than putting a silently-ignored key on the wire.

Caps go to their own route at their own role floor (RoleAdmin, where the
agent body is RoleEditor -- that gap is the privilege-escalation fix). The
panel states the rule the feature turns on: an empty set enforces nothing,
and setting any cap makes an unlabelled resource deny."
```

---

### Task 11: Policies — editor, Validate, Test

The largest screen and the last, because it depends on Task 2's route and has the most field rules.

**Files:**
- Modify: `clients/ui/src/screens/policies.tsx`, `clients/ui/src/display.ts`
- Modify: `clients/ui/src/screens/policies.test.tsx`

**Interfaces:**
- Consumes: `api.policyLanguages`, `.policy`, `.createPolicy`, `.updatePolicy`, `.deletePolicy`, `.validatePolicy`, `.testPolicy`, `type PolicyTestVerdict`.
- Produces: `declaresEffect(language: string): boolean` exported from `display.ts`.

- [ ] **Step 1: Export `declaresEffect` from `display.ts`**

The set already exists as the module-private `DECLARED_EFFECT_LANGUAGES`. Add beneath `policyEffect`:

```ts
/** Whether an operator may choose this language's stored `effect`.
 *
 *  For cedar and json the store checks the column against what the text
 *  declares and refuses a disagreement. For rego and xacml it refuses
 *  anything except multiValuedLanguageEffect ("deny") outright
 *  (ErrEffectNotDeclarable) -- so an effect selector on those languages would
 *  offer two options of which one is a guaranteed rejection. */
export function declaresEffect(language: string): boolean {
  return DECLARED_EFFECT_LANGUAGES.has(language)
}
```

- [ ] **Step 2: Write the failing tests**

Append to `clients/ui/src/screens/policies.test.tsx`:

```tsx
describe('PoliciesScreen editor', () => {
  it('offers the languages the server reports, not a hardcoded list', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar', 'json', 'rego', 'xacml'])

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    screen.getByRole('button', { name: 'New policy' }).click()

    const select = await screen.findByLabelText('Language')
    expect(Array.from((select as HTMLSelectElement).options).map((o) => o.value))
      .toEqual(['cedar', 'json', 'rego', 'xacml'])
  })

  // For rego and xacml the store refuses any effect except "deny"
  // (ErrEffectNotDeclarable). A selector there would offer a guaranteed 4xx.
  // BLANK holds language: '' and languages arrive asynchronously. A draft that
  // reaches the panel with '' renders "A  policy can define rules of both
  // effects" -- declaresEffect('') is false and the name interpolates empty.
  it('never opens an editor on the empty language', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar', 'rego'])

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    ;(await screen.findByRole('button', { name: 'New policy' })).click()

    const select = await screen.findByLabelText('Language')
    expect((select as HTMLSelectElement).value).toBe('cedar')
    expect(screen.queryByText(/^A\s+policy can define/)).not.toBeInTheDocument()
  })

  // An empty list means either "not loaded" or "this build registers no
  // engines". Neither permits authoring, and a form with an empty selector
  // invites a save that cannot succeed.
  it('offers no New policy button when the build registers no engines', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue([])

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    expect(await screen.findByText(/no policy engines registered/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'New policy' })).not.toBeInTheDocument()
  })

  it('offers no effect choice for a language that cannot declare one', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar', 'rego'])

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    screen.getByRole('button', { name: 'New policy' }).click()

    const select = await screen.findByLabelText('Language')
    expect(screen.getByLabelText('Effect')).toBeInTheDocument()

    fireEvent.change(select, { target: { value: 'rego' } })

    await waitFor(() => expect(screen.queryByLabelText('Effect')).not.toBeInTheDocument())
    expect(screen.getByText(/resolved only when a request is evaluated/i)).toBeInTheDocument()
  })

  it('sends deny as the effect for a language that cannot declare one', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['rego'])
    const create = vi.spyOn(api, 'createPolicy').mockResolvedValue(policy({}))

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    screen.getByRole('button', { name: 'New policy' }).click()

    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'p' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ language: 'rego', effect: 'deny' }),
    ))
  })

  // validate fails CLOSED: an unparseable candidate is a 400 carrying the
  // engine's message, not a 200 with valid:false. The engine's words are the
  // only useful part.
  it('shows the engine’s own message when validation refuses', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar'])
    vi.spyOn(api, 'validatePolicy').mockRejectedValue(
      new APIError(400, 'cedar: unexpected token at line 2'),
    )

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    screen.getByRole('button', { name: 'New policy' }).click()
    ;(await screen.findByRole('button', { name: 'Validate' })).click()

    expect(await screen.findByRole('alert')).toHaveTextContent('unexpected token at line 2')
  })

  // The two legs answer different questions and can disagree: a policy correct
  // in isolation may be overridden or made redundant by an existing one. That
  // divergence is the most valuable thing this endpoint reports.
  it('renders both legs and says so when they disagree', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar'])
    vi.spyOn(api, 'testPolicy').mockResolvedValue({
      isolated: { effect: 'deny', reason: 'classification SECRET exceeds cap' },
      with_existing_policies: { effect: 'allow', reason: 'permitted by policy 3f2a', policy_id: '3f2a' },
      tier: { value: 1, source: 'declared' },
      legs_evaluated: { principal: true, agent: true, delegation: true },
    })

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    ;(await screen.findByRole('button', { name: 'New policy' })).click()
    ;(await screen.findByRole('button', { name: 'Test' })).click()
    ;(await screen.findByRole('button', { name: 'Run test' })).click()

    expect(await screen.findByText(/classification SECRET exceeds cap/)).toBeInTheDocument()
    expect(screen.getByText(/permitted by policy 3f2a/)).toBeInTheDocument()
    // The divergence must be called out, not left for the reader to spot.
    expect(screen.getByText(/differ/i)).toBeInTheDocument()
  })

  it('renders the test verdict, effect and reason together', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar'])
    vi.spyOn(api, 'testPolicy').mockResolvedValue({
      effect: 'deny', reason: 'resource classification SECRET exceeds cap CONFIDENTIAL',
      source: 'policy', policy_id: 'p1',
    })

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    screen.getByRole('button', { name: 'New policy' }).click()
    ;(await screen.findByRole('button', { name: 'Test' })).click()
    screen.getByRole('button', { name: 'Run test' }).click()

    expect(await screen.findByText(/exceeds cap CONFIDENTIAL/)).toBeInTheDocument()
  })
})
```

- [ ] **Step 3: Run to verify they fail**

```bash
cd clients/ui && npm run test -- policies
```

- [ ] **Step 4: Implement the editor**

`useEditor` as in Task 7, with:

```tsx
const BLANK: Policy = {
  id: '', name: '', description: '', language: '', policy_content: '',
  effect: 'deny', version: 0, enabled: true, created_at: '', updated_at: '',
}
```

Load the languages once. **The draft must never hold `language: ''`** — the
effect control branches on `declaresEffect(draft.language)`, and for `''` that
is false, so an unloaded language renders the "cannot declare an effect"
message with a blank language name in it. Two rules:

- `create()` seeds from the first loaded language, not from `BLANK`'s `''`:
  `editor.create({ ...BLANK, language: languages[0] })`.
- **While `languages` is empty, offer no New policy button at all.** An empty
  list has two causes and both make authoring impossible: the request has not
  resolved yet, or this build registers no engines (the server returns `[]`,
  never `null` — there is a Go test pinning exactly that). Render `Loading` in
  the first case; if the fetch resolved to an empty array, say so plainly —
  *this build has no policy engines registered, so policies cannot be
  authored here* — rather than presenting a form whose language selector has
  nothing in it.

Editing an existing policy is unaffected: its language comes from the stored
row, which the database's own CHECK constrains to the four valid values.

Load them once:

```tsx
const [languages, setLanguages] = useState<string[]>([])
useEffect(() => {
  let live = true
  api.policyLanguages().then(
    (ls) => { if (live) setLanguages(ls) },
    () => { if (live) setLanguages([]) },
  )
  return () => { live = false }
}, [])
```

Fields: `name`, `description` as `TextInput`; `language` as `Select options={languages}`; `enabled` as `Checkbox`; `policy_content` as `Textarea`.

The effect control is conditional, and switching to a non-declaring language pins the value:

```tsx
{declaresEffect(editor.draft.language) ? (
  <Field label="Effect" htmlFor="effect"
    hint="Checked against what the policy text declares; a disagreement is refused.">
    <Select id="effect" options={['allow', 'deny']} value={editor.draft.effect}
      onChange={(e) => editor.patch({ effect: e.target.value })} />
  </Field>
) : (
  <p className="mb-3 text-xs text-muted-foreground">
    A {editor.draft.language} policy can define rules of both effects, resolved only when a
    request is evaluated. The stored effect is a fixed placeholder for this language and is
    not yours to choose.
  </p>
)}
```

and in the language `onChange`:

```tsx
onChange={(e) => {
  const language = e.target.value
  // The store refuses anything but multiValuedLanguageEffect for a language
  // whose engine cannot declare an effect, so switching pins the value rather
  // than carrying the previous language's choice into a guaranteed refusal.
  editor.patch(declaresEffect(language) ? { language } : { language, effect: 'deny' })
}}
```

- [ ] **Step 5: Implement Validate and Test**

Validate is one button and one state:

```tsx
const [validation, setValidation] = useState<string | null>(null)
// ...
<Button variant="outline" onClick={() => {
  setValidation(null)
  api.validatePolicy(editor.draft!.language, editor.draft!.policy_content).then(
    () => setValidation('valid'),
    (err: unknown) => setValidation(describeError(err)),
  )
}}>Validate</Button>
```

Render `validation === 'valid'` as a `Badge tone="good"`, anything else through `ErrorBanner` — a refusal is a 400 carrying the engine's own words.

Test is a prefilled JSON textarea. The prefill is a complete valid request, so its shape documents itself:

```tsx
function blankTestRequest(language: string, text: string): string {
  return JSON.stringify({
    language,
    policy_content: text,
    principal: { subject: 'operator@example.com', attributes: {} },
    action: { tool: 'Read', raw_input: '{"file_path":"/tmp/notes.txt"}' },
    resource: { id: '/tmp/notes.txt' },
    agent: { trust_tier: 2, enabled: true, suspended: false, allowed_tools: ['Read'] },
    delegation: { depth: 0, max_action_tier: 1, classification_caps: {}, purpose: 'testing' },
  }, null, 2)
}
```

A `Test` button reveals a `Textarea` seeded with that plus a `Run test` button
calling `api.testPolicy(...)`. Render a `JSON.parse` failure as an
`ErrorBanner` saying the request is not valid JSON, so a typo is never
mistaken for a policy verdict.

#### The response is TWO verdicts, and the difference between them is the point

`PolicyTestVerdict` as declared in `api.ts` is **one nested leg**, not the
envelope. The server returns (`test_input.go:185`):

```ts
export interface PolicyTestLeg {
  effect: string
  reason: string
  source?: string
  policy_id?: string
}

export interface PolicyTestResult {
  /** The candidate evaluated ALONE. singlePolicySource makes the fold see
   *  nothing but this policy, so this answers "did I write this rule
   *  correctly" with nothing else able to interfere. */
  isolated: PolicyTestLeg
  /** The candidate folded in with everything the tenant already has. This is
   *  what would actually happen. */
  with_existing_policies: PolicyTestLeg
  /** The tier, and which of the two paths produced it. */
  tier: { value: number; source: string }
  /** Which legs the evaluation actually ran. */
  legs_evaluated: { principal: boolean; agent: boolean; delegation: boolean }
}
```

Fix `api.ts` to return `PolicyTestResult` — nothing consumes `testPolicy` yet,
so this breaks no caller (confirm with a grep). Keep `PolicyTestLeg` exported;
the panel renders two of them.

**Render both, side by side, and say plainly when they disagree.** A policy can
be correct in isolation and still not change the outcome — overridden by an
existing policy, or redundant with one. That divergence is the single most
valuable thing this endpoint reports, and a UI showing one verdict hides it:

```
isolated                  deny   resource classification SECRET exceeds …
with existing policies    allow  permitted by policy 3f2a… (allow-ops-reads)

⚠ These differ. Your policy denies on its own, but folded in with this
  tenant's existing policies the request is allowed.
```

Also render `tier` (value plus whether it was derived or declared) and
`legs_evaluated` — a leg that did not run is a leg your test input did not
exercise, which is the usual reason a test "passes" without proving anything.

**Give the request a named type too.** The audit that found this also found
`testPolicy(req: unknown)` accepts anything: `decodeJSON` does not reject
unknown or missing fields, so a misnamed nested key (`rawInput` for
`raw_input`) yields a 200 carrying a silently different evaluation. Declare
`PolicyTestRequest` mirroring `policyTestRequest`'s json tags — `language`,
`policy_content`, `principal{subject,attributes}`, `action{tool,raw_input}`,
`resource`, `agent{trust_tier,enabled,suspended,allowed_tools}`,
`delegation{depth,max_action_tier,classification_caps,purpose}` — and have the
panel parse the textarea into it.

- [ ] **Step 6: Add delete, and run everything**

Edit and Delete buttons per row plus a `ConfirmRow`, following `label-rules.tsx`.

```bash
cd clients/ui && npm run lint && npm run test
cd ../.. && make test
```

Expected: the whole suite green, Go included.

- [ ] **Step 7: Commit**

```bash
git add clients/ui/src/screens/policies.tsx clients/ui/src/screens/policies.test.tsx clients/ui/src/display.ts
git commit -m "feat(ui): author policies, validate them, and test them

The language selector reads GET /v1/policy-languages rather than a constant,
so it cannot drift from the engines this build registers.

The effect control appears only for cedar and json. For rego and xacml the
store refuses any value except the fixed placeholder (ErrEffectNotDeclarable),
so a selector there would offer two options of which one is a guaranteed
rejection; switching to such a language pins the value instead of carrying
the previous choice into a refusal.

Validate fails closed -- an unparseable candidate is a 400 carrying the
engine's own message, not a 200 with valid:false -- so the engine's words are
what the panel shows.

Test is a prefilled JSON textarea rather than a fifteen-field nested form.
The prefill is a complete valid request, so the shape documents itself, and a
JSON parse failure is reported as a parse failure so a typo is never mistaken
for a policy verdict."
```

---

### Task 12: Tell operators the console exists

Plan-added, not from the spec. `docs/quickstart.md` walks a user from nothing to a working install and never mentions the admin UI; shipping full CRUD that no document points at repeats the problem this work started from.

**Files:**
- Modify: `docs/quickstart.md`, `docs/user-guide.md`

- [ ] **Step 1: Add a quickstart section**

Verified facts to write against — do not restate them from memory:

- **The PAP's port is ephemeral.** `docs/user-guide.md:127` derives it as
  `export PAP="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"`.
  Never write a literal `8080` as the host port.
- **`deploy/stratium` already prints it.** Both `up` and `status` emit a
  `pap=<host:port>` line (`deploy/stratium:1071` and `:1266`). The quickstart
  should point the reader at that line rather than teaching a second way to
  find it. `deploy/stratium:766` refuses to persist `pap_addr` at all — this
  project's standing rule is persist identity, never addresses.
- **`docs/quickstart.md` mentions the UI zero times today** (verified by grep).
  This is a new section, not an edit.

Add it after the step that brings the stack up. It should say: open the
`pap=` address `up` printed, sign in with the same Keycloak operator, and note
that the label rules and classification caps the quickstart installs with
`curl` are editable there. Keep it short — the quickstart's job is to get
someone running, and the console is one paragraph of that, not a tour.

- [ ] **Step 2: Update `docs/user-guide.md`**

It already mentions the UI at lines 96, 138, 159-170 and 373-389. Line 138
("Open `http://$PAP/` in a browser for the admin UI") is correct and stays.
Add the screen list and what each can now do. Correct any statement, anywhere
in the file, that describes the UI as read-only or as a viewer.

- [ ] **Step 3: Verify every claim you wrote**

For each screen you list, confirm it exists in `clients/ui/src/screens/` and is
exported from `screens/index.ts`. For each capability you claim, confirm the
`api.ts` method exists. A docs task that describes a console slightly
differently from the one that shipped is worse than no docs.

- [ ] **Step 4: Commit**

```bash
git add docs/quickstart.md docs/user-guide.md
git commit -m "docs: point operators at the admin console

quickstart.md walked a user to a working install without mentioning the UI at
all, and installs label rules and classification caps with curl -- both of
which are now editable in the browser."
```

---

## Self-Review

**Spec coverage.** Every section of the spec maps to a task: the write transport (4), form primitives (5), the file split (3), per-screen scope (7, 8, 9, 10, 11), N14 (asserted in the tests of 7, 8), the 403 change (1), `/v1/policy-languages` (2), GET-before-edit and the clobber guard (6), the testing standard (throughout). Task 12 is plan-added and labelled as such.

**Rulings made while writing this plan:**

1. **The stale-write guard compares whole objects, not `updated_at`.** The spec says `updated_at`; three of the five editable resources do not have one. Recorded in Task 4.
2. **`crud.ts` is `crud.tsx`.** It exports `Loading`, which returns JSX.
3. **The agent update path strips `classification_caps` before sending.** The spec says caps never travel on the agent body; since `GET` returns the column, honouring that requires an explicit strip rather than merely omitting a form field.
4. **Task 12 was added.** The spec is silent on documentation.

**Known gaps, deliberately not closed:**

- The optional `location.hash` deep links from the spec's decision 5 are not in any task. They are additive, cost about fifteen lines, and are easier to judge once the screens exist.
- The `Test` panel's JSON prefill hardcodes a plausible request. If the test-input shape changes server-side, the prefill goes stale and the operator sees a 400. No test guards this, because the shape lives in Go and the prefill in TypeScript — the same class of problem `/v1/policy-languages` solved for languages, left open here because the payload is far larger than a string list.
