# Design — the PAP admin console

**Date:** 2026-08-23
**Status:** approved, not implemented

---

## The problem

`clients/ui` is a complete, tested, OIDC-authenticated React application
embedded in the `stratium-pap` binary. It is also a **read-only viewer**, and
not by omission of screens — by omission of transport. `api.ts`'s only request
helper is:

```ts
async function request<T>(method: string, path: string): Promise<T>
```

There is no body parameter. Seven of its eight calls are `GET`; the eighth is
`revokeDelegation`, a `POST` with an empty body. Nothing in this application can
create or edit anything.

Meanwhile the PAP exposes full CRUD on six resources plus two policy verbs. The
gap:

| Capability | API | UI today |
|---|---|---|
| List the six resources | yes | yes |
| Revoke a delegation | yes | yes |
| Approve / deny an approval | yes | **no** |
| Create/edit policy, agent, tier override, tool catalog | yes | **no** |
| `resource-label-rules` | yes, full CRUD | **no screen at all** |
| `classification-caps` | yes | **no** |
| `policies/validate`, `policies/test` | yes | **no** |

The two missing resources are the two newest, and they are the pair that
produces every denial in the demos: label rules assign the classification, caps
set the ceiling. `deploy/stratium up` installs both with `curl` because there is
nowhere to click.

The approvals gap is the sharpest. The escalation feature's premise is a human
deciding — `STRATIUM_PEP_APPROVAL_TIMEOUT` exists to hold a tool call open for
exactly that person. This UI lists pending approvals and offers no button, so
that human reaches for `curl` while an agent blocks.

## What already exists, and is therefore not built here

| Thing | State |
|---|---|
| React app, Vite, vitest, ESLint | `clients/ui`, 1779 lines incl. tests |
| OIDC login + callback + token refresh | `auth.ts` (284 lines), `callback.ts` |
| shadcn-shaped primitives, no Radix | `ui.tsx`: Button, Badge, Card, Table, THead, TRow, TCell, EmptyRow, ErrorBanner, ScreenHeader |
| Six list screens | `screens.tsx` (373 lines) |
| Embedding into the PAP binary | `//go:embed dist`, proven real by `ui_test.go` |
| Build + test wiring | `make ui`, `make ui-test`; `make test` depends on both |
| Role enforcement | `routeTable`'s `MinRole` per route, server-side |

Dependencies today: `react`, `react-dom`. Bundle: 260K, of which 229K is React.

## Shorthand used below

The repository's own notation, carried into this spec so it matches the code
comments an implementer will read:

- **N14** — the UI never decides what an operator may do; it asks and reports.
- **N7** — an approval's approver is fixed to the delegation chain's root
  principal; a role is necessary but never sufficient.
- **R2 / R7** — the classification rules: an unlabelled resource denies under
  any configured cap (R2), and an empty-prefix label rule is the tenant-wide
  catch-all that prevents that (R7).

## Decisions

| # | Question | Decision |
|---|---|---|
| 1 | New UI or extend? | **Extend `clients/ui`.** A second UI for the same API is indefensible. |
| 2 | How to edit Cedar/Rego source? | **Monospace textarea + server-side Validate and Test.** Zero new dependencies. |
| 3 | Syntax highlighting? | **No.** CodeMirror plus `codemirror-lang-rego` (v0.1.0, one maintainer) and `codemirror-lang-cedar` (v0.2.7, untouched since 2024-09) is ~12 packages and roughly doubles a bundle that ships inside the enforcement binary. Correctness comes from the real compiler behind `/validate`, not from colouring. |
| 4 | Modal dialogs? | **No.** `ui.tsx` states a dialog means adding Radix. An inline panel replaces the table. |
| 5 | Router? | **No.** The current screen is `useState`. Optional `location.hash` deep links, ~15 lines, no dependency. |
| 6 | Generic CRUD component? | **No.** The seven screens are genuinely different shapes. Share `useResource()` and the panel shell only. |
| 7 | Client-side role gating? | **Never.** N14 stands. |

Decision 3 is the one most likely to be second-guessed later. The argument is not
that highlighting has no value — it is that this bundle is embedded in the binary
that enforces policy, and two single-maintainer grammars are a poor trade for
colour when the server holds a real Cedar and Rego compiler one request away.

Decision 6 resists the obvious abstraction. A schema-driven `<CrudScreen>` would
have to absorb: approvals (approve/deny on an immutable row), delegations
(revoke only), caps (a string map at a different role floor), tool catalog (no
delete exists), and policies (a code editor plus two extra verbs). The result is
the least readable file in the repository.

## Layout

```
clients/ui/src/
  api.ts               + body-carrying request(), + write methods, + 2 types
  ui.tsx               + Field, TextInput, NumberInput, Checkbox, Select,
                         Textarea, StringListInput, ConfirmRow, Panel
  crud.ts              useResource(): load / error / reload           (~40 lines)
  screens/
    index.ts           the SCREENS array
    policies.tsx       agents.tsx        tier-overrides.tsx
    tool-catalog.tsx   label-rules.tsx   approvals.tsx    delegations.tsx
```

`screens.tsx` is deleted; its six components move into `screens/` unchanged
apart from the additions below. At 373 lines today, adding CRUD for seven
resources to one file would exceed the 800-line ceiling in the project's own
coding-style rules.

## The write transport

```ts
async function request<T>(method: string, path: string, body?: unknown): Promise<T>
```

When `body` is present: `JSON.stringify` it and set `Content-Type:
application/json`. Everything else — the `Authorization` header, the 401 token
drop, the `APIError` carrying status plus the server's own body text — is
unchanged and already correct.

## The screens

Server-owned fields are never rendered as inputs. `PUT` is a full replace on
every resource, so each form holds every editable field and sends all of them.

### Policies — `Editor` to write, `Admin` to delete

Editable: `name`, `description`, `language`, `effect` (`allow` | `deny`),
`enabled`, `policy_content`.
Server-owned: `id`, `version`, `created_at`, `updated_at`.

**Four languages are registered, not two** — `newPolicyRegistry()` returns
`cedar`, `json`, `rego`, `xacml`. The selector does not hardcode them: it reads
`GET /v1/policy-languages` (new, `RoleViewer`), which returns the registry's own
keys. Hardcoding would be "a second thing to keep in step" — the exact failure
`uiConfig.IdPEndpoints` is deliberately not served in order to avoid — and its
symptom would be silent: register a fifth engine and the console simply cannot
author it, with nothing failing to say so.

Two extra actions, both `Editor`:

- **Validate** — `POST /v1/policies/validate` with `{language, text}`. It **fails
  closed**: an unparseable candidate returns **400 carrying the engine's own
  message**, not `200 {valid:false}`. The panel renders that body verbatim.
- **Test** — `POST /v1/policies/test`. The request is a full simulated
  authorization input: `{language, policy_content, principal{subject,
  attributes}, action{tool, raw_input}, resource{}, agent{trust_tier, enabled,
  suspended, allowed_tools}, delegation{depth, max_action_tier,
  classification_caps, purpose}}`. It is presented as a **prefilled JSON
  textarea**, not a fifteen-field nested form: the prefill is a complete valid
  request, so the shape documents itself, and it is strictly better than the
  `curl` it replaces. The response renders as a verdict card: `effect`,
  `reason`, `source`, `policy_id`.

### Agents — `Editor` to write, `Admin` to delete and to set caps

Editable: `name`, `provider`, `model_id`, `trust_tier`, `enabled`, `suspended`,
`allowed_tools` (string list).

**`classification_caps` is NOT on this form.** `store.UpdateAgent` passes eight
parameters — name, provider, model_id, trust_tier, enabled, suspended,
allowed_tools, id — and caps is not among them. It is read back via `RETURNING`
to populate the response but never written. A caps field on the agent form would
accept input, save without error, and change nothing: an operator would believe
they had tightened a security ceiling that never moved.

Caps get their own panel section, hitting `PUT`/`DELETE
/v1/agents/{id}/classification-caps` at `Admin`. A map editor of
hierarchy → level rows. The screen states the rule that governs the whole
feature: **an empty map is the off switch; any cap set makes unlabelled
resources deny.**

### Tier overrides — `Editor` to write, `Admin` to delete

Editable: `tool_or_verb`, `action_tier`. **Nothing else.** `store` ignores
`ID`, `TenantID`, `BuiltinTier`, `CreatedAt` and `CreatedBy` on input and sets
them authoritatively; `BuiltinTier` in particular must never be operator-supplied.
It is displayed beside the override so the operator can see what they are
overriding.

### Tool catalog — `Editor` to write, no delete

Editable: `tool_name`, `action_tier` (`number | null`), `verb`,
`resource_field`, `command_field`.

**The API has no `DELETE /v1/tool-catalog/{id}`,** so the screen offers none.

`action_tier` is nullable and `null` is not `0`. It renders as a "derive the
tier" checkbox; checked sends `null`, unchecked reveals a numeric input.

### Resource label rules — new screen, `Editor` to write, `Admin` to delete

Editable: `prefix`, `hierarchy`, `level`. Server-owned: `id`, `tenant_id`.

**`prefix` may legitimately be the empty string** and is not marked required.
`""` is a prefix of every resource id, making such a row R7's catch-all — the
documented answer to "a tenant enabled a cap and now everything denies."
`migrations/000019` deliberately omits a `length(prefix) > 0` CHECK. Enforcing
one in the browser would re-add the constraint the schema author refused to add,
and would remove the only tenant-wide unblock from the UI most likely to be open
when it is needed.

When `prefix` is empty the field renders the hint: *matches every resource —
this tenant's catch-all.* Deleting such a row warns that unlabelled resources
will deny under any configured cap.

`hierarchy` and `level` are stored verbatim and never case-folded on the way in;
the form does not normalise them either.

### Approvals — `Admin`

Approve and Deny buttons on pending rows, hitting
`POST /v1/approvals/{id}/{approve,deny}`. The row's existing columns are
unchanged.

N7's approver-identity check is enforced server-side: `respond.go` maps
`store.ErrApproverNotRootPrincipal` to a 403 whose message **carries only the
approval id**, deliberately echoing neither the operator identity nor the
approval's `root_principal`. The panel displays that message as-is and must not
attempt to render a "you are X, this needs Y" comparison — the server withholds
both halves on purpose.

### Delegations

Unchanged. `revokeDelegation` already exists.

## The four constraints

**1. N14 — the UI never decides who may do what.** Every button renders for
every operator. The request goes with the operator's own token and the server
refuses it or does not. No button is hidden, greyed, or pre-flighted against a
role. `TestViewer_CanListButCannotDecide` and `_CannotRevoke` prove those
refusals hold with this client bypassed entirely.

**2. The 403 must earn N14 — the first of two server changes.** `ui.tsx`'s `ErrorBanner`
comment claims "a 403 from the PAP says which role floor refused the request."
It does not. `server.go:357` and `:361` both write the bare word `forbidden`.
Under N14 a Viewer sees a Delete button and learns nothing from pressing it.
Both paths gain a real message:

```go
// resolveRole failed
"your token carries no recognised role claim"
// !role.meets(min)
"this action requires role admin; your token carries editor"
```

The role floors are already published in the route table and
`docs/user-guide.md`, so naming one discloses nothing. The false `ui.tsx`
comment is corrected in the same change.

**2b. `GET /v1/policy-languages` — the second server change.** `RoleViewer`,
returning `newPolicyRegistry()`'s keys sorted. It is the only way the browser
can know which languages this build actually supports, and deriving it from the
registry makes the selector incapable of drifting from the engines.

**3. Edit opens with a GET of the single object,** not the list row. `PUT` is a
full replace; the form must hold every field, freshly fetched.

**4. Last-write-wins, with a guard.** There is no `If-Match` and `Version` is
server-owned, so two operators editing one policy silently clobber. Before
saving, re-`GET` and compare `updated_at`; if it moved, refuse and say *"this
changed while you were editing"*. About ten lines, and it converts a silent
overwrite of policy into a prompt.

## Testing

`make test` already runs `ui` then `ui-test` before the Go suite, so these are
not optional and the embedded `dist` is rebuilt automatically.

Tests spy at the **`fetch` boundary and assert the serialized body**. Mocking the
`api` module and asserting `api.updatePolicy` was called proves the button is
wired to a function — not that the request carried `policy_content`, not that
`action_tier` was `null` rather than `0`. Every failure this suite exists to
catch is a field the form dropped or coerced.

| Test | Proves |
|---|---|
| `request()` with a body | Sends JSON and `Content-Type` |
| Each form's save | The payload carries every editable field |
| A stubbed 403 | The server's words render; no client-side gating |
| Label rule with `prefix: ""` | Empty prefix reaches the wire unrejected |
| Tool catalog "derive the tier" | Sends `action_tier: null`, never `0` |
| Agent caps control | Hits `/classification-caps`; the agent form never offers the field |
| `updated_at` moved | The clobber guard blocks and explains |
| Go: both 403 paths | The new messages name the floor and the missing claim |
| Go: `/v1/policy-languages` | Returns the registry's keys; adding an engine changes the response with no second edit |
| The language selector | Renders options from the endpoint, not from a constant |

## Out of scope

- **A router and deep links beyond an optional `location.hash`.**
- **Syntax highlighting** — decision 3.
- **A dialog library** — decision 4.
- **Tool catalog delete** — the API has none; adding one is a separate change.
- **An audit-log screen** — no API exists to back it.
- **Bulk operations** — no bulk endpoints exist.
- **Optimistic concurrency in the API** (`If-Match`/ETag). The client-side guard
  above is a mitigation, not a fix; a real fix belongs in the PAP.

## Risks

- **N14 plus a full CRUD surface means Viewers see buttons that always fail.**
  The 403 change makes that informative rather than mystifying, but it remains a
  deliberate trade: the alternative is a UI that claims an authorization
  decision it does not make.
- **The prefilled-JSON Test panel may prove clumsy.** Upgrade path: promote
  subject, tool, resource, tier and depth to real inputs and keep JSON as an
  advanced view. Deliberately not built first.
- **The clobber guard is best-effort.** It narrows the window; it does not close
  it. Two saves inside one round-trip still race.
- **`screens.tsx` is deleted and its contents move.** The diff will look larger
  than the behaviour change; the move is mechanical and should be its own commit.
