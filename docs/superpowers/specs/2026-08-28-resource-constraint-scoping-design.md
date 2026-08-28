# Design — scoping a delegation to a resource subtree

Gives `resource_constraints` a write path and prefix semantics, so an operator
can express the sentence §4.4 of the validation journeys says every operator
wants and none can write:

> this agent may do destructive things, but only under `/workspace/`

Status: design, approved 2026-08-28. Fix #2 in
[`docs/validation-journeys.md`](../../validation-journeys.md) §5.
Depends on the shell resource identity shipped the same day
([`2026-08-28-shell-resource-identity-design.md`](2026-08-28-shell-resource-identity-design.md)).

---

## The problem

`resource_constraints` is a real column, checked on every hop of every chain
(`internal/authz/delegation.go`'s `checkResourceConstraints`), and **no
supported caller can populate it.** `CreateDelegation` hardcodes an empty map
for every root and copies the parent's for every child; the PAP exposes only
`GET /v1/delegations` and `POST /v1/delegations/{id}/revoke`. Proven at
`TestIntegration_Journey43_ResourceConstraintsAreEnforcedButUnreachable`.

This matters because it is the only dimension that could answer §4.1. The
action-tier ladder cannot distinguish `rm -rf ./node_modules` from `rm -rf /`
— same tier, same required trust — so permitting the routine case permits the
catastrophic one. Scope is the axis that separates them, and it is the axis
with no setter.

## What makes this more than a missing setter

**The existing semantics cannot express a scope.** `checkResourceConstraints`
compares by exact string equality, deliberately: its own comment records that
prefixes, wildcards and ranges are each "a place a widening can hide, and
values here are opaque caller-defined strings with no ordering to narrow
along."

So a constraint can say *"exactly this one resource id"* and nothing else. A
write path alone would ship a feature that cannot do the thing it exists for.
Prefix semantics are the substance of this change; the setter is the easy half.

---

## Decisions

1. **A new `id_prefix` key with prefix semantics.** Every other key keeps
   today's exact-match behaviour untouched, so the strict rule and its
   rationale survive for the cases they were written for.
2. **Constraints live on the agent row**, set only by an operator, copied onto
   roots at issuance and onto children from their parents — mirroring
   `classification_caps` exactly (migration `000020`). The PEP that runs
   `session-start` is the untrusted party; it can neither set nor omit this.
3. **Every resource id must satisfy every prefix constraint.** A shell command
   naming three paths satisfies a constraint only if all three are under it.
   A decoy path adds an obligation rather than relieving one — the same safety
   shape as the strictest-wins label fold.
4. **An id containing a `..` segment fails any prefix constraint.** Rejected on
   the segment, never resolved: nothing here may assume a resource id is a
   filesystem path (it may be an S3 key, an API route, a document id).
5. **A constraint prefix must be non-empty and end with `/`**, validated at
   write time. This closes the boundary trap where `/workspace` matches
   `/workspace-evil/secrets.txt`, and keeps both matching and narrowing as a
   bare `strings.HasPrefix` with no boundary logic anywhere.
6. **A command naming no path denies** under a prefix constraint. `npm test`
   identifies nothing to check, and an unevaluable constraint must not read as
   a satisfied one.

Decisions 4 and 5 are the security core. Without 4, `cat /workspace/../etc/shadow`
satisfies `/workspace/`. Without 5, `/workspace` admits `/workspace-evil/`.

---

## Surface

### Storage

    -- migration 000021_agent_resource_constraints
    ALTER TABLE agents
        ADD COLUMN resource_constraints JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE agents
        ALTER COLUMN resource_constraints DROP DEFAULT;

Mirrors `000020_agent_classification_caps` exactly, including the two-step
default. The `DEFAULT` exists only to backfill existing rows and is dropped
immediately after, matching `000001_baseline`'s refusal to give
`delegations.approved_tools` or `delegations.classification_caps` a default:
an INSERT must state its intent rather than inherit a silent one.

### Routes

| Route | Role | Purpose |
|---|---|---|
| `PUT /v1/agents/{id}/resource-constraints` | `RoleAdmin` | set the scope |
| `GET /v1/agents/{id}/resource-constraints` | `RoleViewer` | read it |
| `DELETE /v1/agents/{id}/resource-constraints` | `RoleAdmin` | remove it |

`PUT` request:

```json
{ "resource_constraints": { "id_prefix": "/workspace/" } }
```

`PUT`/`GET` response, mirroring `models.AgentCapsView`:

```json
{
  "agent_id": "…",
  "resource_constraints": { "id_prefix": "/workspace/" },
  "unsatisfiable_tools": ["Glob", "Grep", "TodoWrite", "WebFetch", "WebSearch"],
  "live_delegations": 2
}
```

`unsatisfiable_tools` carries the same warning the caps view does and is
computed by the same rule: a catalogued tool with neither a `resource_field`
nor a `command_field` produces no identity, so it can satisfy no constraint at
all. The caps view's own helper was corrected on 2026-08-28 to stop reporting
`command_field` tools as unsatisfiable; both views should share it rather than
grow a second copy that can drift.

`live_delegations` is the same warning, for the same reason: this write does
not touch delegations already issued.

### Enforcement plumbing

`authz.Request` gains one field:

```go
// ResourceIDs are every identity this call resolved to — the catalogued
// resource field's own id, plus one per path a command_field tool's command
// names. Prefix constraints are evaluated against every member.
ResourceIDs []string
```

The PDP already builds exactly this slice for labelling; this is its second
consumer, not a second derivation. `DelegationLeg` takes it as a parameter.

---

## Semantics, in order

For each hop's constraints, given the request's `ResourceIDs`:

| Case | Result |
|---|---|
| No constraints | satisfied (unrestricted — unchanged convention) |
| A key other than `id_prefix` | exact match against `resource[key]`, exactly as today, including the deny-if-absent rule |
| `id_prefix` present, `ResourceIDs` empty | **DENY** — nothing to check, and unevaluable must not read as satisfied |
| Any id contains a `..` segment | **DENY** |
| Any id fails `strings.HasPrefix(id, prefix)` | **DENY**, naming the offending id |
| Otherwise | satisfied |

A `..` *segment*, not the substring: `/workspace/..hidden/x` is fine,
`/workspace/../x` is not. Split on `/` and compare each segment to `..`.

## Narrowing

`models.ScopeNarrows` gains one case: for `id_prefix`, a child narrows iff
`strings.HasPrefix(child, parent)` — deeper is narrower, shallower is wider,
equal is valid.

    parent /workspace/   child /workspace/src/   -> narrows, valid
    parent /workspace/   child /workspace/       -> equal, valid
    parent /workspace/   child /                 -> widens, REJECTED
    parent /workspace/   child /other/           -> not a subtree, REJECTED

§4.3.1's existing rules are unchanged: a child may still neither introduce a
key its parent leaves open nor drop one its parent sets.

## Validation, in order (write time)

1. Each key must be a non-empty string.
2. For `id_prefix`: non-empty, ends with `/`, contains no `..` segment.
3. Unknown keys are accepted — they are opaque caller-defined attributes with
   exact-match semantics, and the decision path already treats them that way.

## Errors

| Condition | Status |
|---|---|
| `id_prefix` does not end with `/` | `400`, naming the rule |
| `id_prefix` empty | `400`, directing to `DELETE` |
| `id_prefix` contains `..` | `400` |
| Agent not found, or another tenant's | `404` (indistinguishable, by design) |
| Caller below `RoleAdmin` | `403` |

---

## Testing

Pure, in `internal/authz` and `pkg/models`:

- Every id must satisfy: two ids under the prefix pass, one outside denies.
- A decoy cannot relieve an obligation: `[/workspace/a, /etc/shadow]` denies.
- `..` in any id denies, and `..hidden` does not.
- Empty `ResourceIDs` under a prefix constraint denies.
- Exact-match keys are bit-for-bit unchanged, including deny-if-absent.
- `ScopeNarrows`: deeper valid, shallower rejected, sibling rejected, equal
  valid; introduce and drop still rejected.

Live, on the PAP tenant:

- A fielded tool inside the prefix allows and outside denies.
- A shell command wholly inside the prefix allows.
- A shell command with one path outside denies, naming that path.
- `cat /workspace/../etc/shadow` denies.
- A path-free command denies.
- The constraint reaches the delegation through `PUT` → `CreateDelegation`,
  read back through `GET /v1/delegations`.

`TestIntegration_Journey43_ResourceConstraintsAreEnforcedButUnreachable`'s
second subtest asserts no write path exists. It must fail, which is its
`WHEN THIS FAILS` marker firing correctly, and it gets inverted.

## Out of scope

- **Per-session narrowing** via a `CreateDelegationRequest` field. Addable
  later as field 7 without breaking any client; YAGNI until someone needs one
  agent scoped to two directories.
- **Relaxing §4.3.1** so a child may introduce a constraint its parent leaves
  open. That is J6's separate question.
- **Prefix semantics for keys other than `id_prefix`.** Exact match stays the
  default for opaque attributes, for the reason its comment already gives.

## Risks

- **Prefix matching is only as good as the id.** A tool whose catalogued
  `resource_field` names something that is not a path makes `id_prefix`
  meaningless for it — not unsafe, but not the control an operator thinks they
  bought. `unsatisfiable_tools` does not catch this, because such a tool does
  produce an id. A second, narrower mismatch is cardinality rather than type:
  a fielded (non-shell) tool's `resource_field` yields exactly one id per
  call (`resourceFromID`), so a tool that acts on a LIST of targets is
  checked against only one of them. `satisfiesIDPrefix`'s "every identity
  must satisfy the prefix" guarantee is over the identities the PDP
  RESOLVED, not over every resource the call actually touches — the same gap
  as the type mismatch above, one call short of what the operator assumes is
  covered.
- **Setting a constraint silently disables tools**, exactly as a cap does. The
  response's `unsatisfiable_tools` is the mitigation and it is advisory. This
  is the same footgun J1 documented for caps, and the same argument for turning
  the caps API's list into a refusal applies here.
- **Under-extraction of shell paths weakens this too.** `ShellResourceIDs`
  missing a path means one fewer obligation, so a command could satisfy a
  constraint it should fail. That risk is recorded in the shell identity design
  and now has a second consumer — worth restating there.

## References

- `services/internal/authz/delegation.go` — `checkResourceConstraints`
- `services/pkg/models/delegation.go` — `ScopeNarrows` and §4.3.1
- `services/internal/store/agent_caps.go` — the mechanism this mirrors
- `services/migrations/000020_agent_classification_caps.*` — the migration shape
- [`docs/validation-journeys.md`](../../validation-journeys.md) §4.1, §4.3, §4.4, §5
- [`2026-08-28-shell-resource-identity-design.md`](2026-08-28-shell-resource-identity-design.md)
