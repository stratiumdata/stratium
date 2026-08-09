# Phase 2b — Policy verdicts, the fold inside `Decide`, and provenance

Implements spec §3.8 **G7**. Four tasks.

**Why first.** No policy engine exists in this repository yet. Before any engine
is written, the contract it produces has to be settled, and the deny-overrides
fold has to live where it can be mutation-tested. Doing this after the first
engine lands means retrofitting the engine as well.

**Scope boundary.** No engine is implemented here. `policy.Unconfigured()`
remains the only provider; it simply returns a verdict instead of a `LegResult`.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- `internal/authz` stays **pure**: a `PolicyVerdict` is plain data. No engine
  dependency enters the package.
- **Deny-overrides ignores priority.** Priority is recorded for audit and
  debugging only (spec §3.3 Y7 removed priority as security-relevant). Anyone
  reintroducing priority ordering into the fold is reintroducing the bug class
  Y7 eliminated.
- Strict root `.golangci.yml`. `go test -race ./...`, `golangci-lint run ./...`,
  and `go vet -tags integration ./...` clean before each commit.

---

## Task 1 — `PolicyVerdict` and the fold

**Files:** `services/internal/authz/types.go`, `verdict.go` (new),
`compound.go`, and their tests.

```go
// PolicyVerdict is one policy's answer about the principal. It is plain data:
// the engines produce it, authz consumes it, and no engine dependency enters
// this package.
type PolicyVerdict struct {
	Effect Effect
	Reason string

	// Source names the engine or grant model — "cedar", "rego", "xacml",
	// "json", "entitlement". Recorded for provenance.
	Source string

	// PolicyID identifies the specific policy or entitlement row.
	PolicyID string

	// Priority is recorded for audit and debugging and is NOT consulted by the
	// fold. Deny-overrides makes priority security-irrelevant (spec §3.3 Y7);
	// ordering by it here would reinstate the bug class Y7 removed.
	Priority int
}
```

Replace `Request.PrincipalDecision LegResult` with
`Request.PrincipalVerdicts []PolicyVerdict`.

**The fold**, in `verdict.go`:

```go
// FoldVerdicts combines policy verdicts with deny-overrides and default-deny.
//
//  1. any deny            -> DENY
//  2. otherwise no allow  -> DENY (default-deny)
//  3. otherwise any escalate -> ESCALATE
//  4. otherwise           -> ALLOW
//
// Step 2 is what preserves the invariant that an unevaluated principal leg
// denies. It used to hold because LegResult's zero value was EffectDeny; it
// now holds because a nil slice contains no allow. Same guarantee, different
// mechanism — which is why it is pinned by its own test rather than assumed
// to have carried over.
//
// The effect is order-independent by construction. The attributed reason is
// made order-independent too: among equally-decisive verdicts the fold picks
// the lexicographically smallest (Source, PolicyID), so a decision's recorded
// reason does not change between runs because a map iterated differently.
// Every verdict is preserved in provenance regardless, so nothing is lost.
func FoldVerdicts(vs []PolicyVerdict) (LegResult, *PolicyVerdict)
```

Wire it into `Decide`, replacing `res.Principal = req.PrincipalDecision`.

**Tests.** A table over: empty slice denies; nil slice denies; a single deny
denies; a single allow allows; allow + deny denies; allow + escalate escalates;
deny + escalate denies; several denies attribute deterministically to the same
one regardless of input order (shuffle and assert stability); the deciding
verdict is returned; and priority does **not** change any outcome — construct a
high-priority allow against a low-priority deny and assert DENY.

**Mutation-check your own tests** and report survivors: remove the deny loop;
remove the default-deny; swap steps 3 and 4; make the fold order-dependent by
dropping the deterministic selection.

---

## Task 2 — Provenance through `Result` and into the audit chain

**Files:** `services/internal/authz/types.go`, `compound.go`;
`services/pkg/audit/chain.go`; a new migration; and their tests.

`Result` gains:

```go
	// PrincipalVerdicts is every verdict consulted, in the order supplied.
	// Deciding names the one the reason was attributed to, or nil when the
	// decision was default-deny with no verdict at all.
	PrincipalVerdicts []PolicyVerdict
	Deciding          *PolicyVerdict
```

`audit.Entry` gains `PolicySource` and `PolicyID` (strings; empty when no
verdict decided).

**This will fail `TestHash_CoversEveryField`** — it asserts the mutation
table's length against `reflect.TypeOf(Entry{}).NumField()`. That is the guard
working, added after a review found `PrevHash` uncovered by the hash. **Update
the serialization and the mutation table; do not weaken the assertion.** Add
both fields to `Hash()`'s length-prefixed serialization and to the mutation
table, then confirm the field-coverage test catches their omission by deleting
each write in turn.

Add migration `000005_audit_policy_provenance` adding two nullable text
columns, and extend `store.AppendAudit`'s INSERT and tail read to carry them —
the tail read reconstructs a full `Entry` for `audit.Link`, so a missed column
breaks chain verification rather than merely losing data.

**Verify against a live database** that a chain written with provenance
verifies end to end, and that the down migration reverses.

---

## Task 3 — The policy provider returns verdicts

**Files:** `services/internal/policy/policy.go`, `policy_test.go`;
`services/internal/pdpgrpc/server.go` and its tests.

`PrincipalPolicy.Evaluate` returns `[]authz.PolicyVerdict`. `Unconfigured()`
returns exactly one verdict: `Effect: EffectDeny`, `Source: "none"`,
`Reason: "principal: no policy engine configured (Phase 2)"` — one verdict
rather than zero, so the specific reason survives into the response and the
audit row instead of being replaced by the generic default-deny text.

**Keep the no-allow guard.** It parses the package's AST for exported
constructors returning `PrincipalPolicy` and requires each to be wired into the
test. It now has to assert that no constructor produces a verdict slice
containing an `EffectAllow`. **Verify it still bites** by temporarily adding an
`AllowAll()` and confirming it is named.

The gRPC server passes the verdicts through and populates the response's
provenance fields.

---

## Task 4 — End-to-end verification

Extend the Phase 1c integration suite. Against a live stack:

1. A decision still denies at the principal leg, and the response now carries
   `source: "none"` and the specific unconfigured reason.
2. The audit row records the provenance, and `audit.Verify` passes over a chain
   whose entries carry it.
3. The concurrency measurement is unchanged — ten concurrent calls, one tenant,
   still 10/0. The audit row grew by two columns; confirm that did not disturb
   the advisory-lock path.
4. Compose still comes up clean from a fresh volume.

Report literal output for each. Clean up containers and volumes.
