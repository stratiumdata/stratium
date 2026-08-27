# Conformance cases

Every Stratium SDK — and the Go reference in `stratium-pep` — must pass these.
They encode behaviour that is otherwise reimplemented per language, where a
wrong answer is silent: a stale ALLOW served after a revocation, an escalation
timeout mistaken for approval.

Each case is one JSON object:

| Field | Meaning |
|---|---|
| `name` | Matches the filename. |
| `subject` | `"cache"` or `"escalation"` — which unit the runner exercises. |
| `config` | Unit configuration. Cache: `staleness_window_seconds`. Escalation: `poll_interval_seconds`, `timeout_seconds`. |
| `steps` | Ordered actions. Each has `at` (seconds on a fake clock) and an operation. |
| `expect` | What must be true at the end. |

The clock is fake and advances only via `at`. A runner that uses a real clock
is not running these cases.

## Cache steps

- `{"at": 0, "put": {"effect": "ALLOW", "epoch": 1, "delegation_expires_at": 1e9}}`
- `{"at": 29, "get": {"epoch": 1, "token_expires_at": 1e9}, "expect": "hit"}`

`expect` is `"hit"` or `"miss"`. A hit that fails any usability condition is a
miss — there is no third outcome.

Three rules a runner enforces, stated here the way the escalation section
states its own:

- Every step is a `put` or a `get`. A step that is neither is rejected rather
  than skipped — a silently-skipped step is a case that reports green while
  binding less than it reads as binding.
- Every `get` carries `expect`. A `get` without one reads the cache and
  asserts nothing.
- Every case contains at least one `get`. A case that only writes never reads
  the cache at all.

The third rule is **Python-only today.** Go's `runCacheCase` enforces the
first two (`conformance_test.go:252` and `:264`) but has no "case never gets"
check, so a fixture with no `get` step passes Go and fails Python. Python
being the stricter of the two is the safe direction — the case it rejects
binds nothing in either language — but an undocumented asymmetry inside a
suite whose stated purpose is that "a case that passes here and fails in Go is
a drift report" would be rediscovered as a false drift report. It is written
down instead. Do not close it by loosening Python.

## Escalation steps

- `{"at": 0, "poll": "pending"}` — the scripted GetApproval status at that instant
- `{"at": 4, "poll": "approved"}`
- `{"at": 0, "poll_raises": "connection reset"}` — GetApproval fails as a
  transport call instead of returning a status. The message text is not
  asserted on; a runner just needs to make the poll call raise.

`expect` always carries `retried` (whether Decide was retried) and at least
one of `effect` (`"ALLOW"`, `"DENY"`, or `null` for a transport failure) or
`allowed` (`true`/`false`); `reason_contains` is optional. A case asserting
neither `effect` nor `allowed` binds nothing and a runner must reject it. Use
`allowed` instead of `effect` whenever the case touches one of the divergences
below.

## Known divergences between implementations

Three differences are intentional, and a runner must not be written as though
they are bugs. They are recorded here rather than special-cased silently:

| Case | Go | Python | Why |
|---|---|---|---|
| An RPC error anywhere in the escalation path — the `GetApproval` poll, or the retry `Decide` after an approval | `EFFECT_DENY` | `effect` is `None` | Go's `(Effect, string)` return has no way to say "no decision was reached". Python's `Decision.effect` is `Effect \| None` and every transport failure in that SDK uses `None`. Both refuse the call. |
| Synthesised timeout wording | `approval X did not resolve within the escalation timeout` | `timed out after Ns without a decision` | Each implementation writes its own diagnostic. Cases assert that the reason names the approval id, never the phrasing. |
| Reason text on synthesised denials | `stratium-pep: …` | `stratium: …` | Prefix only; the retry's own PDP reason is passed through unprefixed by both, which is the part that matters. |

Cases covering these assert on **`allowed`**, never on the exact `effect` or
reason string, so both implementations can pass the same fixture honestly.
`escalation-poll-failure-is-not-an-allow.json` is what binds the first row —
it scripts a `poll_raises` step and asserts only `allowed: false`.

The first row deliberately names two call sites, because they are two
instances of ONE divergence rather than two divergences. A failing retry
`Decide` after an approval has the identical shape: Go returns `EFFECT_DENY`
(`escalation.go:204`), Python returns the retry's own decision with
`effect is None` (`_escalation.py:86`). Only the poll instance has a fixture
today; a case added for the retry instance is covered by this same row and
must assert `allowed` for the same reason. Do not record it as a new
divergence. Adding that case is a format change, not a fixture-authoring job:
no step key scripts the retry's `Decide` — both runners hardcode their
`retry()` to ALLOW — so binding the retry instance means designing a new step
key and changing every runner that reads these cases.

## `cache-never-serves-an-escalation` binds behaviour, not structure

The reference implementation refuses to serve a cached ESCALATE from two
places: `put` refuses to store one, and `_usable` refuses to serve one even
if it were stored. Both are optional on their own — an implementation with
only one of the two guards is conformant, because the case asserts the
observable outcome ("was an ESCALATE ever served"), not which internal guard
produced it. Do not read this case tolerating a single guard as a defect in
the suite and go add a second assertion to force both; there is nothing to
fix here.
