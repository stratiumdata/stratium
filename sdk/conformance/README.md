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

## Escalation steps

- `{"at": 0, "poll": "pending"}` — the scripted GetApproval status at that instant
- `{"at": 4, "poll": "approved"}`

`expect` carries `effect` (`"ALLOW"`, `"DENY"`, or `null` for a transport
failure), `retried` (whether Decide was retried), and optionally
`reason_contains`.

## Known divergences between implementations

Two differences are intentional, and a runner must not be written as though
they are bugs. They are recorded here rather than special-cased silently:

| Case | Go | Python | Why |
|---|---|---|---|
| A `GetApproval` RPC error | `EFFECT_DENY` | `effect` is `None` | Go's `(Effect, string)` return has no way to say "no decision was reached". Python's `Decision.effect` is `Effect \| None` and every transport failure in that SDK uses `None`. Both refuse the call. |
| Reason text on synthesised denials | `stratium-pep: …` | `stratium: …` | Prefix only; the retry's own PDP reason is passed through unprefixed by both, which is the part that matters. |

Cases covering these assert on **`allowed`**, never on the exact `effect` or
reason string, so both implementations can pass the same fixture honestly.
