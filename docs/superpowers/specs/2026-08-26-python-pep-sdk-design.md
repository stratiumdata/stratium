# Design — a Python SDK for building a custom PEP

**Date:** 2026-08-26
**Status:** approved, not implemented
**Scope:** the first of five language SDKs. Go, Java, JavaScript and C++ follow
this one, and only after it has been proven against a live stack.

---

## The problem

Stratium enforces policy through `stratium-pep`, one binary with five surfaces:
`session-start`, `hook`, `mcp`, `proxy`, `extauthz`. Each stands between an
agent and the thing it is about to do. A developer whose enforcement point is
none of those five — an in-process check inside their own service, a framework
integration, a language runtime nobody has written a surface for — has no
supported path. They must read the proto and infer the semantics.

This SDK gives them the calls, done well, so writing a PEP is a small amount
of ordinary code.

## Turnkey, and what that includes

A developer writing a PEP should not have to reimplement the lifecycle around
the two calls. This SDK owns it:

| Included | Why a PEP needs it |
|---|---|
| **Session lifecycle** | Mint a delegation, hold the token, re-issue it once when a denial names the token as the problem. Without it every PEP author writes their own expiry race. |
| **Escalation** | `EFFECT_ESCALATE` means a human must approve. The SDK polls `GetApproval` to a timeout and returns the settled outcome. |
| **Decision cache** | A PDP round trip per tool call is the difference between usable and not, and the staleness window is where correctness lives. |

**DPoP is not included, and does not apply to this shape.**
`CreateDelegation` mints a plain bearer token — `internal/pdpgrpc/delegation.go:235`,
"jkt is empty: CreateDelegation mints a bearer token". Sender-constraining
exists for tokens crossing a network boundary to a `proxy` or `extauthz` that
must prove the presenter holds the key. An in-process PEP holding the token it
minted has no such boundary. `Decide` denies a sender-constrained token
presented without a proof (`errNoProof`), but this SDK never holds one.

### The cost of turnkey, and the control on it

Turnkey means reimplementing per language what `stratium-pep` already has in Go:
roughly 1,461 lines across `cache.go` (513), `local_cache.go` (319),
`escalation.go` (302), `session_file.go` (136), `reissue.go` (133) and
`config.go` (58). Five languages, five copies, each free to drift.

That risk is real and this repository has already demonstrated it at trivial
scale: `display.ts` mirrored four tier-name strings from Go's `String()`,
carried a doc comment saying so, and had a test pinning them — and still
drifted, `PRIVILEGED` against `PLATFORM_TRUSTED`, undetected because the test
asserted the wrong value. `cache.go`'s 513 lines decide when a cached ALLOW may
still be served; the same failure there serves a decision the PDP has since
revoked, and reports nothing.

**So the design carries its own control: a language-agnostic conformance
suite.** A directory of JSON fixtures — scripted PDP responses, a fake clock,
and the decision each SDK must reach — that every implementation runs against.
Go included, so the reference is bound by it too.

```
sdk/conformance/
  cases/
    cache-serves-within-staleness-window.json
    cache-refuses-after-window.json
    escalate-approved-within-timeout.json
    escalate-times-out-is-not-an-allow.json
    transport-failure-is-not-a-decision.json
  README.md      what a runner must implement
```

Case names above are illustrative; the set that shipped is whatever
`sdk/conformance/cases/` currently holds. There is no re-issue case: re-issue
turned out to be reactive (below), so it has no fixed clock threshold a
language-agnostic fixture could script.

This is the same rule the rest of this repository already follows, applied
across languages rather than within one: **a duplicate is allowed only where
something automatically fails on divergence.** Five hand-written caches with a
shared suite is a defensible design. Five without one is five silent
authorization bugs waiting to be found separately.

The suite is built alongside the Python SDK and is a deliverable of this spec,
not a later intention.

## What already exists, and is therefore not built here

| Thing | State |
|---|---|
| The PDP's gRPC service | `proto/pdp/v1/pdp.proto`, 601 lines, 11 messages |
| Generated clients for all five target languages | `protoc` emits them; Go, Python, Java, JS and C++ are all first-class gRPC targets |
| Go stubs | `services/internal/pdpgrpc` — **`internal/`**, so no external Go code can import them. A Go SDK will need them moved to `pkg/`, as `grpctarget` already was. |
| Go generation | `make proto`, raw `protoc`, not buf |

**Reaching the PDP is close to free.** This SDK's value is entirely in what
the generated stub does not do.

## The API

Two calls are all a PEP needs.

```python
grant = client.create_delegation(
    subject="you@example.com", agent_id=AGENT,
    tools=["Read", "Grep"], max_action_tier=1,
    purpose="my custom PEP", ttl_seconds=3600,
)

d = client.decide(
    agent_id=AGENT, subject="you@example.com",
    tool="Read", raw_input={"file_path": "/tmp/notes.txt"},
    token=grant.token,
)
if d:
    ...do the thing...
else:
    ...refuse, showing d.reason...
```

`parent_delegation_id` on `create_delegation` is what builds chains — an
orchestrator handing narrower authority to a sub-agent.

### Types

```python
class Effect(Enum):
    DENY = 0; ALLOW = 1; ESCALATE = 2

@dataclass(frozen=True)
class Decision:
    allowed: bool              # True only when effect is ALLOW
    effect: Effect | None      # None means no decision was reached
    reason: str
    approval_id: str | None    # set when ESCALATE
    error: Exception | None    # set when the PDP could not be asked
    legs: Legs                 # principal / agent / delegation: effect + reason each
    denied_leg: str | None
    denied_at_depth: int | None

@dataclass(frozen=True)
class Grant:
    token: str
    delegation_id: str
    granted_scope: Scope       # what was granted, NOT what was asked for
    epoch: int
```

`granted_scope` is deliberately distinct from the requested scope. The PDP
narrows, and a PEP that assumes it received what it requested is wrong about
its own authority.

## The four footguns this API closes

**1. `Decision.__bool__` returns `allowed`.** Every Python object is truthy by
default, so `if client.decide(...)` against a plain object is **always true** —
the most natural line a developer writes would allow everything, silently and
unconditionally. Defining `__bool__` makes `if d:` and `if not d:` correct
rather than forbidding an idiom people will reach for regardless.

This is the mirror of `EFFECT_DENY = 0` in the proto, where an unset enum field
decodes to DENY and the language's default is already safe. Here the default is
maximally unsafe, so the SDK spends a `__bool__` buying back what protobuf got
for free.

**2. `decide()` returns on transport failure; it does not raise.** An exception
is one `except Exception: pass` away from becoming an allow. A returned
`Decision` whose `allowed` is False cannot be swallowed. `error` and `reason`
carry the failure so an outage stays visible.

**3. `effect is None` when nothing was decided.** The project's standing rule —
transport errors must never be recorded as policy decisions — made structural.
There is no `Effect` value to log, so audit code cannot claim the policy denied
when the PDP was never reached.

| | `allowed` | `effect` | `error` |
|---|---|---|---|
| Policy denied | `False` | `DENY` | `None` |
| Escalation required | `False` | `ESCALATE` | `None` |
| PDP unreachable | `False` | `None` | the transport error |

**4. `raw_input` is serialised deterministically.** Accepts a `str`, or a dict
rendered with `sort_keys=True` and no whitespace. The PDP digests this value for
approval matching, so a retry must produce identical bytes: two dicts differing
only in insertion order must not become two different approvals.

`Decision` is a frozen dataclass — it cannot be mutated into an allow after the
fact.

**ESCALATE is neither allow nor deny.** It means a human must approve first.
`allowed` is False for it, with `effect` and `approval_id` available to a PEP
that wants to wait. The boolean cannot pass an unapproved escalation.

## Layout

```
sdk/
  python/
    pyproject.toml         runtime: grpcio.  build: grpcio-tools
    stratium/
      __init__.py          the public surface: Client, Session, Decision,
                           Effect, Grant, Scope, Leg, Legs
      _session.py          mint, hold, cache, escalate, re-issue once on a
                           denial that names the token
      _escalation.py       poll GetApproval to a timeout
      _cache.py            decision cache and its staleness window
      _pdp/                generated stubs, committed
    tests/                 safety properties + the conformance runner
    example/custom_pep.py  a real PEP, run against a live stack
    README.md
sdk/conformance/           language-agnostic fixtures every SDK must pass
```

Everything under a leading underscore is private. The public surface is
whatever `stratium.__all__` lists, which shipped as eight names: `Client`,
`Session`, `Decision`, `Effect`, `Grant`, `Scope`, `Leg`, `Legs`. The four
beyond the original list are the value types a caller unavoidably receives —
`Session` is the turnkey entry point itself, and `Scope`, `Leg` and `Legs` are
reachable from a `Grant` or a `Decision`, so exporting them is what lets a
caller name and annotate what it was already handed. A PEP author still should
not need to know a cache exists, and still cannot reach into it.

`sdk/` rather than `clients/`: `clients/ui` is an application, not a library,
and four more SDKs follow.

Import name `stratium`, distribution name `stratium-sdk`. Generated stubs live
under `stratium._pdp` so nobody imports them by accident and couples their code
to protobuf types.

### Generated stubs are committed, and a check forbids drift

A published library whose users need `protoc` installed is a library people do
not install, so the stubs are committed. Committed generated code drifts, so
`make proto-python` regenerates and a check asserts regeneration produces **no
diff**.

This is the third instance of one pattern in this repository, and it is worth
stating as a rule: **a duplicate is allowed only where something automatically
fails on divergence.** `display.ts`'s tier names drifted until a parity test was
added. `dist/` is deliberately never committed, and `ui_test.go` fails if the
embedded copy is a placeholder. Neither a comment saying "keep in sync" nor a
convention is sufficient — it takes a check.

`make proto` currently emits Go only and requires `protoc-gen-go`. The Python
path needs `grpcio-tools` instead, so it is a separate target with its own tool
check, matching how that Makefile already fails loudly with an install hint.

## Testing

**Unit tests run an in-process gRPC server** serving a scripted PDP: real
protobuf serialisation, nothing leaving the process.

| Property | How |
|---|---|
| ALLOW allows; DENY and ESCALATE do not | three effects, three assertions |
| `bool(d)` tracks `allowed` | the footgun that would otherwise allow everything |
| Unreachable PDP: `allowed=False`, `effect is None`, `error` set | dial a closed port |
| dict `raw_input` is order-independent | same pairs, different insertion order, identical bytes |
| A cached ALLOW is not served past the staleness window | fake clock, one PDP response, two calls straddling the boundary |
| An escalation that times out is **not** an allow | scripted `GetApproval` that never settles |
| An approved escalation allows exactly once | the approval is spent, not reusable |
| A denial naming the token re-issues exactly once, and the retry's answer is final | scripted DENY whose reason names the token, then a fresh grant |

Each is mutation-verified: removing `__bool__` must fail the truthiness test;
making transport errors raise must fail the unreachable test; dropping
`sort_keys` must fail the determinism test; widening the staleness comparison
from `<` to `<=` must fail the cache test. A test that still passes with its
protection removed is not a test.

**The conformance suite is a second, independent gate.** Its fixtures are data,
not Python, so the same cases run against the Go reference and against every
SDK that follows. A case that passes in Python and fails in Go is a drift
report — which is the entire reason it exists.

## The live proof

`example/custom_pep.py`, roughly 60 lines, against `pdp-pap`:

1. Mint a delegation for `tools=["Read"], max_action_tier=1`
2. `decide(tool="Read", ...)` — expect ALLOW
3. `decide(tool="Bash", ...)` — expect DENY, because `Bash` is not in the grant
4. Print both with the PDP's own reason strings
5. Exit non-zero if either differs from expectation

**Assert on reason strings, not exit codes** — the standard `example/` already
holds, and what catches a denial that occurred for the wrong cause.

It takes the agent id as an argument; the Agents screen of the admin console
lists agents by name.

`pdp-pap` is chosen deliberately over a spare PDP: its tenant is the one the
admin console administers, so **the delegation the SDK mints appears in the
console** — the agent's name, the purpose the script passed, depth 0, and the
scope the PDP actually granted. That closes a loop no unit test can, through a
fully independent path, verifiable by a human in a browser.

## Out of scope

- **DPoP.** Not applicable to a PEP holding its own bearer token; see
  "Turnkey, and what that includes".
- **`IssueToken`.** `CreateDelegation` already returns a token; a separate
  issuance path is only needed for the sender-constrained flows this SDK does
  not serve. **The consequence, unstated until now:** where the reference
  re-issues a TOKEN for the delegation it already holds
  (`IssueToken{DelegationId: …}`), `Session._ask` calls `create_delegation`
  and re-mints a WHOLE delegation. Every refresh therefore produces a new
  delegation id and a new epoch, and since the delegation id is in the cache
  key, every entry the session holds becomes unreachable — the decision cache
  is discarded on every token refresh. An SDK written from this one should
  prefer `IssueToken` as soon as `stratium.Client` exposes it; `pdp.proto`
  already defines `PDPService.IssueToken`, so this is a missing SDK method,
  not a protocol limit.

  Second-order, and the part a future SDK author needs: because a re-mint
  changes the delegation id, `Session`'s two expiry conditions can never
  disagree. `_expires_at` is `token_expiry` of the same grant
  `_token_expires_at` is read from, and an entry written under an older
  delegation is unreachable rather than merely stale — so Python's
  `tokenNotExpired` condition can never be the deciding one. Go has no such
  redundancy: `hook.go:298` writes the reissued token's expiry under the
  UNCHANGED delegation id, while `consultCache` reads with the session file's
  original token, which `reissue.go` deliberately never writes back. Fixing
  the re-mint dissolves the redundancy and that condition starts carrying
  weight. Do **not** resolve the redundancy the other way by deleting a cache
  condition: it is redundant only for as long as this gap is open.
- **The other four languages.** This design is the reference they follow, and
  none should start before this one has run against a live stack.
- **A control-plane client for the PAP's 35 HTTP routes.** A separate program
  of work whose first task is an OpenAPI spec that does not exist.

## Known gap: the suite cannot bind a composition

`sdk/conformance/` has exactly two subjects, `cache` and `escalation`, and they
never compose. The cache subject drives the decision cache directly against one
implicit entry with no key concept at all; the escalation subject drives the
escalation resolver with no cache in sight.

That gap is not theoretical. It is how this SDK shipped its one security defect:
`Session.check` cached the decision produced *after* a human approved an
escalation, so one approval of `Bash(rm -rf /data)` authorized unlimited
identical repeats for the whole staleness window. Every unit was correct on its
own — `put()` refuses an `ESCALATE`, the resolver returns the settled verdict —
and the suite passed 11/11 the entire time, because the defect existed only in
the composition of two things it tests separately.

Two rules an SDK must obey are therefore bound by nothing in the shared suite:

- **Nothing derived from the escalation path is ever cached** — not the approved
  ALLOW, not a timeout's synthetic DENY, not a denial. Only the decision that
  settled before any wait began. It holds by POSITION, not by inspecting the
  resolved effect: that response is an ordinary ALLOW or DENY and no check on it
  could distinguish it from one the PDP reached unaided.
- **The delegation id is part of the cache key**, so a re-issue misses
  structurally rather than by convention.

Both are currently bound by one Python test and one Go test — in the two
implementations that already have them. A third language gets no signal from the
artifact that is supposed to be the cross-language contract.

Closing this needs a third conformance subject that drives a session-shaped
object end to end, designed to be drivable in five languages. That is a design
decision rather than a fixture, and it should be settled before the next SDK
starts rather than after.

## Risks

- **`grpcio` is a heavy runtime dependency** and a native wheel. Some Python
  environments resist it. There is no alternative for a gRPC client, and it is
  already installed in this repo's environment (1.76.0).
- **The example depends on an agent existing in `pdp-pap`'s tenant.** It takes
  the id as an argument rather than creating one, so a tenant with no agents
  gives a clear failure rather than a silent one.
- **Delegations minted by the example persist.** They expire on their TTL and
  are visible in the console; the example uses a short TTL and a purpose string
  that names itself.
