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

## What this is NOT

**Not an embeddable PEP.** `stratium-pep` carries roughly 1,461 lines of
surface-agnostic decision logic — `cache.go` (513), `local_cache.go` (319),
`escalation.go` (302), `session_file.go` (136), `reissue.go` (133),
`config.go` (58) — covering decision caching and its staleness window,
approval polling, session files, and re-issuance. None of that is in scope.

An SDK that reimplemented it would be reimplementing it five times, once per
language, each copy free to drift. This repository has already demonstrated
that failure at trivial scale: `display.ts` mirrored four tier-name strings
from Go's `String()`, carried a doc comment saying so, had a test pinning
them — and still drifted, `PRIVILEGED` against `PLATFORM_TRUSTED`, undetected
because the test asserted the wrong value. `cache.go` is 513 lines deciding
when a cached ALLOW may still be served. A staleness bug in a Python port
serves a decision the PDP has since revoked, and reports nothing.

A first SDK that says plainly it does not own those is better than one that
pretends to.

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
      __init__.py          Client, Decision, Grant, Effect — the public surface
      _pdp/                generated stubs, committed
    tests/                 the four safety properties, no network
    example/custom_pep.py  a real PEP, run against a live stack
    README.md
```

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

Each is mutation-verified: removing `__bool__` must fail the truthiness test;
making transport errors raise must fail the unreachable test; dropping
`sort_keys` must fail the determinism test. A test that still passes with its
protection removed is not a test.

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

- **Decision caching, approval polling, session files, re-issuance, DPoP.**
  `stratium-pep` owns these; see "What this is NOT".
- **`IssueToken` and `GetApproval`.** Needed for escalation handling, which
  arrives with it.
- **The other four languages.** This design is the reference they follow, and
  none should start before this one has run against a live stack.
- **A control-plane client for the PAP's 35 HTTP routes.** A separate program
  of work whose first task is an OpenAPI spec that does not exist.

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
