# stratium-sdk

Python SDK for building a Stratium policy enforcement point (PEP) against the
PDP's gRPC service. It is a sixth way to enforce, alongside the five
`stratium-pep` subcommands documented in [`docs/pep/README.md`](../../docs/pep/README.md)
— a library you import and call, not a binary you configure.

Only runtime dependency: `grpcio`.

## Install

```bash
python3 -m pip install -e sdk/python          # to use it
python3 -m pip install -e 'sdk/python[dev]'   # to also run its tests
```

## The two calls

A PEP built with this SDK makes two calls: mint a delegation once, then check
every tool call against it.

```python
from stratium import Client, Session

# TLS by default, verified against the system roots. For a private CA pass
# ca_file="/path/to/ca.pem"; against the local Docker stack (plaintext) use
# Client(pdp_addr, insecure=True).
with Client(pdp_addr) as client:
    # Call one: get a token. Session's constructor makes it for you --
    # this is Client.create_delegation() under the hood.
    # A PDP verifies who the session is for by default: pass the person's OIDC
    # token as principal_token=..., and subject must equal the identity in it.
    # The local Docker stack has verification off, so it needs no token.
    session = Session(
        client, subject="you@example.com", agent_id=agent_id,
        tools=["Read"], max_action_tier=1,
        purpose="my custom PEP", ttl_seconds=300,
    )

    # Call two, made once per tool call.
    decision = session.check(tool="Read", raw_input={"file_path": "/tmp/x"})
    if decision:
        ...  # run the tool
    else:
        ...  # refuse it; decision.reason says why
```

`Session.check(*, tool, raw_input, resource=None)` is the turnkey surface
(`stratium/_session.py`): it consults an in-memory decision cache first, asks
the PDP on a miss, resolves an `ESCALATE` by polling for human approval and
retrying, and renews its token once if a denial names the token as the
problem. `stratium/_client.py`'s `Client.decide()` and
`Client.create_delegation()` are the lower-level calls `Session` is built on,
for a caller that wants to manage its own delegation lifecycle instead
(`example/custom_pep.py` uses `Session`, the recommended path — it is the only
one exercised against a live PDP so far).

`Session(..., harness="cursor")` names the agent harness whose tools the
session checks, so the PDP decides them under its shared tool names; leave it
out for tools of your own. `Session.report(tool=..., raw_input=...)` tells the
PDP a checked call has run, so it can flag one it never allowed. The
[LiteLLM guardrail](../../docs/pep/litellm.md) is built on both.

`Session(..., principal_token=None)` and
`Client.create_delegation(..., principal_token=None)` take the principal's OIDC
token from your identity provider. A root delegation needs it unless the PDP
runs with principal verification off, and the PDP reads the principal from the
token. A child is authorized by its parent's token instead, so passing
`principal_token` together with `parent_delegation_id` raises `ValueError`. A
`Session` uses the token once, to create its delegation.

A `Session` holds one delegation for its whole life and never creates
another. When that delegation expires or is revoked, every `check()` is
refused; `Session.expired` says when it has expired. Build a new `Session`
to carry on.

### What each step is bounded by

- **The cache** serves a hit only while all of: the delegation's `epoch`
  hasn't changed, the delegation itself hasn't expired, the token's own `exp`
  claim hasn't passed, and the entry is within `staleness_window` seconds of
  when it was written (default 30s) — all four in `stratium/_cache.py`'s
  `_usable()`. Entries are keyed on
  `(delegation_id, agent_id, subject, tool, raw_input)` — the delegation is
  part of the key, as it is in `stratium-pep`'s `cacheKey`, so a new `Session`
  never reads another's entries. **Nothing that comes out of the escalation path is
  cached** —
  not the `ESCALATE` itself (refused on both the write and the read side), and
  not the decision the wait eventually settles on: not the post-approval
  `ALLOW`, not a timeout's synthesised `DENY`, not a denial. A human approving
  one specific pending action is not the PDP producing a replayable verdict
  about every future identical call, so caching that `ALLOW` would let the next
  identical call skip the human step this one required — for the whole
  staleness window, with no PDP round trip and no second human. `Session.check`
  guarantees it by position rather than by inspecting the effect: the
  escalation branch returns directly and the `put` is only reachable on the
  path where no wait ever began, the same structure as `stratium-pep`'s
  `local_cache.go`.
- **Escalation** polls `GetApproval`, presenting the session's delegation
  token (the PDP reports an approval only to a holder of its delegation's
  token), every `approval_poll_interval` seconds
  (default 2.0) until it sees `approved`, `denied`, or `approval_timeout`
  seconds elapse (default 120.0) — `stratium/_escalation.py`'s
  `resolve_escalation()`, invoked from `Session.check` only when the PDP
  answers `ESCALATE` and hands back an `approval_id`. The wait is bounded by a
  poll count as well as by the timeout, so no injected `clock` can make it
  unbounded; a non-positive `approval_poll_interval` is refused as a `DENY`
  rather than polled.
- **Token renewal** happens at most once per `check()` call, only when the
  denial's reason mentions `"token"` or `"expired"`
  (`Session._token_is_the_problem`). The session asks the PDP for a new token
  for the same delegation (`Client.issue_token`), which the PDP gives only
  while that delegation is still good. A second denial after the renewal is a
  real denial with a fresh token, not another retry — matching
  `stratium-pep`'s own `reissue.go`, which makes the same deliberate choice
  not to loop.

Verified in `sdk/python/tests/test_session.py`:
`test_check_allows_and_caches` (one PDP round trip for two identical checks),
`test_the_cache_expires_and_the_pdp_is_asked_again` (a miss past the
staleness window), `test_an_escalation_retries_with_the_approval_id_and_can_allow`,
`test_a_token_denial_renews_the_token_once_and_the_retry_can_allow`,
`test_a_token_denial_renews_only_once_even_if_the_retry_denies_again` and
`test_a_session_never_replaces_its_delegation`.

## The public surface

Everything importable from `stratium` is in `stratium/__init__.py`'s
`__all__`: `Client`, `Session`, `Decision`, `Effect`, `Grant`, `Leg`, `Legs`,
`Scope`. Nothing else in this package is a supported interface — modules
named with a leading underscore (`_client`, `_session`, `_cache`,
`_escalation`, `_types`) can change shape between releases.

## Four safety properties

These are the reason this SDK exists rather than a PEP author calling the
generated gRPC stubs directly. Each one closes a mistake that is easy to make
against raw protoc output and hard to make against these types.

### 1. `Decision.__bool__` is `allowed` — and that has a cost

Every Python object is truthy by default, so without a `__bool__` override,
`if client.decide(...):` would be true for every response — an `ALLOW`, a
`DENY`, an `ESCALATE`, all the same. `Decision.__bool__` returns `self.allowed`
(`stratium/_types.py`), so the idiom a PEP author reaches for anyway is the
correct one. Verified by `test_truthiness_tracks_allowed` in
`sdk/python/tests/test_types.py`.

**The cost is sharp, and documented on the type itself:** a `Decision` is now
*falsy* unless it allows, so `some_decision or fallback` silently discards a
`DENY` or an `ESCALATE` and returns `fallback` instead — turning a refusal
into whatever the fallback says. This is not hypothetical: per
`Decision.__bool__`'s own docstring, it broke a test helper in this
repository written as `decision or allow()`, which quietly replaced every
`ESCALATE` under test with an `ALLOW`. Use an explicit `None` check instead
when defaulting: `d if d is not None else fallback`.

### 2. `allowed` is true only for `ALLOW` — `ESCALATE` still needs a human

`decision_from_response` sets `allowed = effect is Effect.ALLOW`
(`stratium/_types.py`). An `ESCALATE` response is not an allow and not (yet) a
denial: it means a human must approve before the call proceeds, and
`approval_id` is how a caller that wants to wait finds that approval.
Verified by `test_only_allow_is_allowed` and
`test_escalation_is_not_an_allow_but_says_so` in `tests/test_types.py`.

An unrecognized `Effect` value — one a newer PDP might send that this build
has never heard of — is read as `DENY`, not passed through as a raw int:
`test_an_unknown_effect_is_read_as_deny` binds this.

### 3. A transport failure returns, it does not raise

`Client.decide()` catches every exception — an unreachable PDP, a non-OK gRPC
status, a deadline — and returns `decision_from_error(err)` rather than
propagating it (`stratium/_client.py`). That `Decision` has `effect=None`,
never `Effect.DENY`, specifically so that nothing downstream can log or audit
"the policy denied this call" for a call the policy was never asked about.
`allowed` is still `False`, so the call is refused either way. Verified by
`test_unreachable_pdp_denies_without_raising` and
`test_a_pdp_error_status_is_also_not_a_policy_decision` in
`tests/test_client.py`, and `test_transport_failure_is_not_a_policy_decision`
in `tests/test_types.py`.

`Client.create_delegation()` is the one deliberate exception to "never
raises": it raises on failure instead of returning an empty `Grant`, because
there is no safe placeholder value for "you have no authority" that a caller
could mistake for permission — a PEP that cannot mint has nothing to enforce
with. Verified by
`test_create_delegation_raises_rather_than_returning_an_empty_grant`.

### 4. `raw_input` from a dict is serialized with sorted keys

`canonical_raw_input()` (`stratium/_types.py`) passes a `str` through
untouched, but renders a `Mapping` with `sort_keys=True` and no whitespace.
The PDP digests `raw_input` to match a retried call against the approval a
human granted, so `{"a": 1, "b": 2}` and `{"b": 2, "a": 1}` — the same call,
built by two different code paths — must serialize identically or a retry
after escalation would digest as a different call than the one approved.
Verified by `test_raw_input_is_canonical_and_order_independent` in
`tests/test_types.py` and, end to end, by
`test_decide_sends_the_fields_the_pdp_reads` in `tests/test_client.py`, which
asserts the wire request carries `'{"a":1,"b":2}'`.

## What the SDK owns, and what it does not

**It owns:** the session (creating a delegation and renewing its token, in
`stratium/_session.py`), escalation (polling and retrying an `ESCALATE`, in
`stratium/_escalation.py`), and the decision cache (`stratium/_cache.py`, a
Python port of `services/cmd/stratium-pep/cache.go`'s `cacheEntryUsable`).
All three are exercised through `Session.check()` — see "The two calls,"
above.

**It does not do DPoP** (RFC 9449 sender-constrained tokens), and the reason
is concrete rather than a scope cut: `CreateDelegation` mints a plain bearer
token. `services/internal/pdpgrpc/delegation.go:235` says so directly —
`// jkt is empty: CreateDelegation mints a bearer token, unchanged by Phase
15.` DPoP exists in this system for `stratium-pep proxy` and `extauthz`
(`docs/pep.md`, "Sender-constrained tokens on `proxy`"), where the token
travels from a caller the PEP does not control, over a network hop where it
could leak, to a PEP that must prove whoever is presenting it is the party it
was minted for. An in-process PEP built with this SDK mints its own token via
`Client.create_delegation()` and holds it itself — it is never handed the
token by someone else, and never hands it to anyone else — so there is no
sender-binding boundary here to prove. `IssueToken`, the RPC that accepts a
`dpop_jwk` and produces a bound token, is likewise out of scope: this SDK
never calls it.

## The conformance suite

`sdk/conformance/cases/*.json` (11 files as of this writing) are fixtures
that bind the decision cache and escalation logic across every Stratium SDK
*and* the Go reference in `stratium-pep` — not tests owned by one language,
but data every implementation must agree on. A case that passes in one
language and fails in another is a drift report, which is the entire reason
the suite is data files and not hand-written tests per language: see
[`sdk/conformance/README.md`](../conformance/README.md) for the field format
and the (small, deliberate, documented) list of divergences between Go and
Python wording that the cases are written to tolerate.

Run it in both languages from the repo root:

```bash
# Go reference (11/11 passing as of this writing)
make sdk-conformance

# Python (this SDK; also runs as part of `pytest tests/`)
cd sdk/python && python3 -m pytest tests/test_conformance.py -v
```

Note the target name: `sdk-conformance`, not `conformance` — the latter is
spec §7's pre-existing, unrelated property gate.

## The evaluation-order lesson

**A denial names the first gate that refused, not every gate that would
have.** This is the thing most likely to confuse a new PEP author, because
the PDP's `reason` string reads like a complete explanation and isn't one.

`example/custom_pep.py`, run against a live PDP and captured verbatim in
[`example/README.md`](example/README.md), mints a delegation scoped to
`tools=["Read"], max_action_tier=1` and checks three calls. The observed
output:

```
  ALLOW Read
  DENY  Grep   tool "Grep" not in delegation approved_tools at depth 0
  DENY  Bash   action tier DESTRUCTIVE exceeds delegation max_action_tier READ_ONLY at depth 0

enforcement: 3/3 as expected
```

`Bash` running `rm -rf /tmp/x` is denied for `max_action_tier` — its command
is classified `DESTRUCTIVE`, which exceeds this `READ_ONLY` delegation's
ceiling — and that check runs *before* the tool-name check, so `Bash`'s
denial never mentions `approved_tools` even though `Bash` isn't in that list
either. Only `Grep`'s denial, which clears the tier gate and is refused on
tool name instead, actually says so. Read `example/README.md` in full for the
PDP-side evaluation order (`DelegationLeg` in
`services/internal/authz/delegation.go`) that produces this, and for a case
where the example's own first draft asked one denial to prove two different
things and caught itself doing it.

## Development

Generated gRPC stubs (`stratium/_pdp/pdp_pb2*.py`) are committed so
installing the package does not require `protoc`. They're regenerated from
`proto/pdp/v1/pdp.proto` and checked for drift from the repo root:

```bash
make proto-python        # regenerate the stubs
make proto-python-check  # fail if the committed stubs are stale
```

Install for local development and run the unit tests (70 as of this writing,
including the 11 conformance cases above):

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest tests/ -q
```
