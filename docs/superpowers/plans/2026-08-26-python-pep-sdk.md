# Python PEP SDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A turnkey Python SDK for writing a custom PEP against the Stratium PDP, plus a language-agnostic conformance suite that every future SDK — and the Go reference — must pass.

**Architecture:** Generated gRPC stubs stay private under `stratium._pdp`. A thin public surface (`Client`, `Decision`, `Grant`, `Effect`) closes four footguns the raw stub leaves open. Three private modules own the lifecycle — session, escalation, cache — reimplementing behaviour that today lives only in `stratium-pep`'s Go. `sdk/conformance/` holds JSON fixtures encoding that behaviour once, so drift between implementations fails a test rather than shipping.

**Tech Stack:** Python 3.12, `grpcio` (runtime), `grpcio-tools` (build), `pytest`. Go 1.x for the reference conformance runner.

**Spec:** `docs/superpowers/specs/2026-08-26-python-pep-sdk-design.md`

## Global Constraints

- **`Decision.__bool__` returns `allowed`.** Every Python object is truthy by default, so `if client.decide(...)` on a plain object is always true and would allow every call.
- **`allowed` is `True` only for `EFFECT_ALLOW`.** `ESCALATE` is not an allow.
- **`decide()` returns on transport failure; it never raises.** An exception is one `except Exception: pass` from becoming an allow.
- **`effect is None` when no decision was reached.** Transport errors must never be recorded as policy decisions.
- **`raw_input` from a dict is serialised `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.** The PDP digests it for approval matching; a retry must produce identical bytes.
- **A cache entry is usable only if ALL FIVE hold**, matching `services/cmd/stratium-pep/cache.go`'s `cacheEntryUsable`: the decision is not `ESCALATE`; the epoch is current; the delegation is not expired; the token is not expired; and `now <= cached_at + staleness_window` (**inclusive** — Go is `!now.After(CachedAt.Add(staleness))`).
- **The staleness clock runs from the entry's own `cached_at`, never from last use.**
- **A cache hit failing any condition is indistinguishable from a miss.** Not a distinct outcome a caller can handle.
- **An escalation that times out is a DENY**, with a reason naming the timeout.
- **An approved escalation means retry `Decide`**; that retry's result is the answer. The approval is not itself an allow.
- **Everything under a leading underscore is private.** The public surface is `Client`, `Decision`, `Grant`, `Effect` only.
- **Generated stubs are committed, and `make proto-python` must produce no diff.**
- **No DPoP.** `CreateDelegation` mints a plain bearer token (`internal/pdpgrpc/delegation.go:235`).
- **Python 3.12+**, and the only runtime dependency is `grpcio`.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `sdk/python/pyproject.toml` | Package metadata, deps, pytest config |
| `sdk/python/stratium/__init__.py` | The public surface and nothing else |
| `sdk/python/stratium/_types.py` | `Effect`, `Decision`, `Grant`, `Scope`, `Legs` |
| `sdk/python/stratium/_client.py` | `Client`: `decide`, `create_delegation`, channel lifetime |
| `sdk/python/stratium/_cache.py` | Decision cache and the five usability conditions |
| `sdk/python/stratium/_escalation.py` | Poll `GetApproval`, retry `Decide`, timeout to DENY |
| `sdk/python/stratium/_session.py` | Mint, hold, re-issue and retry once |
| `sdk/python/stratium/_pdp/` | Generated stubs, committed |
| `sdk/python/tests/` | Unit tests plus the conformance runner |
| `sdk/python/example/custom_pep.py` | A real PEP, run against a live stack |
| `sdk/conformance/cases/*.json` | The fixtures every implementation must pass |
| `sdk/conformance/README.md` | What a runner must implement |
| `services/cmd/conformance/main.go` | The Go runner, binding the reference to the same fixtures |

**Modified:** `Makefile` (a `proto-python` target and a drift check).

---

### Task 1: Scaffold, generated stubs, and the no-drift check

**Files:**
- Create: `sdk/python/pyproject.toml`, `sdk/python/stratium/__init__.py`, `sdk/python/stratium/_pdp/__init__.py`, `sdk/python/README.md`
- Modify: `Makefile`
- Test: `sdk/python/tests/test_generated.py`

**Interfaces:**
- Produces: `stratium._pdp.pdp_pb2` and `stratium._pdp.pdp_pb2_grpc`, importable. Every later task consumes these.

- [ ] **Step 1: Write the failing test**

`sdk/python/tests/test_generated.py`:

```python
"""The generated stubs are committed, so they can drift from the .proto.

This asserts they exist and carry the shapes the SDK depends on. `make
proto-python` regenerating with no diff is the other half, enforced by the
Makefile target rather than here.
"""


def test_generated_stubs_are_importable_and_carry_the_expected_shapes():
    from stratium._pdp import pdp_pb2, pdp_pb2_grpc

    # DENY must be zero: an unset enum field decodes to it, which is what
    # makes a truncated or empty response fail closed.
    assert pdp_pb2.EFFECT_DENY == 0
    assert pdp_pb2.EFFECT_ALLOW == 1
    assert pdp_pb2.EFFECT_ESCALATE == 2

    assert hasattr(pdp_pb2_grpc, "PDPServiceStub")
    for field in ("agent_id", "subject", "tool", "raw_input", "token"):
        assert field in pdp_pb2.DecideRequest.DESCRIPTOR.fields_by_name
    for field in ("effect", "reason", "approval_id", "epoch"):
        assert field in pdp_pb2.DecideResponse.DESCRIPTOR.fields_by_name
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd sdk/python && python3 -m pytest tests/test_generated.py -q
```

Expected: FAIL — `ModuleNotFoundError: No module named 'stratium'`.

- [ ] **Step 3: Create the package skeleton**

`sdk/python/pyproject.toml`:

```toml
[project]
name = "stratium-sdk"
version = "0.1.0"
description = "Build a Stratium policy enforcement point"
requires-python = ">=3.12"
dependencies = ["grpcio>=1.60"]

[project.optional-dependencies]
dev = ["grpcio-tools>=1.60", "pytest>=8"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["stratium*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

`sdk/python/stratium/__init__.py` — empty for now; Task 2 fills it.
`sdk/python/stratium/_pdp/__init__.py` — empty, marks the generated package.

- [ ] **Step 4: Add the Makefile target**

Append to `Makefile`, beside the existing `proto` target:

```make
proto-python: ## Generate Python stubs into the SDK (requires grpcio-tools)
	@python3 -c 'import grpc_tools' 2>/dev/null || { \
		echo "grpcio-tools not found: pip install grpcio-tools"; exit 1; }
	python3 -m grpc_tools.protoc \
		--proto_path=$(PROTO_DIR) \
		--python_out=sdk/python/stratium/_pdp \
		--grpc_python_out=sdk/python/stratium/_pdp \
		$(PROTO_DIR)/pdp/v1/pdp.proto
	@# grpc_tools emits `from pdp.v1 import ...`, which only resolves if the
	@# generated directory is on sys.path. Rewriting to a relative import keeps
	@# the stubs importable as stratium._pdp.* without touching sys.path.
	@python3 - <<'EOF'
	import pathlib, re
	for f in pathlib.Path("sdk/python/stratium/_pdp").rglob("*_pb2*.py"):
	    s = f.read_text()
	    f.write_text(re.sub(r'^from pdp\.v1 import', 'from . import', s, flags=re.M))
	EOF

# NOTE for anyone verifying this check. Two obvious ways to test it both
# report SUCCESS while proving nothing, and both were tried here first:
#
#   1. Hand-edit a generated file. This target regenerates BEFORE diffing, so
#      the edit is overwritten and the check passes.
#   2. Append a COMMENT to the .proto. protoc does not serialize comments into
#      the descriptor without --include_source_info, so the stubs regenerate
#      byte-identical and the check passes.
#
# Only a real schema change proves it — add a throwaway message or field, e.g.
#   message DriftProbe { string x = 1; }
# then `make proto-python-check` exits 2 with a stale-diff report. Revert with
# `git checkout -- proto/`.
proto-python-check: proto-python ## Fail if the committed stubs are stale
	@git diff --quiet -- sdk/python/stratium/_pdp || { \
		echo "generated Python stubs are stale; run 'make proto-python' and commit"; \
		git diff --stat -- sdk/python/stratium/_pdp; exit 1; }
```

- [ ] **Step 5: Generate, and confirm the shape**

```bash
pip install grpcio-tools
make proto-python
ls sdk/python/stratium/_pdp/
```

Expected: `pdp_pb2.py` and `pdp_pb2_grpc.py` present, under a `pdp/v1/` subpath or flattened depending on protoc's output — if nested, move them to `_pdp/` directly and re-run the import rewrite so `from stratium._pdp import pdp_pb2` resolves.

- [ ] **Step 6: Run the test to verify it passes**

```bash
cd sdk/python && python3 -m pip install -e '.[dev]' && python3 -m pytest tests/ -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add sdk/python Makefile
git commit -m "feat(sdk): scaffold the Python SDK and generate its PDP stubs

Generated stubs are committed so installing the package does not require
protoc. Committed generated code drifts, so proto-python-check regenerates
and fails on any diff -- the same rule the rest of this repository already
follows for duplicated knowledge.

The stubs live under stratium._pdp, private, so nobody imports them by
accident and couples their code to protobuf types."
```

---

### Task 2: The public types, and the four footguns

**Files:**
- Create: `sdk/python/stratium/_types.py`
- Modify: `sdk/python/stratium/__init__.py`
- Test: `sdk/python/tests/test_types.py`

**Interfaces:**
- Consumes: `stratium._pdp.pdp_pb2` from Task 1.
- Produces:
```python
class Effect(Enum): DENY = 0; ALLOW = 1; ESCALATE = 2
@dataclass(frozen=True) class Leg:   effect: Effect | None; reason: str
@dataclass(frozen=True) class Legs:  principal: Leg; agent: Leg; delegation: Leg
@dataclass(frozen=True) class Scope: max_action_tier: int; tools: tuple[str, ...]
@dataclass(frozen=True) class Grant: token: str; delegation_id: str; granted_scope: Scope; epoch: int
@dataclass(frozen=True) class Decision:
    allowed: bool; effect: Effect | None; reason: str
    approval_id: str | None; error: Exception | None
    legs: Legs; denied_leg: str | None; denied_at_depth: int | None
    def __bool__(self) -> bool: ...
def decision_from_response(resp) -> Decision: ...
def decision_from_error(err: Exception) -> Decision: ...
def canonical_raw_input(value: str | Mapping) -> str: ...
```

- [ ] **Step 1: Write the failing tests**

`sdk/python/tests/test_types.py`:

```python
import json

import pytest

from stratium import Decision, Effect
from stratium._types import canonical_raw_input, decision_from_error


def _allow() -> Decision:
    from stratium._pdp import pdp_pb2
    from stratium._types import decision_from_response
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW, reason="permitted")
    )


def _escalate() -> Decision:
    from stratium._pdp import pdp_pb2
    from stratium._types import decision_from_response
    return decision_from_response(
        pdp_pb2.DecideResponse(
            effect=pdp_pb2.EFFECT_ESCALATE, reason="needs approval", approval_id="ap-1"
        )
    )


def test_only_allow_is_allowed():
    from stratium._pdp import pdp_pb2
    from stratium._types import decision_from_response

    assert _allow().allowed is True
    assert _escalate().allowed is False
    deny = decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_DENY, reason="no")
    )
    assert deny.allowed is False


# Every Python object is truthy by default. Without __bool__, `if
# client.decide(...)` is ALWAYS true -- the most natural line a PEP author
# writes would allow every call, silently and unconditionally.
def test_truthiness_tracks_allowed():
    assert bool(_allow()) is True
    assert bool(_escalate()) is False
    assert not _escalate()


# An escalation is neither allow nor deny: a human must approve first. The
# approval id is how a PEP that wants to wait finds the approval.
def test_escalation_is_not_an_allow_but_says_so():
    d = _escalate()
    assert d.allowed is False
    assert d.effect is Effect.ESCALATE
    assert d.approval_id == "ap-1"


# Transport errors must never be recorded as policy decisions: there is no
# Effect to log, because the policy was never consulted.
def test_transport_failure_is_not_a_policy_decision():
    err = RuntimeError("connection refused")
    d = decision_from_error(err)
    assert d.allowed is False
    assert d.effect is None
    assert d.error is err
    assert "connection refused" in d.reason


def test_decision_is_frozen():
    d = _allow()
    with pytest.raises(Exception):
        d.allowed = True  # type: ignore[misc]


# The PDP digests raw_input for approval matching, so the same arguments must
# produce the same bytes on a retry regardless of dict insertion order.
def test_raw_input_is_canonical_and_order_independent():
    a = canonical_raw_input({"b": 2, "a": 1})
    b = canonical_raw_input({"a": 1, "b": 2})
    assert a == b
    assert a == '{"a":1,"b":2}'
    assert json.loads(a) == {"a": 1, "b": 2}


def test_raw_input_string_is_passed_through_untouched():
    assert canonical_raw_input('{"z":1,  "a":2}') == '{"z":1,  "a":2}'
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd sdk/python && python3 -m pytest tests/test_types.py -q
```

Expected: FAIL — `ImportError: cannot import name 'Decision'`.

- [ ] **Step 3: Implement the types**

`sdk/python/stratium/_types.py`:

```python
"""The public value types, and the four footguns they close.

Nothing here talks to the network. The safety properties live in the types
themselves so that a PEP author gets them without reading documentation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from ._pdp import pdp_pb2


class Effect(Enum):
    """Mirrors pdp.v1.Effect.

    DENY is zero deliberately: protobuf decodes an unset enum field as zero,
    so a truncated or empty response says deny. The safe answer is the one you
    get by accident.
    """

    DENY = 0
    ALLOW = 1
    ESCALATE = 2


def _effect(raw: int) -> Effect:
    # An unknown value from a newer PDP is NOT passed through: it would reach
    # `allowed` as "not ALLOW" today, but a caller matching on the enum would
    # see something it cannot handle. Deny is the honest reading of "this
    # build does not understand the answer".
    try:
        return Effect(raw)
    except ValueError:
        return Effect.DENY


@dataclass(frozen=True)
class Leg:
    effect: Effect | None
    reason: str


@dataclass(frozen=True)
class Legs:
    principal: Leg
    agent: Leg
    delegation: Leg


@dataclass(frozen=True)
class Scope:
    max_action_tier: int
    tools: tuple[str, ...]


@dataclass(frozen=True)
class Grant:
    token: str
    delegation_id: str
    granted_scope: Scope
    """What the PDP actually granted, which is not what was requested: it
    narrows. A PEP that assumes otherwise is wrong about its own authority."""
    epoch: int


@dataclass(frozen=True)
class Decision:
    allowed: bool
    effect: Effect | None
    reason: str
    approval_id: str | None
    error: Exception | None
    legs: Legs
    denied_leg: str | None
    denied_at_depth: int | None

    def __bool__(self) -> bool:
        """Truthiness IS allowed.

        Without this, every Decision is truthy -- Python's default for any
        object -- and `if client.decide(...)` allows every call. Defining it
        makes the idiom people will reach for anyway the correct one.
        """
        return self.allowed


def _leg(effect_raw: int, reason: str) -> Leg:
    return Leg(effect=_effect(effect_raw), reason=reason)


def decision_from_response(resp: pdp_pb2.DecideResponse) -> Decision:
    effect = _effect(resp.effect)
    return Decision(
        allowed=effect is Effect.ALLOW,
        effect=effect,
        reason=resp.reason,
        approval_id=resp.approval_id or None,
        error=None,
        legs=Legs(
            principal=_leg(resp.principal_effect, resp.principal_reason),
            agent=_leg(resp.agent_effect, resp.agent_reason),
            delegation=_leg(resp.delegation_effect, resp.delegation_reason),
        ),
        denied_leg=resp.denied_leg or None,
        denied_at_depth=resp.denied_at_depth if resp.denied_leg else None,
    )


def decision_from_error(err: Exception) -> Decision:
    """A transport failure, which is NOT a policy decision.

    effect stays None so audit code cannot record a denial the policy never
    issued. allowed is False so the call is refused either way.
    """
    empty = Leg(effect=None, reason="")
    return Decision(
        allowed=False,
        effect=None,
        reason=f"stratium: the PDP could not be asked: {err}",
        approval_id=None,
        error=err,
        legs=Legs(principal=empty, agent=empty, delegation=empty),
        denied_leg=None,
        denied_at_depth=None,
    )


def canonical_raw_input(value: str | Mapping) -> str:
    """The tool's arguments as the PDP will digest them.

    A str is passed through untouched: the caller owns those bytes. A Mapping
    is rendered with sorted keys and no whitespace, so two dicts differing only
    in insertion order do not become two different approvals on a retry.
    """
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
```

`sdk/python/stratium/__init__.py`:

```python
"""Build a Stratium policy enforcement point.

    grant = client.create_delegation(...)
    d = client.decide(tool="Read", raw_input={"file_path": "/tmp/x"},
                      token=grant.token, ...)
    if d:
        ...
"""

from ._types import Decision, Effect, Grant, Leg, Legs, Scope

__all__ = ["Decision", "Effect", "Grant", "Leg", "Legs", "Scope"]
```

- [ ] **Step 4: Run to verify they pass**

```bash
cd sdk/python && python3 -m pytest tests/ -q
```

- [ ] **Step 5: Prove the tests have teeth**

Run each mutation, confirm the named test FAILS, then restore:

| Mutation | Must fail |
|---|---|
| delete `__bool__` from `Decision` | `test_truthiness_tracks_allowed` |
| `allowed=effect is not Effect.DENY` | `test_only_allow_is_allowed` |
| `decision_from_error` sets `effect=Effect.DENY` | `test_transport_failure_is_not_a_policy_decision` |
| drop `sort_keys=True` | `test_raw_input_is_canonical_and_order_independent` |

Record the real output of each in the commit body.

- [ ] **Step 6: Commit**

```bash
git add sdk/python/stratium/_types.py sdk/python/stratium/__init__.py sdk/python/tests/test_types.py
git commit -m "feat(sdk): the public types, and the four footguns they close"
```

---

### Task 3: `Client.decide` and `Client.create_delegation`

**Files:**
- Create: `sdk/python/stratium/_client.py`
- Modify: `sdk/python/stratium/__init__.py`
- Test: `sdk/python/tests/conftest.py`, `sdk/python/tests/test_client.py`

**Interfaces:**
- Consumes: `_types` from Task 2, `_pdp` from Task 1.
- Produces:
```python
class Client:
    def __init__(self, pdp_addr: str, *, connect_timeout: float = 5.0) -> None
    def create_delegation(self, *, subject: str, agent_id: str, tools: Sequence[str],
                          max_action_tier: int, purpose: str, ttl_seconds: int,
                          parent_delegation_id: str | None = None) -> Grant
    def decide(self, *, agent_id: str, subject: str, tool: str,
               raw_input: str | Mapping, token: str,
               resource: Mapping[str, str] | None = None) -> Decision
    def get_approval(self, approval_id: str) -> str
    def close(self) -> None
    def __enter__(self) -> Client
    def __exit__(self, *exc) -> None
```

- [ ] **Step 1: Write the fake PDP fixture**

`sdk/python/tests/conftest.py` — an in-process gRPC server, so real protobuf
serialisation runs but nothing leaves the process:

```python
from concurrent import futures

import grpc
import pytest

from stratium._pdp import pdp_pb2, pdp_pb2_grpc


class FakePDP(pdp_pb2_grpc.PDPServiceServicer):
    """Serves scripted responses and counts calls.

    The call count is what proves a cache was used: a second decide() that
    does not increment it was served locally.
    """

    def __init__(self):
        self.decide_responses: list = []
        self.delegation_responses: list = []
        self.approval_responses: list = []
        self.decide_calls: list = []
        self.approval_calls: list = []

    def Decide(self, request, context):
        self.decide_calls.append(request)
        if not self.decide_responses:
            context.abort(grpc.StatusCode.INTERNAL, "no scripted response")
        nxt = self.decide_responses.pop(0)
        return nxt(request) if callable(nxt) else nxt

    def CreateDelegation(self, request, context):
        return self.delegation_responses.pop(0)

    def GetApproval(self, request, context):
        self.approval_calls.append(request)
        return self.approval_responses.pop(0)


@pytest.fixture
def fake_pdp():
    servicer = FakePDP()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pdp_pb2_grpc.add_PDPServiceServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    servicer.addr = f"127.0.0.1:{port}"
    yield servicer
    server.stop(None)
```

- [ ] **Step 2: Write the failing tests**

`sdk/python/tests/test_client.py`:

```python
import grpc
import pytest

from stratium import Client, Effect
from stratium._pdp import pdp_pb2


def test_decide_allows_and_carries_the_pdps_reason(fake_pdp):
    fake_pdp.decide_responses.append(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW, reason="permitted by policy p1")
    )
    with Client(fake_pdp.addr) as c:
        d = c.decide(agent_id="a", subject="s", tool="Read",
                     raw_input={"file_path": "/tmp/x"}, token="t")
    assert d
    assert d.effect is Effect.ALLOW
    assert d.reason == "permitted by policy p1"


def test_decide_sends_the_fields_the_pdp_reads(fake_pdp):
    fake_pdp.decide_responses.append(pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW))
    with Client(fake_pdp.addr) as c:
        c.decide(agent_id="a1", subject="s1", tool="Read",
                 raw_input={"b": 2, "a": 1}, token="tok",
                 resource={"id": "/tmp/x"})
    req = fake_pdp.decide_calls[0]
    assert req.agent_id == "a1"
    assert req.subject == "s1"
    assert req.tool == "Read"
    assert req.token == "tok"
    assert dict(req.resource) == {"id": "/tmp/x"}
    # Canonical, so a retry digests identically.
    assert req.raw_input == '{"a":1,"b":2}'


# The single most important test in this file. A PDP that cannot be reached
# must never produce an allow, and must not claim the policy denied.
def test_unreachable_pdp_denies_without_raising():
    closed = "127.0.0.1:1"  # nothing listens here
    with Client(closed, connect_timeout=0.5) as c:
        d = c.decide(agent_id="a", subject="s", tool="Read", raw_input="{}", token="t")
    assert d.allowed is False
    assert not d
    assert d.effect is None          # no decision was reached
    assert d.error is not None
    assert "could not be asked" in d.reason


def test_create_delegation_returns_the_granted_scope_not_the_requested_one(fake_pdp):
    fake_pdp.delegation_responses.append(
        pdp_pb2.CreateDelegationResponse(
            delegation_id="d1", token="tok", epoch=7,
            granted_scope=pdp_pb2.GrantedScope(max_action_tier=1, tools=["Read"]),
        )
    )
    with Client(fake_pdp.addr) as c:
        g = c.create_delegation(subject="s", agent_id="a",
                                tools=["Read", "Bash"], max_action_tier=4,
                                purpose="p", ttl_seconds=60)
    assert g.token == "tok"
    assert g.delegation_id == "d1"
    assert g.epoch == 7
    # Asked for two tools at tier 4, granted one at tier 1.
    assert g.granted_scope.tools == ("Read",)
    assert g.granted_scope.max_action_tier == 1


def test_a_pdp_error_status_is_also_not_a_policy_decision(fake_pdp):
    # No scripted response -> the servicer aborts with INTERNAL.
    with Client(fake_pdp.addr) as c:
        d = c.decide(agent_id="a", subject="s", tool="Read", raw_input="{}", token="t")
    assert d.allowed is False
    assert d.effect is None
    assert isinstance(d.error, grpc.RpcError)
```

- [ ] **Step 3: Run to verify they fail**

```bash
cd sdk/python && python3 -m pytest tests/test_client.py -q
```

Expected: FAIL — `ImportError: cannot import name 'Client'`.

- [ ] **Step 4: Implement the client**

`sdk/python/stratium/_client.py`:

```python
"""The PDP client.

Every method that can fail returns a value rather than raising. An exception
is one `except Exception: pass` away from becoming an allow; a Decision whose
allowed is False cannot be swallowed that way.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import grpc

from ._pdp import pdp_pb2, pdp_pb2_grpc
from ._types import (
    Decision, Grant, Scope, canonical_raw_input,
    decision_from_error, decision_from_response,
)


class Client:
    def __init__(self, pdp_addr: str, *, connect_timeout: float = 5.0) -> None:
        self._addr = pdp_addr
        self._timeout = connect_timeout
        self._channel = grpc.insecure_channel(pdp_addr)
        self._stub = pdp_pb2_grpc.PDPServiceStub(self._channel)

    def decide(
        self, *, agent_id: str, subject: str, tool: str,
        raw_input: str | Mapping, token: str,
        resource: Mapping[str, str] | None = None,
    ) -> Decision:
        req = pdp_pb2.DecideRequest(
            agent_id=agent_id, subject=subject, tool=tool,
            raw_input=canonical_raw_input(raw_input), token=token,
        )
        if resource:
            req.resource.update(resource)
        try:
            return decision_from_response(self._stub.Decide(req, timeout=self._timeout))
        except Exception as err:  # noqa: BLE001 -- deliberate; see the module docstring
            # Every failure mode lands here: an unreachable PDP, a non-OK
            # status, a deadline. All of them mean the same thing -- no
            # decision was reached -- and all of them must refuse the call.
            return decision_from_error(err)

    def create_delegation(
        self, *, subject: str, agent_id: str, tools: Sequence[str],
        max_action_tier: int, purpose: str, ttl_seconds: int,
        parent_delegation_id: str | None = None,
    ) -> Grant:
        """Mint a delegation.

        Raises on failure, unlike decide(): there is no safe fallback value
        for "you have no authority" that a caller could mistake for one, and a
        PEP that cannot get a token has nothing to enforce with.
        """
        req = pdp_pb2.CreateDelegationRequest(
            subject=subject, agent_id=agent_id, purpose=purpose,
            ttl_seconds=ttl_seconds,
            requested_scope=pdp_pb2.RequestedScope(
                max_action_tier=max_action_tier, tools=list(tools)
            ),
        )
        if parent_delegation_id:
            req.parent_delegation_id = parent_delegation_id

        resp = self._stub.CreateDelegation(req, timeout=self._timeout)
        return Grant(
            token=resp.token,
            delegation_id=resp.delegation_id,
            granted_scope=Scope(
                max_action_tier=resp.granted_scope.max_action_tier,
                tools=tuple(resp.granted_scope.tools),
            ),
            epoch=resp.epoch,
        )

    def get_approval(self, approval_id: str) -> str:
        """The approval's current status, lowercased.

        Here rather than in _escalation so that nothing outside this class
        touches the stub: a Session reaching into client._stub would couple
        two modules through a private attribute, and every later SDK would
        copy the shape.
        """
        from ._pdp import pdp_pb2

        resp = self._stub.GetApproval(
            pdp_pb2.GetApprovalRequest(approval_id=approval_id), timeout=self._timeout
        )
        return (resp.status or "").lower()

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
```

Add `Client` to `__init__.py`'s imports and `__all__`.

- [ ] **Step 5: Run to verify they pass**

```bash
cd sdk/python && python3 -m pytest tests/ -q
```

- [ ] **Step 6: Prove the transport test has teeth**

Change `decide`'s `except` clause to re-raise, run `tests/test_client.py`, and
confirm `test_unreachable_pdp_denies_without_raising` FAILS. Restore, confirm
green, and record both outputs in the commit body.

- [ ] **Step 7: Commit**

```bash
git add sdk/python/stratium/_client.py sdk/python/stratium/__init__.py sdk/python/tests/
git commit -m "feat(sdk): Client.decide and Client.create_delegation

decide() returns on every failure and never raises: an exception is one bare
except away from an allow. create_delegation DOES raise, because there is no
value meaning 'you have no authority' that a caller could mistake for one.

Tests run an in-process gRPC server, so real protobuf serialisation happens
and nothing leaves the process."
```

---

### Task 4: The decision cache

**Files:**
- Create: `sdk/python/stratium/_cache.py`
- Test: `sdk/python/tests/test_cache.py`

**Interfaces:**
- Consumes: `Effect`, `Decision` from Task 2.
- Produces:
```python
@dataclass(frozen=True)
class CacheEntry:
    decision: Decision; cached_at: float; epoch: int
    delegation_expires_at: float
class DecisionCache:
    def __init__(self, staleness_window: float, *, max_entries: int = 512,
                 clock: Callable[[], float] = time.monotonic) -> None
    def key(self, *, agent_id: str, subject: str, tool: str, raw_input: str) -> str
    def get(self, key: str, *, last_known_epoch: int,
            token_expires_at: float) -> Decision | None
    def put(self, key: str, decision: Decision, *, epoch: int,
            delegation_expires_at: float) -> None
```

**This task reimplements `services/cmd/stratium-pep/cache.go`.** Read
`cacheEntryUsable` there before starting; the five conditions below are its
contract, and the conformance suite in Task 7 will hold both implementations
to it.

- [ ] **Step 1: Write the failing tests**

`sdk/python/tests/test_cache.py`:

```python
import pytest

from stratium import Effect
from stratium._cache import DecisionCache
from stratium._pdp import pdp_pb2
from stratium._types import decision_from_response


def allow() -> object:
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW, reason="ok")
    )


def escalate() -> object:
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ESCALATE, reason="approve me")
    )


class Clock:
    def __init__(self, t: float = 0.0): self.t = t
    def __call__(self) -> float: return self.t


def fresh(window: float = 30.0):
    clock = Clock()
    return DecisionCache(window, clock=clock), clock


def store(cache, key="k", decision=None, *, epoch=1, expires=1e9, token="tok"):
    cache.put(key, decision or allow(), epoch=epoch,
              delegation_expires_at=expires, token=token)


def look(cache, key="k", *, epoch=1, token="tok", token_expires=1e9):
    return cache.get(key, last_known_epoch=epoch, token=token,
                     token_expires_at=token_expires)


# The boundary is INCLUSIVE, matching Go's !now.After(CachedAt.Add(staleness)).
def test_serves_within_the_window_including_its_last_instant():
    cache, clock = fresh(30.0)
    store(cache)
    clock.t = 29.999
    assert look(cache) is not None
    clock.t = 30.0
    assert look(cache) is not None, "the boundary instant is inside the window"


def test_refuses_past_the_window():
    cache, clock = fresh(30.0)
    store(cache)
    clock.t = 30.001
    assert look(cache) is None


# The clock runs from the entry's own cached_at, never from last use --
# otherwise a busy key never goes stale.
def test_reading_does_not_extend_the_window():
    cache, clock = fresh(30.0)
    store(cache)
    for t in (10.0, 20.0, 29.0):
        clock.t = t
        assert look(cache) is not None
    clock.t = 30.001
    assert look(cache) is None


# W4: an ESCALATE is never served from cache, on write OR read. It means a
# human must approve THIS call; replaying it approves a call nobody saw.
def test_an_escalation_is_never_cached_and_never_served():
    cache, clock = fresh(30.0)
    store(cache, decision=escalate())
    assert look(cache) is None


def test_a_stale_epoch_is_a_miss():
    cache, _ = fresh(30.0)
    store(cache, epoch=1)
    assert look(cache, epoch=2) is None, "a revocation bumped the epoch"


def test_an_expired_delegation_is_a_miss():
    cache, clock = fresh(30.0)
    store(cache, expires=5.0)
    clock.t = 6.0
    assert look(cache) is None


def test_an_expired_token_is_a_miss():
    cache, clock = fresh(30.0)
    store(cache)
    clock.t = 1.0
    assert look(cache, token_expires=0.5) is None


def test_a_different_token_is_a_miss():
    cache, _ = fresh(30.0)
    store(cache, token="tok-a")
    assert look(cache, token="tok-b") is None


# Different arguments to the same tool are different decisions.
def test_the_key_separates_arguments():
    cache, _ = fresh(30.0)
    k1 = cache.key(agent_id="a", subject="s", tool="Read", raw_input='{"p":"/a"}')
    k2 = cache.key(agent_id="a", subject="s", tool="Read", raw_input='{"p":"/b"}')
    assert k1 != k2
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd sdk/python && python3 -m pytest tests/test_cache.py -q
```

Expected: FAIL — no module named `stratium._cache`.

- [ ] **Step 3: Implement the cache**

`sdk/python/stratium/_cache.py`:

```python
"""The decision cache, and the five conditions an entry must satisfy.

This is a port of services/cmd/stratium-pep/cache.go's cacheEntryUsable. The
conditions are ALL required and are checked in one place, because a hit that
fails any of them must be indistinguishable from a miss -- fail closed means
an invalid entry is not a separate outcome a caller could decide to handle.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from ._types import Decision, Effect


@dataclass(frozen=True)
class CacheEntry:
    decision: Decision
    cached_at: float
    epoch: int
    delegation_expires_at: float
    # No token field, deliberately. Go's cacheEntry has none either: its four
    # fields are Decision, Epoch, DelegationExpiresAt and CachedAt. Storing the
    # token and comparing it would discard the whole cache whenever a token is
    # reissued -- which cache.go's own package doc names as the reason it keys
    # on the delegation rather than the token.


class DecisionCache:
    def __init__(
        self, staleness_window: float, *, max_entries: int = 512,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window = staleness_window
        self._max = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, CacheEntry] = OrderedDict()

    def key(self, *, agent_id: str, subject: str, tool: str, raw_input: str) -> str:
        # raw_input is already canonical (see _types.canonical_raw_input), so
        # equal arguments hash equal regardless of how the caller spelled them.
        h = hashlib.sha256()
        for part in (agent_id, subject, tool, raw_input):
            h.update(part.encode())
            h.update(b"\x00")
        return h.hexdigest()

    def put(
        self, key: str, decision: Decision, *, epoch: int,
        delegation_expires_at: float, token: str,
    ) -> None:
        # W4, write side. An ESCALATE means a human must approve THIS call;
        # replaying it would approve a call nobody ever saw. The read side
        # refuses one too -- both halves, because the failure is silent.
        if decision.effect is Effect.ESCALATE:
            return
        # A decision that was never reached is not a decision to cache.
        if decision.effect is None:
            return

        self._entries[key] = CacheEntry(
            decision=decision, cached_at=self._clock(), epoch=epoch,
            delegation_expires_at=delegation_expires_at, token=token,
        )
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def get(
        self, key: str, *, last_known_epoch: int, token: str, token_expires_at: float,
    ) -> Decision | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if not self._usable(entry, last_known_epoch, token, token_expires_at):
            # Deleted rather than left to rot: an unusable entry can never
            # become usable again, since none of the five conditions recovers.
            del self._entries[key]
            return None
        return entry.decision

    def _usable(
        self, entry: CacheEntry, last_known_epoch: int, token: str,
        token_expires_at: float,
    ) -> bool:
        now = self._clock()
        return (
            entry.decision.effect is not Effect.ESCALATE
            and entry.epoch == last_known_epoch
            and now < entry.delegation_expires_at
            and now < token_expires_at
            # INCLUSIVE at the boundary, matching Go's
            # !now.After(CachedAt.Add(staleness)). The clock runs from the
            # entry's own cached_at, so reading never extends the window.
            and now <= entry.cached_at + self._window
        )
```

- [ ] **Step 4: Run to verify they pass**

```bash
cd sdk/python && python3 -m pytest tests/ -q
```

- [ ] **Step 5: Prove the boundary test has teeth**

Change `now <= entry.cached_at + self._window` to `now < ...`, run the tests,
and confirm `test_serves_within_the_window_including_its_last_instant` FAILS.
Restore.

Then the ESCALATE guard, which is deliberately in TWO places. Removing it from
`put` alone fails nothing — the read-side guard in `_usable` still refuses the
entry, which is defence in depth working as intended, not a gap. Removing it
from `_usable` alone also fails nothing unless a test inserts a `CacheEntry`
directly, bypassing `put`. Both halves need their own test: one that goes
through `put`, and one that seeds the store directly and then reads. Record
each mutation's real output.

- [ ] **Step 6: Commit**

```bash
git add sdk/python/stratium/_cache.py sdk/python/tests/test_cache.py
git commit -m "feat(sdk): the decision cache and its five usability conditions

A port of stratium-pep's cacheEntryUsable. All five are required and checked
in one place, because a hit failing any of them must be indistinguishable
from a miss: fail closed means an invalid entry is not a separate outcome a
caller could choose to handle.

The staleness boundary is inclusive, matching Go's
!now.After(CachedAt.Add(staleness)), and the clock runs from the entry's own
cached_at so that reading never extends the window."
```

---

### Task 5: Escalation

**Files:**
- Create: `sdk/python/stratium/_escalation.py`
- Test: `sdk/python/tests/test_escalation.py`

**Interfaces:**
- Consumes: `Decision`, `Effect` from Task 2; the stub from Task 1.
- Produces:
```python
def resolve_escalation(
    poll: Callable[[str], str], retry_decide: Callable[[], Decision], *,
    approval_id: str, poll_interval: float, timeout: float,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Decision
```

`poll` takes an approval id and returns its lowercased status. Passing a
callable rather than a stub keeps this module free of protobuf and makes every
test below a plain function instead of a fake gRPC object.

**The contract, from `services/cmd/stratium-pep/escalation.go`:** an approval
being granted is **not** an allow. It means `Decide` may now be retried, and
that retry's answer is the decision. A timeout is a DENY naming the timeout.

- [ ] **Step 1: Write the failing tests**

`sdk/python/tests/test_escalation.py`:

```python
from stratium import Effect
from stratium._escalation import resolve_escalation
from stratium._pdp import pdp_pb2
from stratium._types import decision_from_response


def escalated(approval_id="ap-1"):
    return decision_from_response(pdp_pb2.DecideResponse(
        effect=pdp_pb2.EFFECT_ESCALATE, reason="needs approval", approval_id=approval_id))


def allowed():
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW, reason="permitted"))


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def polls(*statuses):
    """A poll callable returning scripted statuses, then 'pending' forever."""
    remaining = list(statuses)

    def poll(approval_id: str) -> str:
        return remaining.pop(0) if remaining else "pending"

    return poll


# An approval is permission to ASK AGAIN, not permission to act. The retry's
# answer is the decision -- policy may still deny for an unrelated reason.
def test_an_approval_retries_decide_and_returns_that_answer():
    clock = Clock()
    poll = polls("pending", "approved")
    retried = []

    def retry():
        retried.append(True)
        return allowed()

    d = resolve_escalation(
        poll, retry, approval_id="ap-1",
        poll_interval=1.0, timeout=30.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert retried, "an approval must retry Decide"
    assert d.allowed is True
    assert d.effect is Effect.ALLOW


# The critical one. A timeout must not become an allow, and must not silently
# return the original ESCALATE either -- a caller checking `if d:` on an
# ESCALATE gets False, but a caller matching on effect deserves the truth.
def test_a_timeout_is_a_deny_naming_the_timeout():
    clock = Clock()
    poll = polls()  # never settles

    d = resolve_escalation(
        poll, lambda: allowed(), approval_id="ap-1",
        poll_interval=1.0, timeout=3.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert d.allowed is False
    assert d.effect is Effect.DENY
    assert "timed out" in d.reason
    assert "ap-1" in d.reason


def test_a_denied_approval_is_a_deny_and_does_not_retry():
    clock = Clock()
    poll = polls("denied")
    retried = []

    d = resolve_escalation(
        poll, lambda: (retried.append(True), allowed())[1],
        approval_id="ap-1", poll_interval=1.0, timeout=30.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert not retried, "a denied approval must not retry Decide"
    assert d.allowed is False
    assert d.effect is Effect.DENY


# A GetApproval that errors is a transport failure, not a decision.
def test_a_polling_failure_denies_without_claiming_the_policy_denied():
    def broken(approval_id: str) -> str:
        raise RuntimeError("connection reset")

    clock = Clock()
    d = resolve_escalation(
        broken, lambda: allowed(), approval_id="ap-1",
        poll_interval=1.0, timeout=30.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert d.allowed is False
    assert d.effect is None, "no policy decision was reached"
    assert d.error is not None
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd sdk/python && python3 -m pytest tests/test_escalation.py -q
```

- [ ] **Step 3: Implement**

`sdk/python/stratium/_escalation.py`:

```python
"""Resolving an EFFECT_ESCALATE.

An escalation means a human must approve before this call may proceed. The
contract, from services/cmd/stratium-pep/escalation.go: an approval is
permission to ASK AGAIN, not permission to act. Decide is retried and that
answer is the decision -- policy may still deny for an unrelated reason.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from ._types import Decision, Effect, Leg, Legs, decision_from_error

_TERMINAL_APPROVED = "approved"
_TERMINAL_DENIED = "denied"


def _deny(reason: str) -> Decision:
    empty = Leg(effect=None, reason="")
    return Decision(
        allowed=False, effect=Effect.DENY, reason=reason,
        approval_id=None, error=None,
        legs=Legs(principal=empty, agent=empty, delegation=empty),
        denied_leg=None, denied_at_depth=None,
    )


def resolve_escalation(
    poll: Callable[[str], str], retry_decide: Callable[[], Decision], *,
    approval_id: str, poll_interval: float, timeout: float,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Decision:
    deadline = clock() + timeout
    while True:
        try:
            status = poll(approval_id)
        except Exception as err:  # noqa: BLE001
            # The PDP could not be asked. Not a policy decision -- effect
            # stays None so nothing records a denial that never happened.
            return decision_from_error(err)

        if status == _TERMINAL_APPROVED:
            # Permission to ask again, NOT permission to act.
            return retry_decide()
        if status == _TERMINAL_DENIED:
            return _deny(f"stratium: approval {approval_id} was denied")

        if clock() >= deadline:
            # Never an allow, and never the original ESCALATE: a caller
            # matching on effect deserves to know this settled as a refusal.
            return _deny(
                f"stratium: approval {approval_id} timed out after {timeout}s "
                f"without a decision"
            )
        sleep(poll_interval)
```

- [ ] **Step 4: Run to verify they pass**

```bash
cd sdk/python && python3 -m pytest tests/ -q
```

- [ ] **Step 5: Prove the timeout test has teeth**

Change the timeout branch to `return decision` (the original ESCALATE) and
confirm `test_a_timeout_is_a_deny_naming_the_timeout` FAILS. Then change the
approved branch to `return allowed_decision` without calling `retry_decide`
and confirm `test_an_approval_retries_decide_and_returns_that_answer` FAILS.
Restore after each; record both outputs.

- [ ] **Step 6: Commit**

```bash
git add sdk/python/stratium/_escalation.py sdk/python/tests/test_escalation.py
git commit -m "feat(sdk): resolve an escalation by polling, then retrying Decide

An approval is permission to ask again, not permission to act: Decide is
retried and that answer is the decision, because policy may still refuse for
an unrelated reason. A timeout is a DENY naming the approval and the timeout,
never an allow and never the original ESCALATE. A GetApproval that errors is
a transport failure with effect None, so nothing records a policy denial that
never happened."
```

---

### Task 6: The session — mint, hold, re-issue

**Files:**
- Create: `sdk/python/stratium/_session.py`
- Modify: `sdk/python/stratium/_client.py`, `sdk/python/stratium/__init__.py`
- Test: `sdk/python/tests/test_session.py`

**Interfaces:**
- Consumes: everything above.
- Produces:
```python
class Session:
    def __init__(self, client: Client, *, subject: str, agent_id: str,
                 tools: Sequence[str], max_action_tier: int, purpose: str,
                 ttl_seconds: int, staleness_window: float = 30.0,
                 approval_poll_interval: float = 2.0, approval_timeout: float = 120.0,
                 clock: Callable[[], float] = time.monotonic) -> None
    def check(self, *, tool: str, raw_input: str | Mapping,
              resource: Mapping[str, str] | None = None) -> Decision
    @property
    def grant(self) -> Grant
```

`Session.check` is the whole turnkey surface: cache, then `Decide`, then
escalation if needed, and re-issue-and-retry-once when the token is the
problem.

- [ ] **Step 1: Write the failing tests**

`sdk/python/tests/test_session.py`:

```python
from stratium import Client, Effect, Session
from stratium._pdp import pdp_pb2


def grant_resp(token="tok", epoch=1, tools=("Read",), tier=1, did="d1"):
    return pdp_pb2.CreateDelegationResponse(
        delegation_id=did, token=token, epoch=epoch,
        granted_scope=pdp_pb2.GrantedScope(max_action_tier=tier, tools=list(tools)),
    )


def allow(reason="permitted"):
    return pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW, reason=reason, epoch=1)


def deny(reason="not in delegation approved_tools"):
    return pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_DENY, reason=reason, epoch=1)


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def session(fake_pdp, clock, **kw):
    fake_pdp.delegation_responses.append(grant_resp())
    c = Client(fake_pdp.addr)
    return Session(c, subject="s", agent_id="a", tools=["Read"],
                   max_action_tier=1, purpose="test", ttl_seconds=3600,
                   clock=clock, **kw)


def test_check_allows_and_caches(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.append(allow())
    s = session(fake_pdp, clock, staleness_window=30.0)

    first = s.check(tool="Read", raw_input={"file_path": "/tmp/x"})
    second = s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    assert first and second
    # One PDP round trip for two identical checks: the cache was used.
    assert len(fake_pdp.decide_calls) == 1


def test_the_cache_expires_and_the_pdp_is_asked_again(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.extend([allow(), allow()])
    s = session(fake_pdp, clock, staleness_window=30.0)

    s.check(tool="Read", raw_input={"file_path": "/tmp/x"})
    clock.t = 30.001
    s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    assert len(fake_pdp.decide_calls) == 2


def test_different_arguments_are_different_decisions(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.extend([allow(), deny()])
    s = session(fake_pdp, clock)

    a = s.check(tool="Read", raw_input={"file_path": "/tmp/a"})
    b = s.check(tool="Read", raw_input={"file_path": "/tmp/b"})

    assert a
    assert not b
    assert len(fake_pdp.decide_calls) == 2


def test_a_deny_is_returned_with_the_pdps_own_reason(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.append(deny("tool \"Bash\" not in delegation approved_tools"))
    s = session(fake_pdp, clock)

    d = s.check(tool="Bash", raw_input={})
    assert not d
    assert d.effect is Effect.DENY
    assert "not in delegation approved_tools" in d.reason


# The grant is what the PDP gave, not what was asked for.
def test_the_session_exposes_the_granted_scope(fake_pdp):
    clock = Clock()
    s = session(fake_pdp, clock)
    assert s.grant.granted_scope.tools == ("Read",)
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd sdk/python && python3 -m pytest tests/test_session.py -q
```

- [ ] **Step 3: Implement**

`sdk/python/stratium/_session.py`:

```python
"""A held delegation, and the check loop around it.

Session.check is the turnkey surface: consult the cache, ask the PDP, resolve
an escalation if one comes back, and re-issue once if the token was the
problem. Everything it returns is a Decision, including every failure.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence

from ._cache import DecisionCache
from ._escalation import resolve_escalation
from ._types import Decision, Effect, Grant, canonical_raw_input


class Session:
    def __init__(
        self, client, *, subject: str, agent_id: str, tools: Sequence[str],
        max_action_tier: int, purpose: str, ttl_seconds: int,
        staleness_window: float = 30.0, approval_poll_interval: float = 2.0,
        approval_timeout: float = 120.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._subject = subject
        self._agent_id = agent_id
        self._mint = dict(
            subject=subject, agent_id=agent_id, tools=list(tools),
            max_action_tier=max_action_tier, purpose=purpose, ttl_seconds=ttl_seconds,
        )
        self._ttl = ttl_seconds
        self._clock = clock
        self._poll = approval_poll_interval
        self._approval_timeout = approval_timeout
        self._window = staleness_window
        self._cache = DecisionCache(staleness_window, clock=clock)

        self._grant: Grant = client.create_delegation(**self._mint)
        self._expires_at = clock() + ttl_seconds

    @property
    def grant(self) -> Grant:
        return self._grant

    def check(
        self, *, tool: str, raw_input: str | Mapping,
        resource: Mapping[str, str] | None = None,
    ) -> Decision:
        canonical = canonical_raw_input(raw_input)
        key = self._cache.key(
            agent_id=self._agent_id, subject=self._subject,
            tool=tool, raw_input=canonical,
        )

        hit = self._cache.get(
            key, last_known_epoch=self._grant.epoch,
            token=self._grant.token, token_expires_at=self._expires_at,
        )
        if hit is not None:
            return hit

        decision = self._ask(tool=tool, raw_input=canonical, resource=resource)

        if decision.effect is Effect.ESCALATE and decision.approval_id:
            decision = resolve_escalation(
                self._client.get_approval,
                lambda: self._ask(tool=tool, raw_input=canonical, resource=resource),
                approval_id=decision.approval_id,
                poll_interval=self._poll, timeout=self._approval_timeout,
                clock=self._clock,
            )

        self._cache.put(
            key, decision, epoch=self._grant.epoch,
            delegation_expires_at=self._expires_at, token=self._grant.token,
        )
        return decision

    def _ask(self, *, tool: str, raw_input: str, resource) -> Decision:
        decision = self._client.decide(
            agent_id=self._agent_id, subject=self._subject, tool=tool,
            raw_input=raw_input, token=self._grant.token, resource=resource,
        )
        if not self._token_is_the_problem(decision):
            return decision

        # Re-issue and retry ONCE. stratium-pep's reissue.go deliberately does
        # not try to tell "the token expired" from "the policy denied" before
        # re-issuing -- both reach here, and a second denial with a fresh
        # token is a real denial.
        try:
            self._grant = self._client.create_delegation(**self._mint)
        except Exception:  # noqa: BLE001
            # Could not re-mint. The original decision stands, and it was not
            # an allow.
            return decision
        self._expires_at = self._clock() + self._ttl
        self._cache = DecisionCache(self._window, clock=self._clock)
        return self._client.decide(
            agent_id=self._agent_id, subject=self._subject, tool=tool,
            raw_input=raw_input, token=self._grant.token, resource=resource,
        )

    def _token_is_the_problem(self, decision: Decision) -> bool:
        # Only a real policy denial mentioning the token is worth re-minting
        # for. A transport failure (effect None) is not: re-minting would need
        # the same unreachable PDP.
        if decision.effect is not Effect.DENY:
            return False
        reason = decision.reason.lower()
        return "expired" in reason or "token" in reason
```

Export `Session` from `__init__.py`.

- [ ] **Step 4: Run to verify they pass**

```bash
cd sdk/python && python3 -m pytest tests/ -q
```

- [ ] **Step 5: Prove the cache is really being used**

Make `check` skip the cache lookup entirely, run the tests, and confirm
`test_check_allows_and_caches` FAILS on `len(fake_pdp.decide_calls) == 1`.
Restore. Record the output.

- [ ] **Step 6: Commit**

```bash
git add sdk/python/stratium/_session.py sdk/python/stratium/__init__.py sdk/python/tests/test_session.py
git commit -m "feat(sdk): Session.check -- cache, decide, escalate, re-issue once

The turnkey surface. A held delegation, a decision cache in front of the PDP,
escalation resolved by polling and retrying, and one re-issue-and-retry when
the token is what the denial was about -- matching reissue.go, which
deliberately does not try to tell an expired token from a policy denial before
re-minting.

Asserting on the fake PDP's call count is what proves the cache was used: two
identical checks that produce one round trip."
```

---

### Task 7: The conformance suite

**Files:**
- Create: `sdk/conformance/README.md`, `sdk/conformance/cases/*.json`
- Create: `sdk/python/tests/test_conformance.py`

**Interfaces:**
- Consumes: `DecisionCache` (Task 4), `resolve_escalation` (Task 5).
- Produces: the fixture format below, and a Python runner. Task 8 writes the
  Go runner against the same files.

**This is the control that makes five hand-written implementations
defensible.** The fixtures are data, so the same cases bind Python, Go, and
every SDK that follows. A case passing in one language and failing in another
is a drift report, which is the entire point.

- [ ] **Step 1: Write the fixture format**

`sdk/conformance/README.md`:

```markdown
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

- `{"at": 0, "put": {"effect": "ALLOW", "epoch": 1, "token": "tok", "delegation_expires_at": 1e9}}`
- `{"at": 29, "get": {"epoch": 1, "token": "tok", "token_expires_at": 1e9}, "expect": "hit"}`

`expect` is `"hit"` or `"miss"`. A hit that fails any usability condition is a
miss — there is no third outcome.

## Escalation steps

- `{"at": 0, "poll": "pending"}` — the scripted GetApproval status at that instant
- `{"at": 4, "poll": "approved"}`

`expect` carries `effect` (`"ALLOW"`, `"DENY"`, or `null` for a transport
failure), `retried` (whether Decide was retried), and optionally
`reason_contains`.
```

- [ ] **Step 2: Write the cases**

`sdk/conformance/cases/cache-serves-within-staleness-window.json`:

```json
{
  "name": "cache-serves-within-staleness-window",
  "subject": "cache",
  "config": { "staleness_window_seconds": 30 },
  "steps": [
    { "at": 0, "put": { "effect": "ALLOW", "epoch": 1, "token": "tok", "delegation_expires_at": 1000000000 } },
    { "at": 29, "get": { "epoch": 1, "token": "tok", "token_expires_at": 1000000000 }, "expect": "hit" },
    { "at": 30, "get": { "epoch": 1, "token": "tok", "token_expires_at": 1000000000 }, "expect": "hit" }
  ],
  "expect": { "note": "the boundary instant is INSIDE the window: Go is !now.After(cachedAt+staleness)" }
}
```

`sdk/conformance/cases/cache-refuses-after-window.json`:

```json
{
  "name": "cache-refuses-after-window",
  "subject": "cache",
  "config": { "staleness_window_seconds": 30 },
  "steps": [
    { "at": 0, "put": { "effect": "ALLOW", "epoch": 1, "token": "tok", "delegation_expires_at": 1000000000 } },
    { "at": 31, "get": { "epoch": 1, "token": "tok", "token_expires_at": 1000000000 }, "expect": "miss" }
  ],
  "expect": {}
}
```

`sdk/conformance/cases/cache-reading-does-not-extend-the-window.json`:

```json
{
  "name": "cache-reading-does-not-extend-the-window",
  "subject": "cache",
  "config": { "staleness_window_seconds": 30 },
  "steps": [
    { "at": 0, "put": { "effect": "ALLOW", "epoch": 1, "token": "tok", "delegation_expires_at": 1000000000 } },
    { "at": 10, "get": { "epoch": 1, "token": "tok", "token_expires_at": 1000000000 }, "expect": "hit" },
    { "at": 25, "get": { "epoch": 1, "token": "tok", "token_expires_at": 1000000000 }, "expect": "hit" },
    { "at": 31, "get": { "epoch": 1, "token": "tok", "token_expires_at": 1000000000 }, "expect": "miss" }
  ],
  "expect": { "note": "the clock runs from the entry's own cached_at, never from last use" }
}
```

`sdk/conformance/cases/cache-never-serves-an-escalation.json`:

```json
{
  "name": "cache-never-serves-an-escalation",
  "subject": "cache",
  "config": { "staleness_window_seconds": 30 },
  "steps": [
    { "at": 0, "put": { "effect": "ESCALATE", "epoch": 1, "token": "tok", "delegation_expires_at": 1000000000 } },
    { "at": 1, "get": { "epoch": 1, "token": "tok", "token_expires_at": 1000000000 }, "expect": "miss" }
  ],
  "expect": { "note": "an approval covers THIS call; replaying it approves a call nobody saw" }
}
```

`sdk/conformance/cases/cache-stale-epoch-is-a-miss.json`:

```json
{
  "name": "cache-stale-epoch-is-a-miss",
  "subject": "cache",
  "config": { "staleness_window_seconds": 30 },
  "steps": [
    { "at": 0, "put": { "effect": "ALLOW", "epoch": 1, "token": "tok", "delegation_expires_at": 1000000000 } },
    { "at": 1, "get": { "epoch": 2, "token": "tok", "token_expires_at": 1000000000 }, "expect": "miss" }
  ],
  "expect": { "note": "a revocation bumped the epoch; the cached ALLOW is dead" }
}
```

`sdk/conformance/cases/cache-expired-token-is-a-miss.json`:

```json
{
  "name": "cache-expired-token-is-a-miss",
  "subject": "cache",
  "config": { "staleness_window_seconds": 30 },
  "steps": [
    { "at": 0, "put": { "effect": "ALLOW", "epoch": 1, "token": "tok", "delegation_expires_at": 1000000000 } },
    { "at": 5, "get": { "epoch": 1, "token": "tok", "token_expires_at": 2 }, "expect": "miss" }
  ],
  "expect": {}
}
```

`sdk/conformance/cases/escalation-approved-retries-decide.json`:

```json
{
  "name": "escalation-approved-retries-decide",
  "subject": "escalation",
  "config": { "poll_interval_seconds": 1, "timeout_seconds": 30 },
  "steps": [
    { "at": 0, "poll": "pending" },
    { "at": 1, "poll": "approved" }
  ],
  "expect": {
    "retried": true,
    "effect": "ALLOW",
    "note": "an approval is permission to ask again, not permission to act"
  }
}
```

`sdk/conformance/cases/escalation-timeout-is-not-an-allow.json`:

```json
{
  "name": "escalation-timeout-is-not-an-allow",
  "subject": "escalation",
  "config": { "poll_interval_seconds": 1, "timeout_seconds": 3 },
  "steps": [
    { "at": 0, "poll": "pending" },
    { "at": 1, "poll": "pending" },
    { "at": 2, "poll": "pending" },
    { "at": 3, "poll": "pending" }
  ],
  "expect": { "retried": false, "effect": "DENY", "reason_contains": "timed out" }
}
```

`sdk/conformance/cases/escalation-denied-does-not-retry.json`:

```json
{
  "name": "escalation-denied-does-not-retry",
  "subject": "escalation",
  "config": { "poll_interval_seconds": 1, "timeout_seconds": 30 },
  "steps": [
    { "at": 0, "poll": "denied" }
  ],
  "expect": { "retried": false, "effect": "DENY" }
}
```

- [ ] **Step 3: Write the Python runner**

`sdk/python/tests/test_conformance.py`:

```python
"""Runs sdk/conformance/cases against this SDK.

These fixtures bind every implementation, Go included. A case that passes here
and fails in Go is a drift report -- which is why they are data and not tests.
"""

import json
import pathlib

import pytest

from stratium import Effect
from stratium._cache import DecisionCache
from stratium._escalation import resolve_escalation
from stratium._pdp import pdp_pb2
from stratium._types import decision_from_response

CASES = sorted((pathlib.Path(__file__).parents[2] / "conformance" / "cases").glob("*.json"))
assert CASES, "no conformance cases found -- has sdk/conformance/cases moved?"


class FakeClock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def _decision(effect_name: str):
    effect = {"ALLOW": pdp_pb2.EFFECT_ALLOW, "DENY": pdp_pb2.EFFECT_DENY,
              "ESCALATE": pdp_pb2.EFFECT_ESCALATE}[effect_name]
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=effect, reason="scripted", approval_id="ap-1")
    )


def _run_cache(case, clock):
    cache = DecisionCache(case["config"]["staleness_window_seconds"], clock=clock)
    for step in case["steps"]:
        clock.t = float(step["at"])
        if "put" in step:
            p = step["put"]
            cache.put(_KEY, _decision(p["effect"]), epoch=p["epoch"],
                      delegation_expires_at=p["delegation_expires_at"], token=p["token"])
        elif "get" in step:
            g = step["get"]
            got = cache.get(_KEY, last_known_epoch=g["epoch"], token=g["token"],
                            token_expires_at=g["token_expires_at"])
            want = step["expect"]
            actual = "hit" if got is not None else "miss"
            assert actual == want, (
                f'{case["name"]}: at t={step["at"]} expected {want}, got {actual}'
            )


_KEY = "conformance-key"


def _run_escalation(case, clock):
    statuses = [s["poll"] for s in case["steps"]]
    calls = {"n": 0}
    retried = {"yes": False}

    def poll(approval_id: str) -> str:
        i = min(calls["n"], len(statuses) - 1)
        calls["n"] += 1
        return statuses[i]

    def retry():
        retried["yes"] = True
        return _decision("ALLOW")

    cfg = case["config"]
    d = resolve_escalation(
        poll, retry, approval_id="ap-1",
        poll_interval=cfg["poll_interval_seconds"],
        timeout=cfg["timeout_seconds"],
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )

    want = case["expect"]
    assert retried["yes"] == want["retried"], f'{case["name"]}: retried mismatch'
    if want.get("effect") is None and "effect" in want:
        assert d.effect is None
    elif "effect" in want:
        assert d.effect is Effect[want["effect"]], (
            f'{case["name"]}: effect {d.effect}, want {want["effect"]}'
        )
    if "reason_contains" in want:
        assert want["reason_contains"] in d.reason


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_conformance_case(path):
    case = json.loads(path.read_text())
    assert case["name"] == path.stem, "case name must match its filename"
    clock = FakeClock()
    if case["subject"] == "cache":
        _run_cache(case, clock)
    elif case["subject"] == "escalation":
        _run_escalation(case, clock)
    else:
        pytest.fail(f'unknown subject {case["subject"]!r}')
```

- [ ] **Step 4: Run the suite**

```bash
cd sdk/python && python3 -m pytest tests/test_conformance.py -v
```

Expected: all nine cases PASS.

- [ ] **Step 5: Prove the cases bind something**

Change the cache's boundary from `<=` to `<`, run the suite, and confirm
`cache-serves-within-staleness-window` FAILS naming `t=30`. Restore. Then make
the escalation timeout return the original ESCALATE and confirm
`escalation-timeout-is-not-an-allow` FAILS. Restore. Record both.

- [ ] **Step 6: Commit**

```bash
git add sdk/conformance sdk/python/tests/test_conformance.py
git commit -m "test(sdk): a language-agnostic conformance suite

Nine cases encoding the behaviour every SDK reimplements: the inclusive
staleness boundary, that reading never extends the window, that an ESCALATE is
never served from cache, that a bumped epoch kills a cached ALLOW, and that an
escalation timeout is a DENY rather than an allow.

They are JSON, not tests, so the same cases bind Python, the Go reference, and
every SDK that follows. A case passing in one language and failing in another
is a drift report, which is the entire reason they exist."
```

---

### Task 8: The Go conformance runner

**Files:**
- Create: `services/cmd/conformance/main.go`, `services/cmd/conformance/main_test.go`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `sdk/conformance/cases/*.json` from Task 7; the cache and escalation
  logic in `services/cmd/stratium-pep`.
- Produces: `make conformance`, running the same cases against Go.

**Why this task exists:** without it the fixtures describe what Python does,
and the "reference" is bound by nothing. Binding Go too is what makes a
divergence a report about *which* implementation is wrong.

- [ ] **Step 1: Write the failing test**

`services/cmd/conformance/main_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The cases live outside the Go module, so a moved directory must fail loudly
// here rather than silently running zero cases.
func TestEveryConformanceCaseRuns(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "sdk", "conformance", "cases")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v -- if sdk/conformance moved, update this path", dir, err)
	}
	if len(entries) == 0 {
		t.Fatal("no conformance cases found")
	}

	ran := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		c, err := loadCase(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if err := runCase(c); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		ran++
	}
	if ran == 0 {
		t.Fatal("zero cases ran")
	}
	t.Logf("%d conformance cases ran against the Go reference", ran)
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd services && go test ./cmd/conformance/
```

Expected: FAIL — `undefined: loadCase`.

- [ ] **Step 3: Implement the runner**

`services/cmd/conformance/main.go` defines `type Case`, `loadCase(path)
(Case, error)`, and `runCase(Case) error`, mirroring the Python runner: a fake
clock, the same `put`/`get`/`poll` steps, and the same hit/miss and
effect/retried assertions. It exercises the same predicates
`stratium-pep` uses — `cacheEntryUsable`'s five conditions and
`resolveApproval`'s terminal outcomes — rather than a second copy of them.
Where those are unexported in `package main` of `stratium-pep`, lift the
predicate into a small internal package both binaries import; do **not**
duplicate the logic into this runner, which would defeat the entire point of
the task.

`main()` runs every case and exits non-zero on the first failure, printing the
case name and what differed.

- [ ] **Step 4: Add the Makefile target**

```make
conformance: ## Run the SDK conformance cases against the Go reference
	cd $(GO_DIR) && go test ./cmd/conformance/ -v
```

- [ ] **Step 5: Run it**

```bash
make conformance
```

Expected: every case passes, and the log line names how many ran.

- [ ] **Step 6: Prove it binds Go**

Temporarily widen `withinStalenessWindow` in
`services/cmd/stratium-pep/cache.go` from `!now.After(...)` to
`now.Before(...)`, run `make conformance`, and confirm
`cache-serves-within-staleness-window` FAILS. Restore and re-run. Record both
outputs — this is the proof that the reference is bound rather than trusted.

- [ ] **Step 7: Commit**

```bash
git add services/cmd/conformance Makefile
git commit -m "test: run the conformance cases against the Go reference

Without this the fixtures describe what the Python SDK does and the reference
is bound by nothing. Binding Go too is what turns a divergence into a report
about which implementation is wrong.

The runner calls stratium-pep's own predicates rather than reimplementing
them; a second copy of cacheEntryUsable inside the runner would pass its own
cases while the product drifted."
```

---

### Task 9: The live proof

**Files:**
- Create: `sdk/python/example/custom_pep.py`, `sdk/python/example/README.md`

- [ ] **Step 1: Write the example**

`sdk/python/example/custom_pep.py` — roughly 60 lines:

```python
#!/usr/bin/env python3
"""A custom PEP, in about sixty lines.

Mints a delegation for Read only, then checks two calls: one it should be
allowed to make and one it should not. Exits non-zero if either differs, and
asserts on the PDP's own reason strings rather than on exit codes -- a denial
for the wrong reason is a failure, not a pass.

    python3 custom_pep.py --pdp localhost:56378 --agent <uuid> --subject you@example.com
"""

import argparse
import sys

from stratium import Client, Session


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdp", required=True, help="host:port of the PDP")
    ap.add_argument("--agent", required=True, help="an agent id in the PDP's tenant")
    ap.add_argument("--subject", required=True)
    args = ap.parse_args()

    with Client(args.pdp) as client:
        session = Session(
            client, subject=args.subject, agent_id=args.agent,
            tools=["Read"], max_action_tier=1,
            purpose="stratium python sdk example", ttl_seconds=300,
        )
        print(f"delegation {session.grant.delegation_id}")
        print(f"  granted tools: {list(session.grant.granted_scope.tools)}")
        print(f"  granted tier:  {session.grant.granted_scope.max_action_tier}")
        print()

        expectations = [
            ("Read", {"file_path": "/tmp/notes.txt"}, True, None),
            ("Bash", {"command": "rm -rf /tmp/x"}, False, "approved_tools"),
        ]

        failures = 0
        for tool, raw_input, want_allowed, want_reason in expectations:
            d = session.check(tool=tool, raw_input=raw_input)
            verdict = "ALLOW" if d else "DENY "
            print(f"  {verdict} {tool:6} {d.reason}")

            if bool(d) != want_allowed:
                print(f"    MISMATCH: expected {'ALLOW' if want_allowed else 'DENY'}")
                failures += 1
            elif want_reason and want_reason not in d.reason:
                # A denial for the wrong cause is not a pass.
                print(f"    MISMATCH: expected the reason to mention {want_reason!r}")
                failures += 1

        print()
        print(f"enforcement: {len(expectations) - failures}/{len(expectations)} as expected")
        return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run it against the live stack**

```bash
PAP="localhost:$(docker compose -f deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"
PDP="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pdp-pap 50051 | sed -E 's/.*://')"
# An agent id from that tenant -- the admin console's Agents screen lists them by name.
cd sdk/python && python3 example/custom_pep.py --pdp "$PDP" --agent "<uuid>" --subject you@example.com
```

Expected: `enforcement: 2/2 as expected`, exit 0, with the PDP's real reason
strings printed for both.

**Do not run `deploy/stratium down`, `docker compose down`, or pass `-v` to
any docker command.** The live stack must survive.

- [ ] **Step 3: Confirm the delegation reached the tenant**

Open the admin console, go to Delegations, and find the row: the agent's name,
purpose `stratium python sdk example`, depth 0, and the tools the PDP actually
granted. Capture that observation in `example/README.md` — it is the proof no
unit test can give, through a fully independent path.

- [ ] **Step 4: Commit**

```bash
git add sdk/python/example
git commit -m "feat(sdk): a custom PEP in sixty lines, run against a live stack

Mints a delegation for Read only, then checks Read and Bash. Asserts on the
PDP's own reason strings, not exit codes: a denial for the wrong cause is a
failure, not a pass.

Pointed at pdp-pap deliberately -- its tenant is the one the admin console
administers, so the delegation this mints is visible in the console with the
agent's name, the purpose string, and the scope the PDP actually granted."
```

---

### Task 10: Documentation

**Files:**
- Create/modify: `sdk/python/README.md`
- Modify: `docs/pep/README.md`

- [ ] **Step 1: Write the SDK README**

Cover: install, the two calls, `Session.check`, the four safety properties and
why each exists, what the SDK owns (session, escalation, cache) and what it
does not (DPoP, and why: `CreateDelegation` mints a bearer token), and how to
run the conformance suite.

- [ ] **Step 2: Add it to the surfaces page**

`docs/pep/README.md` lists five surfaces. Add a sixth row for the SDK — an
in-process PEP you write yourself — and say plainly that it is a library, not
a subcommand of `stratium-pep`.

- [ ] **Step 3: Verify every claim**

For each capability the README states, confirm the method exists in
`stratium/__init__.py`'s `__all__`. For each behaviour, point at the test that
holds it. A README describing a slightly different SDK than the one that
shipped is worse than none.

- [ ] **Step 4: Commit**

```bash
git add sdk/python/README.md docs/pep/README.md
git commit -m "docs: document the Python SDK and list it beside the five PEP surfaces"
```

---

## Self-Review

**Spec coverage.** Every section maps to a task: the API (2, 3), the four
footguns (2), turnkey session/escalation/cache (4, 5, 6), the conformance suite
(7, 8), layout and generation (1), testing (throughout), the live proof (9),
docs (10). DPoP's exclusion is stated in Task 6's `_token_is_the_problem` and
in Task 10's README.

**Rulings made while writing:**

1. **`create_delegation` raises; `decide` does not.** The spec says failures
   return rather than raise, but that reasoning is about a value a caller might
   mistake for permission. There is no such value for "you have no authority",
   and a PEP that cannot mint has nothing to enforce with. Recorded in Task 3.
2. **An unknown `Effect` value maps to `DENY`,** not passed through. A newer
   PDP returning an effect this build does not know must not reach a caller's
   match statement as an unhandled case.
3. **Task 8 lifts `stratium-pep`'s predicates into a shared package** rather
   than reimplementing them in the runner. A runner with its own copy of
   `cacheEntryUsable` would pass its own cases while the product drifted —
   exactly the failure the suite exists to prevent.

**Known gaps, deliberate:**

- **No `IssueToken`.** `CreateDelegation` already returns a token; the separate
  issuance path serves sender-constrained flows this SDK does not.
- **No chained delegations in the example.** `parent_delegation_id` is on the
  API and untested here; the depth examples in `example/depth/` cover the
  semantics in Go.
- **`Session` re-mints on any denial mentioning "token" or "expired".** A
  substring match on a reason string is crude. It matches `reissue.go`'s own
  deliberate refusal to distinguish the two cases, but a PDP that reworded its
  denials would silently stop re-minting. Worth an explicit sentinel in the
  proto later.
