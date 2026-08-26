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
