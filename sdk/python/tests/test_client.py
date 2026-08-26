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
