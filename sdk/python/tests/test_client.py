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


# approval_id names a pending approval to CONSUME (the retry after an
# EFFECT_ESCALATE), not create. Sent only when given, and only via the
# `optional string` presence mechanism -- an explicitly-sent "" is a
# different (invalid) request than an omitted field, so only a presence
# check tells "sent" from "not sent" apart.
def test_decide_sends_approval_id_when_given(fake_pdp):
    fake_pdp.decide_responses.append(pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW))
    with Client(fake_pdp.addr) as c:
        c.decide(agent_id="a", subject="s", tool="Read", raw_input="{}",
                 token="t", approval_id="ap-1")
    req = fake_pdp.decide_calls[0]
    assert req.HasField("approval_id")
    assert req.approval_id == "ap-1"


def test_decide_leaves_approval_id_unset_by_default(fake_pdp):
    fake_pdp.decide_responses.append(pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW))
    with Client(fake_pdp.addr) as c:
        c.decide(agent_id="a", subject="s", tool="Read", raw_input="{}", token="t")
    req = fake_pdp.decide_calls[0]
    assert not req.HasField("approval_id")


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


def test_create_delegation_sends_every_field(fake_pdp):
    fake_pdp.delegation_responses.append(pdp_pb2.CreateDelegationResponse(
        delegation_id="d1", token="tok", epoch=1,
        granted_scope=pdp_pb2.GrantedScope(max_action_tier=1, tools=["Read"])))
    with Client(fake_pdp.addr) as c:
        c.create_delegation(subject="you@example.com", agent_id="a1",
                            tools=["Read", "Grep"], max_action_tier=2,
                            purpose="a custom PEP", ttl_seconds=900)
    req = fake_pdp.delegation_calls[0]
    assert req.subject == "you@example.com"
    assert req.agent_id == "a1"
    assert req.purpose == "a custom PEP"
    assert req.ttl_seconds == 900
    assert list(req.requested_scope.tools) == ["Read", "Grep"]
    assert req.requested_scope.max_action_tier == 2


# parent_delegation_id is what makes a delegation a CHILD. Unforwarded, every
# chained delegation silently becomes a root -- full authority instead of
# narrowed, with nothing reporting an error.
def test_parent_delegation_id_is_forwarded_when_given(fake_pdp):
    fake_pdp.delegation_responses.append(pdp_pb2.CreateDelegationResponse(
        delegation_id="d2", token="tok", epoch=1,
        granted_scope=pdp_pb2.GrantedScope(max_action_tier=1, tools=["Read"])))
    with Client(fake_pdp.addr) as c:
        c.create_delegation(subject="s", agent_id="a", tools=["Read"],
                            max_action_tier=1, purpose="p", ttl_seconds=60,
                            parent_delegation_id="parent-1")
    assert fake_pdp.delegation_calls[0].parent_delegation_id == "parent-1"


def test_a_root_delegation_sends_no_parent(fake_pdp):
    fake_pdp.delegation_responses.append(pdp_pb2.CreateDelegationResponse(
        delegation_id="d3", token="tok", epoch=1,
        granted_scope=pdp_pb2.GrantedScope(max_action_tier=1, tools=["Read"])))
    with Client(fake_pdp.addr) as c:
        c.create_delegation(subject="s", agent_id="a", tools=["Read"],
                            max_action_tier=1, purpose="p", ttl_seconds=60)
    assert fake_pdp.delegation_calls[0].parent_delegation_id == ""


# The deliberate asymmetry with decide(): there is no value meaning "you have
# no authority" that a caller could mistake for permission, so this raises.
def test_create_delegation_raises_rather_than_returning_an_empty_grant(fake_pdp):
    with pytest.raises(grpc.RpcError):          # no scripted response -> abort
        with Client(fake_pdp.addr) as c:
            c.create_delegation(subject="s", agent_id="a", tools=["Read"],
                                max_action_tier=1, purpose="p", ttl_seconds=60)


# Task 5 compares this against "approved" and "denied". A PDP answering
# "Approved" would fall through to the timeout branch, quietly turning an
# approved escalation into a deny.
def test_get_approval_lowercases_the_status(fake_pdp):
    fake_pdp.approval_responses.append(pdp_pb2.GetApprovalResponse(status="APPROVED"))
    with Client(fake_pdp.addr) as c:
        assert c.get_approval("ap-1") == "approved"
    assert fake_pdp.approval_calls[0].approval_id == "ap-1"


# TWO scripted responses on purpose. With one, the second call fails whether
# or not close() worked -- the fixture is exhausted either way -- and the test
# passes for a reason unrelated to what it claims. With two, an open channel
# succeeds here, so a refusal can only mean the channel really closed.
def test_leaving_the_context_manager_closes_the_channel(fake_pdp):
    fake_pdp.decide_responses.extend([
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW),
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW),
    ])
    c = Client(fake_pdp.addr)
    with c:
        assert c.decide(agent_id="a", subject="s", tool="Read",
                        raw_input="{}", token="t")

    after = c.decide(agent_id="a", subject="s", tool="Read", raw_input="{}", token="t")
    assert after.allowed is False
    assert after.effect is None
    # One scripted response is left unused: proof the failure was the closed
    # channel and not an exhausted fixture.
    assert len(fake_pdp.decide_calls) == 1
