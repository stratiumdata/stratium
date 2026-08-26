from stratium import Effect
from stratium._escalation import resolve_escalation
from stratium._pdp import pdp_pb2
from stratium._types import decision_from_error, decision_from_response


def escalated(approval_id="ap-1"):
    return decision_from_response(pdp_pb2.DecideResponse(
        effect=pdp_pb2.EFFECT_ESCALATE, reason="needs approval", approval_id=approval_id))


def allowed():
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW, reason="permitted"))


def denied(reason="insufficient tier"):
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_DENY, reason=reason))


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


# Anything but ALLOW from the retry collapses to DENY, matching
# escalation.go: a leg the approval does not cover may have started refusing
# between the escalation and the retry.
def test_a_retry_that_denies_collapses_to_deny_naming_the_approval():
    clock = Clock()
    poll = polls("approved")
    retried_decision = denied("insufficient tier")

    d = resolve_escalation(
        poll, lambda: retried_decision, approval_id="ap-1",
        poll_interval=1.0, timeout=30.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert d.allowed is False
    assert d.effect is Effect.DENY
    assert "ap-1" in d.reason
    # Not a bare passthrough: the SUT's own wrapping ran.
    assert d.reason != retried_decision.reason
    assert "insufficient tier" in d.reason


# The critical collapse case: a retry that itself comes back ESCALATE must
# NOT be handed to the caller as the question it already asked.
def test_a_retry_that_escalates_again_collapses_to_deny_not_escalate():
    clock = Clock()
    poll = polls("approved")

    d = resolve_escalation(
        poll, lambda: escalated("ap-2"), approval_id="ap-1",
        poll_interval=1.0, timeout=30.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert d.allowed is False
    assert d.effect is Effect.DENY


# A retry that fails at the transport layer is not a policy decision either.
def test_a_retry_that_fails_at_transport_keeps_effect_none():
    clock = Clock()
    poll = polls("approved")
    transport_failure = decision_from_error(RuntimeError("connection reset"))

    d = resolve_escalation(
        poll, lambda: transport_failure, approval_id="ap-1",
        poll_interval=1.0, timeout=30.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert d.allowed is False
    assert d.effect is None, "no policy decision was reached"
    assert d.error is not None


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
