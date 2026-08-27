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
    polled = []

    def poll(approval_id: str) -> str:
        polled.append(approval_id)
        return "pending"  # never settles

    d = resolve_escalation(
        poll, lambda: allowed(), approval_id="ap-1",
        poll_interval=1.0, timeout=3.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert d.allowed is False
    assert d.effect is Effect.DENY
    assert "timed out" in d.reason
    assert "ap-1" in d.reason
    # Paired clock and sleep, so the DEADLINE is what ends this wait -- polls
    # at t=0,1,2,3 and stops the instant it is reached. The count bound (5
    # here) is the backstop for an unpaired caller and must never be the
    # tighter of the two: a bound that fired first would cut a real wait short
    # of the timeout its caller asked for.
    assert clock.t == 3.0
    assert len(polled) == 4


def test_a_denied_approval_is_a_deny_and_does_not_retry():
    clock = Clock()
    poll = polls("denied")
    retried = []

    d = resolve_escalation(
        poll, lambda: (retried.append(True), allowed())[1],
        approval_id="ap-1", poll_interval=1.0, timeout=30.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert not retried
    assert d.effect is Effect.DENY
    # Decisive: the timeout path would also produce DENY without retrying, so
    # what distinguishes them is that this settled on the FIRST poll rather
    # than after burning the whole 30s deadline.
    assert clock.t == 0.0


# Anything but ALLOW from the retry collapses to DENY, matching
# escalation.go: a leg the approval does not cover may have started refusing
# between the escalation and the retry.
def test_a_retry_that_denies_collapses_to_deny_keeping_the_pdps_reason():
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
    # Unprefixed: the PDP's own words survive the collapse, so a human reading
    # the denial can tell a policy verdict from an SDK diagnostic.
    assert d.reason == retried_decision.reason


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


# DecideResponse.approval_id is guaranteed populated whenever effect is
# ESCALATE. A PDP violating that contract has given us nothing to poll for --
# deny immediately rather than guess (and never call poll with an empty id,
# which would open a fresh approval instead of finding the intended one).
def test_an_empty_approval_id_denies_without_polling_or_retrying():
    clock = Clock()
    polled = []
    retried = []

    def poll(approval_id: str) -> str:
        polled.append(approval_id)
        return "pending"

    d = resolve_escalation(
        poll, lambda: (retried.append(True), allowed())[1],
        approval_id="", poll_interval=1.0, timeout=30.0,
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )
    assert d.allowed is False
    assert d.effect is Effect.DENY
    assert not polled, "must not poll with an empty approval id"
    assert not retried, "must not retry Decide either"


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


def tripwire(limit: int, status: str = "pending"):
    """A poll callable that RAISES once past `limit` calls.

    The tripwire is what keeps a regression in the two G1 tests below a
    failure rather than a hang. resolve_escalation catches whatever poll
    raises and returns a transport failure (effect None), so an unbounded
    loop fails the DENY assertions in milliseconds. Asserting on wall-clock
    waiting instead would hang the suite on exactly the regression the test
    exists to catch.
    """
    calls: list[str] = []

    def poll(approval_id: str) -> str:
        calls.append(approval_id)
        if len(calls) > limit:
            raise AssertionError(f"polled {len(calls)} times, bound is {limit}")
        return status

    return poll, calls


# G1. The wait is bounded by a poll COUNT as well as by the deadline. The
# deadline is only as good as the clock it is measured on: a caller who fakes
# `clock` without also faking `sleep` never advances it, so `clock() >=
# deadline` is never true and the deadline bounds nothing. That pairing is
# constructible through the documented public API -- both are keyword
# arguments with independent defaults -- and resolve_escalation's OWN default
# sleep is the real time.sleep, which is that shape whenever the caller's
# clock is fake.
def test_a_clock_that_never_advances_still_terminates():
    clock = Clock()                     # frozen at 0.0: nothing moves it
    limit = 12                          # int(0.01 / 0.001) + 2
    poll, calls = tripwire(limit)

    d = resolve_escalation(
        poll, lambda: allowed(), approval_id="ap-1",
        poll_interval=0.001, timeout=0.01,
        clock=clock,                    # and deliberately NO sleep=
    )

    # The same timeout DENY the deadline produces -- one timeout behaviour,
    # not two.
    assert d.effect is Effect.DENY
    assert "timed out" in d.reason
    assert "ap-1" in d.reason
    assert len(calls) == limit
    assert clock.t == 0.0, "the deadline never fired here; the count did"


# A non-positive interval is a caller mistake that the count bound would
# divide by: 0 raises ZeroDivisionError and a negative yields a negative
# bound. Refused up front, and refused as a Decision rather than an exception
# -- Session.check's contract is that every failure comes back as one.
def test_a_non_positive_poll_interval_denies_without_polling():
    for interval in (0.0, -1.0):
        poll, calls = tripwire(5)
        d = resolve_escalation(
            poll, lambda: allowed(), approval_id="ap-1",
            poll_interval=interval, timeout=30.0,
            clock=Clock(), sleep=lambda s: None,
        )
        assert d.effect is Effect.DENY, interval
        assert "poll_interval" in d.reason, interval
        assert not calls, interval
