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
    if not approval_id:
        # DecideResponse.approval_id is guaranteed populated whenever effect
        # is ESCALATE. A PDP that violates its own contract has given us
        # nothing to poll for, and polling with an empty id would open a
        # fresh approval instead. Deny rather than guess.
        return _deny("stratium: escalation carried no approval id")
    if poll_interval <= 0:
        # The poll bound below divides by this: 0 raises ZeroDivisionError and
        # a negative yields a negative bound. Refused here, and refused as a
        # Decision rather than an exception -- Session.check's contract is that
        # every failure comes back as one -- so a caller mistake can never
        # become either a crash or an unbounded wait.
        return _deny(
            f"stratium: poll_interval must be positive, got {poll_interval}"
        )

    deadline = clock() + timeout
    timed_out = _deny(
        f"stratium: approval {approval_id} timed out after {timeout}s "
        f"without a decision"
    )
    # Bounded by a poll COUNT as well as by the deadline. The deadline is only
    # as good as the clock it is measured on, and `clock` and `sleep` are
    # independent keyword arguments with independent defaults: fake the first
    # without the second and nothing ever advances it, so `clock() >= deadline`
    # is never true and this loop polls GetApproval forever. The count holds
    # regardless of what any caller injects, including this function's own
    # default pair. Both exits produce the SAME timeout deny -- one timeout
    # behaviour, not two.
    for _ in range(int(timeout / poll_interval) + 2):
        try:
            status = poll(approval_id)
        except Exception as err:  # noqa: BLE001
            # The PDP could not be asked. Not a policy decision -- effect
            # stays None so nothing records a denial that never happened.
            return decision_from_error(err)

        if status == _TERMINAL_APPROVED:
            # Permission to ask again, NOT permission to act. The retry must
            # carry the approval id so the PDP consumes this approval instead
            # of opening another one.
            retried = retry_decide()
            if retried.effect is Effect.ALLOW:
                return retried
            # Anything else collapses to DENY, matching escalation.go: a leg
            # the approval does not cover may have started refusing between the
            # escalation and the retry, and -- defensively -- a retry that
            # comes back ESCALATE again must not be handed to a caller as the
            # question it already asked.
            if retried.effect is None:
                return retried          # transport failure: not a decision
            # The retry's OWN reason, unprefixed. This is the PDP's verdict
            # text, not a diagnostic this SDK synthesised, and a human reading
            # the denial must be able to tell the two apart -- the same rule
            # escalation.go states for this exact branch.
            return _deny(retried.reason)
        if status == _TERMINAL_DENIED:
            return _deny(f"stratium: approval {approval_id} was denied")

        if clock() >= deadline:
            break
        sleep(poll_interval)
    # Never an allow, and never the original ESCALATE: a caller matching on
    # effect deserves to know this settled as a refusal.
    return timed_out
