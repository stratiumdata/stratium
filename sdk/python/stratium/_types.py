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
    escalate_at: int | None = None
    """The threshold the delegation was issued with: at or above this tier a
    call waits for a human. None means it never escalates."""


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

        THE COST, and it is sharp: a Decision is now FALSY unless it allows,
        so `or` and `and` over one silently discard non-allow answers.

            d = maybe_decision or fallback   # WRONG

        A DENY or an ESCALATE is falsy, so that line throws away the real
        answer and keeps the fallback -- turning a refusal into whatever
        `fallback` says. This is not hypothetical: it hit a test helper in
        this repository written as `decision or allow()`, which quietly
        replaced every ESCALATE under test with an ALLOW.

        Use an explicit None check when defaulting:

            d = maybe_decision if maybe_decision is not None else fallback
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
