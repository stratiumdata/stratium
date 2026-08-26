"""A held delegation, and the check loop around it.

Session.check is the turnkey surface: consult the cache, ask the PDP, resolve
an escalation if one comes back, and re-issue once if the token was the
problem. Everything it returns is a Decision, including every failure.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable, Mapping, Sequence

from ._cache import DecisionCache
from ._escalation import resolve_escalation
from ._types import Decision, Effect, Grant, canonical_raw_input


def token_expiry(token: str) -> float:
    """The unix time a delegation token expires, from its own `exp` claim.

    Decoded, never verified -- the PDP signs and verifies these, and a PEP
    reading an expiry to decide whether to bother asking is not
    authenticating anything. Go does the same with jwt.ParseUnverified.

    FAILS CLOSED. Malformed, no `exp`, or a non-numeric `exp` all return 0.0
    -- already expired -- so the cache refuses the entry. Go's
    tokenNotExpired returns false in exactly those cases. The tempting
    alternative, defaulting a missing claim to infinity, reads as harmless and
    means "this token never expires", which combined with a decision cache is
    a permanently serveable ALLOW.

    No new dependency: a JWT is three base64url segments and the middle one is
    JSON, so grpcio remains the SDK's only runtime requirement.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)          # restore stripped padding
        exp = json.loads(base64.urlsafe_b64decode(payload))["exp"]
        return float(exp)
    except Exception:  # noqa: BLE001 -- any failure to read exp means expired
        return 0.0


class Session:
    def __init__(
        self, client, *, subject: str, agent_id: str, tools: Sequence[str],
        max_action_tier: int, purpose: str, ttl_seconds: int,
        staleness_window: float = 30.0, approval_poll_interval: float = 2.0,
        approval_timeout: float = 120.0,
        clock: Callable[[], float] = time.time,
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
        self._token_expires_at = token_expiry(self._grant.token)

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
            token_expires_at=self._token_expires_at,
        )
        if hit is not None:
            return hit

        decision = self._ask(tool=tool, raw_input=canonical, resource=resource)

        if decision.effect is Effect.ESCALATE and decision.approval_id:
            decision = resolve_escalation(
                self._client.get_approval,
                lambda: self._ask(tool=tool, raw_input=canonical, resource=resource,
                                  approval_id=decision.approval_id),
                approval_id=decision.approval_id,
                poll_interval=self._poll, timeout=self._approval_timeout,
                clock=self._clock,
            )

        self._cache.put(
            key, decision, epoch=self._grant.epoch,
            delegation_expires_at=self._expires_at,
        )
        return decision

    def _ask(self, *, tool: str, raw_input: str, resource,
             approval_id: str | None = None) -> Decision:
        decision = self._client.decide(
            agent_id=self._agent_id, subject=self._subject, tool=tool,
            raw_input=raw_input, token=self._grant.token, resource=resource,
            approval_id=approval_id,
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
        self._token_expires_at = token_expiry(self._grant.token)
        self._cache = DecisionCache(self._window, clock=self._clock)
        return self._client.decide(
            agent_id=self._agent_id, subject=self._subject, tool=tool,
            raw_input=raw_input, token=self._grant.token, resource=resource,
            approval_id=approval_id,
        )

    def _token_is_the_problem(self, decision: Decision) -> bool:
        # Only a real policy denial mentioning the token is worth re-minting
        # for. A transport failure (effect None) is not: re-minting would need
        # the same unreachable PDP.
        if decision.effect is not Effect.DENY:
            return False
        reason = decision.reason.lower()
        return "expired" in reason or "token" in reason
