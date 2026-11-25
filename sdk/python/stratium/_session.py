"""A held delegation, and the check loop around it.

Session.check is the turnkey surface: consult the cache, ask the PDP, resolve
an escalation if one comes back, and renew the token once if it was the
problem. A session holds one delegation and never creates another. Everything it returns is a Decision, including every failure.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import replace
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
        escalate_at: int | None = None,
        principal_token: str | None = None,
        harness: str = "",
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Mint a delegation and hold it.

        `clock` and `sleep` are ONE decision, not two, which is why they sit
        together here and are always passed together into resolve_escalation.
        The escalation wait measures its deadline with `clock` and spends the
        interval with `sleep`; fake only the first and the deadline is on a
        clock nothing ever advances, so `clock() >= deadline` is never true.
        A caller who fakes one SHOULD fake the other -- typically a `sleep`
        that advances the same fake `clock` by the seconds it was handed --
        or the wait runs out resolve_escalation's poll-COUNT bound instead,
        spending approval_timeout in real seconds to get there. That bound is
        what keeps the unpaired shape merely slow rather than unbounded; it is
        a backstop, not a licence to leave the pair unpaired.
        """
        self._client = client
        # One harness per session: see Client.decide. Every call this session
        # checks or reports is that harness's tool.
        self._harness = harness
        self._subject = subject
        self._agent_id = agent_id
        self._mint = dict(
            subject=subject, agent_id=agent_id, tools=list(tools),
            max_action_tier=max_action_tier, purpose=purpose, ttl_seconds=ttl_seconds,
            escalate_at=escalate_at,
            principal_token=principal_token,
        )
        self._clock = clock
        self._sleep = sleep
        self._poll = approval_poll_interval
        self._approval_timeout = approval_timeout
        self._cache = DecisionCache(staleness_window, clock=clock)

        self._grant: Grant = client.create_delegation(**self._mint)
        self._token_expires_at = token_expiry(self._grant.token)
        # The DELEGATION's expiry, from the token that actually came back --
        # never clock() + the ttl_seconds that was asked for. The PDP's grant
        # narrows: _types.Grant.granted_scope states the rule for the scope
        # ("what the PDP actually granted, which is not what was requested"),
        # and the expiry is the same kind of claim about the same grant. Go
        # sources DelegationExpiresAt from tokenExpiry(token) for exactly this
        # reason (local_cache.go:275); recording the requested TTL instead
        # records an expiry for authority this PEP may never have held.
        self._expires_at = self._token_expires_at

    @property
    def grant(self) -> Grant:
        return self._grant

    def check(
        self, *, tool: str, raw_input: str | Mapping,
        resource: Mapping[str, str] | None = None,
    ) -> Decision:
        canonical = canonical_raw_input(raw_input)

        hit = self._cache.get(
            self._key(tool, canonical), last_known_epoch=self._grant.epoch,
            token_expires_at=self._token_expires_at,
        )
        if hit is not None:
            return hit

        decision = self._ask(tool=tool, raw_input=canonical, resource=resource)

        if decision.effect is Effect.ESCALATE and decision.approval_id:
            # RETURNS, deliberately: NOTHING derived from the escalation path is
            # ever cached -- not the approved ALLOW, not a timeout's synthetic
            # DENY, not a denial. Only the decision that settled BEFORE any wait
            # began reaches the put() below, and the only way to guarantee that
            # is for this branch to have no path to it.
            #
            # A human approving one specific pending action is not the PDP
            # producing a general, replayable verdict about every future
            # identical call. Cache the post-approval ALLOW and one approval of
            # Bash(rm -rf /data) silently authorizes unlimited identical repeats
            # for the whole staleness window, with no PDP round trip and no
            # second human -- the "serves an approval that was never granted"
            # failure, reached one step later than the literal ESCALATE value.
            #
            # Same structure as local_cache.go:110-140, which names this failure
            # and prevents it the same way: both its callers place their one
            # storeCacheResult call ONLY on the response that settles before any
            # escalation wait begins, never on resolveApproval's own
            # post-approval retry response. Not enforced by inspecting the
            # resolved effect -- that response is a perfectly ordinary ALLOW or
            # DENY and no check on it could tell it apart from one the PDP
            # reached unaided. It holds by position.
            return resolve_escalation(
                self._client.get_approval,
                lambda: self._ask(tool=tool, raw_input=canonical, resource=resource,
                                  approval_id=decision.approval_id),
                approval_id=decision.approval_id,
                poll_interval=self._poll, timeout=self._approval_timeout,
                # Both, always. See __init__: the deadline is measured on clock
                # and the interval is spent in sleep, so passing one without
                # the other leaves the wait to resolve_escalation's poll-count
                # backstop and spends the whole timeout in real seconds.
                clock=self._clock, sleep=self._sleep,
            )

        # A token renewal inside _ask keeps the delegation, so the key, the
        # epoch and _expires_at still describe the grant that decided.
        self._cache.put(
            self._key(tool, canonical), decision, epoch=self._grant.epoch,
            delegation_expires_at=self._expires_at,
        )
        return decision

    def report(self, *, tool: str, raw_input: str | Mapping) -> bool:
        """Tell the PDP a call this session checked has run. Send the tool and
        input exactly as they were checked; see Client.report_tool_use."""
        return self._client.report_tool_use(
            token=self._grant.token, tool=tool, raw_input=raw_input)

    def _key(self, tool: str, canonical: str) -> str:
        return self._cache.key(
            delegation_id=self._grant.delegation_id, agent_id=self._agent_id,
            subject=self._subject, tool=tool, raw_input=canonical,
        )

    def _ask(self, *, tool: str, raw_input: str, resource,
             approval_id: str | None = None) -> Decision:
        decision = self._client.decide(
            agent_id=self._agent_id, subject=self._subject, tool=tool,
            raw_input=raw_input, token=self._grant.token, resource=resource,
            approval_id=approval_id, harness=self._harness,
        )
        if not self._token_is_the_problem(decision):
            return decision

        # Renew the token and retry ONCE, as stratium-pep's reissue.go does:
        # a new token for the SAME delegation, which the PDP issues only
        # while that delegation is still good. A session never replaces its
        # delegation. One that has expired or been revoked stays refused,
        # and whoever owns the session starts a new one.
        try:
            token = self._client.issue_token(
                delegation_id=self._grant.delegation_id, token=self._grant.token,
                ttl_seconds=self._mint["ttl_seconds"])
        except Exception:  # noqa: BLE001
            # No new token. The original decision stands, and it was not an
            # allow.
            return decision
        self._grant = replace(self._grant, token=token)
        self._token_expires_at = token_expiry(token)
        return self._client.decide(
            agent_id=self._agent_id, subject=self._subject, tool=tool,
            raw_input=raw_input, token=self._grant.token, resource=resource,
            approval_id=approval_id, harness=self._harness,
        )

    @property
    def expired(self) -> bool:
        """Whether this session's delegation has run out. Nothing it checks
        from here on can be allowed."""
        return self._clock() >= self._expires_at

    def _token_is_the_problem(self, decision: Decision) -> bool:
        # Only a real policy denial mentioning the token is worth a renewal.
        # A transport failure (effect None) is not: renewing would need the
        # same unreachable PDP.
        if decision.effect is not Effect.DENY:
            return False
        reason = decision.reason.lower()
        return "expired" in reason or "token" in reason
