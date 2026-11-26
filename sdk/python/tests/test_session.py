import time

import pytest

from stratium import Client, Effect, Session
from stratium._pdp import pdp_pb2


def _b64(payload: str) -> str:
    """A JWT segment: base64url with padding stripped, as real tokens are."""
    import base64
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _jwt(exp=9_999_999_999):
    """A token shaped enough for token_expiry to read a real, far-future exp.

    Every grant_resp() below routes through this by default. A bare opaque
    string like "tok" has no "." in it, so token_expiry("tok") fails closed to
    0.0 -- already expired -- and the decision cache would then refuse every
    entry regardless of what these tests are actually exercising. Only the
    token_expiry-specific tests below want a deliberately-unreadable token.
    """
    return "a." + _b64(f'{{"exp":{exp}}}') + ".c"


def grant_resp(token=None, epoch=1, tools=("Read",), tier=1, did="d1"):
    return pdp_pb2.CreateDelegationResponse(
        delegation_id=did, token=token or _jwt(), epoch=epoch,
        granted_scope=pdp_pb2.GrantedScope(max_action_tier=tier, tools=list(tools)),
    )


def allow(reason="permitted"):
    return pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW, reason=reason, epoch=1)


def deny(reason="not in delegation approved_tools"):
    return pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_DENY, reason=reason, epoch=1)


def escalate(reason="needs approval", approval_id="ap-1"):
    return pdp_pb2.DecideResponse(
        effect=pdp_pb2.EFFECT_ESCALATE, reason=reason, approval_id=approval_id, epoch=1)


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def session(fake_pdp, clock, **kw):
    fake_pdp.delegation_responses.append(grant_resp())
    c = Client(fake_pdp.addr, insecure=True)
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


# A denial that is NOT about the token is not worth a renewal: the same
# delegation would deny the call again.
def test_a_non_token_denial_does_not_renew(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.append(deny("not in delegation approved_tools"))
    s = session(fake_pdp, clock)

    d = s.check(tool="Bash", raw_input={})
    assert not d
    assert fake_pdp.issue_calls == []
    assert len(fake_pdp.delegation_calls) == 1  # only the session's own


# The core of reissue.go's contract: a denial that names the token gets one
# new token for the SAME delegation and one retry, and if that retry allows,
# the caller sees the allow -- not the stale denial.
def test_a_token_denial_renews_the_token_once_and_the_retry_can_allow(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.extend([deny("token expired"), allow()])
    s = session(fake_pdp, clock)
    first_token = s.grant.token
    fake_pdp.issue_responses.append(_jwt(exp=1234))

    d = s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    assert d
    assert len(fake_pdp.decide_calls) == 2          # the original ask, one retry
    assert fake_pdp.decide_calls[1].token == _jwt(exp=1234)
    # The PDP was asked for a token for this delegation, and was shown the
    # one being replaced.
    (asked,) = fake_pdp.issue_calls
    assert (asked.delegation_id, asked.token) == ("d1", first_token)
    # The delegation is the one the session started with. No other was made.
    assert s.grant.delegation_id == "d1"
    assert len(fake_pdp.delegation_calls) == 1


# If the retry ALSO denies for the token, that is a real denial with a fresh
# token, not a reason to renew again. reissue.go deliberately does not loop.
def test_a_token_denial_renews_only_once_even_if_the_retry_denies_again(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.extend([deny("token expired"), deny("token expired")])
    s = session(fake_pdp, clock)
    fake_pdp.issue_responses.append(_jwt())

    d = s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    assert not d
    assert len(fake_pdp.decide_calls) == 2          # no third attempt
    assert len(fake_pdp.issue_calls) == 1
    assert "token expired" in d.reason


# The PDP issues no token for a delegation that has expired or been revoked.
# The session does not make itself a new one: the denial stands, however the
# reason is worded, and however many calls follow.
@pytest.mark.parametrize("reason", [
    "token expired",
    'tool "get_token" not in delegation approved_tools',
])
def test_a_session_never_replaces_its_delegation(fake_pdp, reason):
    clock = Clock()
    fake_pdp.decide_responses.extend([deny(reason), deny(reason)])
    s = session(fake_pdp, clock)   # issue_responses is empty: the PDP refuses

    assert not s.check(tool="get_token", raw_input={})
    d = s.check(tool="get_token", raw_input={"again": True})

    assert not d and reason in d.reason
    assert len(fake_pdp.delegation_calls) == 1
    assert s.grant.delegation_id == "d1"


# A session reports that its delegation has run out, so whoever owns it knows
# to start another.
def test_a_session_is_expired_once_its_delegation_is(fake_pdp):
    clock = Clock()
    fake_pdp.delegation_responses.append(grant_resp(token=_jwt(exp=50)))
    s = Session(Client(fake_pdp.addr, insecure=True), subject="s", agent_id="a",
                tools=["Read"], max_action_tier=1, purpose="test", ttl_seconds=50,
                clock=clock)

    assert not s.expired
    clock.t = 50.0
    assert s.expired


# An escalation's retry must consume the SAME approval, not open a new one --
# the exact bug this SDK exists to avoid: without approval_id on the retry,
# an approved escalation would ask again from scratch and get ESCALATE again.
def test_an_escalation_retries_with_the_approval_id_and_can_allow(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.extend([escalate(approval_id="ap-9"), allow()])
    fake_pdp.approval_responses.append(pdp_pb2.GetApprovalResponse(status="approved"))
    s = session(fake_pdp, clock, approval_poll_interval=0.01, approval_timeout=5.0)

    d = s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    assert d
    assert len(fake_pdp.decide_calls) == 2
    assert fake_pdp.decide_calls[1].approval_id == "ap-9"
    # The poll names the waiting session: the PDP answers no one else.
    assert fake_pdp.approval_calls[0].token == fake_pdp.decide_calls[0].token != ""


# The grant is what the PDP gave, not what was asked for.
# A token whose exp cannot be read is ALREADY EXPIRED, never never-expiring.
# The tempting default -- infinity for a missing claim -- reads as harmless
# and means a cached ALLOW is serveable forever.
@pytest.mark.parametrize("token", [
    "",                                       # empty
    "not-a-jwt",                              # no segments
    "a.b",                                    # too few segments
    "a.!!!not-base64!!!.c",                   # undecodable payload
    "a." + _b64('{"sub":"x"}') + ".c",        # valid JSON, no exp
    "a." + _b64('{"exp":"soon"}') + ".c",     # exp present but not a number
])
def test_an_unreadable_token_expiry_is_treated_as_expired(token):
    from stratium._session import token_expiry
    assert token_expiry(token) == 0.0


def test_a_real_exp_claim_is_read():
    from stratium._session import token_expiry
    assert token_expiry("a." + _b64('{"exp":1787769876}') + ".c") == 1787769876.0


def test_the_session_exposes_the_granted_scope(fake_pdp):
    clock = Clock()
    s = session(fake_pdp, clock)
    assert s.grant.granted_scope.tools == ("Read",)


# Behavioural, not introspective: this must fail for a Session whose default
# clock reads a different epoch than the expiries it is compared against, no
# matter HOW that default is expressed. Session passes its clock into the
# cache, so a wrong default here overrides the cache's own correct one and
# Task 4's test cannot see it.
def test_the_default_clock_shares_an_epoch_with_token_expiry(fake_pdp):
    # A token that expired an hour ago, in unix terms.
    expired = _jwt(exp=time.time() - 3600)
    fake_pdp.delegation_responses.append(grant_resp(token=expired))
    fake_pdp.decide_responses.extend([allow(), allow()])

    c = Client(fake_pdp.addr, insecure=True)
    s = Session(c, subject="s", agent_id="a", tools=["Read"],
                max_action_tier=1, purpose="test", ttl_seconds=3600)   # no clock=

    s.check(tool="Read", raw_input={"file_path": "/tmp/x"})
    s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    # The token is expired, so no entry is ever usable and both checks must
    # reach the PDP. Under a monotonic default the token never looks expired
    # and the second is served from cache -- one call, not two.
    assert len(fake_pdp.decide_calls) == 2


# F1, SECURITY. Nothing derived from the escalation path may be cached. A
# human approving ONE pending action is not the PDP producing a replayable
# verdict about every future identical call -- caching the post-approval
# ALLOW would let the next identical call skip the human step this one
# required. local_cache.go:110-140 states this and prevents it structurally,
# by placing its one storeCacheResult call before the escalation wait begins
# and never after it.
def test_an_approved_escalation_is_not_cached(fake_pdp):
    clock = Clock()
    fake_pdp.decide_responses.extend([
        escalate(approval_id="ap-9"), allow(),   # ask, human approves, retry allows
        escalate(approval_id="ap-9"), allow(),   # the identical call must ask AGAIN
    ])
    fake_pdp.approval_responses.extend([
        pdp_pb2.GetApprovalResponse(status="approved"),
        pdp_pb2.GetApprovalResponse(status="approved"),
    ])
    s = session(fake_pdp, clock, approval_poll_interval=0.01, approval_timeout=5.0)

    first = s.check(tool="Bash", raw_input={"command": "rm -rf /data"})
    second = s.check(tool="Bash", raw_input={"command": "rm -rf /data"})

    assert first and second
    # Four Decide calls, not two: the second check reached the PDP rather than
    # replaying the approved ALLOW out of the cache.
    assert len(fake_pdp.decide_calls) == 4
    # And it needed its own human. One approval authorizing unlimited repeats
    # for the whole staleness window is the failure this test exists for.
    assert len(fake_pdp.approval_calls) == 2


# The same rule for the other escalation outcome: a timeout's synthesised DENY
# is a diagnostic about ONE wait, not a verdict to replay. Real clock and real
# sleep deliberately -- a fake clock without a fake sleep is F2, and this test
# must not depend on that fix. The timeout is short and the poll script is
# generously long so this can never hang.
def test_an_escalation_that_times_out_is_not_cached(fake_pdp):
    fake_pdp.delegation_responses.append(grant_resp())
    fake_pdp.decide_responses.extend([escalate(), escalate()])
    fake_pdp.approval_responses.extend(
        [pdp_pb2.GetApprovalResponse(status="pending")] * 40)

    c = Client(fake_pdp.addr, insecure=True)
    s = Session(c, subject="s", agent_id="a", tools=["Read"], max_action_tier=1,
                purpose="test", ttl_seconds=3600,
                approval_poll_interval=0.005, approval_timeout=0.02)

    first = s.check(tool="Read", raw_input={"file_path": "/tmp/x"})
    second = s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    assert not first and not second
    assert first.effect is Effect.DENY
    # Two Decide calls: the DENY the first wait synthesised was not cached.
    assert len(fake_pdp.decide_calls) == 2


# F2. clock and sleep are ONE decision, not two. Session took only clock, so
# the escalation deadline was measured on the injected clock while the wait
# used the real time.sleep -- with any clock that does not track real time,
# clock() >= deadline is never true and check() polls GetApproval forever.
#
# The poll script is finite and the interval is tiny, so this test cannot hang
# the suite: without the sleep pass-through the real sleep advances nothing,
# the fake clock stays at 0, and the loop runs the script out and reports a
# transport failure (effect None) instead of the timeout DENY asserted here.
def test_an_escalation_times_out_on_the_injected_clock(fake_pdp):
    clock = Clock()
    slept = []

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        clock.t += seconds        # the only thing that advances this clock

    fake_pdp.decide_responses.append(escalate(approval_id="ap-1"))
    fake_pdp.approval_responses.extend(
        [pdp_pb2.GetApprovalResponse(status="pending")] * 10)
    s = session(fake_pdp, clock, sleep=fake_sleep,
                approval_poll_interval=0.01, approval_timeout=0.05)

    d = s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    assert not d
    assert d.effect is Effect.DENY          # settled, not still pending
    assert "ap-1" in d.reason               # names WHICH approval timed out
    # Bounded by the deadline on the injected clock, not by exhausting the
    # scripted poll responses: timeout/interval is 5, so 6 polls at most.
    assert len(fake_pdp.approval_calls) <= 8
    assert slept and all(s == 0.01 for s in slept)


# F3. The cached delegation expiry must come from the credential that actually
# came back, never from the TTL that was asked for. _types.py states the rule
# for granted_scope -- "what the PDP actually granted, which is not what was
# requested: it narrows. A PEP that assumes otherwise is wrong about its own
# authority" -- and the expiry is the same kind of claim about the same grant.
# Go sources DelegationExpiresAt from tokenExpiry(token) for this reason
# (local_cache.go:275).
#
# Read at t=500 with a 10s requested TTL and a token the PDP issued good until
# t=1000. clock()+ttl_seconds says the delegation died at t=10 and the entry
# misses; the token itself says otherwise, and the token is the credential.
# The huge staleness window and the far-future epoch keep the other three
# usability conditions out of the way, so the ONLY thing that can decide this
# is where _expires_at came from.
def test_the_delegation_expiry_comes_from_the_token_not_the_requested_ttl(fake_pdp):
    clock = Clock()
    fake_pdp.delegation_responses.append(grant_resp(token=_jwt(exp=1000)))
    fake_pdp.decide_responses.extend([allow(), allow()])

    c = Client(fake_pdp.addr, insecure=True)
    s = Session(c, subject="s", agent_id="a", tools=["Read"], max_action_tier=1,
                purpose="test", ttl_seconds=10, staleness_window=1e6, clock=clock)

    s.check(tool="Read", raw_input={"file_path": "/tmp/x"})
    clock.t = 500.0
    s.check(tool="Read", raw_input={"file_path": "/tmp/x"})

    assert len(fake_pdp.decide_calls) == 1


# The threshold rides on the mint arguments, so it reaches the first
# delegation; leaving it out asks for nothing.
def test_a_session_forwards_its_escalation_threshold(fake_pdp):
    session(fake_pdp, Clock(), escalate_at=2)
    session(fake_pdp, Clock())
    asked, not_asked = fake_pdp.delegation_calls
    assert asked.requested_scope.escalate_at == 2
    assert not not_asked.requested_scope.HasField("escalate_at")


# A Session mints a ROOT delegation, so the principal's token it was given
# has to reach the PDP with that request.
def test_session_sends_the_principal_token_when_minting(fake_pdp):
    session(fake_pdp, Clock(), principal_token="oidc-token")
    assert fake_pdp.delegation_calls[0].principal_token == "oidc-token"


def test_a_sessions_harness_rides_on_every_decision_and_report_uses_its_token(fake_pdp):
    fake_pdp.delegation_responses.append(grant_resp(tools=("Bash",)))
    fake_pdp.decide_responses.append(pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW))
    with Client(fake_pdp.addr, insecure=True) as c:
        s = Session(c, subject="s", agent_id="a", tools=["Bash"], max_action_tier=3,
                    purpose="p", ttl_seconds=60, harness="devin")
        assert s.check(tool="exec", raw_input={"command": "ls"})
        assert s.report(tool="exec", raw_input={"command": "ls"}) is True
    assert fake_pdp.decide_calls[0].harness == "devin"
    assert fake_pdp.report_calls[0].token == s.grant.token
    assert fake_pdp.report_calls[0].raw_input == fake_pdp.decide_calls[0].raw_input
