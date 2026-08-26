import pytest

from stratium import Effect
from stratium._cache import DecisionCache
from stratium._pdp import pdp_pb2
from stratium._types import decision_from_response


def allow() -> object:
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW, reason="ok")
    )


def escalate() -> object:
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ESCALATE, reason="approve me")
    )


class Clock:
    def __init__(self, t: float = 0.0): self.t = t
    def __call__(self) -> float: return self.t


def fresh(window: float = 30.0):
    clock = Clock()
    return DecisionCache(window, clock=clock), clock


def store(cache, key="k", decision=None, *, epoch=1, expires=1e9, token="tok"):
    # `decision or allow()` would be wrong here: Decision.__bool__ tracks
    # `allowed`, which is False for an ESCALATE decision, so the `or` would
    # silently swap a passed-in escalate() for allow(). Must check identity.
    cache.put(key, decision if decision is not None else allow(), epoch=epoch,
              delegation_expires_at=expires, token=token)


def look(cache, key="k", *, epoch=1, token="tok", token_expires=1e9):
    return cache.get(key, last_known_epoch=epoch, token=token,
                     token_expires_at=token_expires)


# The boundary is INCLUSIVE, matching Go's !now.After(CachedAt.Add(staleness)).
def test_serves_within_the_window_including_its_last_instant():
    cache, clock = fresh(30.0)
    store(cache)
    clock.t = 29.999
    assert look(cache) is not None
    clock.t = 30.0
    assert look(cache) is not None, "the boundary instant is inside the window"


def test_refuses_past_the_window():
    cache, clock = fresh(30.0)
    store(cache)
    clock.t = 30.001
    assert look(cache) is None


# The clock runs from the entry's own cached_at, never from last use --
# otherwise a busy key never goes stale.
def test_reading_does_not_extend_the_window():
    cache, clock = fresh(30.0)
    store(cache)
    for t in (10.0, 20.0, 29.0):
        clock.t = t
        assert look(cache) is not None
    clock.t = 30.001
    assert look(cache) is None


# W4: an ESCALATE is never served from cache, on write OR read. It means a
# human must approve THIS call; replaying it approves a call nobody saw.
def test_an_escalation_is_never_cached_and_never_served():
    cache, clock = fresh(30.0)
    store(cache, decision=escalate())
    assert look(cache) is None


# The write-side guard in put() already refuses to store an ESCALATE, so the
# above test alone can never exercise the read-side guard in _usable: the
# entry never reaches the dict for get() to reject. Insert one directly,
# bypassing put(), to prove the read side refuses it independently.
def test_an_escalation_already_in_the_store_is_still_refused_on_read():
    cache, clock = fresh(30.0)
    from stratium._cache import CacheEntry
    cache._entries["k"] = CacheEntry(
        decision=escalate(), cached_at=0.0, epoch=1,
        delegation_expires_at=1e9, token="tok",
    )
    assert look(cache) is None


def test_a_stale_epoch_is_a_miss():
    cache, _ = fresh(30.0)
    store(cache, epoch=1)
    assert look(cache, epoch=2) is None, "a revocation bumped the epoch"


def test_an_expired_delegation_is_a_miss():
    cache, clock = fresh(30.0)
    store(cache, expires=5.0)
    clock.t = 6.0
    assert look(cache) is None


def test_an_expired_token_is_a_miss():
    cache, clock = fresh(30.0)
    store(cache)
    clock.t = 1.0
    assert look(cache, token_expires=0.5) is None


def test_a_different_token_is_a_miss():
    cache, _ = fresh(30.0)
    store(cache, token="tok-a")
    assert look(cache, token="tok-b") is None


# Different arguments to the same tool are different decisions.
def test_the_key_separates_arguments():
    cache, _ = fresh(30.0)
    k1 = cache.key(agent_id="a", subject="s", tool="Read", raw_input='{"p":"/a"}')
    k2 = cache.key(agent_id="a", subject="s", tool="Read", raw_input='{"p":"/b"}')
    assert k1 != k2
