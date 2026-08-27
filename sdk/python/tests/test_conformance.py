"""Runs sdk/conformance/cases against this SDK.

These fixtures bind every implementation, Go included. A case that passes here
and fails in Go is a drift report -- which is why they are data and not tests.
"""

import json
import pathlib

import pytest

from stratium import Effect
from stratium._cache import DecisionCache
from stratium._escalation import resolve_escalation
from stratium._pdp import pdp_pb2
from stratium._types import decision_from_response

CASES = sorted((pathlib.Path(__file__).parents[2] / "conformance" / "cases").glob("*.json"))
assert CASES, "no conformance cases found -- has sdk/conformance/cases moved?"


class FakeClock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def _decision(effect_name: str):
    effect = {"ALLOW": pdp_pb2.EFFECT_ALLOW, "DENY": pdp_pb2.EFFECT_DENY,
              "ESCALATE": pdp_pb2.EFFECT_ESCALATE}[effect_name]
    return decision_from_response(
        pdp_pb2.DecideResponse(effect=effect, reason="scripted", approval_id="ap-1")
    )


def _run_cache(case, clock):
    # Every rejection below exists because a fixture that asserts nothing must
    # not pass -- a silently-skipped step or an unread cache is a case that
    # reports green while binding no behaviour at all, and these cases bind
    # five languages. The Go runner refuses the same shapes
    # (conformance_test.go:246,262).
    cache = DecisionCache(case["config"]["staleness_window_seconds"], clock=clock)
    gets = 0
    for i, step in enumerate(case["steps"]):
        clock.t = float(step["at"])
        if "put" in step:
            p = step["put"]
            cache.put(_KEY, _decision(p["effect"]), epoch=p["epoch"],
                      delegation_expires_at=p["delegation_expires_at"])
        elif "get" in step:
            gets += 1
            assert "expect" in step, (
                f'{case["name"]}: step {i}: get step asserts nothing (no "expect")'
            )
            g = step["get"]
            got = cache.get(_KEY, last_known_epoch=g["epoch"],
                            token_expires_at=g["token_expires_at"])
            want = step["expect"]
            actual = "hit" if got is not None else "miss"
            assert actual == want, (
                f'{case["name"]}: at t={step["at"]} expected {want}, got {actual}'
            )
        else:
            pytest.fail(f'{case["name"]}: step {i} has neither put nor get')
    assert gets, (
        f'{case["name"]}: no get step -- the case never reads the cache '
        f'and binds nothing'
    )


_KEY = "conformance-key"


def _run_escalation(case, clock):
    # Each step scripts either a returned status ("poll") or a raised
    # error ("poll_raises"), so a case can exercise the GetApproval
    # transport-failure path without a real transport.
    actions = []
    for s in case["steps"]:
        if "poll_raises" in s:
            actions.append(("raise", s["poll_raises"]))
        elif "poll" in s:
            actions.append(("status", s["poll"]))
        else:
            pytest.fail(f'{case["name"]}: step has neither poll nor poll_raises')
    calls = {"n": 0}
    retried = {"yes": False}

    def poll(approval_id: str) -> str:
        i = min(calls["n"], len(actions) - 1)
        calls["n"] += 1
        kind, value = actions[i]
        if kind == "raise":
            raise RuntimeError(value)
        return value

    def retry():
        retried["yes"] = True
        return _decision("ALLOW")

    cfg = case["config"]
    d = resolve_escalation(
        poll, retry, approval_id="ap-1",
        poll_interval=cfg["poll_interval_seconds"],
        timeout=cfg["timeout_seconds"],
        clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + s),
    )

    want = case["expect"]
    assert retried["yes"] == want["retried"], f'{case["name"]}: retried mismatch'
    # A case must assert effect, allowed, or both -- never neither, or it
    # binds nothing. allowed is the only assertion available to a case that
    # touches a documented Go/Python divergence (see the README).
    assert "effect" in want or "allowed" in want, (
        f'{case["name"]}: expect asserts neither effect nor allowed -- binds nothing'
    )
    if "allowed" in want:
        assert d.allowed == want["allowed"], (
            f'{case["name"]}: allowed {d.allowed}, want {want["allowed"]}'
        )
    if "effect" in want:
        if want["effect"] is None:
            assert d.effect is None
        else:
            assert d.effect is Effect[want["effect"]], (
                f'{case["name"]}: effect {d.effect}, want {want["effect"]}'
            )
    if "reason_contains" in want:
        assert want["reason_contains"] in d.reason


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_conformance_case(path):
    case = json.loads(path.read_text())
    assert case["name"] == path.stem, "case name must match its filename"
    clock = FakeClock()
    if case["subject"] == "cache":
        _run_cache(case, clock)
    elif case["subject"] == "escalation":
        _run_escalation(case, clock)
    else:
        pytest.fail(f'unknown subject {case["subject"]!r}')


# F9. A fixture that asserts nothing must not pass. The escalation branch
# already refuses a case that binds neither effect nor allowed; the cache
# branch refused nothing -- it silently skipped a step that was neither a put
# nor a get, took a get with no "expect" as a KeyError rather than a verdict on
# the fixture, and passed a case that never read the cache at all. The Go
# runner t.Fatalf's on the first two (conformance_test.go:246,262); the third
# is the same defect one level up, and these cases bind five languages.
_PUT = {"effect": "ALLOW", "epoch": 1, "delegation_expires_at": 1e9}
_GET = {"epoch": 1, "token_expires_at": 1e9}


@pytest.mark.parametrize("steps", [
    # The malformed step is sandwiched between a put and a passing get, so the
    # "no get at all" guard cannot cover for the missing one: with the step
    # rejection removed, step 1 is silently skipped and the case goes green.
    pytest.param([{"at": 0, "put": _PUT}, {"at": 1},
                  {"at": 2, "get": _GET, "expect": "hit"}],
                 id="step_is_neither_put_nor_get"),
    pytest.param([{"at": 0, "put": _PUT}, {"at": 1, "get": _GET}], id="get_has_no_expect"),
    pytest.param([{"at": 0, "put": _PUT}], id="case_never_gets"),
])
def test_the_cache_runner_rejects_a_case_that_binds_nothing(steps):
    case = {"name": "synthetic", "subject": "cache",
            "config": {"staleness_window_seconds": 30.0}, "steps": steps}
    with pytest.raises((AssertionError, pytest.fail.Exception)):
        _run_cache(case, FakeClock())
