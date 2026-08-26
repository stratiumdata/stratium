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
    cache = DecisionCache(case["config"]["staleness_window_seconds"], clock=clock)
    for step in case["steps"]:
        clock.t = float(step["at"])
        if "put" in step:
            p = step["put"]
            cache.put(_KEY, _decision(p["effect"]), epoch=p["epoch"],
                      delegation_expires_at=p["delegation_expires_at"])
        elif "get" in step:
            g = step["get"]
            got = cache.get(_KEY, last_known_epoch=g["epoch"],
                            token_expires_at=g["token_expires_at"])
            want = step["expect"]
            actual = "hit" if got is not None else "miss"
            assert actual == want, (
                f'{case["name"]}: at t={step["at"]} expected {want}, got {actual}'
            )


_KEY = "conformance-key"


def _run_escalation(case, clock):
    statuses = [s["poll"] for s in case["steps"]]
    calls = {"n": 0}
    retried = {"yes": False}

    def poll(approval_id: str) -> str:
        i = min(calls["n"], len(statuses) - 1)
        calls["n"] += 1
        return statuses[i]

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
    if want.get("effect") is None and "effect" in want:
        assert d.effect is None
    elif "effect" in want:
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
