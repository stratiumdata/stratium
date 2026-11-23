"""Unit tests for the guardrail, against a fake PDP client.

    pip install 'litellm[proxy]' pytest -e sdk/python
    pytest deploy/litellm
"""

import asyncio
import base64
import json
import types

import pytest
from fastapi import HTTPException
from litellm.types.utils import ModelResponse, ModelResponseStream

from stratium import Decision, Effect, Grant, Leg, Legs, Scope
from stratium_guardrail import Engine, StratiumChatGuardrail, StratiumMCPGuardrail, load_config

CFG = dict(pdp_addr="x", connect_timeout=1.0, poll=0.01, approval_timeout=0.05, ttl=60,
           tier=3, tools=["Read"], insecure=True, ca_file=None, agent_id="agent-1",
           subject="alice", harness="", unread_routes="refuse")


def decision(allowed: bool, reason: str = "") -> Decision:
    leg = Leg(Effect.ALLOW, "")
    return Decision(allowed, Effect.ALLOW if allowed else Effect.DENY, reason, None, None,
                    Legs(leg, leg, leg), None, None)


class FakeClient:
    """Refuses any tool named in `deny`; records what it was asked."""

    def __init__(self, deny=(), down=False):
        self.deny, self.down = set(deny), down
        self.delegations, self.decisions, self.reports = [], [], []

    def create_delegation(self, **kw):
        if self.down:
            raise ConnectionError("PDP unreachable")
        self.delegations.append(kw)
        exp = base64.urlsafe_b64encode(b'{"exp":9999999999}').decode().rstrip("=")
        return Grant(f"a.{exp}.c", f"d{len(self.delegations)}", Scope(3, ("Read",)), 1)

    def decide(self, **kw):
        self.decisions.append(kw)
        return decision(kw["tool"] not in self.deny, f"{kw['tool']} is not granted")

    def report_tool_use(self, **kw):
        self.reports.append(kw)
        return True


def guard(client, **cfg):
    """The chat guardrail; its .mcp is the MCP one on the same engine."""
    engine = Engine(client=client, config={**CFG, **cfg})
    g = StratiumChatGuardrail(engine=engine, guardrail_name="stratium-chat")
    g.mcp = StratiumMCPGuardrail(engine=engine, guardrail_name="stratium-mcp")
    return g


def run(coro):
    return asyncio.run(coro)


def tool_call(i, name, args):
    return {"id": f"call_{i}", "type": "function", "index": i,
            "function": {"name": name, "arguments": json.dumps(args)}}


def reply(*calls, content="On it."):
    return ModelResponse(choices=[{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": content, "tool_calls": list(calls)}}])


AUTH = types.SimpleNamespace(metadata={}, user_id=None, token="keyhash", request_route="/v1/chat/completions")

# --- configuration -----------------------------------------------------------


def test_a_missing_setting_stops_start_up():
    with pytest.raises(ValueError, match="STRATIUM_PEP_PDP_ADDR"):
        load_config({})


def test_durations_are_read_as_stratium_pep_reads_them():
    env = {"STRATIUM_PEP_PDP_ADDR": "pdp:50051", "STRATIUM_PEP_CONNECT_TIMEOUT": "500ms",
           "STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "2s", "STRATIUM_PEP_APPROVAL_TIMEOUT": "2m",
           "STRATIUM_PEP_TTL_SECONDS": "3600", "STRATIUM_PEP_REQUESTED_TIER": "3",
           "STRATIUM_PEP_REQUESTED_TOOLS": "Read,Bash"}
    cfg = load_config(env)
    assert (cfg["connect_timeout"], cfg["poll"], cfg["approval_timeout"]) == (0.5, 2.0, 120.0)
    assert cfg["tools"] == ["Read", "Bash"] and cfg["insecure"] is False
    with pytest.raises(ValueError, match="not a duration"):
        load_config({**env, "STRATIUM_PEP_CONNECT_TIMEOUT": "5"})

# --- MCP gateway ---------------------------------------------------------------


def mcp_request(tool="write_file", args=None, server="files", key_meta=None):
    return {"mcp_tool_name": tool, "mcp_arguments": args or {"path": "/proj/a.txt"},
            "mcp_server_name": server, "user_api_key_hash": "keyhash",
            "metadata": {"user_api_key_metadata": key_meta or {}}}


CALL = types.SimpleNamespace(call_type="call_mcp_tool")


def test_an_allowed_mcp_call_is_decided_as_the_client_names_it_then_reported():
    c = FakeClient()
    g = guard(c)
    req = mcp_request()
    run(g.mcp.apply_guardrail({}, req, "request", CALL))
    assert c.decisions[0]["tool"] == "files-write_file"
    assert c.decisions[0]["raw_input"] == '{"path":"/proj/a.txt"}'
    done = {"mcp_tool_call_metadata": {"name": "write_file", "mcp_server_name": "files",
                                       "arguments": {"path": "/proj/a.txt"}}, "user_api_key_hash": "keyhash"}
    run(g.mcp.apply_guardrail({}, done, "response"))
    assert (c.reports[0]["tool"], c.reports[0]["raw_input"]) == ("files-write_file", {"path": "/proj/a.txt"})
    assert len(c.delegations) == 1, "the report reuses the decision's delegation"


def test_a_refused_mcp_call_raises_with_the_pdps_reason():
    g = guard(FakeClient(deny={"files-write_file"}))
    with pytest.raises(HTTPException) as err:
        run(g.mcp.apply_guardrail({}, mcp_request(), "request", CALL))
    assert err.value.status_code == 403 and "is not granted" in err.value.detail["error"]


def test_listing_tools_decides_nothing():
    c = FakeClient(deny={"files-write_file"})
    run(guard(c).mcp.apply_guardrail({}, mcp_request(args={}), "request", types.SimpleNamespace(call_type=None)))
    assert c.decisions == []


def test_the_pdp_being_down_refuses_an_mcp_call():
    with pytest.raises(HTTPException) as err:
        run(guard(FakeClient(down=True)).mcp.apply_guardrail({}, mcp_request(), "request", CALL))
    assert "could not be reached" in err.value.detail["error"]

# --- who is calling ------------------------------------------------------------


def test_a_keys_metadata_names_its_agent_harness_and_tools():
    c = FakeClient()
    auth = types.SimpleNamespace(metadata={"stratium_agent_id": "agent-9", "stratium_harness": "devin",
                                           "stratium_tools": "Read,Bash", "stratium_tier": 2},
                                 user_id="bob", token="k2", request_route="/v1/chat/completions")
    run(guard(c).async_post_call_success_hook({}, auth, reply(tool_call(0, "exec", {"command": "ls"}))))
    d = c.delegations[0]
    assert (d["agent_id"], d["subject"], d["tools"], d["max_action_tier"]) == ("agent-9", "bob", ["Read", "Bash"], 2)
    assert c.decisions[0]["harness"] == "devin"


def test_the_configured_subject_wins_over_the_keys_placeholder_user():
    c = FakeClient()
    auth = types.SimpleNamespace(metadata={}, user_id="default_user_id", token="k", request_route="/v1/chat/completions")
    run(guard(c).async_post_call_success_hook({}, auth, reply(tool_call(0, "Read", {}))))
    assert c.delegations[0]["subject"] == "alice"


def test_chat_and_mcp_calls_from_one_key_share_a_delegation():
    c = FakeClient()
    g = guard(c)
    run(g.async_post_call_success_hook({}, AUTH, reply(tool_call(0, "Read", {}))))
    run(g.mcp.apply_guardrail({}, mcp_request(), "request", CALL))
    assert len(c.delegations) == 1


SPOOF = {"user_api_key_metadata": {"stratium_agent_id": "EVIL"},
         "user_api_key_auth": {"metadata": {"stratium_agent_id": "EVIL"}},
         "user_api_key_user_id": "EVIL", "user_api_key_hash": "EVIL",
         "metadata": {"user_api_key_metadata": {"stratium_agent_id": "EVIL", "stratium_tools": "Bash"},
                      "user_api_key_user_id": "EVIL"}}


def test_a_chat_body_cannot_name_its_own_agent_subject_or_tools():
    """The body is the client's. LiteLLM passes unknown fields through, and
    these are the names its own bookkeeping uses."""
    c = FakeClient()
    run(guard(c).async_post_call_success_hook(dict(SPOOF), AUTH, reply(tool_call(0, "Read", {}))))
    d = c.delegations[0]
    assert (d["agent_id"], d["subject"], d["tools"]) == ("agent-1", "alice", ["Read"])

    c = FakeClient()
    out = run(guard(c, agent_id="").async_post_call_success_hook(
        dict(SPOOF), AUTH, reply(tool_call(0, "Read", {}))))
    assert c.delegations == [] and "names no Stratium agent" in out.choices[0].message.content


def test_an_mcp_calls_arguments_cannot_name_an_agent():
    c = FakeClient()
    req = mcp_request(args={"path": "/a", **SPOOF}, key_meta={"stratium_agent_id": "agent-7"})
    run(guard(c).mcp.apply_guardrail({}, req, "request", CALL))
    assert c.delegations[0]["agent_id"] == "agent-7"


def test_a_key_with_no_agent_is_refused():
    c = FakeClient()
    out = run(guard(c, agent_id="").async_post_call_success_hook({}, AUTH, reply(tool_call(0, "Read", {}))))
    assert out.choices[0].message.tool_calls is None and c.decisions == []
    assert "names no Stratium agent" in out.choices[0].message.content


def test_each_client_session_gets_its_own_delegation():
    c = FakeClient()
    g = guard(c)
    for sid in ("s1", "s1", "s2"):
        run(g.async_post_call_success_hook({"litellm_session_id": sid}, AUTH, reply(tool_call(0, "Read", {}))))
    assert len(c.delegations) == 2

# --- chat replies, not streamed ---------------------------------------------------


def test_allowed_tool_calls_pass_untouched():
    out = run(guard(FakeClient()).async_post_call_success_hook({}, AUTH, reply(
        tool_call(0, "Read", {"file_path": "/a"}), tool_call(1, "Bash", {"command": "ls"}))))
    assert [t.function.name for t in out.choices[0].message.tool_calls] == ["Read", "Bash"]
    assert out.choices[0].message.content == "On it." and out.choices[0].finish_reason == "tool_calls"


def test_a_refused_call_is_removed_and_the_others_kept():
    c = FakeClient(deny={"Write"})
    out = run(guard(c).async_post_call_success_hook({}, AUTH, reply(
        tool_call(0, "Write", {"file_path": "/a"}), tool_call(1, "Bash", {"command": "ls"}))))
    msg = out.choices[0].message
    assert [(t.id, t.function.name) for t in msg.tool_calls] == [("call_1", "Bash")]
    assert "[Stratium refused Write: Write is not granted]" in msg.content
    assert out.choices[0].finish_reason == "tool_calls"
    assert c.decisions[0]["raw_input"] == '{"file_path": "/a"}', "the arguments go as the model wrote them"


def test_when_every_call_is_refused_the_reply_becomes_text():
    out = run(guard(FakeClient(deny={"Write"})).async_post_call_success_hook(
        {}, AUTH, reply(tool_call(0, "Write", {}))))
    assert out.choices[0].message.tool_calls is None and out.choices[0].finish_reason == "stop"


def test_the_pdp_being_down_removes_every_call():
    out = run(guard(FakeClient(down=True)).async_post_call_success_hook({}, AUTH, reply(tool_call(0, "Read", {}))))
    assert out.choices[0].message.tool_calls is None and "could not be reached" in out.choices[0].message.content


def test_a_reply_that_is_not_a_completion_is_refused_unless_it_cannot_hold_a_tool_call():
    """Listed by what is read, not by route: an Anthropic Messages reply, a
    Responses API reply and anything LiteLLM adds later are all refused."""
    from litellm.types.utils import EmbeddingResponse
    g = guard(FakeClient())
    for unread in ({"content": [{"type": "tool_use", "name": "Bash"}]}, types.SimpleNamespace(output=[])):
        with pytest.raises(HTTPException) as err:
            run(g.async_post_call_success_hook({}, AUTH, unread))
        assert err.value.status_code == 501
    run(g.async_post_call_success_hook({}, AUTH, EmbeddingResponse()))
    run(guard(FakeClient(), unread_routes="allow").async_post_call_success_hook({}, AUTH, {"content": []}))


def test_a_stream_on_a_route_that_is_not_read_is_refused_unless_allowed():
    chunks = stream_of(("Bash", {"command": "ls"}))
    for route in ("/v1/messages", "/v1/responses", "/v1/something/new", None):
        auth = types.SimpleNamespace(metadata={}, user_id=None, token="k", request_route=route)
        with pytest.raises(HTTPException) as err:
            streamed(guard(FakeClient()), chunks, auth)
        assert err.value.status_code == 501, route
    auth = types.SimpleNamespace(metadata={}, user_id=None, token="k", request_route="/v1/messages")
    assert streamed(guard(FakeClient(), unread_routes="allow"), chunks, auth) == chunks


# --- chat replies, streamed ----------------------------------------------------------


def chunk(delta, finish=None):
    return ModelResponseStream(choices=[{"index": 0, "delta": delta, "finish_reason": finish}])


def stream_of(*calls):
    """Text, then each call's name and its arguments in two pieces, then the end."""
    out = [chunk({"role": "assistant", "content": "On "}), chunk({"content": "it."})]
    for i, (name, args) in enumerate(calls):
        a = json.dumps(args)
        out.append(chunk({"tool_calls": [{"index": i, "id": f"call_{i}", "type": "function",
                                          "function": {"name": name, "arguments": ""}}]}))
        for part in (a[: len(a) // 2], a[len(a) // 2:]):
            out.append(chunk({"tool_calls": [{"index": i, "function": {"arguments": part}}]}))
    return out + [chunk({}, "tool_calls")]


def streamed(g, chunks, auth=AUTH):
    async def source():
        for c in chunks:
            yield c

    async def collect():
        return [c async for c in g.async_post_call_streaming_iterator_hook(auth, source(), {})]
    return run(collect())


def calls_in(chunks):
    got = {}
    for c in chunks:
        for d in c.choices[0].delta.tool_calls or []:
            e = got.setdefault(d.index, {"id": None, "name": "", "arguments": ""})
            e["id"] = e["id"] or d.id
            e["name"] += d.function.name or ""
            e["arguments"] += d.function.arguments or ""
    return [got[i] for i in sorted(got)]


def text_in(chunks):
    return "".join(c.choices[0].delta.content or "" for c in chunks)


def test_a_stream_with_no_tool_call_is_passed_on_as_it_is():
    chunks = [chunk({"role": "assistant", "content": "hello"}), chunk({}, "stop")]
    c = FakeClient()
    assert streamed(guard(c), chunks) == chunks and c.delegations == []


def test_a_stream_whose_calls_are_all_allowed_arrives_unchanged():
    chunks = stream_of(("Read", {"file_path": "/a"}), ("Bash", {"command": "ls"}))
    assert streamed(guard(FakeClient()), chunks) == chunks


def test_a_refused_streamed_call_never_reaches_the_client():
    c = FakeClient(deny={"Write"})
    out = streamed(guard(c), stream_of(("Write", {"file_path": "/a"}), ("Bash", {"command": "ls"})))
    assert calls_in(out) == [{"id": "call_1", "name": "Bash", "arguments": '{"command": "ls"}'}]
    assert "Write" not in json.dumps([ch.model_dump() for ch in out if ch.choices[0].delta.tool_calls])
    assert text_in(out).startswith("On it.") and "[Stratium refused Write: Write is not granted]" in text_in(out)
    assert out[-1].choices[0].finish_reason == "tool_calls"
    assert [d["raw_input"] for d in c.decisions] == ['{"file_path": "/a"}', '{"command": "ls"}']


def test_a_stream_with_every_call_refused_ends_as_text():
    out = streamed(guard(FakeClient(deny={"Write"})), stream_of(("Write", {"file_path": "/a"})))
    assert calls_in(out) == [] and out[-1].choices[0].finish_reason == "stop"


def test_the_pdp_being_down_holds_back_every_streamed_call():
    out = streamed(guard(FakeClient(down=True)), stream_of(("Read", {"file_path": "/a"})))
    assert calls_in(out) == [] and "could not be reached" in text_in(out)
    assert "PDP unreachable" not in text_in(out), "the transport's own text stays in the log"


def test_every_choice_of_a_streamed_reply_is_decided():
    """n > 1: each choice carries its own tool calls, in the same chunks."""
    def both(delta0, delta1, finish=None):
        return ModelResponseStream(choices=[
            {"index": 0, "delta": delta0, "finish_reason": finish},
            {"index": 1, "delta": delta1, "finish_reason": finish}])

    def call(name, args):
        return {"tool_calls": [{"index": 0, "id": f"id_{name}", "type": "function",
                                "function": {"name": name, "arguments": json.dumps(args)}}]}
    chunks = [both({"role": "assistant", "content": "a"}, {"role": "assistant", "content": "b"}),
              both(call("Read", {"file_path": "/a"}), call("Write", {"file_path": "/b"})),
              both({}, {}, "tool_calls")]
    c = FakeClient(deny={"Write"})
    out = streamed(guard(c), chunks)
    assert sorted(d["tool"] for d in c.decisions) == ["Read", "Write"]
    by_choice = {}
    for ch in out:
        for choice in ch.choices:
            e = by_choice.setdefault(choice.index, {"calls": [], "text": "", "finish": None})
            e["calls"] += [t.function.name for t in choice.delta.tool_calls or []]
            e["text"] += choice.delta.content or ""
            e["finish"] = choice.finish_reason or e["finish"]
    assert by_choice[0] == {"calls": ["Read"], "text": "a", "finish": "tool_calls"}
    assert by_choice[1]["text"].startswith("b")
    assert by_choice[1]["calls"] == [] and by_choice[1]["finish"] == "stop"
    assert "[Stratium refused Write: Write is not granted]" in by_choice[1]["text"]
