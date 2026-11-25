"""Stratium guardrail for the LiteLLM proxy.

Asks the Stratium PDP about two kinds of tool call that pass through LiteLLM,
with one guardrail class for each:

- StratiumMCPGuardrail: a call LiteLLM's MCP gateway is about to execute,
  which is refused before it runs and reported after it has run;
- StratiumChatGuardrail: a call a model proposes in a chat completion,
  streamed or not, which is removed from the reply before the client
  receives it.

They are two classes because LiteLLM drives them differently: a guardrail
that implements apply_guardrail, as the MCP gateway needs, is not given the
reply object of a chat completion to edit.

Neither holds any policy. It sends the tool name and the input as they arrived and
acts on the PDP's answer. See docs/pep/litellm.md.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
import re
from collections import OrderedDict

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

from stratium import Client, Session

# What is read is listed; everything else is refused. A list of what is NOT
# read would pass any route added to LiteLLM later.
#
# Streams are read on the completions routes only (chat and text).
READ_STREAMS = ("/completions",)
# Replies with no `choices` that cannot carry a tool call.
TOOLLESS_REPLIES = frozenset({
    "EmbeddingResponse", "ImageResponse", "TranscriptionResponse", "RerankResponse",
    "HttpxBinaryResponseContent", "OpenAIModerationResponse",
})
# ponytail: one session per key and client session, kept in memory. A proxy
# with more live sessions than this starts the oldest again; raise it, or move
# the tokens to LiteLLM's cache, if that shows up in the audit trail.
MAX_SESSIONS = 4096


def _seconds(name: str, raw: str) -> float:
    """A Go duration as stratium-pep takes it: 500ms, 5s, 2m."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m)", raw.strip())
    if not m:
        raise ValueError(f"{name}: {raw!r} is not a duration like 500ms, 5s or 2m")
    return float(m.group(1)) * {"ms": 0.001, "s": 1.0, "m": 60.0}[m.group(2)]


def load_config(env=os.environ) -> dict:
    """The settings, under stratium-pep's names. Every one is required except
    the last block; a missing one stops LiteLLM at start-up."""
    required = ("STRATIUM_PEP_PDP_ADDR", "STRATIUM_PEP_CONNECT_TIMEOUT",
                "STRATIUM_PEP_APPROVAL_POLL_INTERVAL", "STRATIUM_PEP_APPROVAL_TIMEOUT",
                "STRATIUM_PEP_TTL_SECONDS", "STRATIUM_PEP_REQUESTED_TIER",
                "STRATIUM_PEP_REQUESTED_TOOLS")
    missing = [k for k in required if not env.get(k)]
    if missing:
        raise ValueError("missing required configuration: " + ", ".join(missing))
    insecure = env.get("STRATIUM_PEP_PDP_INSECURE", "").lower() in ("1", "true")
    return {
        "pdp_addr": env["STRATIUM_PEP_PDP_ADDR"],
        "connect_timeout": _seconds("STRATIUM_PEP_CONNECT_TIMEOUT", env["STRATIUM_PEP_CONNECT_TIMEOUT"]),
        "poll": _seconds("STRATIUM_PEP_APPROVAL_POLL_INTERVAL", env["STRATIUM_PEP_APPROVAL_POLL_INTERVAL"]),
        "approval_timeout": _seconds("STRATIUM_PEP_APPROVAL_TIMEOUT", env["STRATIUM_PEP_APPROVAL_TIMEOUT"]),
        "ttl": int(env["STRATIUM_PEP_TTL_SECONDS"]),
        "tier": int(env["STRATIUM_PEP_REQUESTED_TIER"]),
        "tools": [t for t in env["STRATIUM_PEP_REQUESTED_TOOLS"].split(",") if t],
        "insecure": insecure,
        "ca_file": env.get("STRATIUM_PEP_PDP_CA_FILE") or None,
        # For a proxy that serves one agent, or keys with no metadata of their
        # own. A key's stratium_* metadata wins over these.
        "agent_id": env.get("STRATIUM_PEP_AGENT_ID", ""),
        "subject": env.get("STRATIUM_PEP_SUBJECT", ""),
        "harness": env.get("STRATIUM_PEP_HARNESS", ""),
        "unread_routes": env.get("STRATIUM_LITELLM_UNREAD_ROUTES", "refuse"),
    }


def _get(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def caller(request_data: dict, auth=None) -> tuple[dict, str | None, str]:
    """The calling key's (metadata, user, key hash), read only from what the
    proxy itself filled in after authenticating the key.

    A chat request's body is the client's: it can carry fields of any name,
    and LiteLLM passes them through. So on that path nothing is read from the
    body, only from the UserAPIKeyAuth object the proxy hands the hook.

    The MCP gateway hands over no such object. Its request_data is built by
    the proxy, with the client's arguments nested under mcp_arguments, and
    the key's details under metadata.
    """
    if auth is not None:
        return dict(_get(auth, "metadata") or {}), _get(auth, "user_id"), _get(auth, "token") or ""
    md = request_data.get("metadata") or {}
    return (dict(md.get("user_api_key_metadata") or {}), md.get("user_api_key_user_id"),
            request_data.get("user_api_key_hash") or "")


class Refused(Exception):
    """No delegation could be had for this caller."""


def refusal(status: int, reason: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": f"Stratium: {reason}"})


log = logging.getLogger("stratium.litellm")
UNREACHED = "no decision: the Stratium PDP could not be reached"


def _why(err: Exception) -> str:
    """One line for the client. What the PDP itself said is passed on; a
    failure to reach it is not, because that text names internal addresses.
    The full error goes to the proxy's log."""
    log.warning("stratium: %s: %s", type(err).__name__, err)
    code = getattr(err, "code", None)
    name = getattr(code() if callable(code) else None, "name", "")
    details = getattr(err, "details", None)
    if not callable(details) or name in ("UNAVAILABLE", "DEADLINE_EXCEEDED", "UNKNOWN", ""):
        return UNREACHED
    return str(details()).splitlines()[0]


class Engine:
    """The PDP client and the delegations, shared by both guardrails so a key
    has one delegation whichever way its calls arrive."""

    def __init__(self, client=None, config=None):
        self.cfg = config or load_config()
        self.client = client or Client(
            self.cfg["pdp_addr"], connect_timeout=self.cfg["connect_timeout"],
            insecure=self.cfg["insecure"], ca_file=self.cfg["ca_file"])
        self._sessions: OrderedDict[tuple, Session] = OrderedDict()

    def session(self, request_data: dict, auth=None) -> Session:
        """The delegation for this key and client session, minted on first
        use. Raises if the key names no agent or the PDP will not grant one."""
        meta, user, key_id = caller(request_data, auth)
        agent = meta.get("stratium_agent_id") or self.cfg["agent_id"]
        if not agent:
            raise Refused("this key names no Stratium agent (stratium_agent_id)")
        if user == "default_user_id":
            user = None  # the proxy's master key: a placeholder, nobody's principal
        subject = meta.get("stratium_subject") or user or self.cfg["subject"]
        if not subject:
            raise Refused("this key names no subject for the Stratium delegation")
        harness = meta.get("stratium_harness", self.cfg["harness"])
        tools = meta.get("stratium_tools") or self.cfg["tools"]
        if isinstance(tools, str):
            tools = [t for t in tools.split(",") if t]
        tier = int(meta.get("stratium_tier", self.cfg["tier"]))
        # The client's own label. It only splits one key's calls into
        # separate delegations; it cannot reach another key's.
        client_session = str(request_data.get("litellm_session_id") or "")
        ident = (agent, subject, harness, tuple(tools), tier, key_id, client_session)

        session = self._sessions.get(ident)
        # A session ends with its delegation. The next request starts another,
        # as the first request for this key did.
        if session is None or session.expired:
            # staleness_window=0: every call is decided by the PDP and leaves
            # its own audit row, which is what a report is matched against.
            session = Session(
                self.client, subject=subject, agent_id=agent, tools=tools,
                max_action_tier=tier, purpose="litellm guardrail",
                ttl_seconds=self.cfg["ttl"], staleness_window=0.0,
                approval_poll_interval=self.cfg["poll"],
                approval_timeout=self.cfg["approval_timeout"], harness=harness)
            self._sessions[ident] = session
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)
        else:
            self._sessions.move_to_end(ident)
        return session

    async def decide(self, request_data: dict, auth, tool: str, raw_input) -> tuple[bool, str]:
        """(allowed, reason). Never raises: whatever goes wrong is a refusal."""
        try:
            # The SDK blocks, and an escalation waits for a person. A thread
            # keeps the proxy's event loop free meanwhile.
            # ponytail: the default thread pool bounds how many approvals can
            # be waited on at once; give this its own executor if that binds.
            session = await asyncio.to_thread(self.session, request_data, auth)
            decision = await asyncio.to_thread(session.check, tool=tool, raw_input=raw_input)
        except Refused as err:
            return False, str(err)
        except Exception as err:  # noqa: BLE001 -- no decision was reached
            return False, _why(err)
        if decision.error is not None:
            return False, _why(decision.error)
        return bool(decision), decision.reason or "denied by policy"

    async def report(self, request_data: dict, tool: str, raw_input) -> None:
        try:
            session = await asyncio.to_thread(self.session, request_data, None)
            await asyncio.to_thread(session.report, tool=tool, raw_input=raw_input)
        except Exception:  # noqa: BLE001 -- a report is a record, not a decision
            pass


_shared: Engine | None = None


class StartupError(RuntimeError):
    """The guardrail cannot be built from this environment.

    Deliberately not a ValueError. LiteLLM catches ValueError and TypeError
    from a guardrail's constructor, logs "starting WITHOUT this guardrail" and
    starts. Any other exception stops the proxy.
    """


def shared_engine() -> Engine:
    global _shared
    if _shared is None:
        try:
            _shared = Engine()
        except (ValueError, TypeError) as err:
            raise StartupError(f"stratium guardrail: {err}") from err
    return _shared


class StratiumMCPGuardrail(CustomGuardrail):
    """Modes: pre_mcp_call and post_mcp_call."""

    def __init__(self, engine=None, **kwargs):
        self.engine = engine or shared_engine()
        super().__init__(**kwargs)

    async def apply_guardrail(self, inputs, request_data, input_type, logging_obj=None):
        """Decide an MCP call before it runs; report it once it has."""
        if input_type == "request" and "mcp_tool_name" in request_data:
            if _get(logging_obj, "call_type") != "call_mcp_tool" or self._description_scan(request_data):
                return inputs  # tools/list, or a scan: nothing is being called
            tool = self._mcp_tool(request_data.get("mcp_server_name"), request_data["mcp_tool_name"])
            allowed, reason = await self.engine.decide(
                request_data, None, tool, request_data.get("mcp_arguments") or {})
            if not allowed:
                raise refusal(403, f"{tool} refused: {reason}")
        elif input_type == "response" and request_data.get("mcp_tool_call_metadata"):
            called = request_data["mcp_tool_call_metadata"]
            tool = self._mcp_tool(called.get("mcp_server_name"), called.get("name"))
            await self.engine.report(request_data, tool, called.get("arguments") or {})
        return inputs

    @staticmethod
    def _description_scan(request_data) -> bool:
        """Whether LiteLLM is asking if a tool's description may be shown.

        Before a call to a tool it has not listed yet, LiteLLM puts that
        question to every guardrail. It has the shape of a call with no
        arguments and comes with the call's own logging object, and the call
        itself follows with its arguments. Deciding the question would
        refuse a tool the PDP allows only for some arguments.

        The one difference is the message LiteLLM writes: for this question
        it names the description, for a call it does not. Only an exact
        match counts. A tool with no description, and anything else that
        does not match, is decided as a call.
        """
        name = str(request_data.get("mcp_tool_name") or "")
        description = request_data.get("mcp_tool_description")
        if not description or "\n" in name or request_data.get("mcp_arguments"):
            return False
        messages = request_data.get("messages") or [None]
        return _get(messages[0], "content") == f"Tool: {name}\nDescription: {description}\nArguments: {{}}"

    @staticmethod
    def _mcp_tool(server, name) -> str:
        """The tool as the MCP client names it: <server>-<tool>."""
        return f"{server}-{name}" if server else str(name)



class StratiumChatGuardrail(CustomGuardrail):
    """Mode: post_call."""

    def __init__(self, engine=None, **kwargs):
        self.engine = engine or shared_engine()
        super().__init__(**kwargs)

    def _unread(self, what: str) -> None:
        """Refuse a reply this file cannot read tool calls from, unless the
        operator has chosen to pass those unchecked."""
        if self.engine.cfg["unread_routes"] != "allow":
            raise refusal(501, f"tool calls in {what} are not checked yet; "
                               "set STRATIUM_LITELLM_UNREAD_ROUTES=allow to pass them unchecked")

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        choices = _get(response, "choices")
        if choices is None:
            # Not a completion. Only the kinds known to carry no tool call
            # pass; anything else may hold one in a shape not read here.
            if type(response).__name__ not in TOOLLESS_REPLIES:
                self._unread(f"a {type(response).__name__} reply")
            return response
        for choice in choices:
            message = _get(choice, "message")
            calls = _get(message, "tool_calls") or []
            # The older way to propose one call. It is the same question.
            legacy = _get(message, "function_call")
            if not calls and not legacy:
                continue
            kept, notes = [], []
            if legacy:
                name = _get(legacy, "name") or ""
                allowed, reason = await self.engine.decide(
                    data, user_api_key_dict, name, _get(legacy, "arguments") or "{}")
                if not allowed:
                    message.function_call = None
                    notes.append(f"[Stratium refused {name}: {reason}]")
            for call in calls:
                fn = _get(call, "function")
                name = _get(fn, "name") or ""
                allowed, reason = await self.engine.decide(
                    data, user_api_key_dict, name, _get(fn, "arguments") or "{}")
                if allowed:
                    kept.append(call)
                else:
                    notes.append(f"[Stratium refused {name}: {reason}]")
            if notes:
                message.tool_calls = kept or None
                message.content = "\n".join(filter(None, [_get(message, "content"), *notes]))
                if not kept and not _get(message, "function_call"):
                    choice.finish_reason = "stop"
        return response

    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data):
        """Hold back every chunk from the first tool-call delta, decide once
        the stream ends, then release the calls or replace them. Text before
        the first tool call is passed on as it arrives."""
        route = _get(user_api_key_dict, "request_route") or ""
        if not route.endswith(READ_STREAMS):
            self._unread(f"a stream on {route or 'an unnamed route'}")
            async for chunk in response:
                yield chunk
            return

        held = []
        async for chunk in response:
            if held or any(self._tool_deltas(c) or self._legacy(c) for c in _get(chunk, "choices") or []):
                held.append(chunk)
            else:
                yield chunk
        if not held:
            return

        # Every choice in the held chunks, put back together: a reply asked
        # for with n > 1 carries a set of tool calls per choice.
        replies: dict[int, dict] = {}
        template = None
        for chunk in held:
            for choice in _get(chunk, "choices") or []:
                r = replies.setdefault(choice.index, {"text": "", "calls": {}, "finish": None, "legacy": None})
                r["text"] += _get(choice.delta, "content") or ""
                r["finish"] = choice.finish_reason or r["finish"]
                fc = self._legacy(choice)
                if fc is not None:
                    template = template or (chunk, choice)
                    r["legacy"] = r["legacy"] or {"name": "", "arguments": ""}
                    r["legacy"]["name"] += _get(fc, "name") or ""
                    r["legacy"]["arguments"] += _get(fc, "arguments") or ""
                for d in self._tool_deltas(choice):
                    template = template or (chunk, choice)
                    call = r["calls"].setdefault(d.index, {"id": None, "name": "", "arguments": ""})
                    fn = _get(d, "function")
                    call["id"] = call["id"] or _get(d, "id")
                    call["name"] += _get(fn, "name") or ""
                    call["arguments"] += _get(fn, "arguments") or ""

        refused = False
        for _, r in sorted(replies.items()):
            r["kept"], r["notes"] = [], []
            if r["legacy"]:
                allowed, reason = await self.engine.decide(
                    request_data, user_api_key_dict, r["legacy"]["name"], r["legacy"]["arguments"] or "{}")
                if not allowed:
                    r["notes"].append(f"[Stratium refused {r['legacy']['name']}: {reason}]")
                    r["legacy"] = None
                    refused = True
            for _, call in sorted(r["calls"].items()):
                allowed, reason = await self.engine.decide(
                    request_data, user_api_key_dict, call["name"], call["arguments"] or "{}")
                if allowed:
                    r["kept"].append(call)
                else:
                    r["notes"].append(f"[Stratium refused {call['name']}: {reason}]")
                    refused = True
        if not refused:
            for chunk in held:
                yield chunk
            return

        # Something was refused, so the held chunks are not sent. Each choice
        # is written out again: its text, each allowed call whole and
        # renumbered, and a closing chunk that carries the refusals as text.
        tool_part = next((copy.deepcopy(d) for c in held for ch in _get(c, "choices") or []
                          for d in self._tool_deltas(ch)), None)

        def piece(index: int, content=None, call=None, legacy=None, finish=None):
            chunk = copy.deepcopy(template[0])
            choice = copy.deepcopy(template[1])
            choice.index, choice.finish_reason = index, finish
            choice.delta.content = content
            choice.delta.function_call = legacy
            if call is None:
                choice.delta.tool_calls = None
            else:
                part = copy.deepcopy(tool_part)
                part.index, part.id = call[0], call[1]["id"]
                part.function.name, part.function.arguments = call[1]["name"], call[1]["arguments"]
                choice.delta.tool_calls = [part]
            chunk.choices = [choice]
            if _get(chunk, "usage") is not None:
                chunk.usage = None
            return chunk

        out = []
        for index, r in sorted(replies.items()):
            if r["text"]:
                out.append(piece(index, content=r["text"]))
            if r["legacy"]:
                out.append(piece(index, legacy=dict(r["legacy"])))
            out += [piece(index, call=(i, call)) for i, call in enumerate(r["kept"])]
            finish = r["finish"] if not r["notes"] else (
                "tool_calls" if r["kept"] else "function_call" if r["legacy"] else "stop")
            out.append(piece(index, content=("\n" + "\n".join(r["notes"])) if r["notes"] else None, finish=finish))
        usage = next((u for u in (_get(c, "usage") for c in reversed(held)) if u is not None), None)
        if usage is not None:
            out[-1].usage = usage
        for chunk in out:
            yield chunk

    @staticmethod
    def _tool_deltas(choice) -> list:
        return _get(_get(choice, "delta"), "tool_calls") or []

    @staticmethod
    def _legacy(choice):
        """A delta's function_call: the older, single-call form."""
        return _get(_get(choice, "delta"), "function_call")
