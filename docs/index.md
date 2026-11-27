---
hide:
  - navigation
---

# Stratium

**Authorization for AI agents, decided per tool call.**

An agent acting on someone's behalf makes thousands of tool calls an hour, with
the same credentials the whole time. Most authorization stops at "is this
session valid". Stratium asks a much narrower question, every time:

> May **this agent**, acting under **this person's** delegated authority, at
> **this point in a delegation chain**, perform **this action** on **this
> resource**, right now?

`Bash("ls -la")` and `Bash("rm -rf /")` are the same tool, agent, session and
credentials. To Stratium they are different questions.

[Get started](quickstart.md){ .md-button .md-button--primary }
[Try the hosted demo](demo.md){ .md-button }
[Read the concepts](concepts.md){ .md-button }
[GitHub](https://github.com/stratiumdata/stratium){ .md-button }

---

## The rule everything follows from

**The component being policed never classifies its own actions.** The
enforcement point next to the agent forwards the tool call's arguments
verbatim. The server derives the danger tier, the resource identity, and the
classification itself. The test for any change:

> *Could a hostile enforcement point get a better answer by lying?*

## Four sentences

1. The enforcement point forwards bytes and enforces an answer. It classifies
   nothing.
2. The decision point derives the tier, the resource identity, and the
   classification itself, from data it trusts, never from a caller's claim.
3. `allow = principal ∧ agent ∧ delegation`, with the delegation as a
   structural ceiling no policy can raise, and the trust tier as a floor no
   delegation can lower.
4. Every ambiguity denies.

## Three planes

| Plane | Binary | What it does | Trusted? |
|---|---|---|---|
| **PDP**, decision point | `stratium-pdp` | Answers one RPC, `Decide`. Owns all classification, derivation, and token verification. One process per tenant. | Yes |
| **PAP**, administration point | `stratium-pap` | Policies, agents, tool catalog, label rules, approvals. Humans sign in over OIDC. Serves the admin UI. | Yes, and the only internet-facing part |
| **PEP**, enforcement point | `stratium-pep` | Runs beside the agent and turns a tool call into a question, and the answer into a block or a pass. | **No, by design** |

## Where to go

<div class="grid cards" markdown>

-   :material-rocket-launch: **Try it**

    ---

    From a fresh clone to a coding agent whose tool calls are authorized,
    with one script.

    [Try the hosted demo](demo.md) · [Quickstart](quickstart.md) ·
    [A default posture](default-posture.md) · [What it does not stop](limits.md)

-   :material-lightbulb-on: **Understand it**

    ---

    What the system decides and why it holds, without reading code.

    [Concepts](concepts.md) · [Glossary](glossary.md)

-   :material-map-marker-path: **Do something with it**

    ---

    Step-by-step journeys: keep an agent in its workspace, protect sensitive
    data, require approval for risky actions, hand a sub-agent less, stop an
    agent now, investigate an incident.

    [User journeys](journeys/index.md)

-   :material-shield-lock: **Enforce it**

    ---

    Six enforcement surfaces: Claude Code / Codex hooks, an MCP proxy, a gRPC
    proxy, Envoy `ext_authz`, and a Python SDK.

    [Which surface do I want?](pep/README.md)

-   :material-cog: **Run it**

    ---

    Install, configure, and operate the PDP and PAP: policies, agents,
    delegations, approvals, and audit.

    [User guide](user-guide.md) · [Architecture](architecture.md)

</div>

---

Stratium is open source under the Apache-2.0 license.
[Contributing](https://github.com/stratiumdata/stratium/blob/main/CONTRIBUTING.md) ·
[Report a vulnerability](https://github.com/stratiumdata/stratium/blob/main/SECURITY.md)
