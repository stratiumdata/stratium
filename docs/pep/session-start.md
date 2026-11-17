# `stratium-pep session-start`

Issues a root delegation and writes it to a session file. **Nothing else in the
PEP works until this has run** — `hook` and `mcp` read that file on every call,
and with no file every tool call denies.

Run it once per agent session, before the agent starts.

---

## Where it sits

```
you  ──▶  stratium-pep session-start  ──▶  PDP (CreateDelegation)
                    │
                    └──▶  session file  ◀── read fresh by every `hook` / `mcp` call
```

It is the only mode that *creates* authority. The other four spend it.

---

## Configuration

Eight variables, all required. Run it with none and the binary lists exactly
what it wants — **observed**:

```
$ stratium-pep session-start
stratium-pep: missing required configuration: STRATIUM_PEP_PDP_ADDR,
STRATIUM_PEP_AGENT_ID, STRATIUM_PEP_SUBJECT, STRATIUM_PEP_SESSION_FILE,
STRATIUM_PEP_CONNECT_TIMEOUT, STRATIUM_PEP_REQUESTED_TIER,
STRATIUM_PEP_REQUESTED_TOOLS, STRATIUM_PEP_TTL_SECONDS
```

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_PEP_PDP_ADDR` | `localhost:50051` | The PDP's gRPC address. Ephemeral under Docker — resolve it, don't store it. |
| `STRATIUM_PEP_AGENT_ID` | `0f8f833a-…` | An agent row's uuid, from `POST /v1/agents`. |
| `STRATIUM_PEP_SUBJECT` | `you@example.com` | The principal delegating. A policy must name it, or issuance fails. |
| `STRATIUM_PEP_SESSION_FILE` | `/run/stratium/session.json` | Where the delegation lands. |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | `5s` | Bounds the gRPC dial only. |
| `STRATIUM_PEP_PDP_CA_FILE` | `/etc/stratium/pdp-ca.pem` | Optional. PEM CA bundle to verify the PDP's TLS certificate with, instead of the system roots. |
| `STRATIUM_PEP_PDP_INSECURE` | `true` | Optional. Plaintext connection to the PDP, for a local development stack only. Default is TLS. Conflicts with `STRATIUM_PEP_PDP_CA_FILE`. |
| `STRATIUM_PEP_REQUESTED_TIER` | `3` | Ceiling on action tier, 0–4. |
| `STRATIUM_PEP_REQUESTED_TOOLS` | `Read,Grep,Glob` | Comma-separated. Empty is refused, not treated as "all". |
| `STRATIUM_PEP_TTL_SECONDS` | `3600` | Delegation lifetime. |

`STRATIUM_PEP_PURPOSE` is optional and free text; it is recorded on the
delegation and shown in audit.

`STRATIUM_PEP_ESCALATE_AT` is optional too. It asks for a lower escalation
threshold than the agent's own, so more calls wait for a human. It can never
raise or remove the agent's threshold. The threshold actually granted is in
the session file, under `granted_scope.escalate_at`.

> **These eight are not `hook`'s eight.** They overlap in five. Exporting only
> this set and then launching an agent leaves every tool call denying with
> `missing required configuration` — a denial that reads exactly like a policy
> denial until you open the reason. See [`hook.md`](hook.md).

---

## Worked example

```bash
export STRATIUM_PEP_PDP_ADDR="localhost:50051" \
       STRATIUM_PEP_PDP_INSECURE=true \
       STRATIUM_PEP_AGENT_ID="0f8f833a-ef4c-4e7e-bbb5-00d259cf5c19" \
       STRATIUM_PEP_SUBJECT="agent-tester@example.com" \
       STRATIUM_PEP_SESSION_FILE="$PWD/.stratium-session.json" \
       STRATIUM_PEP_CONNECT_TIMEOUT=5s \
       STRATIUM_PEP_REQUESTED_TIER=3 \
       STRATIUM_PEP_REQUESTED_TOOLS="Read,Grep,Glob" \
       STRATIUM_PEP_TTL_SECONDS=3600 \
       STRATIUM_PEP_PURPOSE="nightly docs build"

stratium-pep session-start
```

Success is silent, exit `0`. The session file:

```json
{
  "delegation_id": "0527310d-f2c3-4444-9fae-12d08836c12f",
  "granted_scope": { "max_action_tier": 3, "tools": ["Read", "Grep", "Glob"] },
  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9…",
  "epoch": 94
}
```

**PASS if** `granted_scope.tools` is non-empty. An empty list means the
principal holds none of what you asked for — see the first failure below.

---

## Failures you will actually hit

**`none of the requested tools are held by this principal`**

No policy grants your `STRATIUM_PEP_SUBJECT`. Issuance is clamped by what the
principal may delegate, and with no policy that set is empty. Create one before
retrying:

```bash
curl -sS -X POST "http://$PAP/v1/policies" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"grant","description":"let this principal delegate",
       "language":"rego","effect":"deny","enabled":true,
       "policy_content":"package stratium.policy\n\nallow if {\n\tinput.principal.subject == \"agent-tester@example.com\"\n}"}'
```

`"effect"` must be `"deny"` even for a policy that allows. A Rego policy can
produce either outcome per request, so the column holds a fixed placeholder
rather than a claim about behaviour; sending `"allow"` is a `400` that says so.

**`agent <uuid>: not found`** — the agent row does not exist in the tenant this
PDP serves. A PDP serves exactly one tenant, named at startup.

**`delegation chain is not well-formed: acting delegation … was issued to agent
X, not Y`** — the session file is from a different agent. Delete it and re-run.

---

## The session file is bearer authority

Anyone who can read it can act as this delegation until it expires. Treat it
like a credential: a private path, not a shared temp directory, and not
somewhere a build artifact collector will sweep up.

## Expiry and re-issue

The delegation lasts `TTL_SECONDS`. `hook` re-reads the file on **every** call,
so a revocation between two tool calls takes effect on the next one. On expiry
the PEP attempts a re-issue; if that is refused you will see

```
stratium-pep: re-issue token: PDP returned an error: rpc error: code = PermissionDenied
```

which means run `session-start` again.

## Grant discovery tools, not just access tools

An agent that can `Read` but not `Glob` or `Grep` will thrash — it cannot find
what it is allowed to open. Grant the discovery tools alongside the access ones
unless you specifically mean to prevent search.

---

## See also

- [`hook.md`](hook.md) — the surface that consumes this session file.
- [`mcp.md`](mcp.md) — the same, for MCP servers.
- [`../pep.md`](../pep.md) § "Starting a session" — the operator reference.
