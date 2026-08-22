# example/extauthz — policing the agent's own cognition

A real local model (`llama3.2` via Ollama, through LiteLLM) decides its own
tool calls with one tool, `ask_model(model, prompt)`. Calling that tool means
asking an LLM by name — but the *model doing the reasoning* and the *model
`ask_model` calls* are different things, and only the second one is policed.

`ask_model`'s HTTP request goes to **Envoy's** published port. Envoy's
`ext_authz` filter calls `stratium-pep extauthz` on every request before ever
routing it onward to LiteLLM, and `stratium-pep extauthz` asks the PDP.
`llama3.2` is allowed; `gpt-4o` is declared in LiteLLM but deliberately
unreachable (`api_base: http://127.0.0.1:1`), so a passing run proves policy
refused it *before* reachability was ever consulted — a 502 from LiteLLM
would look identical to a human skimming the transcript, so `main.go` tells
the two apart explicitly (see **Denial vs. unreachability**, below).

## Two different addresses, on purpose

```go
// The agent's own reasoning goes direct to LiteLLM, bypassing Envoy on
// purpose. Only the ask_model TOOL takes the policed path. Route both through
// Envoy and this example deadlocks the moment the deny fires: the agent needs
// a model call in order to tell you its model call was refused.
llm := &agent.LLM{BaseURL: "http://" + litellmAddr, Model: "llama3.2"}
```

`agent.LLM` — the model driving this program's own `agent.Run` loop — dials
LiteLLM directly. `extauthzTransport` — what `ask_model` actually calls —
dials Envoy. If both went through Envoy, denying `ask_model("gpt-4o", ...)`
would also deny the *reasoning* call that has to report the denial back to
the model, and the loop would have no way to say anything at all.

## Running it

The agent row `pep-extauthz`'s own fixed identity names already exists on
this stack (seeded once by `services/internal/store/extauthz_integration_test.go`'s
own `seedExtauthzAgentOnce`, or by the one-time `psql` step below on a stack
where those tests have never run) — nothing in `main.go` writes it. See **The
one row that lives in `deploy/seed/`**, below, for exactly why not.

```bash
cd example
dc() { docker compose -f ../deploy/docker/docker-compose.yml "$@"; }
# One-time, only if the Precheck below reports the row missing:
dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres \
  psql -h 127.0.0.1 -U stratium_migrate -d stratium -q \
  -f /dev/stdin < ../deploy/seed/extauthz-example-agent.sql

export EXAMPLE_PDP_ADDR="localhost:$(dc port pdp-extauthz 50051 | sed -E 's/.*://')"
export EXAMPLE_ENVOY_ADDR="localhost:$(dc port envoy 10000 | sed -E 's/.*://')"
export EXAMPLE_LITELLM_ADDR="localhost:$(dc port litellm 4000 | sed -E 's/.*://')"
export EXAMPLE_PAP_ADDR="localhost:$(dc port pap-extauthz 8080 | sed -E 's/.*://')"
export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"
go run ./extauthz
```

`main.go` then, in order: prechecks Ollama/LiteLLM/Envoy/the PDP/pap-extauthz,
**and that the seed above was applied** — a missing fixture reads as setup,
exactly like a missing Ollama model, never as a policy denial; seeds one
`tool_catalog` row per model name through **pap-extauthz's own HTTP API**
(see **Tool identity is the request path**, below); runs `stratium-pep
session-start` requesting **only** `llama3.2`'s tool identity; mints a
DPoP-bound token (extauthz refuses an unbound one exactly as `proxy` does,
spec §4.7.2 K5 — see `example/proxy/README.md`'s own **Sender-constrained
tokens** section, unchanged here beside which PDP is dialed); and hands the
whole thing to `agent.Run` with a task that asks `llama3.2` then `gpt-4o` the
same question, expecting `llama3.2` **ALLOWED** and `gpt-4o` **DENIED** for
`not in delegation approved_tools` — both are cataloged at the identical
action tier, so a tier ceiling can never be the reason.

## Tool identity is the request path

`cmd/stratium-pep/extauthz.go`'s own `decideRequestFromCheck` sets
`DecideRequest.Tool` to the request's **path** ("M1: the request path IS the
tool identity") — not a field this program picks, and not something it can
put in the request *body*: Envoy's `ext_authz` filter never forwards the body
at all, so the `"model"` field inside the JSON a caller posts to
`/chat/completions` is invisible to the PDP no matter what it says. The one
route `envoy.yaml` wires to LiteLLM is a `/chat/completions` **prefix**
match, shared by every model — it creates no way to tell two models' requests
apart on its own.

`toolIdentity(model)` closes that gap without touching `envoy.yaml`: it
appends the model as a **query parameter**,
`/chat/completions?model=llama3.2`. Envoy's `Path` attribute
[includes the query string](https://github.com/envoyproxy/envoy/blob/v1.37.0/api/envoy/service/auth/v3/attribute_context.proto)
(confirmed live — see `extauthz.go`'s own `observedURI` doc comment), so this
becomes a genuinely different `DecideRequest.Tool` per model, while Envoy's
own prefix *route* match ignores it entirely (prefix matching operates on
the path component only).

**The query is not merely visible to LiteLLM — it is what LiteLLM routes
on, ahead of the body.** LiteLLM's own model-resolution precedence
(`proxy_server.py`) is
`general_settings["completion_model"] or user_model or model or data.get("model")`,
where `model` is the request's **query parameter** and `data.get("model")`
is the **body** — the query wins whenever both are present. Confirmed live:
an `?model=gpt-4o` request with no `"model"` key in the body still selects
`gpt-4o`'s dead upstream. That is why `Call` sends the model **only** in the
query and omits it from the body entirely (see **Only one value to
disagree with**, below) — the value policy sees and the value LiteLLM routes
on are the same value by construction, not merely by this program's own care
to keep two copies in sync. One function, `toolIdentity`, builds the
tool_catalog row name, the delegation's requested tool, and the literal
path+query this program sends — so the three can never drift into three
different spellings of the same model.

## Only one value to disagree with

An earlier version of this example sent `"model"` in both the query and the
JSON body — always the same value, so it worked, but for a reason that
depended on LiteLLM's own precedence order holding. `docker-compose.yml`
pins `ghcr.io/berriai/litellm:main-latest`, a **floating** tag, on an
internal precedence chain whose own inline comment reads "for azure
deployments" — not a guarantee this example is entitled to lean on forever.
Had that order ever reversed, sending a policed model in the query and a
different, unpoliced one in the body would have been silently accepted:
nothing in this suite would fail, because this program always sent body ==
query, so the two could never be caught disagreeing. That is the bypass this
design exists to avoid, sitting one config change away.

`Call` now omits `"model"` from the body entirely — the query is the *only*
value present for the PDP's decision and LiteLLM's routing to possibly
disagree about, and it is the same value either way it is resolved. One
deleted JSON key converts a coincidence (both orderings happen to agree
today) into a structural guarantee (there is nothing left to disagree).

## The DPoP proof's `htu` does not carry the query

RFC 9449 §4.3 item 9 excludes the query from `htu` comparison, and
`extauthz.go`'s own `observedURI` strips everything from the first `?`
onward before comparing. So both models' calls sign the **same** `htu` —
`http://envoy.stratium.test/chat/completions` — even though they carry
different `Tool` identities. Only the query varies per model; `htu` is fixed.

## Denial vs. unreachability

- **403** from Envoy is a **decision**: `ext_authz`, or the PDP behind it,
  looked at this exact call and said no —
  `agent.Result{Allowed:false, Reason: <body>}`.
- **500/502/503** means Envoy let the request through to LiteLLM and LiteLLM
  then failed to reach the model's own upstream — exactly `gpt-4o`'s
  deliberately unreachable `api_base`, which LiteLLM reports as a **500**
  (`litellm.InternalServerError`, "Connection error"), confirmed live — not a
  502/503, which are also caught for the same "let through, not refused"
  reading in case a future LiteLLM version reports it differently. Any of the
  three means `ext_authz` did **not** refuse the call: this example is broken
  (the delegation must be holding the `gpt-4o` tool when it should not), not
  policy working, and is returned as a Go `error` so `agent.Run` aborts
  instead of recording a transport failure as a decision.
- Any other transport failure is a Go `error` too, never a decision.

## The one row that lives in `deploy/seed/`

`pep-extauthz` (docker-compose.yml) is configured with a literal
`STRATIUM_PEP_AGENT_ID`, read from its own startup config and never from
anything a live HTTP request could carry — Envoy forwards a *token*, not an
identity (`extauthz.go`'s own package doc, NO SESSION FILE). `POST
/v1/agents` cannot produce that row: `store.CreateAgent`'s own doc comment
states plainly that `id` is ignored on input. That is a property of the
**stack**, not of this example, so the fixture lives at the stack level too:
`deploy/seed/extauthz-example-agent.sql`, one idempotent
`INSERT ... ON CONFLICT DO NOTHING`, the same precedent
`deploy/seed/proxy-example-agent.sql` already sets. It seeds the identical
literal id `services/internal/store/extauthz_integration_test.go`'s own
`extauthzAgentID` hardcodes, and that test file's own `seedExtauthzAgentOnce`
inserts the same row with the same `ON CONFLICT DO NOTHING` — so on a stack
where those tests have already run, this file's own `psql` step is simply a
no-op that leaves the existing row alone.

`main.go` itself holds no database credential and imports no SQL driver. It
only ever *checks* the row exists (`agentSeededProbe`, one more `Precheck`
entry) and names the exact `psql` command to run if it does not.

## A model that will not always narrate

`llama3.2` sometimes keeps calling `ask_model("llama3.2", ...)` again instead
of moving on to `gpt-4o`, or stops after the deny without a closing sentence
— the same unreliability `example/proxy/README.md`'s own **A model that will
not stop calling `fetch`** section describes for its own tool. Nothing here
suppresses that; every repeat is genuinely re-authorized and genuinely
re-sent. `enforcement: 2/2` only requires that `llama3.2` was tried and
allowed at least once, and `gpt-4o` was tried and denied at least once — not
that the model narrated cleanly, which is a model limitation `report.go`
already distinguishes from an enforcement failure.
