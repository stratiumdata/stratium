# example — a custom PEP in about sixty lines

`custom_pep.py` is the first place in this repo the Python SDK talks to a
real PDP over the wire. Every test under `sdk/python/tests/` runs against
`FakePDP` (`tests/conftest.py`), a scripted gRPC servicer that returns
whatever `Decision` a test hands it — it has no tier logic, no tool catalog,
no delegation-chain walk. This example is what happens when the same SDK
code asks the actual `pdp-pap` service, running the real policy evaluation
in `services/internal/authz`.

It mints one delegation scoped to `tools=["Read"], max_action_tier=1`, then
checks three calls: `Read`, expected ALLOW; `Grep`, expected DENY because the
delegation doesn't hold it (`approved_tools`); and `Bash` running `rm -rf`,
expected DENY too, but for a *different* reason — it never reaches the
tool-name check at all, because its tier exceeds the delegation's ceiling
first. Each check asserts on the PDP's own `reason` string, not just on
`allowed`/`denied`, because a denial for the wrong cause is a failure, not a
pass (see `Decision.__bool__`'s own docstring in `stratium/_types.py`, and
`example/proxy/README.md` at the repo root, which holds the same standard for
the Go surfaces).

## Running it

Ports are ephemeral — re-derive them, never hardcode one:

```bash
cd sdk/python
PDP="localhost:$(docker compose -f ../../deploy/docker/docker-compose.yml port pdp-pap 50051 | sed -E 's/.*://')"
python3 example/custom_pep.py --pdp "$PDP" --agent <uuid> --subject you@example.com
```

The agent id must name a row in `pdp-pap`'s tenant (`tenant-pap-e2e-integration`)
that is `enabled`, not `suspended`, and holds `trust_tier >= 1` (`READ_ONLY`'s
row in `internal/authz/agent.go`'s `TrustTable`). The run below used
`claude-code-trial` (`3422a63e-4ce5-4339-bfac-d6887594651d`), an agent whose
`allowed_tools` is deliberately unrestricted (`[]`) — chosen so that the
delegation's own `approved_tools`, not the agent's allowlist, is the only
thing that can refuse a tool the delegation didn't request.

No new dependency, Python 3.12+, and nothing under `sdk/python/stratium/`
changed to make this run — see "What actually happened," below, for why that
matters.

## What actually happened

Run on 2026-08-26, against a live stack that had been up for several days
(`pdp-pap` "Up 3 days" in `docker compose ps`), with `PDP=localhost:56378` at
the time (re-derive per the command above — it will not be 56378 by the time
you read this). This is the exact, unedited stdout and exit code of a real
run, captured to a file rather than retyped:

```
$ python3 example/custom_pep.py --pdp "$PDP" \
    --agent 3422a63e-4ce5-4339-bfac-d6887594651d --subject sdk-example@example.com
delegation 8ac77236-e91f-4365-b5e5-b66fd009e06b
  granted tools: ['Read']
  granted tier:  1

  ALLOW Read   
  DENY  Grep   tool "Grep" not in delegation approved_tools at depth 0
  DENY  Bash   action tier DESTRUCTIVE exceeds delegation max_action_tier READ_ONLY at depth 0

enforcement: 3/3 as expected
$ echo $?
0
```

Reproducible: repeated immediately after against the same live stack (a
second delegation, `b5d34f4d-cbaf-4dd9-8021-f81c97dac800`), identical shape —
`ALLOW Read`, `DENY Grep` for `approved_tools`, `DENY Bash` for
`max_action_tier`, `enforcement: 3/3`, exit `0`.

### The first draft asked one denial to prove two different things, and got 1/2

This example originally checked only `Read` and `Bash`, expecting `Bash` to
be denied for `approved_tools` — the same reason `Grep` is denied above. Run
for real, it came back `enforcement: 1/2`, exit `1`:

```
delegation d3b45ab8-157c-48a5-8527-8323970d8e23
  granted tools: ['Read']
  granted tier:  1

  ALLOW Read   
  DENY  Bash   action tier DESTRUCTIVE exceeds delegation max_action_tier READ_ONLY at depth 0
    MISMATCH: expected the reason to mention 'approved_tools'

enforcement: 1/2 as expected
```

`Bash` *was* denied, correctly — but for `action tier DESTRUCTIVE exceeds
delegation max_action_tier READ_ONLY at depth 0`, not for `approved_tools`.
The script's own reason assertion caught the mismatch and failed loudly
rather than passing for the wrong reason, exactly as it's meant to. That
result was reported as observed rather than tuned away by picking a
different expected string — see "Why," directly below, for the actual
mechanism, and the two-line fix was adding `Grep` as a *second* denial case
so the example demonstrates `approved_tools` and `max_action_tier` as the two
genuinely different gates they are, instead of asking one `Bash` call to
stand in for both.

### Why: the tier ceiling is checked before `approved_tools`, and `rm -rf` is DESTRUCTIVE

`DelegationLeg` (`services/internal/authz/delegation.go`) walks each hop in a
delegation chain and checks, in this fixed order, before it ever reaches the
tool-name check:

```go
if derived > d.MaxActionTier {
    return LegResult{Effect: EffectDeny, Reason: fmt.Sprintf(
        "action tier %s exceeds delegation max_action_tier %s at depth %d",
        derived, d.MaxActionTier, d.Depth)}, d.Depth
}
if a.Tool != "" && !d.HasTool(a.Tool) {
    return LegResult{Effect: EffectDeny, Reason: fmt.Sprintf(
        "tool %q not in delegation approved_tools at depth %d",
        a.Tool, d.Depth)}, d.Depth
}
```

The doc comment above it says plainly that the tier check is "checked first;
unchanged by this leg." `Bash`'s raw input, `{"command": "rm -rf /tmp/x"}`, is
classified `DESTRUCTIVE` by the built-in shell command classifier
(`internal/authz/catalog.go`'s own comment: `"rm -rf /"` derives `DESTRUCTIVE`,
`"ls -la"` derives `READ_ONLY`) — deliberately, by design, so that a PEP can't
be tricked by a benign-looking tool name into under-classifying a destructive
command. `DESTRUCTIVE` (4) exceeds this delegation's `max_action_tier`, 1
(`READ_ONLY`), so the tier gate denies before `approved_tools` is ever
consulted. That would be true of this exact call for **any** delegation
minted with `max_action_tier=1`, regardless of what its `approved_tools` list
holds or how permissive the agent's own `allowed_tools` is — the tier ceiling
and the tool allowlist are independent gates, and either alone is enough to
deny, but only one of them gets to name itself as the reason.

**Why the fake PDP never caught this:** `FakePDP` (`tests/conftest.py`)
returns whatever `Decision` a test scripts — it never runs `DeriveTier` or
`DelegationLeg`, so a unit test asserting "`Bash` denied, reason mentions
`approved_tools`" was only ever testing that the SDK reports back whatever
reason string the fixture was told to hand it. This example is the first
place in the SDK's history that reason string comes from the real evaluation
order instead, and the real order disagrees with what every prior task
assumed a `Read`-only delegation would say about an unheld, destructive
`Bash` call.

**This was a finding about the example's own choice of `Bash` command, not a
bug in the PDP or the SDK.** The tier-before-tools order is intentional (the
doc comment says so), and classifying `rm -rf` as `DESTRUCTIVE` is
intentional too — a `Bash` command classified at or below `READ_ONLY` (e.g.
`ls -la`) would have cleared the tier gate and reached `approved_tools`
instead. Rather than swap `rm -rf` for a milder command (which would have
hidden the tier-ceiling behavior entirely) or loosen the assertion to accept
either reason (which would have let a `Bash` refused for the wrong cause pass
silently), the fix keeps `rm -rf` and adds `Grep` as a distinct third case,
so the example demonstrates both gates explicitly instead of conflating them.

### What the `Bash` case teaches: a denial names the first gate, not every gate

`Grep` and `Bash` are both denied above, and neither is in this delegation's
`approved_tools`. Only `Grep`'s denial says so. `Bash`'s reason never mentions
tools at all — `DelegationLeg` returned as soon as the tier check failed, so
`HasTool` was never even called for it. **Evaluation order is observable, and
a denial names the first gate that refused, not every gate that would have.**
A PEP author reading only the reason string for `Bash` above would have no
way to tell, from that string alone, whether `Bash` is also absent from
`approved_tools` — it might be, or the delegation might hold it and it would
still be denied, because the tier check runs first regardless. Anyone
building alerting, dashboards, or a runbook on top of these reason strings
should assume "denied for tier" says nothing about tool membership, and vice
versa; the two checks are logically independent even though only one gets to
speak when both would have refused the call. That is exactly the gap `Grep`
closes here: it isolates `approved_tools` as a denial reason so the example
can show it actually fires, rather than always being shadowed by a tier
check that ran first.

## Confirming the delegation reached the tenant

`pdp-pap` and `stratium-pap` are pinned to the same tenant,
`tenant-pap-e2e-integration` (`deploy/docker/docker-compose.yml`), so the
delegation this script mints is administered by the same console/API that
manages the agent. Verified over the API with a `pap-admin` token — a real
browser against the console was not used for this check, the API was:

```bash
dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }
KC="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"
PAP="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"
ADMIN=$(curl -sS -X POST "http://$KC/realms/stratium/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=stratium-pap \
  -d username=pap-admin -d password=pap_admin_local_dev_only -d 'scope=openid email' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
curl -sS "http://$PAP/v1/delegations?agent_id=3422a63e-4ce5-4339-bfac-d6887594651d" \
  -H "Authorization: Bearer $ADMIN"
```

The agent row (`GET /v1/agents/3422a63e-4ce5-4339-bfac-d6887594651d`) names
it `"name": "claude-code-trial"`. The delegation row for
`8ac77236-e91f-4365-b5e5-b66fd009e06b`, the one minted by the 3/3 run captured
above, appears in that tenant's list exactly as granted:

```json
{
  "id": "8ac77236-e91f-4365-b5e5-b66fd009e06b",
  "agent_id": "3422a63e-4ce5-4339-bfac-d6887594651d",
  "user_id": "sdk-example@example.com",
  "approved_tools": ["Read"],
  "max_action_tier": 1,
  "purpose": "stratium python sdk example",
  "depth": 0,
  "root_delegation_id": "8ac77236-e91f-4365-b5e5-b66fd009e06b",
  "revoked": false
}
```

Agent name `claude-code-trial`, purpose `stratium python sdk example`, depth
`0`, and `approved_tools: ["Read"]` — the scope the PDP actually granted, not
merely what was requested — all present, confirming the same fact the console's
Delegations screen would show through a fully independent path from the gRPC
`Decide` calls above.

## Leftovers

Every delegation this script mints carries `purpose: "stratium python sdk
example"` and a 300-second TTL, so repeated runs are both identifiable in the
tenant's delegation list and self-expiring; nothing here needs manual
cleanup.
