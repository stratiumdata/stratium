# Manual test plan — resource labelling

How to exercise per-tenant resource classification labelling by hand, against a
real stack, in the state the feature is in today.

**Every step below was executed end to end against a live stack on 2026-08-19**,
not written from reading the code. Where the two disagreed the observed
behaviour won — five commands in an earlier draft were wrong, and each is
flagged inline where the surprise is worth knowing.

Ports are resolved at runtime because the compose file binds ephemeral host
ports.

---

## What you can test, and the one thing you cannot

The feature lets an operator register per-tenant rules mapping a **resource-id
prefix** to a `(hierarchy, level)` classification. At decision time the PDP
resolves a resource's label by **longest matching prefix** and hands it to the
delegation's classification cap check.

**Everything on the labelling side is reachable through the admin plane.**
Parts A and C1–C5 need nothing but `curl` and `grpcurl`.

**The cap itself is not.** Nothing in the API sets, raises, lowers, or repairs
a delegation's `classification_caps`: issuance writes an empty map on every
root delegation, children copy their parent's map unchanged, and the create RPC
carries no field for one. So **Part B requires one direct SQL write** to put a
cap in place — there is no other way to reach the enforcement path, and the
project's own integration fixtures do the same thing for the same reason.

That gap is recorded in the spec's open items, not hidden. Part D covers what
it means in practice, including a trap that silently disables enforcement.

---

## 0. Bring up a stack

From the repository root:

```bash
docker compose -f deploy/docker/docker-compose.yml up -d --build --wait --wait-timeout 300
```

Resolve the ports you'll need — they are ephemeral, so read them rather than
assuming:

```bash
dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }   # a function, not a variable
export PAP="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"
export PDP="localhost:$(dc port pdp-pap 50051 | sed -E 's/.*://')"
export KC="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"
export TENANT=tenant-pap-e2e-integration
echo "PAP=$PAP  PDP=$PDP  KC=$KC"
```

> `dc` is a function deliberately. Putting the command in a variable and
> calling `$dc port …` fails — the shell looks for a single command whose name
> is the whole string.


`stratium-pap` and `pdp-pap` are both pinned to `tenant-pap-e2e-integration`.
The tenant is startup configuration and no request can carry one, so a PAP
process serves exactly one tenant for its whole life.

Two `psql` helpers, used throughout. `-h 127.0.0.1` forces TCP so password
authentication is used consistently rather than depending on the image's local
socket rules:

```bash
psqlm() {   # the owner role — used for setup and for reading state
  dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres \
    psql -h 127.0.0.1 -U stratium_migrate -d stratium "$@"
}
psqlapp() { # the PDP's serving role — used to prove what it CANNOT do
  dc exec -T -e PGPASSWORD=stratium_local_dev_only postgres \
    psql -h 127.0.0.1 -U stratium -d stratium "$@"
}
```

**Tear down when finished:**

```bash
docker compose -f deploy/docker/docker-compose.yml down -v --remove-orphans
```

> If this host also runs unrelated Docker projects, note that `down -v` above is
> scoped to this compose file by `-f`. Do not reach for `docker system prune` or
> `--volumes` on the host to reclaim space; `docker builder prune -af` is the
> safe one.

---

## 1. Get operator tokens

The realm is `stratium`, the client is `stratium-pap` (public, direct access
grants enabled). Four operators exist with different group memberships:

| User | Password | Role |
|---|---|---|
| `pap-viewer` | `pap_viewer_local_dev_only` | viewer |
| `pap-editor` | `pap_editor_local_dev_only` | editor |
| `pap-admin` | `pap_admin_local_dev_only` | admin |

```bash
tok() {
  curl -sS -X POST "http://$KC/realms/stratium/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=stratium-pap \
    -d "username=$1" -d "password=$2" -d 'scope=openid email' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
export EDITOR=$(tok pap-editor pap_editor_local_dev_only)
export ADMIN=$(tok pap-admin pap_admin_local_dev_only)
export VIEWER=$(tok pap-viewer pap_viewer_local_dev_only)
```

Sanity check — this should return `200` and a JSON array:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/resource-label-rules"
```

---

## Part A — the admin plane

No SQL. This is the whole operator-facing surface of the feature.

### A1 — Register rules and read them back

Valid hierarchies and levels are fixed in the code:

- `nato`: `UNCLASSIFIED`, `RESTRICTED`, `CONFIDENTIAL`, `SECRET`, `TOP-SECRET`
- `commercial`: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL-COMMERCIAL`, `RESTRICTED-COMMERCIAL`, `HIGHLY-CONFIDENTIAL`

```bash
mkrule() {
  curl -sS -X POST "http://$PAP/v1/resource-label-rules" \
    -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
    -d "{\"prefix\": \"$1\", \"hierarchy\": \"$2\", \"level\": \"$3\"}"
}

mkrule ""                 nato UNCLASSIFIED   # the catch-all
mkrule "/exports/"        nato SECRET
mkrule "/exports/public/" nato UNCLASSIFIED   # a lowering carve-out
```

**Expect: 201**, and each returns the created rule with an `id` and `tenant_id`.

```bash
curl -sS -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/resource-label-rules"
```

**Expect:** three rules, ordered by prefix — the empty prefix first.

### A2 — A duplicate prefix is refused

```bash
mkrule "/exports/" commercial PUBLIC
```

**Expect: 409.** The key is `UNIQUE (tenant_id, prefix)`, deliberately *not*
`(tenant_id, prefix, hierarchy)`. A resource carries exactly one classification
in one hierarchy, so the same prefix under two hierarchies would be a pair no
resource could satisfy — and its only symptom would be total silent denial
under that prefix.

### A3 — An invalid level is refused at write time

```bash
mkrule "/typo/" nato SEKRET
mkrule "/typo/" natoo UNCLASSIFIED
```

**Expect: 400** on both, and the message names the known values. Validation
lives in Go rather than a schema `CHECK`, because a `CHECK` enumerating the ten
valid pairs would be a second copy of the levels table that can drift silently.

**Note what is *not* validated: the prefix.** A typo there is accepted and
produces a rule that silently never matches anything. That is the one field
nothing can check, since any string is a legitimate prefix.

### A4 — Role gating

```bash
# viewer cannot write
curl -sS -o /dev/null -w 'viewer POST   -> %{http_code}\n' \
  -X POST "http://$PAP/v1/resource-label-rules" \
  -H "Authorization: Bearer $VIEWER" -H 'Content-Type: application/json' \
  -d '{"prefix":"/nope/","hierarchy":"nato","level":"SECRET"}'

# editor cannot delete
RULE_ID=$(curl -sS -H "Authorization: Bearer $VIEWER" \
  "http://$PAP/v1/resource-label-rules" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
curl -sS -o /dev/null -w 'editor DELETE -> %{http_code}\n' \
  -X DELETE "http://$PAP/v1/resource-label-rules/$RULE_ID" \
  -H "Authorization: Bearer $EDITOR"
```

**Expect:** `403` on both. Create/update are editor; delete is admin.

### A5 — Every write bumps the tenant epoch

The epoch is what invalidates a PEP's decision cache. A labelling change that
did not bump it would leave stale authorization decisions in flight.

```bash
epoch() {
  psqlm -tAc "SELECT set_config('app.tenant_id','$TENANT',false);
              SELECT epoch FROM tenant_epoch WHERE tenant_id='$TENANT';" | tail -1
}
epoch; mkrule "/tmp-probe/" nato RESTRICTED >/dev/null; epoch
```

**Expect:** the second value is higher. Repeat for `PUT` and `DELETE` — the
trigger fires on all three verbs.

---

## Part B — the decision path

This is where a cap has to be written directly. Read §0's note first.

### B1 — Seed an agent and a catalogued tool

```bash
export AGENT=$(curl -sS -X POST "http://$PAP/v1/agents" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"manual-test-agent","provider":"anthropic","model_id":"claude",
       "trust_tier":3,"enabled":true,"suspended":false,"allowed_tools":[]}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -sS -X POST "http://$PAP/v1/tool-catalog" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"tool_name":"read_file","action_tier":1,"verb":"read",
       "resource_field":"path"}'
echo "AGENT=$AGENT"
```

**`resource_field` is the load-bearing part.** It names which field of the
call's `raw_input` is the resource identity. A tool whose catalog row names no
`resource_field` produces no resource id — and therefore gets no label at all.
See D2.

### B2 — Seed a delegation, with its cap, in one step

**`CreateDelegation` over gRPC will not work here**, and the reason is worth
knowing: a root delegation is clamped by what the *principal* holds, so with no
principal policy configured for this tenant it fails with `none of the requested
tools are held by this principal`. The project's own integration fixtures do not
use that RPC either — they insert the row. Do the same, and put the cap in the
same statement, since §0 already established that no route can add one later.

```bash
export DELEG=$(python3 -c 'import uuid;print(uuid.uuid4())')
psqlm -q -c "BEGIN;
 SELECT set_config('app.tenant_id','$TENANT',true);
 INSERT INTO delegations (id,tenant_id,user_id,agent_id,approved_tools,max_action_tier,
   classification_caps,resource_constraints,purpose,expires_at,revoked,
   parent_delegation_id,root_delegation_id,depth,chain_agent_ids,escalate_at)
 VALUES ('$DELEG','$TENANT','tester@example.com','$AGENT',
   '[\"read_file\",\"Read\",\"list_dir\"]',3,'{\"nato\":\"CONFIDENTIAL\"}','{}',
   'manual test',now()+interval '1 hour',false,NULL,'$DELEG',0,'[\"$AGENT\"]',NULL);
 COMMIT;"
```

`set_config` is required in the same transaction: RLS is the only tenant
boundary and the table is `FORCE ROW LEVEL SECURITY`, so even the owner is
subject to the policy. Without it the `INSERT` is rejected by `WITH CHECK`.

Then issue a token. **`ttl_seconds` is required** — omitting it fails with
`ttl_seconds must be positive`:

```bash
export TOKEN=$(grpcurl -plaintext -import-path proto -proto pdp/v1/pdp.proto \
  -d "{\"delegation_id\":\"$DELEG\",\"ttl_seconds\":3600}" \
  "$PDP" stratium.pdp.v1.PDPService/IssueToken \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
echo "token is ${#TOKEN} chars"
```

The token is a *reference* to the delegation, not a snapshot — the PDP loads it
fresh on every decision, so a later change to the cap or the rules takes effect
on the next call without re-issuing.

### B3 — Read the right field

**This is the step most likely to make a working system look broken.**

`Effect`'s zero value is `EFFECT_DENY` and grpcurl omits default-valued fields,
so a denied decision has **no `effect` key at all**. Worse, the top-level
`effect` is DENY on every call below regardless of labelling, because the
compound decision is `principal ∧ agent ∧ delegation` and this tenant has no
principal policies:

```
"principalReason": "principal: no policies configured for this tenant"
```

**Read `delegationEffect` and `delegationReason`.** That is the leg
classification caps are evaluated on, and treating an absent `delegationEffect`
as DENY is correct.

### B4 — Run decisions

Run from the repository root — the `-proto` path is relative to it. `raw_input`
is a JSON *string* containing JSON, so build it with a tool rather than by
hand-escaping quotes:

```bash
decide() {  # decide <path> [tool] [extra-resource-json]
  python3 - "$1" "${2:-read_file}" "${3:-{\}}" <<'PY' \
  | grpcurl -plaintext -import-path proto -proto pdp/v1/pdp.proto -d @ \
      "$PDP" stratium.pdp.v1.PDPService/Decide
import json, os, sys
path, tool, extra = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
print(json.dumps({
    "agent_id": os.environ["AGENT"], "subject": "tester@example.com",
    "tool": tool, "raw_input": json.dumps({"path": path}),
    "resource": extra, "token": os.environ["TOKEN"],
}))
PY
}
show() { decide "$@" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print(d.get("delegationEffect","EFFECT_DENY"), "|", d.get("delegationReason",""))'; }
```

| Command | Observed | Why |
|---|---|---|
| `show /exports/report.csv` | `EFFECT_DENY` — `resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)` | `/exports/` matches; SECRET > CONFIDENTIAL |
| `show /exports/public/notice.txt` | `EFFECT_ALLOW` | Longest prefix wins *even though it lowers* — a public file inside a classified directory is genuinely public |
| `show /elsewhere/thing.txt` | `EFFECT_ALLOW` | Falls to the catch-all at UNCLASSIFIED |

### B5 — An unlabelled resource denies

Delete the catch-all, then repeat the third call:

```bash
CATCHALL=$(curl -sS -H "Authorization: Bearer $VIEWER" \
  "http://$PAP/v1/resource-label-rules" \
  | python3 -c 'import json,sys; print([r["id"] for r in json.load(sys.stdin) if r["prefix"]==""][0])')
curl -sS -o /dev/null -w 'admin DELETE -> %{http_code}\n' \
  -X DELETE "http://$PAP/v1/resource-label-rules/$CATCHALL" \
  -H "Authorization: Bearer $ADMIN"     # 204
show /nowhere/thing.txt
```

**Expect `delegationEffect` = `EFFECT_DENY`** — `resource declares no classification; the delegation's
classification cap cannot be evaluated and therefore denies`.

This is the cliff. A cap with no catch-all denies every unmatched resource.
Re-create the catch-all before continuing.

### B6 — The carve-out log line

```bash
docker compose -f deploy/docker/docker-compose.yml logs pdp-pap | grep carve-out
```

After running `show /exports/public/notice.txt`, expect:

```
resource label carve-out lowers the classification it overrides
```

carrying `rule_prefix`, `rule_hierarchy`, `rule_level`, `overrides_prefix`,
`overrides_hierarchy`, `overrides_level` — and deliberately **no resource id**,
because the id derives from attacker-influenced input while the rules are
operator-authored configuration.

**See D1 before concluding anything from an empty grep.**

---

## Part C — the security properties

### C1 — A caller cannot declare its own classification

```bash
show /exports/report.csv read_file \
  '{"classification":"UNCLASSIFIED","hierarchy":"nato"}'
```

**Expect `delegationEffect` = `EFFECT_DENY`, still `SECRET exceeds … CONFIDENTIAL`.** The PDP discards both
keys unconditionally before resolving. If this ever returns ALLOW, a caller can
declare itself unclassified and walk past every cap.

### C2 — A caller cannot choose *which rule* labels it

The subtler half. Call an **uncatalogued** tool while naming a permissive id:

```bash
show /exports/report.csv Read '{"id":"/exports/public/decoy"}'
```

`raw_input` names the classified path; the wire `resource.id` names a
permissive decoy. `Read` is in the delegation's approved tools (B2) but has no
`tool_catalog` row, which is the case being tested — check `delegationReason`
rather than `effect` alone, so a denial on the wrong leg is not mistaken for a
pass.

**Expect `delegationEffect` = `EFFECT_DENY`** — `resource declares no classification…`, **not** an allow.
`Read` has no catalog row, so the PDP derives no identity and refuses to label
rather than trusting the caller's `id`. An ALLOW here would mean a caller can
pick its own label by naming a decoy.

### C3 — An unrankable label denies

```bash
psqlm -c "BEGIN; SELECT set_config('app.tenant_id','$TENANT',true);
   INSERT INTO resource_label_rules (tenant_id,prefix,hierarchy,level)
   VALUES ('$TENANT','/exports/typo/','natoo','UNCLASSIFIED'); COMMIT;"
show /exports/typo/x
```

Raw SQL is used deliberately here: the API refuses this rule (A3), and the
point is that the *decision path* must also refuse it rather than trusting a
row that bypassed validation.

**Expect `delegationEffect` = `EFFECT_DENY`** — `unknown classification hierarchy "natoo"…`. If this allows,
one mistyped character turns a capped resource into an unconditional allow.
Delete the rule afterwards.

### C4 — The serving role cannot write

```bash
psqlapp -c "BEGIN; SELECT set_config('app.tenant_id','$TENANT',true);
   DELETE FROM resource_label_rules; COMMIT;"
```

**Expect:** `ERROR: permission denied for table resource_label_rules`. The PDP's
role holds `SELECT` and nothing more; the absent grants are the enforcement.

### C5 — RLS is the tenant boundary

```bash
psqlm -tAc "SELECT set_config('app.tenant_id','some-other-tenant',false);
   SELECT count(*) FROM resource_label_rules;"
```

**Expect: `0`.** No Go query filters by `tenant_id` — a structural test now
enforces that — so this returning your rows would mean the boundary is gone.

---

## Part D — traps

These are the four places where correct behaviour looks like a bug, or a bug
looks like correct behaviour. Each was found during development.

### D1 — Grepping for `carve-out` after a *raise* finds nothing

Only three overrides are logged: one that **lowers** within a hierarchy, one
that **switches** hierarchy, and one that **covers an unrankable rule**. An
override that *raises* within one hierarchy is deliberately silent, because it
tightens.

The line is also emitted **per decision, not per write** — so nothing appears
until traffic actually reaches an id under that prefix.

**Finding nothing is not evidence your rule is inert.** To check a raise, or to
check any rule before traffic arrives, read the rule set back with
`GET /v1/resource-label-rules`.

### D2 — The catch-all does not cover a tool with no `resource_field`

A rule labels an *id*. A tool whose catalog row names no resource field
produces no id, so **no rule matches it — not even the empty-prefix one** — and
those calls keep denying under a cap.

This needs `list_dir` in the delegation's approved tools, so re-run B2 with
`"tools":["read_file","Read","list_dir"]` before testing it:

```bash
curl -sS -X POST "http://$PAP/v1/tool-catalog" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"tool_name":"list_dir","action_tier":1,"verb":"read"}'   # no resource_field

show /exports/public/notice.txt list_dir
```

**Expect `delegationEffect` = `EFFECT_DENY`** — `resource declares no classification…` — even though the
catch-all is registered and the path would otherwise resolve to UNCLASSIFIED.
The path in `raw_input` is irrelevant here: with no `resource_field`, nothing
extracts an id from it.

This is not a corner case — most tools have no single unambiguous resource
argument, and the shipped seed leaves `Glob`, `Grep`, `WebFetch` and
`WebSearch` fieldless on purpose. Before concluding the cliff is closed, walk
the delegation's approved tools and check each catalog row.

### D3 — Revoking and re-issuing removes the cap entirely

Because nothing can set a cap through the API, a re-issued delegation comes
back with an **empty** cap map — and an empty map is not a low cap. The check
allows immediately when no cap is configured.

So revoke-and-re-issue is a way to *stop* a capped delegation, never a way to
adjust one. Verify after any re-issue:

```bash
psqlm -tAc "SELECT set_config('app.tenant_id','$TENANT',false);
   SELECT id, classification_caps FROM delegations ORDER BY created_at DESC LIMIT 3;"
```

### D4 — `/data` matches `/database/x`

Matching is plain string prefix, with no separator vocabulary. `/data` matches
`/database/x`, which is almost never what an operator means.

**Write the trailing separator** — `/data/` — unless you intend the broader
match. To see the hazard rather than just read it, register a rule missing its
separator and call a path the operator never meant to cover:

```bash
mkrule "/exp" nato TOP-SECRET      # meant "/exports/", forgot the slash
show /expenses/q3.csv             # a different directory entirely
```

**Expect `delegationEffect` = `EFFECT_DENY`** — `TOP-SECRET exceeds … CONFIDENTIAL`. `/exp` is a prefix of
`/expenses/q3.csv` and is longer than the catch-all, so an unrelated directory
inherits a classification nobody assigned it. Nothing warns about this; the
rule is valid and behaves exactly as specified.

Delete the rule afterwards, or later steps will inherit it.

---

## What this plan does not test

- **Anything reached through a PEP.** These calls go straight to the PDP. The
  `proxy` and `extauthz` surfaces additionally require DPoP-bound tokens.
- **Cache invalidation end to end.** A5 proves the epoch bumps; proving a PEP
  drops its cached decision needs a PEP in the path.
- **Policy engines seeing the label.** The classification and hierarchy reach
  Rego and Cedar policy input, but exercising that needs a tenant policy that
  reads them.
- **Multi-hierarchy tenants.** Every step above uses `nato`. A tenant running
  `nato` and `commercial` side by side has a case worth its own pass: a
  carve-out that *switches* hierarchy escapes the outer hierarchy's cap
  entirely, which is logged as its own line and is not a lowering.

## Cleaning up

```bash
docker compose -f deploy/docker/docker-compose.yml down -v --remove-orphans
```

The tenant used here is the same one `make integration` uses, and that target
starts by destroying volumes — so leftover manual state cannot corrupt a later
automated run, and vice versa.
