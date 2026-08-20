# Manual test plan — resource labelling

How to exercise per-tenant resource classification labelling by hand, against a
real stack, in the state the feature is in today.

**Every step below was executed end to end against a live stack on 2026-08-19.**
The output shown under each step is what was actually observed, not what the
code suggests should happen — where the two disagreed, the observed behaviour
won, and five commands in an earlier draft were wrong as a result. Each surprise
worth knowing is flagged inline.

Ids, ports and tokens will differ on your run. Everything else should match
character for character.

There is a pass/fail checklist at the end.

---

## What you can test, and the one thing you cannot

The feature lets an operator register per-tenant rules mapping a **resource-id
prefix** to a `(hierarchy, level)` classification. At decision time the PDP
resolves a resource's label by **longest matching prefix** and hands it to the
delegation's classification cap check.

**Everything on the labelling side is reachable through the admin plane.**

**The cap itself is not.** Nothing in the API sets, raises, lowers, or repairs a
delegation's `classification_caps`: issuance writes an empty map on every root
delegation, children copy their parent's map unchanged, and the create RPC
carries no field for one. So **Part B requires one direct SQL write** to reach
the enforcement path at all — the project's own integration fixtures do the same
thing for the same reason.

That gap is recorded in the spec's open items, not hidden. Part D covers what it
means in practice, including a trap that silently disables enforcement.

---

## 0. Bring up a stack

From the repository root:

```bash
docker compose -f deploy/docker/docker-compose.yml up -d --build --wait --wait-timeout 300
```

**Expected:** every service reaches `Healthy`, ending with lines like

```
 ✔ Container docker-keycloak-1 Healthy
 ✔ Container docker-pdp-pap-1 Healthy
 ✔ Container docker-stratium-pap-1 Healthy
```

**PASS if** the command exits 0. **If `postgres` exits 1**, check the logs before
retrying — `initdb: could not create directory … No space left on device` means
the Docker disk is full, not that anything is broken. See "If the stack will not
start" at the end.

Resolve the ports — they are ephemeral, so read them rather than assuming:

```bash
dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }   # a function, not a variable
export PAP="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"
export PDP="localhost:$(dc port pdp-pap 50051 | sed -E 's/.*://')"
export KC="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"
export TENANT=tenant-pap-e2e-integration
echo "PAP=$PAP  PDP=$PDP  KC=$KC"
```

**Expected** — three `localhost:` addresses with **non-empty** port numbers:

```
PAP=localhost:60903  PDP=localhost:60889  KC=localhost:60885
```

**PASS if** all three have a port. A trailing bare `localhost:` means `dc` did
not run.

> `dc` is a function deliberately. Putting the command in a *variable* and
> calling `$C port …` fails — the shell looks for a single command whose name is
> the whole string. That was one of the five wrong commands.

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

---

## 1. Get operator tokens

The realm is `stratium`, the client is `stratium-pap` (public, direct access
grants enabled).

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
echo "editor=${#EDITOR} viewer=${#VIEWER} admin=${#ADMIN} chars"
```

**Expected** — three tokens around 1,100 characters:

```
editor=1155 viewer=1155 admin=1149 chars
```

**PASS if** all three are over 500 characters. A `0` means the token request
failed; re-check `$KC`.

Sanity check:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/resource-label-rules"
```

**Expected:** `200`

> **These tokens expire after 5 minutes.** The realm sets no
> `accessTokenLifespan`, so Keycloak's 300-second default applies — shorter than
> a hand-paced walk through this plan. A bare `unauthorized` body, or a `401`,
> means the token aged out rather than anything being wrong with the request.
> Re-run the three `export` lines and continue; nothing else needs redoing, and
> rules you already created are unaffected.

---

## Part A — the admin plane

No SQL. This is the whole operator-facing surface of the feature.

### A1 — Register rules and read them back

Valid hierarchies and levels are fixed in the code:

- `nato`: `UNCLASSIFIED`, `RESTRICTED`, `CONFIDENTIAL`, `SECRET`, `TOP-SECRET`
- `commercial`: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL-COMMERCIAL`, `RESTRICTED-COMMERCIAL`, `HIGHLY-CONFIDENTIAL`

```bash
mkrule() {
  curl -sS -w '\n%{http_code}\n' -X POST "http://$PAP/v1/resource-label-rules" \
    -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
    -d "{\"prefix\": \"$1\", \"hierarchy\": \"$2\", \"level\": \"$3\"}"
}

mkrule ""                 nato UNCLASSIFIED   # the catch-all
mkrule "/exports/"        nato SECRET
mkrule "/exports/public/" nato UNCLASSIFIED   # a lowering carve-out
```

**Expected** — three creates, each `201`:

```
{"id":"3bbbf04c-…","tenant_id":"tenant-pap-e2e-integration","prefix":"","hierarchy":"nato","level":"UNCLASSIFIED"}
201
{"id":"66b00420-…","tenant_id":"tenant-pap-e2e-integration","prefix":"/exports/","hierarchy":"nato","level":"SECRET"}
201
{"id":"49246e8b-…","tenant_id":"tenant-pap-e2e-integration","prefix":"/exports/public/","hierarchy":"nato","level":"UNCLASSIFIED"}
201
```

**PASS if** all three return `201` and echo back the rule you sent.

```bash
curl -sS -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/resource-label-rules"
```

**Expected** — three rules, **the empty prefix first**:

```json
[{"prefix":"","hierarchy":"nato","level":"UNCLASSIFIED"},
 {"prefix":"/exports/","hierarchy":"nato","level":"SECRET"},
 {"prefix":"/exports/public/","hierarchy":"nato","level":"UNCLASSIFIED"}]
```

**PASS if** three rules come back ordered by prefix. Ordering is asserted by the
query itself, so a different order is a real regression.

### A2 — A duplicate prefix is refused

```bash
mkrule "/exports/" commercial PUBLIC
```

**Expected:**

```
store: already exists: resource label rule for prefix "/exports/"
409
```

**PASS if** `409`. Note the existing rule is `nato` and this one is
`commercial` — **the different hierarchy does not make it a different rule.**
The key is `UNIQUE (tenant_id, prefix)`, deliberately *not*
`(tenant_id, prefix, hierarchy)`: a resource carries exactly one classification
in one hierarchy, so one prefix under two hierarchies would be a pair no
resource could satisfy, whose only symptom is total silent denial.

### A3 — An invalid level or hierarchy is refused at write time

```bash
mkrule "/typo/" nato SEKRET
mkrule "/typo/" natoo UNCLASSIFIED
```

**Expected** — both `400`, each naming the known values:

```
store: invalid request: level "SEKRET" is not a level of hierarchy "nato" (known: UNCLASSIFIED, RESTRICTED, CONFIDENTIAL, SECRET, TOP-SECRET)
400
store: invalid request: unknown classification hierarchy "natoo" (known: commercial, nato)
400
```

**PASS if** both are `400` **and** the message enumerates the valid values — an
error that only says "invalid" would leave an operator guessing.

**Note what is *not* validated: the prefix.** A typo there is accepted and
produces a rule that silently never matches anything. It is the one field
nothing can check, since any string is a legitimate prefix. See D4.

### A4 — Role gating

```bash
curl -sS -o /dev/null -w 'viewer POST   -> %{http_code}\n' \
  -X POST "http://$PAP/v1/resource-label-rules" \
  -H "Authorization: Bearer $VIEWER" -H 'Content-Type: application/json' \
  -d '{"prefix":"/nope/","hierarchy":"nato","level":"SECRET"}'

RULE_ID=$(curl -sS -H "Authorization: Bearer $VIEWER" \
  "http://$PAP/v1/resource-label-rules" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
curl -sS -o /dev/null -w 'editor DELETE -> %{http_code}\n' \
  -X DELETE "http://$PAP/v1/resource-label-rules/$RULE_ID" \
  -H "Authorization: Bearer $EDITOR"
```

**Expected:**

```
viewer POST   -> 403
editor DELETE -> 403
```

**PASS if** both are `403`. Create and update are editor; delete is admin.

### A5 — Every write bumps the tenant epoch

The epoch is what invalidates a PEP's decision cache. A labelling change that
did not bump it would leave stale authorization decisions in flight.

```bash
epoch() {
  psqlm -tAc "SELECT set_config('app.tenant_id','$TENANT',false);
              SELECT epoch FROM tenant_epoch WHERE tenant_id='$TENANT';" | tail -1
}
P="/probe-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:8])')/"   # unique per run
echo "before: $(epoch)"; mkrule "$P" nato RESTRICTED | tail -1; echo "after:  $(epoch)"
```

**Expected** — a `201` between two values, the second strictly higher (yours
will differ; only the increase matters):

```
before: 4
201
after:  5
```

**PASS if** the create returned `201` **and** the epoch increased. Repeat with a
`PUT` and a `DELETE` if you want all three verbs — the trigger fires on each.

> **The prefix must be unique per run, and the status must be visible.** An
> earlier draft used a fixed `/tmp-probe/` and piped the create to `/dev/null`.
> On a second run that write returns `409`, the epoch correctly does not move,
> and the discarded output leaves you looking at a flat epoch with no
> explanation — reading a working trigger as a broken one. Measured on a
> re-run: `before: 7 / after: 7`.

---

## Part B — the decision path

### B1 — Seed an agent and a catalogued tool

```bash
export AGENT=$(curl -sS -X POST "http://$PAP/v1/agents" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"manual-test-agent","provider":"anthropic","model_id":"claude",
       "trust_tier":3,"enabled":true,"suspended":false,"allowed_tools":[]}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "AGENT=$AGENT"

curl -sS -w '\n%{http_code}\n' -X POST "http://$PAP/v1/tool-catalog" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"tool_name":"read_file","action_tier":1,"verb":"read","resource_field":"path"}'
```

**Expected:**

```
AGENT=4eced803-d8bd-4a51-8e2c-4d846b47a189
{"id":"9cd10261-…","tenant_id":"tenant-pap-e2e-integration","tool_name":"read_file","action_tier":1,"verb":"read","resource_field":"path"}
201
```

**PASS if** `$AGENT` is a UUID and the catalog create returns `201` **with
`resource_field` echoed back**. An empty `AGENT` here breaks every later step.

> **On a second run the catalog create returns `409`**, since `read_file` is
> already catalogued and there is no delete route for catalog entries. That is
> harmless — confirm the existing row is right and carry on:
>
> ```bash
> curl -sS -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/tool-catalog" \
>   | python3 -c 'import json,sys
> for e in json.load(sys.stdin): print(e["tool_name"], "| resource_field:", e.get("resource_field","(none)"))'
> ```
>
> ```
> read_file | resource_field: path
> ```
>
> The agent, by contrast, needs a fresh `name` on each run — `UNIQUE
> (tenant_id, name)` applies there too.

**`resource_field` is the load-bearing part.** It names which field of the
call's `raw_input` is the resource identity. A tool whose row names none
produces no resource id, and therefore gets no label at all — see D2.

### B2 — Seed a delegation, with its cap, in one step

**`CreateDelegation` over gRPC will not work here.** A root delegation is
clamped by what the *principal* holds, so with no principal policy configured
for this tenant it fails:

```
ERROR:
  Code: PermissionDenied
  Message: none of the requested tools are held by this principal
```

The project's own integration fixtures do not use that RPC either — they insert
the row. Do the same, and put the cap in the same statement, since no route can
add one later.

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

**Expected** — the `set_config` echo, then silence. **No `ERROR:` line:**

```
         set_config
----------------------------
 tenant-pap-e2e-integration
(1 row)
```

**PASS if** no error appears. `set_config` is required in the same transaction:
RLS is the only tenant boundary and the table is `FORCE ROW LEVEL SECURITY`, so
even the owner is subject to the policy — without it the `INSERT` is rejected by
`WITH CHECK`.

Then issue a token. **`ttl_seconds` is required** — omitting it fails with
`ttl_seconds must be positive`:

```bash
export TOKEN=$(grpcurl -plaintext -import-path proto -proto pdp/v1/pdp.proto \
  -d "{\"delegation_id\":\"$DELEG\",\"ttl_seconds\":3600}" \
  "$PDP" stratium.pdp.v1.PDPService/IssueToken \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
echo "token is ${#TOKEN} chars"
```

**Expected:**

```
token is 346 chars
```

**PASS if** the token is a few hundred characters. `0` means the RPC errored.

The token is a *reference* to the delegation, not a snapshot — the PDP loads it
fresh on every decision, so later changes to the cap or the rules take effect on
the next call without re-issuing.

### B3 — Read the right field

**This is the step most likely to make a working system look broken.**

`Effect`'s zero value is `EFFECT_DENY` and grpcurl omits default-valued fields,
so a denied decision has **no `effect` key at all**. Worse, the top-level
`effect` is DENY on *every* call below regardless of labelling, because the
decision is `principal ∧ agent ∧ delegation` and this tenant has no principal
policies. A full response looks like:

```json
{
  "derivedTier": 1,
  "principalReason": "principal: no policies configured for this tenant",
  "agentEffect": "EFFECT_ALLOW",
  "delegationEffect": "EFFECT_ALLOW",
  "deniedLeg": "principal",
  "reason": "principal: no policies configured for this tenant",
  "epoch": "7"
}
```

That response is a **pass** for labelling purposes: `delegationEffect` is
`EFFECT_ALLOW`. **Read `delegationEffect` and `delegationReason`** — the leg
classification caps are evaluated on. Treating an absent `delegationEffect` as
DENY is correct.

### B4 — Run decisions

Run from the repository root — the `-proto` path is relative to it.

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

for p in /exports/report.csv /exports/public/notice.txt /elsewhere/thing.txt; do
  printf '%-30s ' "$p"; show "$p"
done
```

**Expected** — exactly these three lines:

```
/exports/report.csv            EFFECT_DENY | resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
/exports/public/notice.txt     EFFECT_ALLOW |
/elsewhere/thing.txt           EFFECT_ALLOW |
```

**PASS if** all three match. Each proves something different:

| Line | Proves |
|---|---|
| 1 denies | The label is resolved and the cap is enforced — `/exports/` matches, SECRET > CONFIDENTIAL |
| 2 allows | **Longest prefix wins even when it lowers.** A public file inside a classified directory is genuinely public |
| 3 allows | The empty-prefix catch-all covers everything unmatched |

**If line 2 denies**, longest-prefix resolution is broken and the shorter rule
is winning — the single most important behaviour in the feature.

### B5 — An unlabelled resource denies

```bash
CATCHALL=$(curl -sS -H "Authorization: Bearer $VIEWER" \
  "http://$PAP/v1/resource-label-rules" \
  | python3 -c 'import json,sys; print([r["id"] for r in json.load(sys.stdin) if r["prefix"]==""][0])')
curl -sS -o /dev/null -w 'admin DELETE -> %{http_code}\n' \
  -X DELETE "http://$PAP/v1/resource-label-rules/$CATCHALL" \
  -H "Authorization: Bearer $ADMIN"
show /nowhere/thing.txt
```

**Expected:**

```
admin DELETE -> 204
EFFECT_DENY | resource declares no classification; the delegation's classification cap cannot be evaluated and therefore denies (depth 0)
```

**PASS if** the delete is `204` and the decision now denies where it allowed in
B4. **This is the cliff**: a cap with no catch-all denies every unmatched
resource. Correct behaviour that will read as an outage.

**Re-create the catch-all before continuing:** `mkrule "" nato UNCLASSIFIED`

### B6 — The carve-out log line

```bash
show /exports/public/notice.txt >/dev/null      # generate one
dc logs pdp-pap | grep carve-out | tail -1
```

**Expected** — one `INFO` line naming **both** rules:

```
pdp-pap-1  | time=… level=INFO msg="resource label carve-out lowers the classification it overrides" rule_prefix=/exports/public/ rule_hierarchy=nato rule_level=UNCLASSIFIED overrides_prefix=/exports/ overrides_hierarchy=nato overrides_level=SECRET
```

**PASS if** the line carries all six `rule_*`/`overrides_*` fields **and no
resource id**. The id derives from attacker-influenced input; the rules are
operator-authored configuration, which is why one is logged and the other is
not.

**See D1 before concluding anything from an empty grep.**

---

## Part C — the security properties

These four are the ones to re-run after any change to the decision path. Two of
them were live defects during development.

### C1 — A caller cannot declare its own classification

```bash
show /exports/report.csv read_file '{"classification":"UNCLASSIFIED","hierarchy":"nato"}'
```

**Expected** — identical to B4's first line, as though the wire had said nothing:

```
EFFECT_DENY | resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
```

**PASS if** it still denies on `SECRET`. **An `EFFECT_ALLOW` here is a privilege
escalation** — it would mean any token holder can declare itself unclassified
and walk past every cap.

### C2 — A caller cannot choose *which rule* labels it

The subtler half: `raw_input` names the classified path while the wire
`resource.id` names a permissive decoy, on an **uncatalogued** tool.

```bash
show /exports/report.csv Read '{"id":"/exports/public/decoy"}'
```

**Expected:**

```
EFFECT_DENY | resource declares no classification; the delegation's classification cap cannot be evaluated and therefore denies (depth 0)
```

**PASS if** it denies **for that reason**. `Read` has no catalog row, so the PDP
derives no identity and refuses to label rather than trusting the caller's `id`.

Read the reason, not just the effect: a denial naming `SECRET exceeds…` would
mean something else denied it and this property went untested. **An
`EFFECT_ALLOW` means a caller can pick its own label by naming a decoy.**

### C3 — An unrankable label denies

```bash
psqlm -q -c "BEGIN; SELECT set_config('app.tenant_id','$TENANT',true);
   INSERT INTO resource_label_rules (tenant_id,prefix,hierarchy,level)
   VALUES ('$TENANT','/exports/typo/','natoo','UNCLASSIFIED'); COMMIT;"
show /exports/typo/x
```

Raw SQL is deliberate: the API refuses this rule (A3), and the point is that the
*decision path* must refuse it too rather than trusting a row that bypassed
validation.

**Expected:**

```
EFFECT_DENY | unknown classification hierarchy "natoo"; the delegation's classification cap cannot be evaluated and therefore denies (depth 0)
```

**PASS if** it denies naming the unknown hierarchy. **An `EFFECT_ALLOW` means
one mistyped character turns a capped resource into an unconditional allow.**

Clean up: `psqlm -q -c "BEGIN; SELECT set_config('app.tenant_id','$TENANT',true); DELETE FROM resource_label_rules WHERE prefix='/exports/typo/'; COMMIT;"`

### C4 — The serving role cannot write

```bash
psqlapp -c "BEGIN; SELECT set_config('app.tenant_id','$TENANT',true);
   DELETE FROM resource_label_rules; COMMIT;"
```

**Expected:**

```
ERROR:  permission denied for table resource_label_rules
```

**PASS if** the error appears **and** the rules survive — re-list them to be
sure. The PDP's role holds `SELECT` and nothing more; the absent grants are the
enforcement.

### C5 — RLS is the tenant boundary

```bash
psqlm -tAc "SELECT set_config('app.tenant_id','some-other-tenant',false);
   SELECT count(*) FROM resource_label_rules;"
```

**Expected** — the config echo, then:

```
0
```

**PASS if** the count is `0`. This runs as the table **owner**, so a non-zero
count would mean `FORCE ROW LEVEL SECURITY` is not in effect. No Go query
filters by `tenant_id`; RLS is the only thing scoping reads.

---

## Part D — traps

Four places where correct behaviour looks like a bug, or a bug looks like
correct behaviour. Each was found during development.

### D1 — Grepping for `carve-out` after a *raise* finds nothing

```bash
BEFORE=$(dc logs pdp-pap | grep -c carve-out)
mkrule "/exports/audit/" nato TOP-SECRET >/dev/null
show /exports/audit/x
AFTER=$(dc logs pdp-pap | grep -c carve-out)
echo "carve-out lines before=$BEFORE after=$AFTER"
```

**Expected** — the decision enforces, and the log count is **unchanged**:

```
EFFECT_DENY | resource classification TOP-SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
carve-out lines before=3 after=3
```

**PASS if** the counts are equal. Only three overrides are logged — one that
**lowers** within a hierarchy, one that **switches** hierarchy, one that
**covers an unrankable rule**. A raise within one hierarchy is deliberately
silent because it tightens.

The line is also emitted **per decision, not per write**, so nothing appears
until traffic reaches an id under that prefix. **Finding nothing is not evidence
your rule is inert** — read the rule set back with `GET /v1/resource-label-rules`
instead.

### D2 — The catch-all does not cover a tool with no `resource_field`

```bash
curl -sS -o /dev/null -X POST "http://$PAP/v1/tool-catalog" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"tool_name":"list_dir","action_tier":1,"verb":"read"}'   # no resource_field
show /exports/public/notice.txt list_dir
```

**Expected** — a denial, **with the catch-all still registered** and a path that
would otherwise resolve to UNCLASSIFIED:

```
EFFECT_DENY | resource declares no classification; the delegation's classification cap cannot be evaluated and therefore denies (depth 0)
```

**PASS if** it denies. A rule labels an *id*; a tool naming no resource field
produces no id, so **no rule matches it — not even the empty-prefix one**. The
path in `raw_input` is irrelevant: nothing extracts an id from it.

Not a corner case — most tools have no single unambiguous resource argument, and
the shipped seed leaves `Glob`, `Grep`, `WebFetch` and `WebSearch` fieldless on
purpose. Before concluding the cliff is closed, walk the delegation's approved
tools and check each catalog row.

### D3 — Revoking and re-issuing removes the cap entirely

```bash
psqlm -tAc "SELECT set_config('app.tenant_id','$TENANT',false);
   SELECT id, classification_caps FROM delegations ORDER BY created_at DESC LIMIT 3;"
```

**Expected** — every row you seeded in B2 shows the cap you wrote:

```
7dc1b7b7-…|{"nato": "CONFIDENTIAL"}
48605d6d-…|{"nato": "CONFIDENTIAL"}
```

**PASS if** the caps are there. **You will not see a `{}` row to compare
against, and that absence is the finding** — on this tenant no delegation can
be created through the API at all (B2), so the only rows that exist are ones
written by hand with a cap already in them.

The claim this step exists to convey therefore cannot be demonstrated by
observation here; it is established by reading the code and pinned by three
guard tests:

| Guard | Holds |
|---|---|
| `TestRouteTable_ExposesNoWriteSurfaceForAClassificationCap` | No route writes a cap |
| `TestCreateDelegationRPC_CarriesNoClassificationCapField` | The RPC has no field for one |
| `TestCreateDelegation_RootIsCreatedWithNoClassificationCap` | A root is created with `{}` |

An **empty map is not a low cap** — the check allows immediately when no cap is
configured, so a session re-issued through the API has classification
enforcement switched off entirely on every hierarchy, silently. Revoke-and-
re-issue is a way to *stop* a capped delegation, never to adjust one.

### D4 — `/data` matches `/database/x`

```bash
mkrule "/exp" nato TOP-SECRET >/dev/null    # meant "/exports/", forgot the slash
show /expenses/q3.csv                        # a different directory entirely
```

**Expected:**

```
EFFECT_DENY | resource classification TOP-SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
```

**PASS if** it denies — which is the *hazard*, not a failure. `/exp` is a prefix
of `/expenses/q3.csv` and is longer than the catch-all, so an unrelated
directory inherits a classification nobody assigned it. Matching is plain string
prefix with no separator vocabulary. Nothing warns about this; the rule is valid
and behaves exactly as specified.

**Write the trailing separator** — `/exports/` — unless you intend the broader
match.

Clean up, or later runs inherit it: delete the `/exp` rule via
`DELETE /v1/resource-label-rules/{id}` as admin.

---

## Checklist

| Step | Pass criterion |
|---|---|
| 0 | All services `Healthy`; three non-empty ports |
| 1 | Three tokens; sanity check `200` |
| A1 | Three `201`s; list returns three rules, empty prefix first |
| A2 | `409` on a duplicate prefix in a *different* hierarchy |
| A3 | `400` twice, each naming the valid values |
| A4 | `403` for viewer-create and editor-delete |
| A5 | Epoch strictly increases |
| B1 | Agent UUID; catalog `201` echoing `resource_field` |
| B2 | Insert with no `ERROR:`; token a few hundred chars |
| B4 | Deny / **allow** / allow — the middle one is longest-prefix-lowers |
| B5 | Delete `204`; the previously-allowed path now denies |
| B6 | One INFO line, six rule fields, **no resource id** |
| C1 | Still denies on `SECRET` despite the wire claiming UNCLASSIFIED |
| C2 | Denies with *no classification*, not with *exceeds cap* |
| C3 | Denies naming the unknown hierarchy |
| C4 | `permission denied`; rules survive |
| C5 | Count `0` as the table owner |
| D1 | Carve-out log count unchanged across a raise |
| D2 | Fieldless tool denies with the catch-all present |
| D3 | Seeded delegation has a cap; RPC-created ones have `{}` |
| D4 | `/exp` classifies `/expenses/…` — hazard reproduced |

**The four that matter most** are C1, C2, C3 and B4's middle line. The first
three are security properties whose failure is a privilege escalation; the
fourth is the feature's central behaviour.

---

## What this plan does not test

- **Anything reached through a PEP.** These calls go straight to the PDP; the
  `proxy` and `extauthz` surfaces additionally require DPoP-bound tokens.
- **Cache invalidation end to end.** A5 proves the epoch bumps; proving a PEP
  drops its cached decision needs a PEP in the path.
- **Policy engines seeing the label.** Classification and hierarchy reach Rego
  and Cedar policy input, but exercising that needs a tenant policy reading them.
- **Multi-hierarchy tenants.** Every step above uses `nato`. A tenant running
  `nato` and `commercial` side by side deserves its own pass: a carve-out that
  *switches* hierarchy escapes the outer hierarchy's cap entirely, and is logged
  as its own line rather than as a lowering.

---

## If the stack will not start

`postgres` exiting 1 with `No space left on device` means the Docker disk is
full, not that anything here is broken.

```bash
docker system df           # look at Build Cache
docker builder prune -af   # the safe reclaim
```

**Use `docker builder prune -af` only.** Do not run `docker system prune`, and
never `--volumes`: unused volumes on a shared Docker host may hold another
project's data. Build cache is regenerable; volumes are not.

## Cleaning up

```bash
docker compose -f deploy/docker/docker-compose.yml down -v --remove-orphans
```

`-v` here is scoped to this compose file by `-f`, so it removes only this
project's volume. The tenant used above is the same one `make integration` uses,
and that target destroys volumes before it runs — so leftover manual state
cannot corrupt a later automated run, or the reverse.
