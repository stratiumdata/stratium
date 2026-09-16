# containment — the admin plane, not the enforcement path

Every other directory here puts Stratium in front of a tool call and asks
*does this go through?* This one never makes a tool call. It asks the admin
plane a question no enforcement surface can answer:

> does this **change** let an agent do anything it could not do before?

No model, no PEP, no delegation minted. Just `stratium-pap`, a Keycloak token,
and two routes.

## Running it

```bash
cd example
export EXAMPLE_CONTAINMENT_PAP_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"
export EXAMPLE_KC_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port keycloak 8080 | sed -E 's/.*://')"
go run ./containment
```

You need the **whole** compose stack up (`docker compose ... up -d --wait`), not
just `stratium-pap`. A PAP whose database has no schema still accepts TCP
connections, so the dial probe passes and every read then returns 500 — which
reads exactly like a bug in the route you are testing. The program checks one
pre-existing route before doing anything else and tells you which it is.

## What it proves

**1. `contained: false` means two different things.**

The endpoint is `permset.Contains`, and `Contains` answers the *delegation*
question — "may a **child** hold this?" — not the grant-diff question "did this
get wider?" Those differ, on exactly the case an operator is most likely to try:

```
add a classification cap  (caps: {} → {"nato":"SECRET"})
  contained: false
  reason:    child caps hierarchy nato which parent does not cap
```

Adding a cap **narrows** a grant — an absent cap means *unrestricted*. The
refusal is not a widening claim; it is a deliberate shape rule, because a
child's dimensions must be derivable from its parent's fixed set (spec §4.3.1).
Act 1 puts that next to a genuine widening:

```
empty the tool allowlist  ([Read Write] → [])
  contained: false
  reason:    child has no tool restriction while parent restricts tools
```

Identical status, opposite meanings. **Read the reason, never the boolean
alone.**

`internal/store.containmentReason` asks the other question for agent-grant
writes, and has to pre-fill the before-value to get it. That adapter is not
reachable through this endpoint; a named `permset` operation for it — pure
lattice containment, no shape rules — is recorded as follow-up work.

**2. The union of two contained siblings is itself contained.**

`docs/architecture.md` §19 says two root delegations, "one reaching `/secret`
and one reaching `EXTERNAL_COMMS`", are individually in bounds and jointly an
exfiltration path. Both halves are true. It does **not** follow that a
containment check catches it, and Act 2 runs that exact shape against the live
server to show it does not:

```
sibling A (read, SECRET)   vs the principal's ceiling → contained
sibling B (bash, tier 3)   vs the principal's ceiling → contained
their UNION                vs the principal's ceiling → contained
```

Always, by construction: a union of sets below a ceiling is below that ceiling.
So the sibling risk is a **composition** property, not a permission one — which
is why `GET /v1/principals/{id}/effective` reports instead of enforcing, and
why the principal ceiling listed as future work would not catch this class
either.

**3. `delegations_counted` is load-bearing.**

An empty `approved_tools` means *unrestricted* everywhere else in Stratium, so a
principal holding nothing and a principal holding everything serialize
identically. The count is the only thing that tells them apart.

## Every expectation here is asserted

If the engine's answer stops matching what the prose claims, the program fails
loudly rather than printing a story that is no longer true. That is not
decoration: **the first draft of Act 1 was written from intuition and was wrong
on its very first case**, and this is what caught it. Act 2's lesson was
rewritten for the same reason, after the live server disagreed with the
design note.

If you change `permset` and this example starts failing, read the failure before
editing the expectation — it is telling you the documentation is now wrong.
