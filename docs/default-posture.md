# A default posture

Every tool call is denied until a session is started and a policy permits it.
That is correct behaviour and a brutal first hour, because the question it
leaves you with — *what should I actually set?* — has until now been answered
only by a 1700-line reference where every field is documented and none is
recommended.

This is the recommendation. Three postures, what to change between them, and
the two decisions that are easy to get wrong in a direction that looks fine.

Reference for every field: [`user-guide.md`](user-guide.md) §5. The reasoning
behind the model: [`concepts.md`](concepts.md).

---

## 1. Start here

For a first real agent — one doing development work on a machine you control,
against data you would not mind an engineer reading:

| What | Set it to | Why |
|---|---|---|
| Agent `trust_tier` | `3` (`PLATFORM_TRUSTED`) | Anything less silently caps the agent below what its delegation says. §3. |
| Agent `allowed_tools` | `[]` | Unrestricted at the agent layer; let the delegation be the single tool gate while you are learning the system. Tighten in §2. |
| Agent `enabled` / `suspended` | `true` / `false` | `suspended` is your kill switch — reversible, fleet-wide, effective on the next call. |
| Classification caps | **none** | The single most consequential default here. §4. |
| Delegation `max_action_tier` | The lowest tier that lets the agent finish its work — start at `1` (`READ_ONLY`) and raise it when something denies | The ceiling no policy can raise. Raising it later costs one command; starting high costs you the habit. |
| Delegation `approved_tools` | An explicit list. Never empty. | An empty list means **unrestricted**, everywhere in this system. |
| Delegation `escalate_at` | unset at first; `4` once the agent needs `DESTRUCTIVE` | §5. |
| Delegation TTL | One working session — an hour or two | A delegation is the blast radius of a compromised agent host, measured in time. |
| Policy | One permit for the principal, narrowed later | Without a policy the delegation cannot be issued at all: `session-start` fails with *"none of the requested tools are held by this principal"*. |

That posture enforces the tier ceiling, the tool list, and the audit trail from
the first call, and it will not deny anything you did not ask it to.

---

## 2. Tightening for production

Change these, roughly in this order — each one independently useful, so stop
wherever the friction stops being worth it:

1. **Populate the agent's `allowed_tools`.** Until you do, an agent that
   somehow obtains a wider delegation gets the wider tool set with it. This is
   the cheapest defence-in-depth available.
2. **Drop `max_action_tier` to the lowest tier that works,** per agent rather
   than per fleet. Most agents never legitimately need tier 4.
3. **Shorten the TTL** to the shortest that does not force a re-auth mid-task.
4. **Narrow the policy** from a blanket permit to the actual principals, tools,
   and tiers.
5. **Lower `trust_tier`** to the minimum the agent's real work requires (§3).
   Do this last: it is the one that produces the most confusing denials, because
   the delegation will look correct in every listing.

---

## 3. Trust tier: set it to what the agent needs, not to what it is

An agent's trust tier is a **floor the delegation cannot lift**. Both checks
apply and neither substitutes for the other, so an agent below the floor is
denied while its delegation still reads as though the action were permitted.

| The agent legitimately needs to | Minimum `trust_tier` |
|---|---|
| Read files, search, plan | `0` `UNVERIFIED` |
| Edit files, commit | `1` `REGISTERED` |
| `curl`, `git push`, any cloud CLI | `2` `CERTIFIED` |
| `rm -rf`, `DROP TABLE`, `terraform destroy` | `3` `PLATFORM_TRUSTED` |

The recommendation to start at `3` in §1 is not a claim that every agent
deserves it. It is a claim that you should meet one denial mechanism at a time,
and the trust floor is the least legible of them.

Two things to know before you lower it:

- The bar for each tier is **your** process, not a system-verified fact. There
  is no attestation; the tier records a decision a human made. Enforcement of
  that decision is real, the establishment of it is yours.
- The threshold that bites first is usually `EXTERNAL_COMMS` at `CERTIFIED` —
  it catches `curl http://localhost:3000/health` and `git push` alike.

---

## 4. Classification caps: the decision that is easy to get wrong

**Do not set a classification cap on an agent whose toolkit includes any tool
that declares no resource field.** With a cap configured, those tools deny
*every* call, permanently, and no operator action clears it.

The five that ship this way in Claude Code's catalog:

    Glob    Grep    WebFetch    WebSearch    TodoWrite

`Bash` used to be the sixth and the most consequential. It no longer is: a tool
catalogued with a `command_field` now derives its identity from every path its
command names, and the strictest resulting label decides — so caps and shell
access can coexist. Two caveats that matter operationally:

- **A command naming no path still denies.** `npm test`, `echo hi`, `git status`
  identify no resource, so under a cap they are back in the case above.
- **A shell command still cannot satisfy a `resource_constraint`.** No `id` is
  written for a command-derived resource, deliberately, so a decoy path cannot
  satisfy a constraint while another path does the work.

This is not a misconfiguration you can fix with a better rule. The documented
remedy for an unlabelled resource — an empty-prefix catch-all — cannot reach
these tools: labelling returns before any rule is consulted when there is no
resource id to resolve
(`services/internal/pdpgrpc/label.go:85`). The caps API will list the affected
tools back to you in its response; read that list.

> **A worked example, from this repository.** `deploy/stratium up` grants
> `Read,Grep,Glob` and caps the agent at `nato: CONFIDENTIAL` in the same run.
> Two of those three tools are dead from that moment. The quickstart's own §10
> warns about exactly this, one page after doing it.

**So caps are usable when**, and only when, every tool the delegation grants
declares a `resource_field`. That is a real configuration — a document-retrieval
agent, an MCP filesystem server, an API gated through Envoy — and for those it
works exactly as intended.

**Before setting any cap**, register an empty-prefix catch-all rule. With a cap
set, an unresolvable label denies, so a cap without a catch-all denies nearly
everything. The API enforces this: it returns `409` unless a catch-all exists
or you pass `?allow_uncovered=true`.

Related: [`validation-journeys.md`](validation-journeys.md) J1 and §6, which
covers what this restriction means for the product's honest scope, and the
change that would lift it.

---

## 5. Escalation: the pressure valve, and when to fit it

A misclassified command has exactly two remedies, because tier overrides may
only ever raise a tier and a positive destructive match is never lowered:
**raise the ceiling** (weakens every other action at that tier) or **escalate**
(a human approves, every occurrence).

So `escalate_at` is what lets you grant tier 4 without granting it unattended:

    max_action_tier: 4, escalate_at: 4

means everything up to `EXTERNAL_COMMS` proceeds, and anything `DESTRUCTIVE`
waits for a person. Set it the moment an agent needs destructive operations at
all, because the tier is coarse: `rm -rf ./node_modules` and `rm -rf /` are the
same tier and require the same trust, so the routine case and the catastrophic
one arrive on the same permission.

Two constraints on where this works:

- **Only `hook` and `mcp` can block on a human.** `extauthz` and `proxy`
  degrade to a denial carrying an approval id, because the credential they
  would wait with does not outlive the wait. A blocking approval flow on those
  surfaces is client-side work you have to build.
- **An unattended agent has nobody to approve.** For overnight or CI runs,
  either keep the ceiling below the escalation band or accept that the run
  stops there.

---

## 6. What this posture does not defend against

Stated plainly, so it is not discovered later:

- **A capable agent routes around a denial.** `rm -rf node_modules` denies at
  tier 4; `find . -name node_modules -delete` is `READ_ONLY` and proceeds. The
  classifier is a heuristic and says so in its own source. The controls that
  actually hold are the ceiling, the tool list, and escalation — not the
  classifier.
- **Nothing here constrains *what* an action touches**, only how dangerous the
  action is. Resource constraints exist and are enforced, but no supported API
  can set them.
- **Raw tool inputs are never stored.** The audit chain proves which agent was
  allowed which tool at which tier, never what the command was.

None of these are reasons not to deploy. They are the shape of what you get.

---

## See also

- [`quickstart.md`](quickstart.md) — a working stack in ten minutes
- [`user-guide.md`](user-guide.md) §5 — every field, every route
- [`validation-journeys.md`](validation-journeys.md) — what still needs proving
- [`concepts.md`](concepts.md) — why the model is shaped this way
