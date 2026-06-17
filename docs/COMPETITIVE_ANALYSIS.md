# Competitive Analysis: Stratium vs. Arcade.dev and P0 Security

**Date:** 2026-06-17
**Author:** Competitive research (market-research pass)
**Scope:** Stratium Agent Gateway vs. the two most-cited "agent authorization" vendors a buyer will surface: **Arcade (arcade.dev)** and **P0 Security (p0.dev)**.
**Method:** Public web research for the competitors (sourced inline + §10); Stratium claims are drawn from the codebase and internal docs (`docs/AGENT_GATEWAY_EXPLAINED.md`, `docs/PRD_OPENAI_AGENT_AUTHORIZATION.md`, proto/service review). Where a claim is inference rather than sourced fact, it is labeled.

> **How to read this doc.** It is an *honest* internal competitive analysis, not a sales battlecard. It includes where each competitor wins and where Stratium is genuinely thin, because the market-research standard requires contrarian evidence and downside cases. A public, partnership-friendly comparison page can be extracted from §3 and §5 later, but should not inherit the candid gap analysis in §6–§8.

---

## 1. Bottom Line Up Front

The three products are sold under the same buzzword — "AI agent authorization" — but sit in **three different centers of gravity**:

| Vendor | What it really is | Authorization depth | Where it's weak |
|---|---|---|---|
| **Arcade** | A **tool-calling runtime + managed-OAuth + 7,500-tool catalog** for production agents. "Ship agents, not auth infrastructure." | **Shallow** — OAuth scope intersection + customer-supplied pre/post hooks. No shipped policy engine. | No agent identity, no delegation chains, no classification, no government story. |
| **P0 Security** | A **cloud PAM / just-in-time-access / IGA consolidation** platform ("Authz Control Plane") that recently extended to agents. | **Medium** — runtime, per-action, MCP-native, blends **agent + invoking user** (2-principal). | 2-principal only (no per-hop chains/trust tiers); no data-centric crypto; no classification/FedRAMP. |
| **Stratium** | A **policy decision plane + data-centric encryption (ZTDF)** with first-class agent identity, multi-hop delegation, and classification. | **Deep** — compound per-hop decision across user + agent + delegation chain, action-tier anti-spoofing, classification caps, decision bound to key-unwrap. | No SaaS tool catalog, no managed OAuth refresh, no free hosted tier; far less funding/traction/mindshare than both rivals. |

**The single sentence:** *Arcade helps an agent safely **do** things; P0 decides at runtime whether an agent-plus-user **may** do a thing; Stratium decides whether a specific agent, under a verifiable delegation chain, at a given trust tier, may do a thing **to data at a given classification** — and binds that decision to the encryption itself.*

**Decision this analysis supports:** Stratium should (a) **stop positioning against Arcade as the primary rival** — Arcade is a partial overlap and a plausible *integration partner*; (b) **treat P0 as the closest decision-layer competitor** and counter-position on delegation-chain depth, classification, and data-binding; and (c) **close two unforced product gaps** (no free hosted evaluation tier; no SaaS tool catalog / managed OAuth) that knock Stratium out of evaluations before the architecture conversation begins.

---

## 2. Category map — where the lines actually sit

```
                        AGENT ACTION ENABLEMENT
                    (tool catalog, OAuth, "just make
                       the agent able to do work")
                                 ▲
                                 │            ●  Arcade
                                 │           (7,500 tools, managed
                                 │            OAuth, MCP runtime;
                                 │            authz = scopes + hooks)
                                 │
   CLOUD PAM / JIT / IGA ◄───────┼───────────────────────────────►  DEEP AGENT AUTHORIZATION
   (human + machine access,      │                                   (identity, delegation,
    access graph, JIT grants)    │                                    classification, trust tiers)
                                 │
              ●  P0 Security      │
            (agentless cloud PAM  │                    ●  Stratium
             extended to agents;  │              (NPE identity + per-hop chains
             agent+user blend)    │               + action tiers + classification
                                 │               + ZTDF data-centric crypto)
                                 ▼
                        DATA-CENTRIC ENFORCEMENT
                     (decision bound to the data object
                        / key unwrap, not just the API)
```

- **Arcade** lives at the top — its mass is in *enabling* the action (catalog + OAuth). It touches authorization only via a thin hook surface.
- **P0** lives on the left-center — its mass is *cloud PAM/JIT for humans and machines*, recently extended rightward to per-action agent decisions.
- **Stratium** lives at the bottom-right — the only one of the three combining deep agent authorization semantics **and** data-centric (ZTDF) enforcement.

The three overlap meaningfully only in one narrow band: **"intercept an agent's tool call at runtime and return allow/deny."** All three do that. They diverge sharply on *what fills the decision point* and *what else the platform is for*.

---

## 3. Head-to-head capability matrix

Legend: ✅ shipped/core · 🟡 partial/limited · ❌ absent/not public · *(src)* sourced fact · *(inf)* inference

| Capability | Arcade | P0 Security | Stratium |
|---|---|---|---|
| **Primary category** | Tool-calling runtime + OAuth *(src)* | Cloud PAM / JIT / IGA *(src)* | Policy decision plane + ZTDF data crypto *(internal)* |
| **Intercept agent tool call → allow/deny** | ✅ via MCP runtime + hooks *(src)* | ✅ runtime, per-action, MCP-native *(src)* | ✅ Agent Gateway `ExecuteAction` + MCP + hooks *(internal)* |
| **Shipped policy engine** | ❌ scopes + customer hooks *(src)* | 🟡 policy-as-code "Policy Studio," context-based *(src)* | ✅ ABAC engine in 4 languages: JSON / Rego / Cedar / XACML *(internal)* |
| **First-class agent identity (NPE)** | ❌ "agents act as real users" *(src)* | 🟡 agent identity in a 2-party blend *(src)* | ✅ `AgentAttributes` proto: trust_tier, provider, model_id, allowed_tools *(internal)* |
| **Compound / multi-principal decision** | ❌ OAuth scope ∩ only *(src)* | 🟡 **2-principal**: agent + invoking user *(src)* | ✅ **N-principal per-hop**: user + agent + full delegation chain *(internal)* |
| **Multi-hop delegation chains (agent→sub-agent→…)** | ❌ single-hop OAuth delegation *(src)* | ❌ no public evidence *(src)* | ✅ `DelegationContext` (parent/root/depth/chain), `denied_at_depth` *(internal)* |
| **Agent trust tiers as policy attribute** | ❌ *(src)* | ❌ *(inf)* | ✅ Unverified → Registered → Certified → Platform-Trusted *(internal)* |
| **Action-tier sensitivity + anti-spoofing** | ❌ *(src)* | ❌ *(inf)* | ✅ REASONING→DESTRUCTIVE tiers; `ValidateActionPlan` detects declared≠actual *(internal)* |
| **Data classification hierarchies (NATO/DoD/Commercial)** | ❌ *(src)* | ❌ *(src)* | ✅ STANAG 4774, hierarchical match, ZTDF URIs *(internal)* |
| **Data-centric encryption (decision bound to key unwrap)** | ❌ *(src)* | ❌ access enforced at API boundary *(src)* | ✅ ZTDF manifests, KAS, KEK/DEK, HSM; same `GetDecision` gates action + unwrap *(internal)* |
| **Real-time / cascade revocation** | 🟡 OAuth-token level *(inf)* | ✅ auto-revoke on task complete *(src)* | ✅ revoke root → cascade to all sub-delegations next action *(internal)* |
| **Pre-built SaaS tool catalog** | ✅ **7,500+ tools / ~81 MCP servers** *(src)* | ❌ (not its model) *(inf)* | ❌ ships authz-domain MCP tools only *(internal)* |
| **Managed OAuth / token vaulting for SaaS APIs** | ✅ core moat; creds never reach LLM *(src)* | 🟡 service-account credential rotation *(src)* | ❌ customer wires their own SaaS OAuth *(internal)* |
| **Cloud PAM / JIT for human users (AWS/GCP/Azure/K8s)** | ❌ *(inf)* | ✅ core product, agentless *(src)* | ❌ not its scope *(internal)* |
| **Identity/access graph discovery** | ❌ *(inf)* | ✅ Access Graph / Identity DNA *(src)* | ❌ *(internal)* |
| **Multi-provider agents (Claude + OpenAI) + cross-vendor chains** | 🟡 framework-agnostic clients *(src)* | 🟡 MCP-native, provider-agnostic *(inf)* | ✅ Claude Code/Desktop + Codex/ChatGPT Desktop; cross-provider delegation chains *(internal)* |
| **Deployment** | SaaS-first; VPC/on-prem; air-gapped *claimed* *(src)* | SaaS control plane + agentless connectors *(src)* | **Self-hosted only** (Docker/K8s); air-gapped supported *(internal)* |
| **Government / defense / classification / FedRAMP** | ❌ none *(src)* | ❌ SOC 2 only, no FedRAMP *(src)* | 🟡 STANAG/NIST 800-207-aligned, ZTDF; FedRAMP not yet certified *(internal)* |
| **Standards pedigree** | ✅ authored MCP "URL Elicitation" SEP w/ Anthropic *(src)* | ❌ consumes MCP, no spec authorship *(src)* | 🟡 STANAG 4774, ZTDF, NIST SP 800-207 lineage *(internal)* |
| **Free / self-serve tier** | ✅ Free Hobby + $25/mo Growth *(src)* | ❌ sales-led, no public pricing *(src)* | ❌ no hosted tier; self-host trial only *(internal)* |
| **Total funding (public)** | **~$72M** ($12M seed '25 + $60M A '26) *(src)* | **~$20M** ($5M seed + $15M A '24) *(src)* | Not public *(internal)* |

---

## 4. The competitors in one paragraph each

### Arcade (arcade.dev)
Founded Feb 2024 in SF by **Alex Salazar** (ex-Okta; founder of Stormpath) and **Sam Partee** (ex-Redis applied-AI). Positions as "the MCP runtime / secure action layer behind every production AI agent." Real moat is **managed OAuth/token vaulting** (credentials never reach the model) plus a **7,500+ tool catalog across ~81 MCP servers**, now embedded in LangChain's LangSmith Fleet (Apr 2026). Authorization is **OAuth scope intersection + customer-supplied pre/post hooks** — explicitly *not* a policy engine (independently confirmed by WorkOS). Agents **inherit the user's identity** ("agents act as real users"), so there is no first-class agent identity, no delegation chains, no trust tiers, no classification. Raised a **$60M Series A on Jun 15, 2026** (SYN Ventures lead; Morgan Stanley + Wipro strategic), on top of a $12M seed — **~$72M total**. Authored the MCP **URL Elicitation** spec with Anthropic. SOC 2 (self-stated); **no government/FedRAMP/classification story**. Free tier + self-serve. **Verdict: a strong action-enablement product and a plausible integration partner, not a deep-authorization competitor.**

### P0 Security (p0.dev)
Founded 2022 in SF by **Shashwat Sehgal** (CEO), **Gergely Danyi** (CTO), and **Nathan Brahms**. Core product is an **agentless cloud PAM / just-in-time-access / IGA consolidation** platform — the "Authz Control Plane" — that replaces standing privileges with ephemeral, scoped grants across AWS/GCP/Azure, Kubernetes, SSH/RDP, and SaaS, fed by an **Identity/Access Graph**. In **Feb 2026 it shipped GA agent authorization**: runtime, per-action, **MCP-native**, blending **agent identity + invoking user + tool authorization + resource entitlements** into a single decision with auto-revocation. This is a genuine 2-principal compound decision — **architecturally the closest of the three to Stratium's decision layer** — but it stops there: **no multi-hop delegation chains, no agent trust tiers, no classification, no data-centric crypto, no FedRAMP/defense story**. Funding **~$20M** ($15M Series A, Sep 2024, **SYN Ventures lead, Zscaler strategic**). SOC 2 Type II; sales-led; named logos include **Splunk, Applied Intuition, Finix, TRM**. **Verdict: the real decision-layer rival — counter-position on chain depth, classification, and data binding.**

### Stratium (internal)
A self-hosted, zero-trust **policy decision plane fused with data-centric encryption (ZTDF)**. The Agent Gateway runs a **three-checkpoint** decision (user clearance → agent trust tier → delegation scope) and returns a **compound, per-hop** decision across the entire delegation chain (`denied_at_depth`, `denied_principal`). Agents are **first-class NPEs** with trust tiers (Unverified→Platform-Trusted), action-tier sensitivity (REASONING→DESTRUCTIVE) with `ValidateActionPlan` anti-spoofing, and classification caps backed by **NATO/DoD + Commercial hierarchies and STANAG 4774**. The same `GetDecision` that authorizes an action also gates the **KAS key-unwrap**, so authorization is bound to the data object, not just the API. Multi-provider (Claude Code/Desktop + OpenAI Codex/ChatGPT Desktop) with **cross-provider delegation chains** and fail-closed enforcement. Ships an ABAC engine in four policy languages. **Deployed by the customer (Docker/K8s), air-gap capable; no SaaS option, no SaaS tool catalog, no managed OAuth refresh.**

---

## 5. The decisive differentiators

### vs. Arcade — *"a hook is not an engine, and a borrowed identity is not an agent."*
1. **Identity model.** Arcade's agents have no independent identity — they wear the user's hat. Every action audits as "the user did it." Stratium's agents are NPEs; the audit answers "*which* agent, under *which* delegation, at *which* depth, capped at *which* classification." At ten agents, Arcade can't tell you which one called the wrong API; Stratium can.
2. **Authorization substance.** Arcade ships the *slot* ("bring your own access-control logic" via hooks); Stratium ships the *engine* (compound ABAC, classification, action tiers). A sophisticated buyer who asks "what is the actual decision engine?" gets pointed back at their own code with Arcade.
3. **Architecturally stackable, not substitutable.** Arcade's pre-execution hook calling Stratium's `GetDecision` is a real integration pattern. Stratium can be the decision authority *above* Arcade's tool catalog. This is a partnership conversation, not a head-to-head — and framing it that way is more credible than claiming Arcade is a direct rival.

### vs. P0 — *"two principals is not a chain, and an API gate is not a data gate."*
1. **Chain depth.** P0's compound decision is a **2-principal blend** (agent + invoking user). The moment a planner agent delegates to a sub-agent that delegates again, P0 has no public per-hop model. Stratium evaluates **the whole chain** and reports the exact principal/depth that denied. Multi-agent systems are where the industry is heading — and that's structurally Stratium's lane.
2. **Trust as a policy attribute.** Stratium can write "*only CERTIFIED+ agents may perform DESTRUCTIVE actions on RESTRICTED resources*" as one policy line. P0 has no agent-trust-tier attribute to evaluate against.
3. **Data-centric enforcement.** P0 enforces at the **access/API boundary** — it grants or revokes access to a system. Stratium binds the decision to the **key unwrap (KAS/ZTDF)** — the data object itself stays encrypted unless the compound decision allows it. For SECRET/sovereign data, this is the difference between "we control the door" and "the data is cryptographically inert without authorization."
4. **Classification & sovereignty.** P0 has no NATO/DoD/classification model and no FedRAMP/defense posture. Stratium's STANAG 4774 + hierarchy matching + air-gapped self-host is *the* differentiator in regulated/sovereign segments P0 cannot enter.

---

## 6. ICP differential — where each one wins

**Arcade wins when the buyer's pain is:**
- "My engineers waste half their time managing OAuth tokens for the SaaS APIs the agent must call."
- "I need a Gmail/Slack/Salesforce/Notion tool catalog that just works for LangChain/Claude/Cursor."
- "I'm shipping a consumer or SMB agent that runs against the user's own Workspace/M365 account."
- "Is there a free tier I can try this afternoon?"

**P0 wins when the buyer's pain is:**
- "I need to kill standing privileges and grant just-in-time, time-boxed access across AWS/GCP/Azure and K8s for humans **and** agents."
- "I want one control plane that consolidates PAM + IGA and shows me an access graph of who/what can reach what."
- "My agents are first-party, running against my own cloud, and I want per-action runtime enforcement tied to the invoking user."

**Stratium wins when the buyer's pain is:**
- "I run multi-agent chains and need per-hop attribution — *who said yes at depth 3, and why.*"
- "My environment has classification levels (NATO, DoD, Commercial confidential) that decisions must respect."
- "I need an agent registry where each agent is a first-class NPE with a lifecycle and an earned trust tier."
- "I have an air-gapped / sovereign deployment requirement — the control plane cannot leave my perimeter."
- "I need data-centric encryption (ZTDF) bound to the same authorization decision as the action plane."
- "I must prove to an auditor that this exact call was within a verifiable delegation from this exact user."

**Nobody wins outright when the buyer wants both ergonomics and depth** — e.g., a regulated enterprise that wants Arcade's OAuth catalog *and* Stratium's compound-decision audit. The honest answer there is **integration** (Arcade tools + Stratium decision plane), not a winner-take-all bake-off.

---

## 7. Where Stratium is genuinely thin (read this before any sales call)

1. **No pre-built SaaS tool catalog.** "I want my agent to act in my company's Slack" reaches Arcade in 30 seconds; with Stratium the customer wires their own integration. **First-order gap for the SaaS-integration segment.**
2. **No managed OAuth refresh / broken-auth handling.** Arcade markets this as a headline feature; Stratium sits *downstream* of the token. For buyers whose pain *is* the OAuth tax, Stratium doesn't solve it.
3. **No free hosted evaluation tier.** Both Arcade (free Hobby) and P0 (sales-led PoC) get evaluators hands-on faster. Stratium's self-host-only default reads as friction and drops it from consideration before the architecture conversation. **Unforced loss in the non-regulated segment.**
4. **Far less funding, traction, and mindshare.** Arcade ~$72M with a this-week $60M round, LangChain Fleet distribution, named bank/Prosus customers, and ~925 GitHub stars. P0 ~$20M with Splunk/Zscaler. Stratium's funding and customer logos are not public here — **the comparison is product/architecture-led, and must not over-claim market traction.**
5. **The competition is consolidating around the same backer.** SYN Ventures funded **both** P0 (2024) and Arcade (2026). A well-capitalized category is forming; Stratium's depth advantage has a finite window before rivals build toward it.
6. **The "agents act as real users" story is easier to tell.** It's wrong for compound-decision buyers but intuitive in a tweet. Stratium wins the architecture review; it loses the elevator pitch unless the NPE/delegation framing is made crisp.

---

## 8. Where the competitors are thin (counter-position fuel)

- **Arcade:** authorization is a hook, not an engine; no multi-agent/delegation story; no classification; SaaS-only control plane is a non-starter for air-gapped buyers.
- **P0:** 2-principal ceiling (no per-hop chains, no trust tiers); enforces at the API boundary, not the data object (no cryptographic binding); no classification/sovereignty/FedRAMP; lightly funded (~$20M, Series A ~21 months stale) with minimal OSS mindshare; "first-party agents" framing implies no cross-org/third-party agent trust model.

---

## 9. Recommendations

1. **Re-rank the threat model.** Treat **P0 as the primary decision-layer competitor** and Arcade as a **partial overlap / integration partner**. The current internal posture over-weights Arcade.
2. **Ship two counter-positioning artifacts** grounded in primitives the rivals lack:
   - *"The Agent Identity Gap"* — why agents that borrow user identity can't be audited at scale (aimed at Arcade's model and P0's 2-principal ceiling).
   - *"Two Principals Aren't a Chain"* — a worked delegation-chain walkthrough (planner→researcher→tool) showing `denied_at_depth` attribution that neither rival can produce.
3. **Close the evaluation-funnel gap.** Stand up a **time-boxed hosted sandbox** for evaluation (documented expectation that production goes self-hosted). Arcade's "free to start" is converting evaluators Stratium is structurally locked out of.
4. **Decide the SaaS-catalog question explicitly.** Either (a) publish *"Why Stratium Doesn't Ship a Gmail Tool"* as a deliberate architectural-clarity stance (decision plane, not tool runtime), or (b) partner with Arcade/an integration layer so the catalog gap is answered without owning it. Pick one and say it out loud.
5. **Lead every regulated/sovereign conversation with the two things neither rival has:** classification hierarchies (STANAG/NATO/DoD) and **ZTDF data-centric binding** (decision gates the key unwrap). This is the segment where Stratium is uncontested.
6. **Add a neutral, FUD-free public comparison page** (extracted from §3/§5). Evaluators are already comparing these three; controlling the narrative beats letting them land on a third-party blog.

---

## 10. Risks & caveats

- **Asymmetric sourcing.** Competitor facts are public/sourced; Stratium facts are internal (codebase/docs) and not independently verified by a third party. Treat the matrix as *product-capability* comparison, not validated market performance.
- **No Stratium traction data.** Funding, customers, and deployment counts for Stratium are not established in this analysis. Any GTM conclusion that depends on relative market position is therefore provisional.
- **Fast-moving facts.** Arcade's Series A is two days old (Jun 15, 2026); P0's agent GA is four months old (Feb 2026). Both are actively shipping toward the authorization-depth space — re-validate quarterly. P0 in particular could add delegation depth or classification; that would erode Stratium's clearest moat.
- **Air-gapped claims unverified.** Arcade's air-gapped claim is self-stated and contradicted by an earlier WorkOS write-up; do not concede it without proof.
- **"Closest competitor" is a moving target.** If Arcade's $72M war chest funds a real policy engine, the threat ranking in §9 changes. Monitor Arcade's authorization roadmap, not just its catalog growth.

---

## 11. Sources

**Arcade**
- Arcade homepage & pricing — https://www.arcade.dev/ , https://www.arcade.dev/pricing
- Arcade docs (auth model) — https://docs.arcade.dev/home/auth/how-arcade-helps
- Series A ($60M, Jun 15 2026) — https://finance.yahoo.com/sectors/technology/articles/arcade-raises-60m-become-secure-170500044.html ; https://www.pymnts.com/news/investment-tracker/2026/arcade-raises-60-million-to-control-ai-agents/
- Seed ($12M, Mar 18 2025) — https://www.businesswire.com/news/home/20250318815130/en/Arcade.dev-Scores-%2412M-to-Solve-the-Biggest-Security-Problem-with-AI-Agents
- MCP URL Elicitation SEP — https://www.arcade.dev/blog/https-arcade-dev-blog-mcp-url-elicitation-production-authorization/ ; https://www.businesswire.com/news/home/20251125080912/en/
- LangChain LangSmith Fleet integration — https://blog.langchain.com/arcade-dev-tools-now-in-langsmith-fleet/
- Independent authz analysis — https://workos.com/blog/arcade-vs-workos-agent-authentication-enterprise-auth
- GitHub — https://github.com/ArcadeAI/arcade-mcp

**P0 Security**
- P0 homepage / platform / why-p0 — https://www.p0.dev/ , https://www.p0.dev/platform , https://www.p0.dev/why-p0
- Agent authorization GA (Feb 24 2026) — https://www.businesswire.com/news/home/20260224461833/en/P0-Security-Extends-Its-Authz-Control-Plane-to-Service-Accounts-Workloads-and-AI-Agents
- Identiverse 2026 agentic runtime access control — https://www.01net.it/p0-security-to-showcase-agentic-runtime-access-control-capabilities-at-identiverse-2026/
- Series A ($15M, Sep 10 2024) — https://www.p0.dev/blog/15m-series-a ; https://lsvp.com/company/p0-security/
- Docs — https://docs.p0.dev/
- GitHub — https://github.com/p0-security
- CommonLit case study — https://www.p0.dev/resources/case-study/commonlit

**Stratium (internal)**
- `docs/AGENT_GATEWAY_EXPLAINED.md` — three-checkpoint decision, trust tiers, delegation chains, cascade revocation, multi-provider.
- `docs/PRD_OPENAI_AGENT_AUTHORIZATION.md` — multi-provider (Claude + OpenAI) architecture, cross-provider delegation chains, fail-closed, PAP REST.
- Proto/service review (prior pass) — `AgentAttributes`, `DelegationContext`, `CompoundDecision`, `ActionTier`, `ValidateActionPlan`, KAS/ZTDF binding, ABAC engine (JSON/Rego/Cedar/XACML).
```
