# PRD: MI9 Gap Closure — Runtime Governance for Agent Authorization

**Status:** Draft
**Author:** Benjamin Parrish
**Date:** 2026-04-01
**Reference Paper:** MI9: An Integrated Runtime Governance Framework for Agentic AI (arXiv:2508.03858)
**Depends On:** `PRD_AGENT_AUTHORIZATION.md` (Phase 1), `PRD_TRACE_GAPS.md` (Phase 2)
**Feature Flag:** `agent-runtime-governance`

---

## Background

MI9 (Wang et al., Barclays, 2025) is a runtime governance framework for agentic AI systems
organized around six components: Agency-Risk Index (ARI), Agentic Telemetry Schema (ATS),
Continuous Authorization Monitoring (CAM), Real-Time Conformance Engine (FSM), Behavioral
Drift Detection, and Graduated Containment & Escalation.

A gap analysis against Stratium's current agent authorization implementation (Phase 1) and
planned enhancements (Phase 2 / TRACE gaps) reveals that the two systems operate from
fundamentally different design premises:

> **Stratium** evaluates authorization at the boundary — per-action, at request time,
> against a fixed delegation scope minted at session start.
>
> **MI9** evaluates authorization continuously — against a live behavioral model that
> updates as the agent's goals, memory access patterns, and action sequences evolve
> during execution.

This is not a feature gap. It is a different model of what authorization is. This PRD maps
each MI9 component to its Stratium equivalent, quantifies the gap, and proposes concrete
additions organized into three phases.

---

## Gap Summary

| MI9 Component | Stratium Phase 1 Equivalent | Gap Severity |
|---------------|----------------------------|--------------|
| Agency-Risk Index (ARI) | Static 4-tier trust model | **HIGH** — ARI is continuous and runtime-updated; Stratium tiers are frozen at registration |
| Agentic Telemetry Schema (ATS) | `audit_logs` action-level columns | **CRITICAL** — Stratium captures zero cognitive events (goal revision, memory access, plan changes), which MI9 identifies as the primary source of violations |
| Continuous Authorization Monitoring (CAM) | Compound policy at delegation mint time | **HIGH** — Stratium has no mechanism to adapt authorization as agent goals change during execution |
| Real-Time Conformance Engine (FSM) | Per-action OPA policy evaluation | **HIGH** — Stratium evaluates each action in isolation; MI9 detects multi-step temporal patterns and sequential policy violations |
| Behavioral Drift Detection | None (proposed simple rule-based in Phase 2B) | **HIGH** — Stratium has no statistical drift model; proposed Phase 2B volume thresholds cannot distinguish intentional adaptation from misalignment |
| Graduated Containment | Binary allow/deny + full agent suspension | **HIGH** — Stratium has no intermediate containment levels; any response to a violation requires full delegation revocation |

---

## Detailed Gap Analysis

### Gap 1: Agency-Risk Index — Dynamic vs. Static Trust

**What MI9 does:** Computes a normalized score ARI ∈ [0,1] across three dimensions (Autonomy,
Adaptability, Continuity), each comprising four measurable sub-criteria scored 0–3:

- *Autonomy*: multi-step planning capability, goal management scope, resource orchestration
  breadth, decision authority level
- *Adaptability*: strategy evolution, cross-domain performance learning, environmental
  responsiveness, interaction adaptation
- *Continuity*: memory architecture complexity, operational persistence, state complexity,
  knowledge integration

The ARI score places the agent in one of four governance tiers (≤0.25, ≤0.50, ≤0.75, >0.75)
and determines governance intensity. Critically, ARI is computed and can be updated — an
agent that demonstrates escalating autonomous behavior moves to a higher tier.

**What Stratium does:** Assigns one of four static trust tiers (Unverified=0, Registered=1,
Certified=2, PlatformTrusted=3) at registration time, changeable only by admin action via
`PUT /v1/agents/:id`. The tiers map roughly to MI9's Autonomy dimension but have no
equivalent to Adaptability or Continuity. There is no mechanism for trust tier to change
in response to observed runtime behavior.

**The gap:** Stratium's trust tier is a claim about an agent's intended capability profile,
not an observation of its actual runtime behavior. An agent registered as `Registered` (tier 1)
that subsequently exhibits fully autonomous multi-step replanning remains classified as tier 1
indefinitely until a human admin manually intervenes.

**Impact:** The action-tier-to-trust-tier gate in `requiredTrustTierForAction` in
[agent_auth.go](go/services/platform/agent_auth.go) enforces the correct constraint
(a destructive action requires PlatformTrusted), but the trust tier input to that gate is
stale from registration, not derived from observed behavior.

---

### Gap 2: Agentic Telemetry Schema — Cognitive Event Blindness

**What MI9 does:** Defines three categories of governance-semantic events:

- *Cognitive events*: `plan.start`, `plan.revise`, `goal.set`, `goal.revise`, `memory.read`,
  `memory.write`, `strategy.change` — internal reasoning and state transitions
- *Action events*: `tool.invoke`, `api.call`, `auth.request` — environment-facing operations
- *Coordination events*: `agent.msg.send`, `subagent.spawn`, `human.escalate`,
  `delegation.request` — multi-agent and human interactions

The paper explicitly states: *"Traditional infrastructure monitoring captures operational events
but systematically misses the cognitive processes that create governance risks."* In its
evaluation, LangSmith achieved only 68.52% detection vs. MI9's 99.81%, attributed directly
to cognitive event blindness.

**What Stratium does:** Captures action-level audit events only, with agent-specific columns
(`tool_name`, `action_tier`, `execution_mode`, `conversation_id`, chain fields). The audit
log records *what the agent did*, not *what it was thinking when it decided to do it*.

**The gap:** Stratium has no cognitive event concept at all. Goal revisions, memory access
patterns, plan changes, and strategy adaptations are entirely invisible. The Agent Gateway
processes `ExecuteAction` calls but has no instrumentation hook for the LLM reasoning cycles
that produce those calls. This is not a logging gap — it is an architectural observability gap.
The information is not captured at any point.

**Impact:** The behavioral drift detection proposed in Phase 2B (PRD_TRACE_GAPS.md) is built
on `audit_logs` volume patterns — action events only. This means it can detect "the agent made
many more tool calls than usual" but cannot detect "the agent revised its goal five times in
the last 30 seconds" or "the agent is accessing memory stores outside its declared purpose."
MI9's evaluation shows that the majority of governance violations originate at the cognitive
event layer.

---

### Gap 3: Continuous Authorization Monitoring — Static Scope

**What MI9 does:** Extends authorization beyond the session-start permission grant to be
context-dependent, incorporating:

- Agent's current goals and objective state
- Execution history and behavioral patterns from ATS
- Real-time policy evaluation against dynamic context
- Ability to revoke or modify specific permissions *during* execution without full session termination
- Authority matrices specifying who may delegate which permissions, preventing arbitrary self-escalation
- Default-deny for tier-elevating goal transitions

MI9's example: *"A trading agent cleared for small retail trades could escalate to multi-million
dollar institutional transactions, all while operating within its static, original permissions."*
CAM addresses this by continuously asking whether the current authorization context still
matches the agent's current goal.

**What Stratium does:** The compound policy evaluation (user + agent + delegation) happens at
`ExecuteAction` time against the scopes encoded in the delegation token minted at session start.
The delegation token is immutable — its `max_action_tier`, `approved_tools`, and
`classification_caps` cannot change without revoking the delegation and minting a new one.
`ScopeNarrows()` enforces narrowing at child delegation creation, which is correct, but once
a delegation is live, its scope does not adapt.

**The gap:** Stratium cannot answer the authorization question MI9 considers primary: *"Given
that this agent's goal has changed since the delegation was issued, does the original scope
still apply?"* There is no mechanism to narrow permissions on a running delegation, nor to
detect goal-driven permission escalation patterns within a valid delegation.

**Secondary gap:** Stratium's authority matrices for delegation (ScopeNarrows) enforce that a
child cannot exceed the parent's scope at creation time, but there are no authority matrices
controlling *which principals may re-scope a running agent* or *which goal transitions trigger
automatic permission review*. CAM's default-deny for tier-elevating goal transitions has no
equivalent.

---

### Gap 4: Real-Time Conformance Engine — Sequential Policy Blindness

**What MI9 does:** Uses FSMs following CSP (Communicating Sequential Processes) verification
principles to evaluate temporal patterns across event sequences. Each FSM state represents
progress through a multi-step policy pattern; transitions are triggered by ATS events matching
predicates. Example: the dual-control FSM requires `approve.action` from a manager-role within
60 seconds of `tool.invoke(verb="bank.transfer")`. Absence or timeout constitutes a violation.
O(k) complexity per event where k = active FSM instances.

**What Stratium does:** Evaluates each `ExecuteAction` call as an independent atomic query
against the OPA/Rego compound policy. The policy sees `(subject_attributes, agent_attributes,
delegation_context, resource_attributes)` for the current action only. There is no concept of
session state, action history, or temporal ordering constraints.

**The gap:** Stratium cannot enforce any policy that spans multiple actions. This means the
following classes of violations are undetectable:

- A research-then-execute sequence that bypasses dual-control (read tool, then write tool,
  without required approval between them)
- A tool invoked more than N times without human re-authorization
- Action B always required within time window T after action A (temporal coupling)
- An agent performing `memory.read` on a previously unauthorized resource class before calling
  a delegated tool (preparation-then-exploitation pattern)

The dual-control approval requirement in Phase 2A of PRD_TRACE_GAPS.md addresses agent
*registration* approval, but not intra-session action sequence dual-control. Enforcement of
multi-step action policies requires an FSM-equivalent layer.

---

### Gap 5: Behavioral Drift Detection — Statistical Model Missing

**What MI9 does:** Maintains per-agent, per-goal baselines as frequency distributions of event
types, tool usage patterns, and sequence characteristics. Uses Jensen-Shannon divergence for
discrete sequence distributions and Mann-Whitney U tests for continuous metrics. A change in
behavior while stated goals remain constant (or without a verified goal transition) signals
drift. The key distinction: MI9 separates *verified adaptation* (agent declared a goal change,
behavioral change is consistent with new goal) from *suspicious drift* (behavioral change
without corresponding goal change, or goal change inconsistent with behavioral pattern).

**What Stratium does / plans to do:** Phase 2B of PRD_TRACE_GAPS.md proposes a 30-day P99 ×
configurable multiplier for volume anomalies and an operator consistency bloom filter. Both
are rule-based action-count thresholds with no statistical baseline model and no goal-awareness.

**The gap:** The proposed Phase 2B anomaly detection cannot distinguish between:
- An agent legitimately running more tool calls because it was given a larger task (benign)
- An agent incrementally escalating its tool call volume as a result of goal drift (malicious)

Without goal-conditioned baselines, every volume spike from a high-performing agent is
indistinguishable from a drifting agent. The result is either an unacceptably high false
positive rate (blocking legitimate high-volume agents) or an unacceptably high false negative
rate (missing real drift by setting thresholds conservatively).

The Jensen-Shannon divergence approach also addresses an entirely different threat class:
*changes in the type or sequence of actions*, not just their volume. An agent that maintains
constant volume but shifts from primarily `read` events to primarily `write` events without a
declared goal change is drifting toward a more dangerous action profile — this is invisible
to a volume-only detector.

---

### Gap 6: Graduated Containment — Binary Response

**What MI9 does:** Four escalating containment levels applied based on violation severity,
agent ARI tier, and violation pattern:

1. *State-Preserving Monitoring* — full agent operation continues; governance signal collection
   intensified; human-in-the-loop checkpoints inserted for high-risk decisions
2. *Planning Intervention* — current task completes; new planning cycles and goal modifications
   blocked until manual review
3. *Tool Restriction* — specific tool categories dynamically revoked; safe/read-only alternatives
   provided where possible; remainder of session continues
4. *Execution Isolation* — agent migrated to controlled environment with simulated tool responses;
   behavioral assessment without external impact

Each level is reversible. The escalation controller maps violation patterns to containment
levels using risk-tier-weighted scoring.

**What Stratium does:** Binary responses only. An action is either authorized (ALLOW) or denied
for that action only (DENY). The only session-level intervention is full delegation revocation
(`RevokeDelegation`) or full agent suspension (`SuspendAgent`). Both are all-or-nothing.

**The gap:** When a running agent exhibits suspicious behavior, the only Stratium response is
full termination of its authorization. In many real scenarios this is operationally untenable:
- A long-running data analysis agent that has accumulated 3 hours of work cannot be terminated
  without losing that state
- An agent coordinating with human users cannot be stopped mid-interaction without leaving
  the human in an indeterminate state
- A subagent in a five-deep delegation chain cannot be individually contained; the only option
  is to revoke the root delegation, terminating all five agents simultaneously

This gap means that in practice, security operators will avoid triggering revocation for
anything other than clearly malicious behavior — the operational cost is too high. This
produces a perverse incentive to tolerate suspicious-but-not-certain behavior, exactly the
class of behavior that MI9's graduated containment is designed to address.

---

## Proposed Implementation

Given the architectural depth of these gaps, this PRD organizes work into three phases:

### Phase 3A — Cognitive Telemetry Foundation (prerequisite for all other phases)

All other MI9 gaps depend on having cognitive events. This phase cannot be parallelized with
the others.

**Work required:**

1. **Define the ATS event schema for Stratium.** Extend the agent telemetry model with three
   event categories modeled on MI9's ATS:

   ```
   Cognitive events: goal.set, goal.revise, plan.start, plan.revise,
                     memory.read, memory.write, strategy.change
   Action events:    tool.invoke, api.call, auth.request (already partially logged)
   Coordination events: subagent.spawn, delegation.request, human.escalate, agent.msg.send
   ```

   New table: `agent_telemetry_events` (separate from `audit_logs` to avoid schema bloat):

   ```sql
   CREATE TABLE agent_telemetry_events (
       id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
       agent_id        UUID NOT NULL REFERENCES agents(id),
       delegation_id   UUID REFERENCES delegations(id),
       conversation_id VARCHAR(255),
       tenant_id       VARCHAR(255) NOT NULL,
       event_category  VARCHAR(20) NOT NULL
                       CHECK (event_category IN ('cognitive', 'action', 'coordination')),
       event_verb      VARCHAR(50) NOT NULL,  -- e.g. 'goal.revise', 'tool.invoke'
       event_data      JSONB NOT NULL DEFAULT '{}',
       session_seq     BIGINT NOT NULL,       -- monotonic counter within conversation_id
       root_delegation_id UUID
   );

   CREATE INDEX idx_ate_agent_time ON agent_telemetry_events(agent_id, occurred_at DESC);
   CREATE INDEX idx_ate_conversation ON agent_telemetry_events(conversation_id, session_seq);
   CREATE INDEX idx_ate_verb ON agent_telemetry_events(event_verb);
   CREATE INDEX idx_ate_root_delegation ON agent_telemetry_events(root_delegation_id);
   ```

2. **Add a new Gateway RPC: `RecordTelemetry`.** Agent SDKs submit telemetry events to the
   Gateway, which validates the delegation token, enriches with governance metadata (trust
   tier, chain depth, risk tier), and writes to `agent_telemetry_events`. This is a
   fire-and-forget endpoint — SDK submits and does not block on response.

3. **Extend SDK clients** (Go, Python) with a `RecordEvent(verb, data)` method that batches
   and ships events to the Gateway asynchronously. The SDK is responsible for emitting
   cognitive events based on the framework it wraps (LangChain callbacks, LangGraph node
   instrumentation, etc.). The Gateway does not need to understand LLM internals.

4. **Governance metadata on every event.** Each event enriched with: `agent_id`,
   `delegation_id`, `agent_trust_tier`, `chain_depth`, `root_delegation_id`, `tenant_id`.
   This is the "policy context" in MI9's ATS schema.

**Note on cognitive event instrumentation:** Unlike action events (which the Gateway already
sees), cognitive events must be emitted by the agent framework. For LangChain, this means
callback hooks on `on_chain_start`, `on_tool_start`, `on_agent_action`, `on_agent_finish`.
For custom agents, the SDK provides a `with_telemetry()` context manager. This is a
*best-effort* instrumentation model — not all agent frameworks expose cognitive event hooks.
Governance intensity defaults to action-event-only mode when cognitive events are absent,
which corresponds to LangSmith-level coverage in MI9's evaluation (68.52% detection rate).

---

### Phase 3B — Runtime Authorization Adaptation and Conformance (depends on 3A)

**3B.1: Goal-Aware Authorization**

Introduce a `current_goal` field in the delegation's live state, updated via `RecordTelemetry`
when a `goal.set` or `goal.revise` event arrives. Extend `evaluateDelegationScope` in the
Gateway's action authorization path to check whether the requested action is consistent with
the delegation's *current goal state*, not just its minted scope.

Initial implementation: a configurable `goal_scope_map` in the agent's registration record —
a map of goal prefixes to the maximum action tier permitted for that goal class. Example:
`{"data_analysis": 1, "report_generation": 2, "system_configuration": 3}`. When the current
goal matches `data_analysis`, actions with tier > 1 are denied even if the delegation scope
would otherwise permit them.

This implements a narrowed version of MI9's CAM: context-dependent permission restriction
based on declared current goal, enforced at the IAM layer.

**3B.2: FSM Conformance Engine**

Introduce a `ConformancePolicy` model and a lightweight FSM engine in the Gateway. Policies
are stored in a new `conformance_policies` table and evaluated against the `agent_telemetry_events`
stream for each active conversation.

```sql
CREATE TABLE conformance_policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    tenant_id   VARCHAR(255),    -- null = global
    enabled     BOOLEAN NOT NULL DEFAULT true,
    policy_json JSONB NOT NULL,  -- FSM definition: states, transitions, predicates, temporal bounds
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

FSM definition format (JSON):

```json
{
  "initial_state": "idle",
  "states": {
    "idle": {
      "transitions": [
        {
          "predicate": {"event_verb": "tool.invoke", "event_data.tier": {"gte": 3}},
          "next_state": "pending_approval",
          "timeout_seconds": 60,
          "timeout_state": "violated"
        }
      ]
    },
    "pending_approval": {
      "transitions": [
        {
          "predicate": {"event_verb": "auth.request", "event_data.role": "manager"},
          "next_state": "idle"
        }
      ]
    },
    "violated": { "terminal": true, "action": "escalate" }
  }
}
```

The FSM engine processes new telemetry events asynchronously (not in the action hot path).
When a terminal violation state is reached, it writes to `agent_anomalies` (from Phase 2B)
and fires the webhook. For policies where the violation must block the action (rather than
alert after), the `ConformancePolicy` can be flagged as `blocking: true`, which requires
synchronous pre-action evaluation — at the cost of added latency.

**3B.3: Mid-Session Permission Narrowing**

Add `POST /v1/delegations/:id/narrow` to the Gateway API. Accepts a subset of the current
scope (tools, action tiers, classification caps) and replaces the live delegation's scope
with the intersection of current and provided values. Does not require full revocation or
token re-issuance — instead, writes a `delegation_overrides` record that the Gateway checks
on every `ExecuteAction`. This is the mechanism MI9's CAM uses to "revoke or modify specific
permissions during execution."

```sql
CREATE TABLE delegation_overrides (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegation_id   UUID NOT NULL REFERENCES delegations(id),
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by      VARCHAR(255) NOT NULL,
    reason          TEXT,
    scope_override  JSONB NOT NULL  -- same structure as delegation scope fields
);
```

On every `ExecuteAction`, the Gateway checks for an active override record and applies the
intersection of original scope and override scope. This adds one DB read to the hot path —
acceptable given existing compound policy evaluation overhead.

---

### Phase 3C — Behavioral Drift Detection (depends on 3A)

This phase replaces the simpler volume anomaly detection proposed in Phase 2B of
PRD_TRACE_GAPS.md with MI9's statistical approach.

**3C.1: Goal-Conditioned Baselines**

For each `(agent_id, goal_hash)` pair where `goal_hash` is a stable hash of the agent's
current declared goal, maintain a baseline profile:

- Event type frequency distribution (what fraction of events are cognitive vs. action vs.
  coordination; what verb distribution within each category)
- Action tier distribution (what fraction of actions are at each tier)
- Tool usage distribution (which tools and at what frequency)
- Sequence n-grams for common action pairs (e.g., `tool.invoke("read")` → `tool.invoke("write")`)

Baselines computed from a rolling 30-day window, min 500 events to be considered established.

```sql
CREATE TABLE agent_goal_baselines (
    agent_id        UUID NOT NULL REFERENCES agents(id),
    goal_hash       VARCHAR(64) NOT NULL,
    computed_at     TIMESTAMPTZ NOT NULL,
    event_count     INT NOT NULL,
    baseline_data   JSONB NOT NULL,  -- frequency distributions
    PRIMARY KEY (agent_id, goal_hash)
);
```

**3C.2: Drift Scoring**

On a configurable cadence (default: every 100 new events per conversation), compute drift
scores for any active agent with an established baseline:

- Jensen-Shannon divergence on the event verb distribution within the current session window
  vs. the stored baseline
- Mann-Whitney U test on action tier samples (current session vs. baseline sample)
- JS divergence on tool usage distribution

Combined drift score = weighted sum of the three values (configurable weights). Score exceeds
threshold → `agent_anomalies` record with `anomaly_type = 'GOAL_DRIFT'`.

**3C.3: Verified Adaptation Signaling**

When the agent emits a `goal.revise` or `goal.set` telemetry event, the drift detector
transitions to a new baseline comparison context: it uses the new `goal_hash` for subsequent
drift scoring. The behavioral change associated with a declared goal transition is treated as
expected adaptation, not drift. This is MI9's "verified adaptation signaling" — the distinction
between intentional learning and misalignment.

If the behavioral change is inconsistent with the declared new goal (JS divergence from the
baseline for the new goal is also high), the anomaly type becomes `GOAL_MISMATCH` at higher
severity — indicating the agent declared a goal change but its behavior doesn't match the
claimed new goal.

---

### Phase 3D — Graduated Containment (depends on 3B, 3C)

Replace the binary allow/deny response model with four containment levels modeled on MI9.

**New agent session state machine:**

```
ACTIVE
  │ ARI threshold or drift score exceeds level-1 threshold
  ▼
ENHANCED_MONITORING   — full operation; increased telemetry; checkpoints on high-risk actions
  │ conformance violation or drift score exceeds level-2 threshold
  ▼
PLANNING_RESTRICTED   — current task completes; goal.set and plan.start blocked via conformance engine
  │ repeated violation or high-severity anomaly
  ▼
TOOL_RESTRICTED       — specific tool categories revoked via delegation_overrides
  │ critical violation
  ▼
ISOLATED              — all tool.invoke calls routed to sandbox response provider
```

**Implementation:**

Each level is a different enforcement behavior in the Gateway, not a separate service.
The `delegations` table gains a `containment_level` column (0-4, default 0). The Gateway
checks this on every `ExecuteAction`:

- Level 0: normal authorization path
- Level 1: normal authorization + telemetry sampling rate increased + `CHECKPOINT` events
  emitted before `ActionTierDestructive` actions (gives human observer a signal before, not after)
- Level 2: `goal.set` and `plan.start` events rejected via `RecordTelemetry`; ongoing
  tool invocations continue to be authorized normally
- Level 3: dynamically restricted tool set applied via `delegation_overrides`
- Level 4: `ExecuteAction` succeeds (returns `Authorized: true`) but `Payload` contains
  a canned sandbox response instead of the real forwarded service response; external
  services are not contacted

Level 4 (execution isolation) is the most critical from a blast-radius perspective: the
agent believes its actions are succeeding and does not enter a confusion or retry loop,
but no real side effects occur. This is MI9's "inert tool responses in controlled environment."

**Cascade coordination for multi-agent chains:**

When a parent delegation is moved to containment level > 1, all child delegations in the
chain automatically move to the same level (using the existing cascade logic via
`parent_delegation_id`). When a *child* delegation reaches containment level 2+, the parent's
level increases by 1 (subagent violations trigger enhanced monitoring of the delegating parent),
consistent with MI9's cascade coordination model.

---

## Non-Goals (Phase 3)

- **LLM model-level constraints**: MI9's conformance engine operates on the telemetry stream,
  not on model weights or prompts. This PRD makes no changes to LLM behavior.
- **Pretraining and supply-chain risks**: Explicitly out of scope in MI9's own threat model.
- **Full OWASP LLM Top 10 coverage**: The conformance engine can express some OWASP threats
  as FSM policies, but this PRD does not commit to specific policy implementations.
- **Zero FPR**: MI9 achieves 1.21% FPR at 99.81% detection. Phase 3 targets <5% FPR as an
  acceptable starting point, tightening via policy tuning over time.
- **Cognitive event coverage for opaque API-wrapper agents**: If an agent uses the raw OpenAI
  SDK without LangChain callbacks, cognitive event coverage is impossible. This is
  acknowledged in MI9 itself as a limitation.

---

## Dependency and Sequencing

```
Phase 1 (agent-auth, DONE)
  └── Phase 2A (TRACE governance)
        └── Phase 3A (cognitive telemetry) ◄── PREREQUISITE for all Phase 3 work
              ├── Phase 3B (runtime authorization adaptation)
              ├── Phase 3C (behavioral drift detection)
              └── 3B + 3C ──► Phase 3D (graduated containment)
```

Phase 3A can begin in parallel with Phase 2B (shadow detection / anomaly infrastructure)
since they share the `agent_anomalies` output table but do not block each other.

---

## Open Questions

1. **ARI computation ownership.** MI9 computes ARI from the agent's declared capabilities at
   registration. Should Stratium compute ARI from telemetry observations (behavioral ARI) in
   addition to the static registration profile? Behavioral ARI would drift upward as an agent
   demonstrates higher autonomy, providing a runtime signal to update the trust tier.

2. **Blocking vs. alerting conformance policies.** Synchronous FSM evaluation (blocking mode)
   adds latency to the `ExecuteAction` hot path. What is the acceptable latency budget? The
   existing compound policy evaluation (OPA/Rego + DB read) already adds overhead; adding
   FSM evaluation compounds this.

3. **Cognitive event trust.** Agent-reported telemetry (cognitive events) is self-reported by
   the agent SDK. A malicious agent can omit or falsify cognitive events. Should the conformance
   engine treat absence of expected cognitive events (e.g., no `plan.start` before a complex
   tool chain) as a soft violation signal? MI9 does not address this directly.

4. **Level 4 sandbox provider.** Execution isolation requires a response provider that returns
   plausible-but-inert responses to tool invocations. This is straightforward for `tool.invoke`
   calls the Gateway proxies, but what about direct SDK calls that bypass the Gateway? The
   sandbox is only effective if the Gateway is the only path to real services (true for managed
   tenants, potentially not for self-hosted).

5. **Cold-start baselines.** MI9 recommends conservative thresholds during baseline
   establishment and transfer learning from similar agent objectives for new agents. Defining
   "similar objectives" in the Stratium context requires a semantic similarity measure over
   agent purpose strings, which introduces an LLM dependency into the governance layer itself.
