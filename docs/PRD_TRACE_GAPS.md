# PRD: TRACE Gap Closure — Agent Authorization Phase 2

**Status:** Draft
**Author:** Benjamin Parrish
**Date:** 2026-03-31
**Depends On:** `PRD_AGENT_AUTHORIZATION.md` (Phase 1, feature flag `agent-auth`)
**Feature Flag:** `agent-auth-v2`

---

## Background

A gap analysis against the TRACE framework (Track, Register, Approve, Certify, Expose) —
published by Arvin Bansal at RSAC 2026 — identified four areas where Phase 1 of agent
authorization falls short of enterprise security requirements:

| Gap | TRACE Pillar | Risk |
|-----|-------------|------|
| No dual control at agent creation | R: Register | A single compromised admin account can register a fully-trusted agent with no second approval |
| No automatic revocation on user offboarding | T: Track | Delegations outlive their authorizing user's employment; leaked tokens remain valid until TTL |
| No detection of unsanctioned (shadow) agents | A: Approve | Agents operating outside the gateway are invisible — no alert, no inventory, no containment |
| No behavioral anomaly detection | E: Expose | An agent used by a different operator than its registrant, or exhibiting unusual action patterns, goes unnoticed |

This PRD closes all four gaps. They are organized into two phases based on engineering surface:

- **Phase 2A** — Governance process gaps (dual control, offboarding revocation). Database + workflow changes.
- **Phase 2B** — Observability gaps (shadow AI detection, anomaly monitoring). New signal pipeline.

---

## Design Decisions

| Decision | Choice | Alternatives Considered |
|----------|--------|------------------------|
| Dual control mechanism | Approval queue in existing PAP DB | External workflow (Jira, PagerDuty), synchronous two-admin HTTP handshake |
| Approval token expiry | 24h (configurable) | No expiry, 1h (too aggressive for async review) |
| Offboarding trigger | Webhook endpoint (SCIM-compatible) + manual revoke-by-user API | LDAP/AD polling, Keycloak event stream |
| Shadow agent detection | Gateway traffic + audit log analysis (no endpoint agent required) | Network DLP, eBPF-based syscall tracing |
| Anomaly model | Rule-based (V2); ML scoring deferred to V3 | Statistical baseline, pure ML |
| Anomaly storage | Separate `agent_anomalies` table | Flags in `audit_logs`, external SIEM |
| Notification channel | Webhook-out (Slack/PagerDuty compatible) | In-app only, email |
| Approval scope | Per-agent on creation and on trust-tier upgrade | Per-delegation, per-action |

---

## Part 1 — Phase 2A: Governance Process Gaps

### 1.1 Dual Control at Agent Creation

#### Problem

Phase 1 registration is single-admin: one admin authenticates, POSTs to `POST /v1/agents`,
and the agent is immediately created in `PENDING` state and eligible for use. A single
compromised admin credential is sufficient to register an agent with `TrustTierCertified`
and a broad `AllowedActions` set.

TRACE R pillar requirement: *"Deploying any agent SDK must require a second human to approve,
creating dual control at the creation layer."*

#### Solution: Approval Queue

Introduce an `agent_approval_requests` table and a state machine that prevents an agent
from becoming active until a second admin approves it.

**State machine:**

```
[Create Request]
      │
      ▼
  PENDING_APPROVAL  ◄─── initial state on POST /v1/agents
      │
   ┌──┴──────────────────────┐
   │ second admin approves   │ first admin or requester cancels
   ▼                         ▼
APPROVED                 CANCELLED
   │
   ▼
 agent.enabled = true, cert_status = PENDING
   │
   │ (existing certification flow)
   ▼
CERTIFIED
```

**Rules:**
- The approving admin must be a different principal than the creating admin (`approved_by != created_by`).
- Approval requests expire after `AGENT_APPROVAL_TTL` (default: 24h). Expired requests set the
  agent to `SUSPENDED` automatically.
- Trust tier upgrades (e.g., `Registered → Certified`) require a new approval request. Downgrades
  do not.
- `TrustTierUnverified` agents (read-only, sandboxed) are exempt from dual control — they cannot
  initiate external comms or destructive actions regardless.

#### New Database Objects

```sql
CREATE TABLE agent_approval_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id),
    requested_by    VARCHAR(255) NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING_APPROVAL'
                    CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'CANCELLED', 'EXPIRED')),
    reviewed_by     VARCHAR(255),
    reviewed_at     TIMESTAMPTZ,
    review_note     TEXT,
    -- What change is being approved
    change_type     VARCHAR(30) NOT NULL
                    CHECK (change_type IN ('CREATE', 'TRUST_TIER_UPGRADE')),
    prior_trust_tier SMALLINT,
    requested_trust_tier SMALLINT NOT NULL
);

CREATE INDEX idx_approval_requests_agent ON agent_approval_requests(agent_id);
CREATE INDEX idx_approval_requests_status ON agent_approval_requests(status)
    WHERE status = 'PENDING_APPROVAL';
CREATE INDEX idx_approval_requests_expires ON agent_approval_requests(expires_at)
    WHERE status = 'PENDING_APPROVAL';
```

#### New PAP API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/agents/approvals` | List pending approval requests (admin) |
| `GET` | `/v1/agents/approvals/:id` | Get approval request detail |
| `POST` | `/v1/agents/approvals/:id/approve` | Approve (different admin required) |
| `POST` | `/v1/agents/approvals/:id/cancel` | Cancel (requester or any admin) |

#### Behavior Changes to Existing Endpoints

`POST /v1/agents` — agent is created with `enabled: false`, cert_status `PENDING`, and an
`agent_approval_request` record is created in `PENDING_APPROVAL` state. The response includes
the `approval_request_id` and a `pending_approval: true` field.

`PUT /v1/agents/:id` — if `trust_tier` is increased, a new approval request is created and the
trust tier change is held in the approval record (not applied to the agent) until approved.

#### Audit

All approval lifecycle events (requested, approved, cancelled, expired) are written to
`audit_logs` with `entity_type = 'agent_approval'`.

---

### 1.2 Automatic Revocation on User Offboarding

#### Problem

When a user leaves an organization, their active delegations continue to authorize agent
actions until the delegation TTL expires. If a long-lived delegation token was issued (or
leaked), it remains cryptographically valid. Phase 1 provides `suspendAgent` which revokes
by agent ID, but there is no mechanism to revoke all delegations by user ID on offboarding.

TRACE T pillar requirement: *"When an employee leaves, agent permissions must be revoked
immediately. When roles change, permissions must update at the edge in real time."*

#### Solution: SCIM-Compatible User Lifecycle Webhook

Add a `POST /v1/users/:user_id/revoke-agent-access` endpoint that:
1. Revokes all active delegations where `user_id` matches.
2. Disables re-issuance by writing a `user_agent_access_revoked` record.
3. Returns count of revoked delegations and affected agent IDs.

The endpoint uses the same admin JWT auth as the rest of the PAP API. It is designed to be
callable from SCIM provisioners (Okta, Entra ID, Jumpcloud) via a SCIM `PATCH` or `DELETE`
user event webhook adapter, but does not require SCIM — any system that can make an
authenticated POST can trigger it.

```
POST /v1/users/{user_id}/revoke-agent-access
Authorization: Bearer <admin-jwt>

Request body (optional):
{
  "reason": "offboarding",
  "revoke_future": true   // prevent new delegations for this user_id
}

Response:
{
  "user_id": "alice@corp.com",
  "revoked_delegations": 4,
  "affected_agents": ["agent_a1b2c3d4", "agent_e5f6g7h8"],
  "future_blocked": true
}
```

#### New Database Object

```sql
CREATE TABLE user_agent_access_blocks (
    user_id     VARCHAR(255) PRIMARY KEY,
    blocked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_by  VARCHAR(255) NOT NULL,
    reason      TEXT
);
```

The Gateway's `CreateDelegation` RPC checks this table before minting a token. If the
requesting user is blocked, delegation minting returns `codes.PermissionDenied`.

#### Role Change Handling

For role changes (not full offboarding), the existing `PUT /v1/agents/:id` endpoint already
updates `AllowedTools` and `AllowedActions`. What's missing is a mechanism to
**retroactively narrow in-flight delegations** when an agent's permissions are reduced.

Add `POST /v1/agents/:id/reissue-delegations` that:
1. Revokes all active delegations for the agent.
2. Returns a list of affected `user_id` values so the calling system can notify them
   to re-authenticate and receive a narrowed token.

Active delegations are treated as point-in-time authorization (consistent with the existing
Phase 1 design decision), so re-issuance is the caller's responsibility after this call.

---

## Part 2 — Phase 2B: Observability Gaps

### 2.1 Shadow Agent Detection

#### Problem

TRACE A pillar: *"The fastest growing attack surface in your enterprise is the one your
employees built without you knowing."* Phase 1 assumes agents self-register through the PAP
API and route through the Agent Gateway at `:50054`. Any agent — or any code that mimics an
agent — that bypasses the gateway is completely invisible.

Concretely, a shadow agent scenario in Stratium looks like:
1. An employee writes a script that calls KAS or Platform directly using their OIDC token.
2. The script acts like an agent (automated, high-frequency, non-human pattern) but carries
   no `agent_id` or delegation token.
3. Phase 1 treats this as a regular user request — no agent audit columns populated, no
   trust tier enforcement.

#### Solution: Behavioral Heuristics in Existing Services

Rather than requiring an endpoint agent or network tap, embed lightweight behavioral
heuristics into the existing gRPC interceptors in Platform, Key Manager, and KAS. Flag
requests that look like agents but carry no agent credentials.

**Heuristics (configurable thresholds):**

| Signal | Threshold | Rationale |
|--------|-----------|-----------|
| Request rate from single `sub` | > 20 req/min | Human users don't sustain this rate |
| Identical `user-agent` across requests | any non-browser UA | Scripts/SDKs use static UAs |
| Sequential resource access pattern | > 10 unique resources in 60s | Enumeration pattern |
| Off-hours activity from `sub` | Outside learned active window | Automated vs. human |
| No `X-Conversation-ID` header | Present in all gateway-routed requests | Gateway always sets this |

When ≥ 2 heuristics fire for the same `sub` within a rolling 5-minute window, a
`SHADOW_AGENT_CANDIDATE` event is written to `agent_anomalies` and a webhook notification
is fired.

The `X-Conversation-ID` header heuristic is the most reliable: the Agent Gateway
unconditionally sets this header on all forwarded requests. A direct call to Platform or
KAS that bypasses the gateway will never have it, and can be flagged with zero false positives
for requests that have no legitimate reason to lack it (i.e., non-SDK/non-browser automated calls).

#### New Database Table

```sql
CREATE TABLE agent_anomalies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    anomaly_type    VARCHAR(50) NOT NULL,
                    -- 'SHADOW_AGENT_CANDIDATE', 'OPERATOR_MISMATCH',
                    -- 'UNUSUAL_VOLUME', 'OFF_HOURS_ACTIVITY'
    subject_id      VARCHAR(255),   -- user_id if known
    agent_id        UUID,           -- agent_id if known (null for shadow candidates)
    delegation_id   UUID,
    tenant_id       VARCHAR(255) NOT NULL,
    severity        VARCHAR(10) NOT NULL DEFAULT 'MEDIUM'
                    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    signals         JSONB NOT NULL DEFAULT '{}',  -- fired heuristics + values
    request_count   INT,
    time_window_s   INT,
    status          VARCHAR(20) NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')),
    resolved_by     VARCHAR(255),
    resolved_at     TIMESTAMPTZ,
    resolution_note TEXT
);

CREATE INDEX idx_anomalies_tenant ON agent_anomalies(tenant_id, detected_at DESC);
CREATE INDEX idx_anomalies_subject ON agent_anomalies(subject_id) WHERE subject_id IS NOT NULL;
CREATE INDEX idx_anomalies_status ON agent_anomalies(status) WHERE status = 'OPEN';
CREATE INDEX idx_anomalies_type ON agent_anomalies(anomaly_type);
```

#### New PAP API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/anomalies` | List anomalies (filterable by type, severity, status, tenant) |
| `GET` | `/v1/anomalies/:id` | Get anomaly detail including signals |
| `POST` | `/v1/anomalies/:id/acknowledge` | Mark as acknowledged with note |
| `POST` | `/v1/anomalies/:id/resolve` | Resolve or mark false positive |
| `GET` | `/v1/anomalies/summary` | Counts by type/severity for dashboard |

#### Webhook Notifications

A new `WebhookConfig` in the PAP config (`config/config.go`) accepts an outbound URL
and an HMAC signing secret. When an anomaly is created with severity `HIGH` or `CRITICAL`,
the PAP server POSTs a signed JSON payload to the configured URL. Payload format is
compatible with Slack incoming webhooks and PagerDuty Events v2.

```yaml
# config/examples/pap-server.yaml addition
agent_auth:
  anomaly_webhook:
    url: ""                 # empty = disabled
    signing_secret: ""      # HMAC-SHA256 key for X-Stratium-Signature header
    min_severity: "HIGH"    # LOW | MEDIUM | HIGH | CRITICAL
    timeout_ms: 3000
```

---

### 2.2 Behavioral Anomaly Detection (Registered Agents)

#### Problem

TRACE E pillar: *"Detect anomalies such as an agent being used by someone other than its
designated operator."* Even for registered agents, Phase 1 records what happened but nothing
watches for suspicious patterns.

#### Solution: Operator Consistency Check + Volume Anomaly

Two rule-based checks added to the Agent Gateway's audit flush path (asynchronous, not in
the hot path):

**Check 1: Operator Mismatch**

Each delegation is bound to a `user_id` at creation time (the `sub` claim from the OIDC
token). The gateway validates that the `user_id` in the delegation token matches the
authenticated principal on every `ExecuteAction` call. This is already enforced in Phase 1.

The new addition: if an agent's delegation was historically issued to user set {A, B, C} but
a new delegation arrives for user D who has never previously used this agent, emit an
`OPERATOR_MISMATCH` anomaly at severity `MEDIUM`. This catches credential sharing and
token forwarding patterns.

Implementation: the Gateway maintains a bloom filter per `agent_id` of historical `user_id`
values, seeded from the delegations table at startup and updated on new delegation creation.
A new user_id that doesn't match the bloom filter triggers the anomaly write.

**Check 2: Unusual Action Volume**

A per-agent rolling 1-hour counter is maintained in-memory (with periodic flush to a
`agent_volume_stats` table for persistence across restarts). When an agent's request
rate in a 1-hour window exceeds its 30-day P99 by > 3× (configurable multiplier), emit
an `UNUSUAL_VOLUME` anomaly at severity `MEDIUM`.

For agents with fewer than 7 days of history, the threshold defaults to 100 req/hour.

```sql
CREATE TABLE agent_volume_stats (
    agent_id    UUID NOT NULL REFERENCES agents(id),
    hour_bucket TIMESTAMPTZ NOT NULL,  -- truncated to hour
    request_count INT NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, hour_bucket)
);

CREATE INDEX idx_volume_stats_agent_recent
    ON agent_volume_stats(agent_id, hour_bucket DESC);
```

---

## Non-Goals (Phase 2)

- **ML-based trust scoring**: Rule-based heuristics only. Behavioral ML deferred to Phase 3.
- **Response content inspection**: No payload scanning or DLP. Authorization remains pre-action.
- **Cross-tenant anomaly correlation**: Each tenant's anomalies are evaluated independently.
- **SIEM push integration**: Webhook-out is the integration point. SIEM connectors are the
  responsibility of the operator.
- **Retroactive classification of existing audit logs**: Anomaly detection applies to new
  events only.

---

## Implementation Phases

### Phase 2A (Governance) — Estimated 2 sprints

| Sprint | Work |
|--------|------|
| 1 | `agent_approval_requests` schema + PAP API endpoints + state machine |
| 1 | Modify `POST /v1/agents` and `PUT /v1/agents/:id` to gate on approvals |
| 2 | `user_agent_access_blocks` schema + SCIM-compatible revoke endpoint |
| 2 | `reissue-delegations` endpoint + Gateway block check at delegation minting |
| 2 | Audit logging for all new lifecycle events |

### Phase 2B (Observability) — Estimated 3 sprints

| Sprint | Work |
|--------|------|
| 3 | `agent_anomalies` schema + PAP CRUD endpoints |
| 3 | `X-Conversation-ID` heuristic in Platform/KAS interceptors (zero-false-positive shadow detection) |
| 4 | Remaining shadow detection heuristics + rolling window rate counter |
| 4 | Operator consistency bloom filter in Gateway |
| 5 | `agent_volume_stats` table + unusual volume check |
| 5 | Webhook outbound notifications + HMAC signing |
| 5 | `/v1/anomalies/summary` endpoint for dashboard integration |

---

## Security Considerations

- The approval endpoint (`POST /v1/agents/approvals/:id/approve`) must validate that
  `reviewed_by != requested_by` server-side. Client-supplied principal is not trusted.
- The SCIM webhook endpoint must require the same admin JWT as other PAP endpoints — it
  must not be callable without authentication.
- Bloom filter false positives (a new operator incorrectly flagged as mismatched) produce
  `MEDIUM` anomalies, not automatic denials. Detection is advisory; authorization enforcement
  remains in the compound policy path.
- Anomaly webhook payloads are HMAC-SHA256 signed. Recipients must verify the signature.
  The signing secret must not be stored in config files — use an environment variable or the
  existing secret manager pattern.
- Heuristic thresholds are configurable but must be stored in the database (not config files)
  so changes are audit-logged and cannot be silently modified by a compromised config file.

---

## Open Questions

1. **Approval TTL on creation vs. trust-tier upgrade**: Should a pending trust-tier upgrade
   block the agent from operating at its current (lower) tier, or should it continue operating
   at the existing tier until approved? Recommendation: continue at existing tier.

2. **SCIM provisioner support**: Which identity providers does the org currently use? The
   endpoint is provider-agnostic but we may want to ship a thin Okta webhook adapter as a
   reference implementation.

3. **Anomaly false positive rate**: The 30-day P99 ×3 threshold for volume anomalies is
   conservative. We should instrument a shadow-mode period where anomalies are written but
   not notified, to calibrate before enabling webhook alerts.

4. **Bloom filter persistence**: Should the operator consistency bloom filter be persisted
   to the database at Gateway shutdown, or re-seeded from the delegations table on every
   startup? At scale, re-seeding is expensive. Recommendation: serialize to Redis or a
   `agent_operator_history` table with a daily compaction job.
