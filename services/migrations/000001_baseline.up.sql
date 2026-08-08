-- Baseline schema. Tenancy is structural: every table carries tenant_id from
-- creation, because retrofitting isolation into a security product after it
-- holds customer data is significantly harder.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE agents (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     TEXT NOT NULL,
    name          TEXT NOT NULL,
    provider      TEXT NOT NULL,
    model_id      TEXT,
    trust_tier    SMALLINT NOT NULL DEFAULT 0 CHECK (trust_tier BETWEEN 0 AND 3),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    suspended     BOOLEAN NOT NULL DEFAULT false,
    allowed_tools JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_agents_tenant ON agents(tenant_id);

CREATE TABLE delegations (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            TEXT NOT NULL,
    user_id              TEXT NOT NULL,
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    approved_tools       JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_action_tier      SMALLINT NOT NULL CHECK (max_action_tier BETWEEN 0 AND 4),
    classification_caps  JSONB NOT NULL DEFAULT '{}'::jsonb,
    resource_constraints JSONB NOT NULL DEFAULT '{}'::jsonb,
    purpose              TEXT,
    expires_at           TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked              BOOLEAN NOT NULL DEFAULT false,
    revoked_at           TIMESTAMPTZ,
    parent_delegation_id UUID REFERENCES delegations(id) ON DELETE CASCADE,
    root_delegation_id   UUID NOT NULL,
    depth                SMALLINT NOT NULL DEFAULT 0 CHECK (depth >= 0),
    chain_agent_ids      JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX idx_delegations_tenant ON delegations(tenant_id);
CREATE INDEX idx_delegations_root   ON delegations(root_delegation_id);
CREATE INDEX idx_delegations_active ON delegations(tenant_id, expires_at) WHERE revoked = false;

CREATE TABLE policies (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      TEXT NOT NULL,
    name           TEXT NOT NULL,
    description    TEXT,
    language       TEXT NOT NULL CHECK (language IN ('json','cedar','rego','xacml')),
    policy_content TEXT NOT NULL,
    effect         TEXT NOT NULL CHECK (effect IN ('allow','deny')),
    version        BIGINT NOT NULL DEFAULT 1,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_policies_tenant_enabled ON policies(tenant_id, enabled);

CREATE TABLE entitlements (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    subject_attributes  JSONB NOT NULL DEFAULT '{}'::jsonb,
    resource_attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    actions             JSONB NOT NULL DEFAULT '[]'::jsonb,
    conditions          JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_entitlements_tenant_enabled ON entitlements(tenant_id, enabled);

-- Raise-only action-tier overrides (spec §4.4). The CHECK is a database-level
-- backstop; application code enforces the same rule against the built-in
-- classifier, which the database cannot see.
CREATE TABLE tier_overrides (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    TEXT NOT NULL,
    tool_or_verb TEXT NOT NULL,
    action_tier  SMALLINT NOT NULL CHECK (action_tier BETWEEN 0 AND 4),
    builtin_tier SMALLINT NOT NULL CHECK (builtin_tier BETWEEN 0 AND 4),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   TEXT NOT NULL,
    CONSTRAINT tier_overrides_raise_only CHECK (action_tier >= builtin_tier),
    UNIQUE (tenant_id, tool_or_verb)
);
CREATE INDEX idx_tier_overrides_tenant ON tier_overrides(tenant_id);

-- Revocation epoch (spec §4.8). Bumped by any revocation, suspension, or
-- policy change; a cached decision carrying a stale epoch is never served.
CREATE TABLE tenant_epoch (
    tenant_id  TEXT PRIMARY KEY,
    epoch      BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
