-- Hash-chained, append-only audit (spec §4.9). Each row commits to its
-- predecessor, so any edit or deletion is detectable by re-walking the chain.
--
-- Columns mirror pkg/audit.Entry. Raw tool inputs are NOT stored — only
-- input_digest. Encrypted plaintext and crypto-shredding are deferred until
-- per-tenant key management is specified (spec §8).

CREATE TABLE audit_chain (
    seq        BIGSERIAL PRIMARY KEY,
    tenant_id  TEXT NOT NULL,

    prev_hash  BYTEA NOT NULL,   -- 32 zero bytes for a tenant's first row
    entry_hash BYTEA NOT NULL,   -- SHA-256 over the canonical serialization

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type  TEXT NOT NULL,
    actor       TEXT NOT NULL,

    agent_id           UUID,
    delegation_id      UUID,
    root_delegation_id UUID,
    chain_depth        SMALLINT NOT NULL DEFAULT 0,

    tool_name     TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT '',
    declared_tier SMALLINT NOT NULL DEFAULT 0,
    derived_tier  SMALLINT NOT NULL DEFAULT 0,

    decision        TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY','ESCALATE')),
    denied_leg      TEXT NOT NULL DEFAULT '' CHECK (denied_leg IN ('','principal','agent','delegation')),
    denied_at_depth SMALLINT NOT NULL DEFAULT -1,
    reason          TEXT NOT NULL DEFAULT '',

    input_digest BYTEA,

    CONSTRAINT audit_chain_hash_len CHECK (
        octet_length(prev_hash) = 32 AND octet_length(entry_hash) = 32),
    -- input_digest is also a SHA-256 and must be constrained like its siblings.
    -- Nullable, because an entry need not carry one; but a present value of the
    -- wrong length is a truncated or corrupt digest, not a shorter one.
    CONSTRAINT audit_chain_input_digest_len CHECK (
        input_digest IS NULL OR octet_length(input_digest) = 32)
);

CREATE UNIQUE INDEX audit_chain_tenant_seq   ON audit_chain(tenant_id, seq);
CREATE INDEX audit_chain_tenant_time         ON audit_chain(tenant_id, occurred_at DESC);
CREATE INDEX audit_chain_delegation          ON audit_chain(delegation_id);
CREATE INDEX audit_chain_root                ON audit_chain(root_delegation_id);

-- Append-only, enforced by the database. Rules make UPDATE and DELETE no-ops
-- for every role including the owner, so the application cannot rewrite its
-- own history even if compromised.
CREATE RULE audit_chain_no_update AS ON UPDATE TO audit_chain DO INSTEAD NOTHING;
CREATE RULE audit_chain_no_delete AS ON DELETE TO audit_chain DO INSTEAD NOTHING;

-- Rules do NOT intercept TRUNCATE — only triggers do. Without this, TRUNCATE
-- empties the entire audit trail silently, for any role holding the privilege,
-- and the UPDATE/DELETE rules above give a false sense of immutability.
-- Verified: TRUNCATE as the table owner took the table from 1 row to 0 with no
-- error before this trigger existed.
CREATE OR REPLACE FUNCTION audit_chain_deny_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_chain is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_chain_no_truncate
    BEFORE TRUNCATE ON audit_chain
    FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_deny_truncate();

ALTER TABLE audit_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_chain
    USING (tenant_id = current_tenant())
    WITH CHECK (tenant_id = current_tenant());
