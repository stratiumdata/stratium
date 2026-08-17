-- Spent DPoP proof identifiers (RFC 9449; spec §4.7.2 K8). One row per proof
-- the PDP has accepted, recorded so that a second presentation of the same
-- proof collides against this table's primary key instead of verifying a
-- second time. K8 chose enforcement in the database over relying on the
-- freshness window alone, which leaves a stolen token and its captured proof
-- replayable within that window against the same method and URI.
--
-- The key is the natural one, and it is the PRIMARY KEY rather than a UNIQUE
-- constraint hung off a surrogate uuid `id` column the way every other table
-- here does it. Nothing loads a spent proof by id, references one from
-- another table, or hands an operator a handle to one: the only two
-- operations are "insert this pair" and "delete the expired ones", and both
-- name the pair. A surrogate key would be an extra column and a second index
-- maintained on the decision path, on every network-surface request, to
-- identify rows nothing identifies.
--
-- The pair, not `jti` alone, and that is a correctness requirement rather
-- than a convention followed for its own sake. A `jti` is chosen by the
-- client, so two tenants can independently pick the same value. A constraint
-- on `jti` alone would make one tenant's honest first use collide with
-- another tenant's -- one tenant could deny another's requests by guessing or
-- observing its identifiers -- and the collision would itself disclose that a
-- value had been spent in a tenant that RLS otherwise hides completely.
--
-- expires_at is supplied by the writer rather than defaulted here, because
-- only the writer knows the value: a `jti` need be remembered only for as
-- long as a proof carrying it could still pass the freshness check, which is
-- that proof's own `iat` plus the configured window, spec §4.7.2 K9. Past
-- that instant the proof is refused for staleness whether or not this table
-- still remembers it, so a longer retention buys nothing and an unbounded one
-- degrades every future request. There is deliberately no `spent_at` column:
-- it is expires_at minus that window, and a column nothing reads is the
-- plumbed-but-never-populated field 000013_tool_catalog.up.sql's own comment
-- rules out.
CREATE TABLE spent_proofs (
    tenant_id  TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,

    -- Bounded because this value arrives inside an attacker-chosen JWT and is
    -- written on the decision path. Unbounded, a single request could store
    -- megabytes; and a value past Postgres's btree entry limit would fail the
    -- insert anyway, with "index row size exceeds maximum" -- which reads
    -- like database corruption rather than like a bad request. A refusal at a
    -- named CHECK is the same denial with a diagnosable reason. 255 is around
    -- five times the length of a UUID and six times an unpadded base64url
    -- SHA-256; no legitimate client comes near it. The lower bound restates
    -- in the schema what internal/dpop.Verify already refuses -- an absent or
    -- empty jti claim -- so a future writer that skipped verification could
    -- not record a row keyed on the empty string.
    CONSTRAINT spent_proofs_jti_len CHECK (length(jti) BETWEEN 1 AND 255),

    PRIMARY KEY (tenant_id, jti)
);

-- No further index, and the omission is measured rather than forgotten.
-- idx_*_tenant, which every other tenant-scoped table here carries, would
-- duplicate a prefix of the primary key's own btree. An index on expires_at
-- for the reaper would be paid on every insert -- on the decision path -- to
-- serve a DELETE that removes every row older than a window measured in
-- minutes: at any reaping interval an operator would plausibly choose, that
-- is a large fraction of the table, which the planner will read sequentially
-- regardless of what indexes exist. Add one if a measurement, not an
-- intuition, says otherwise.

ALTER TABLE spent_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE spent_proofs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON spent_proofs
    USING (tenant_id = current_tenant())
    WITH CHECK (tenant_id = current_tenant());

-- RLS is what scopes the reaper, and it is worth stating plainly because the
-- failure it produces is silent. A DELETE issued on a connection that never
-- set app.tenant_id matches no rows under the policy above: no error, no
-- warning, zero rows affected, and a reaper that reports success forever
-- while this table grows without bound. internal/store.ReapSpentProofs goes
-- through beginTenantTx like every other method in that package, so it reaps
-- the one tenant the PDP process was configured for -- see that function's
-- own doc comment for why a cross-tenant sweep is not what this system wants
-- and could not be written without a role far more privileged than any that
-- exists here.

-- Spec §4.7.2 K8, and this GRANT is the one place in the schema where the PDP
-- gains a write outside the audit chain, so the reasoning belongs here rather
-- than in a plan document nobody will have open.
--
-- E7 (§4.6.1), T1 (§4.4.2) and T6 (§4.4.2) withhold writes from stratium_app
-- on authorization CONFIGURATION -- approvals' dispositions, the tool
-- catalog, tier overrides -- because a PDP that could write those would be
-- adjusting its own authority, which is spec defect D1. Replay state is not
-- configuration. A row here records that one specific proof was spent; it is
-- written only by the component that spends it; and there is no value any
-- writer could put in it that widens any decision. The worst a compromised
-- PDP achieves through this grant is denying itself requests it would
-- otherwise have allowed, which is the fail-closed direction. Nothing about
-- this line licenses widening 000012, 000013 or 000017, and the integration
-- proofs those migrations name still hold after it.
--
-- SELECT is not speculative and is not there for a reader that does not
-- exist. Postgres requires SELECT on any table whose columns are read in a
-- statement's conditions: the reaper's DELETE reads expires_at in its WHERE
-- clause, and the tenant_isolation policy above reads tenant_id on every one
-- of these verbs. Without SELECT the DELETE fails outright with
-- insufficient_privilege. It also lets an operator debugging a replay storm
-- inspect this table as the identity that actually writes it.
--
-- UPDATE is absent, completely rather than partially, and the absence is the
-- enforcement in exactly the sense 000012_approvals.up.sql and
-- 000013_tool_catalog.up.sql already argue. A spent proof is never un-spent,
-- re-dated, or edited: the only two legitimate transitions are "did not
-- exist, now does" and "existed, now expired and removed". An UPDATE here
-- would let the component being policed push a spent proof's expiry forward
-- or rewrite its jti, either of which turns replay prevention off for a proof
-- of the attacker's choosing without deleting anything an audit would miss.
-- TestIntegration_SpentProofs_ServingRoleGrantsAreExactlyInsertSelectDelete
-- (internal/store/spent_proof_integration_test.go) holds this shut against a
-- live database, and asserts in the same breath that the three configuration
-- tables above still refuse the PDP's writes.
--
-- No tenant_epoch trigger is attached to this table, and none should be.
-- 000015_tenant_epoch_trigger names policies, agents, tool_catalog,
-- tier_overrides and delegations because a write to any of those changes what
-- a cached decision would evaluate to. Spending a jti changes nothing a
-- decision reads, and bumping the epoch here would invalidate every cached
-- decision in the tenant on every single network-surface request -- turning
-- the cache off, expensively, by accident. Confirmed against that migration's
-- own table list, not assumed.
GRANT INSERT, SELECT, DELETE ON spent_proofs TO stratium_app;
