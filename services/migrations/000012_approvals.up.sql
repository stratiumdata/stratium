-- Approvals: one row per escalated decision (spec §4.6.1 E6-E9). A row
-- records that a decision landed in a delegation's [escalate_at,
-- max_action_tier] band (migrations/000011_delegations_escalate_at) and is
-- waiting on, or has received, a control-plane disposition. See
-- internal/store/approval.go for CreateApproval/LoadApproval — the only two
-- operations the PDP itself ever performs against this table.

CREATE TABLE approvals (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            TEXT NOT NULL,

    -- ON DELETE RESTRICT, matching delegations.agent_id (000001_baseline):
    -- an approval is a record of what was asked and by which agent, and
    -- cascading it away when the agent is later retired would silently
    -- destroy that history the same way it would for a delegation itself.
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    -- No ON DELETE clause on either delegation reference below — defaults
    -- to NO ACTION, matching delegations.root_delegation_id's own precedent
    -- (000001_baseline): a delegation that a pending or historical approval
    -- still names cannot be deleted out from under it.
    delegation_id        UUID NOT NULL REFERENCES delegations(id),
    root_delegation_id   UUID NOT NULL REFERENCES delegations(id),

    -- The requesting principal on the escalated call itself
    -- (DecideRequest.subject / authz.Principal.Subject) — who asked, not
    -- who may approve.
    subject              TEXT NOT NULL,
    -- The chain root delegation's user_id: the ONLY identity spec C21
    -- permits to approve. At chain depth > 0 the immediate delegator is an
    -- agent, not a person, so routing approval anywhere but the root would
    -- let a chain approve itself. No FK: delegations.user_id (what this
    -- value is read from) is itself an opaque caller-supplied string with
    -- no backing table, so this column matches that, not a relation.
    root_principal       TEXT NOT NULL,

    tool_name            TEXT NOT NULL,
    action                TEXT NOT NULL,
    derived_tier          SMALLINT NOT NULL CHECK (derived_tier BETWEEN 0 AND 4),

    -- Binds this row to one specific request — reused unchanged from the
    -- audit chain's own notion of request identity (a SHA-256 digest of the
    -- raw tool input) rather than inventing a second one. Unlike
    -- audit_chain's own input_digest (nullable — 000003_audit_chain), this
    -- one is NOT NULL: every row in this table originates from one
    -- particular escalated Decide call, which always computes a digest
    -- (even empty raw input hashes to a concrete 32-byte value) — there is
    -- no "no digest" case here the way audit_chain's broader, longer-lived
    -- event log has to allow for.
    input_digest          BYTEA NOT NULL,
    CONSTRAINT approvals_input_digest_len CHECK (octet_length(input_digest) = 32),

    -- Closed vocabulary, enforced HERE rather than in Go: CreateApproval
    -- never validates this value client-side, so removing this CHECK is
    -- what actually determines whether an invalid status can be written —
    -- the constraint is the enforcement, not a description of one.
    --
    -- Deliberately no 'expired' member. Expiry is a pure function of
    -- expires_at and the reader's current time; a stored status that must
    -- be kept in step with a timestamp is a status that WILL drift out of
    -- step with it — the same class of bug spec §4.8's revocation epoch
    -- exists to avoid for cached decisions. A reader compares now against
    -- expires_at; nothing ever writes 'expired' here.
    --
    -- DEFAULT 'pending' because that is the only value CreateApproval ever
    -- legitimately writes — see that function's own doc comment.
    -- 'approved'/'denied' are written exclusively by the control plane,
    -- directly against this column, per E7; the PDP has no path to either
    -- value, which the grants below enforce structurally.
    status                TEXT NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'approved', 'denied')),

    requested_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ NOT NULL,

    approved_by           TEXT,
    approved_at           TIMESTAMPTZ
);

CREATE INDEX idx_approvals_tenant ON approvals(tenant_id);

ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON approvals
    USING (tenant_id = current_tenant())
    WITH CHECK (tenant_id = current_tenant());

-- E7 — the PDP never grants an approval, it only reads one (spec §4.6.1).
-- SELECT lets it read a row back (LoadApproval); INSERT lets it create a
-- pending one (CreateApproval). UPDATE is deliberately absent from this
-- statement: there is no Approve RPC anywhere in this system, and the only
-- way a row's status ever becomes 'approved' or 'denied' is a control-plane
-- UPDATE issued under the control plane's own identity, never the PDP's.
--
-- This GRANT line — specifically what it does NOT list — IS that
-- enforcement, not a comment claiming it. A comment can rot out of sync
-- with a later, wider GRANT and nothing would notice; the absence of
-- UPDATE here is what TestIntegration_Approvals_ServingRoleCannotUpdate
-- actually exercises against a live database, and what any later reviewer
-- widening this line would have to consciously override.
GRANT SELECT, INSERT ON approvals TO stratium_app;
