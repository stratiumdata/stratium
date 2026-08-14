-- The admin plane's write role (spec §4.10 N3, phase plan Task 2). This is
-- the mirror image of 000012_approvals.up.sql and 000013_tool_catalog.up.sql:
-- those two migrations' GRANT lines deliberately name what stratium_app may
-- NOT do, and that absence is E7's and T1's enforcement. stratium_pap is the
-- role those rulings defer to — the control plane that actually approves,
-- catalogs, and administers — so it needs exactly the writes stratium_app
-- was denied. Getting this migration wrong in one direction (granting
-- stratium_pap too little) blocks Task 3/4's CRUD endpoints; getting it
-- wrong in the other (touching stratium_app's own GRANT lines, or granting
-- stratium_pap something that lets it reach stratium_app's identity) would
-- silently undo E7 and T1 while every existing test — none of which this
-- migration touches — kept passing. See store_pap_grant_integration_test.go's
-- TestIntegration_StratiumApp_StillCannotWriteApprovalsOrToolCatalog for the
-- regression guard that makes the second failure mode loud instead.
--
-- stratium_pap is a NOLOGIN capability role, created here idempotently
-- (mirroring 000004_audit_ownership.up.sql's own CREATE ROLE IF NOT EXISTS
-- pattern) so a self-hosted operator who never runs
-- deploy/docker/init-db.sql still gets it from the embedded migration alone
-- — the same portability argument migrations/migrations.go's package doc
-- makes generally. The LOGIN identity a real stratium-pap process
-- authenticates as (stratium_pap_login, deploy/docker/init-db.sql) is
-- deliberately NOT created or granted membership here: see this file's own
-- down migration for why a migration granting that membership would be a
-- trap the moment this migration is ever rolled back and reapplied.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'stratium_pap') THEN
        CREATE ROLE stratium_pap NOLOGIN;
    END IF;
END
$$;

-- SELECT alongside INSERT/UPDATE(/DELETE) on every table below, though the
-- phase plan's own task brief names only INSERT/UPDATE. Found live, the same
-- way migrations/000015_tenant_epoch_trigger's own SELECT requirement was:
-- confirmed against this migration's own sandbox database that
-- `UPDATE policies SET ... WHERE id = $1` fails with SQLSTATE 42501
-- (insufficient_privilege) under UPDATE-only privileges, because the WHERE
-- clause reads the id column being compared — Postgres requires SELECT on
-- any column a DML statement reads, not only the ones it writes, the exact
-- rule 000015's own comment already documents for tenant_epoch's `SET epoch
-- = epoch + 1`. A CRUD role that cannot target a specific row cannot UPDATE
-- or DELETE at all in practice, since neither Task 3 nor Task 4 has any
-- reason to write an unqualified, whole-table statement. Without SELECT here,
-- every write this role exists for would fail on its very first WHERE
-- clause — verified, not assumed, per this codebase's own house style.
--
-- DELETE: granted on policies, agents, and tier_overrides, withheld on
-- tool_catalog, approvals, and delegations. A5 says CRUD, and Task 3's own
-- brief text is explicit for the first three — "Create, read, update,
-- delete for the three tables A5 names first" — so DELETE is what that task
-- depends on this migration having already granted. The other three are
-- deliberately narrower:
--   * tool_catalog (T1) — Task 4 only ever creates or corrects a row (tier,
--     verb, field names); no task in this phase names a delete endpoint for
--     it, and this codebase's own precedent (000005_serving_app_grants.up.sql:
--     "Grant what is used, not what might be") argues against a privilege
--     with no caller. A tenant that no longer wants a tool specially
--     classified can already correct the row via UPDATE.
--   * approvals (E7) — a row is a record of what was asked and by which
--     agent (000012_approvals.up.sql's own comment); Task 4 only ever
--     UPDATEs status to 'approved'/'denied'. Deleting one would erase the
--     decision history N4 (every write audited) exists to preserve — this
--     table is closer to a log than to config, and an append-only posture
--     is the right default for it.
--   * delegations (V4) — the schema already carries the sanctioned
--     "delete": revoked/revoked_at (migrations/000001_baseline.up.sql).
--     Task 4's own brief describes revocation as "setting revoked and
--     revoked_at", never a DELETE, and 000012_approvals.up.sql's own
--     comment notes delegation_id/root_delegation_id deliberately carry NO
--     ON DELETE clause specifically so "a delegation that a pending or
--     historical approval still names cannot be deleted out from under
--     it" — granting DELETE here would hand this role a write that the
--     schema's own foreign keys expect never to happen.
-- agents keeps DELETE despite that same append-only instinct because
-- delegations.agent_id and approvals.agent_id are both ON DELETE RESTRICT
-- (000001_baseline.up.sql, 000012_approvals.up.sql): the database itself
-- refuses to let an agent with any delegation or approval history be
-- deleted out from under it, so granting DELETE here cannot orphan that
-- history — it can only remove an agent nothing has ever used, which
-- enabled=false/suspended=true (that table's own sanctioned soft-retirement,
-- per 000001's comment) already handles for one nothing HAS used yet, and
-- which Task 3's own CRUD brief names as this table's fourth verb.
GRANT SELECT, INSERT, UPDATE, DELETE ON policies, agents, tier_overrides TO stratium_pap;
GRANT SELECT, INSERT, UPDATE ON tool_catalog, approvals, delegations TO stratium_pap;

-- audit_chain: INSERT, SELECT — precisely 000004_audit_ownership.up.sql's
-- own GRANT to stratium_app, reproduced for a second writer rather than
-- widened. UPDATE and DELETE are absent here for the same reason they are
-- absent from stratium_app's own line: this role has no legitimate way to
-- rewrite history, only to add to it and read it back.
--
-- That absence is redundant with, not merely mirrored by, 000003_audit_
-- chain.up.sql's own DO INSTEAD NOTHING rules — confirmed live in this
-- migration's own sandbox database, not assumed: a role with ONLY INSERT
-- and SELECT on audit_chain (no UPDATE/DELETE grant at all) that issues
-- `UPDATE audit_chain SET reason = ... WHERE tenant_id = ...` gets back
-- "UPDATE 0", not a permission error — the rule rewrites the statement to
-- nothing before any UPDATE-privilege check would even apply, for every
-- role, granted or not. Temporarily granting stratium_app UPDATE and DELETE
-- on audit_chain in that same sandbox and re-running both statements
-- produced the identical "UPDATE 0" / "DELETE 0", row untouched — the grant
-- genuinely does not matter here, which is what
-- TestIntegration_AuditChain_PAPRoleAppendOnly's own mutation-tested comment
-- records. This migration still withholds UPDATE/DELETE deliberately, the
-- same "least privilege even where a second mechanism would also catch it"
-- discipline 000002_rls.up.sql's FORCE already applies to table ownership.
GRANT INSERT, SELECT ON audit_chain TO stratium_pap;
GRANT USAGE ON SEQUENCE audit_chain_seq_seq TO stratium_pap;

-- tenant_epoch: SELECT, INSERT, UPDATE — exactly 000015_tenant_epoch_
-- trigger.up.sql's own grant to stratium_app, reproduced verbatim for the
-- same reason that migration's own comment already gives: every write this
-- role performs on policies, agents, tool_catalog, tier_overrides, or
-- delegations (UPDATE/DELETE) fires bump_tenant_epoch() in the same
-- transaction, and that trigger runs as whichever role performed the
-- governed write (SECURITY INVOKER, not DEFINER — that migration's own
-- comment), so stratium_pap needs this grant for the identical reason
-- stratium_app does: without it, the trigger's own upsert into tenant_epoch
-- fails with insufficient_privilege, and because the trigger fires inside
-- the same transaction as the governed write, that write is rolled back
-- with it — fail-closed by construction, not by anything this migration
-- adds. SELECT is not optional here any more than it was for stratium_app:
-- `SET epoch = tenant_epoch.epoch + 1` reads the column it increments.
-- Verified in this migration's own sandbox: a write as stratium_pap with
-- only INSERT/UPDATE on tenant_epoch (SELECT withheld) failed exactly the
-- way 000015's own comment predicts for stratium_app, and succeeded, with
-- the epoch visibly bumped, once SELECT was added.
--
-- No DELETE: deleting a tenant's epoch row is never legitimate for any
-- role, stratium_pap included — the same line 000015 already draws.
GRANT SELECT, INSERT, UPDATE ON tenant_epoch TO stratium_pap;
