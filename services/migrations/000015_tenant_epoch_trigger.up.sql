-- Revocation epoch bump (spec §4.8.1 V1). tenant_epoch has existed since the
-- baseline migration (000001) with no writer -- this is that writer. A
-- trigger, not application code, so it cannot be omitted by a future
-- writer, a future migration, or a manual UPDATE the way a Go-side bump
-- could -- the same "unforgettable by construction" argument this codebase
-- already makes for tool_catalog's UNIQUE (tenant_id, tool_name) and for
-- every GRANT-as-enforcement line in 000012_approvals/000013_tool_catalog.
-- internal/store's package doc points here for a Go reader; nothing in Go
-- ever writes tenant_epoch (see that package doc for why -- E7, T1).
--
-- Fires on every INSERT/UPDATE/DELETE of policies, agents, tool_catalog,
-- and tier_overrides: any of these changes what an existing decision would
-- evaluate to. Fires on delegations UPDATE/DELETE only -- an INSERT there
-- is a brand new delegation, purely additive, invalidating no existing
-- decision; bumping on it would make every new agent session invalidate
-- every PEP's cache tenant-wide -- correct but wasteful, and wasteful in a
-- way that would only surface much later as a mysteriously low hit rate.
--
-- One shared function, not five copies: the bump logic is identical
-- regardless of which table fired it, so it is written once and attached
-- five times -- the same shape 000002_rls.up.sql already uses for
-- tenant_isolation across six tables.
CREATE OR REPLACE FUNCTION bump_tenant_epoch() RETURNS trigger AS $$
DECLARE
    v_tenant TEXT;
BEGIN
    -- DELETE has no NEW row; INSERT/UPDATE have no reason to prefer OLD --
    -- branching on TG_OP makes the choice explicit rather than reaching for
    -- a COALESCE(NEW, OLD) that does not work row-wise in plpgsql anyway.
    IF TG_OP = 'DELETE' THEN
        v_tenant := OLD.tenant_id;
    ELSE
        v_tenant := NEW.tenant_id;
    END IF;

    -- No cross-tenant re-parenting case to handle: an UPDATE can never
    -- change which tenant a row belongs to for any role bound by RLS
    -- (every role except a superuser, and neither application role is one
    -- -- 000002_rls.up.sql's own comment). Every governed table is FORCE
    -- ROW LEVEL SECURITY with tenant_id = current_tenant() as both USING
    -- and WITH CHECK, so OLD.tenant_id = NEW.tenant_id = current_tenant()
    -- is already guaranteed by the time this trigger fires -- which is
    -- also exactly why the upsert below never has to worry about
    -- app.tenant_id being wrong for the row it is about to touch: the
    -- governed table's own RLS already proved it right.
    --
    -- Create-on-demand, not seed-on-tenant-creation: this codebase has no
    -- tenant-provisioning table or step to seed from -- tenant_id is a
    -- bare partition key, never a row in a "tenants" table anywhere in
    -- this schema -- so "seed on creation" has no hook to attach to, and
    -- would leave the row missing forever for exactly the tenant an
    -- operator writes into directly with no onboarding step at all. A
    -- trigger that no-ops when the row is missing is an invalidation
    -- mechanism switched off for precisely the tenants nobody set up
    -- carefully; upserting here means every tenant gets a row the first
    -- time it needs one, unconditionally.
    --
    -- The created row starts at epoch 2, not the column's own DEFAULT of
    -- 1: 1 is the value any reader must already treat a genuinely absent
    -- row as (there is no other sane default for "no row yet"), so a row
    -- created here AT 1 would be indistinguishable from "nothing has
    -- happened" to a reader who observed that default before this write --
    -- silently defeating the one bump that just happened. Starting at 2
    -- keeps this first bump observable against that implicit baseline.
    --
    -- The increment (epoch + 1) reads off the row this statement itself
    -- locks -- via ON CONFLICT's row-level lock on tenant_id's primary
    -- key, the same guarantee a plain UPDATE's row lock gives -- not a
    -- value read earlier by this function or by some application-side
    -- read-modify-write. Postgres re-evaluates SET expressions against the
    -- current row once a concurrent writer's lock on it releases
    -- (read-committed's documented EvalPlanQual behavior), so concurrent
    -- bumps to the same tenant serialize to N, N+1, N+2, ... rather than
    -- losing one. A read-then-write-back from application code would not
    -- have this property, which is itself part of V1's case for doing the
    -- bump here instead.
    INSERT INTO tenant_epoch (tenant_id, epoch, updated_at)
    VALUES (v_tenant, 2, NOW())
    ON CONFLICT (tenant_id) DO UPDATE
        SET epoch = tenant_epoch.epoch + 1, updated_at = NOW();

    -- AFTER triggers' return value is ignored by Postgres; NULL is the
    -- idiomatic no-op (contrast a BEFORE trigger, where returning NEW/OLD
    -- controls whether the triggering write proceeds and with what
    -- values -- not a choice this trigger needs to make).
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- SECURITY INVOKER (the default -- no SECURITY DEFINER clause), matching
-- current_tenant() (000002_rls.up.sql) and every other function in this
-- schema: the bump runs as whichever role performed the governed write, so
-- it is subject to the exact same RLS policy that write already satisfied,
-- and needs its own privilege grant (below) to actually perform it.
-- SECURITY DEFINER would swap that transparency for a privilege-escalation
-- surface this schema has no other instance of, for no benefit this task
-- needs: FORCE ROW LEVEL SECURITY applies to a SECURITY DEFINER function's
-- owner too (000002's own comment -- FORCE closes exactly this bypass), so
-- switching would not even remove the need for the grant below, only make
-- who is actually performing the write less obvious to the next reader.
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['policies', 'agents', 'tool_catalog', 'tier_overrides'] LOOP
        EXECUTE format(
            'CREATE TRIGGER tenant_epoch_bump AFTER INSERT OR UPDATE OR DELETE ON %I '
            'FOR EACH ROW EXECUTE FUNCTION bump_tenant_epoch()', t);
    END LOOP;
END $$;

-- delegations: UPDATE OR DELETE only -- see the narrowing rationale in this
-- file's own leading comment. Kept out of the loop above because it is the
-- one table in this set whose trigger event list differs from the other
-- four; folding it in behind a per-table conditional would obscure the one
-- thing that is actually different about it.
CREATE TRIGGER tenant_epoch_bump AFTER UPDATE OR DELETE ON delegations
    FOR EACH ROW EXECUTE FUNCTION bump_tenant_epoch();

-- FOR EACH ROW, not FOR EACH STATEMENT, on every trigger above: two writes
-- in one transaction -- whether two rows touched by one statement or two
-- separate statements -- bump twice, not once. Monotonicity is what every
-- consumer of this counter needs (a bump means "changed since," never
-- "changed exactly once"); density is not a property anything reads.
-- Collapsing multiple bumps into one within a transaction would need a
-- statement-level trigger plus a transition table, or a per-transaction
-- dedupe flag, to buy a guarantee nothing requires. Letting each row-level
-- event bump once is simpler and no less correct.

-- stratium_app needs to actually perform the write above: it does not own
-- tenant_epoch (only stratium_migrate does -- deploy/docker/init-db.sql),
-- and FORCE ROW LEVEL SECURITY (000002_rls.up.sql) applies to every role
-- without BYPASSRLS, ownership included -- so RLS was never the gap here,
-- the missing table privilege was. Without this grant, the moment
-- stratium_app's role (stratium) performs any write this trigger fires on,
-- the trigger's own INSERT/UPDATE into tenant_epoch fails with
-- insufficient_privilege -- and because it fires inside the same
-- transaction as that write, the write it was attached to is rolled back
-- with it. That is fail-closed by construction, not by any extra handling
-- in the function above: a governed write with no corresponding grant here
-- does not silently land un-bumped, it does not land at all. See
-- TestIntegration_TenantEpoch_BumpsForNonOwnerRole (this grant is
-- necessary -- remove it and that test fails on insufficient_privilege --
-- and sufficient) and TestIntegration_TenantEpoch_MissingGrantFailsTheWrite
-- Closed (what happens when it, or something like it, is absent).
--
-- SELECT, INSERT, and UPDATE -- not INSERT/UPDATE alone. This was found
-- wrong empirically, not reasoned correctly the first time: `SET epoch =
-- tenant_epoch.epoch + 1` reads epoch's current value as part of computing
-- its new one, and Postgres requires SELECT privilege on any column an
-- UPDATE (including the DO UPDATE half of an upsert) reads, in addition to
-- UPDATE privilege to write it -- confirmed against this migration's own
-- live database: with SELECT omitted, TestIntegration_TenantEpoch_
-- BumpsForNonOwnerRole failed with "permission denied for table
-- tenant_epoch" on exactly this statement, even though UPDATE alone was
-- granted. This is not "an external reader of tenant_epoch through
-- stratium_app" (that is still Task 2's LoadTenantEpoch, not this task's
-- concern) -- it is the upsert's own arithmetic needing to see the value it
-- increments, which is intrinsic to what "bump" means and has nothing to do
-- with whether anything outside this trigger ever reads the column.
--
-- No DELETE: deleting a tenant's epoch row is never legitimate for any role.
GRANT SELECT, INSERT, UPDATE ON tenant_epoch TO stratium_app;
