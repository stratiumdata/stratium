-- Reverses 000016_stratium_pap_role.up.sql's GRANTs, in the reverse order
-- they were made, mirroring 000015_tenant_epoch_trigger.down.sql's own
-- stated ordering discipline.
--
-- Deliberately does NOT DROP ROLE stratium_pap, unlike
-- 000004_audit_ownership.down.sql's own DROP ROLE stratium_app /
-- stratium_audit_owner. That difference is not an oversight: verified
-- against a real postgres:16 instance, DROP ROLE on a capability role
-- succeeds even while a LOGIN role still holds membership in it (Postgres
-- silently removes the pg_auth_members row rather than blocking the drop —
-- membership is not a dependency the way an object-level GRANT is), but a
-- later CREATE ROLE of the same name is a genuinely new role with a new
-- OID, and that old membership does not come back with it. This migration's
-- own up script re-creates stratium_pap only conditionally (IF NOT EXISTS)
-- and never re-grants it to deploy/docker/init-db.sql's stratium_pap_login
-- — that membership is bootstrap-time, one-shot, outside any migration's
-- reach (by the same design deploy/docker/init-db.sql's own comment already
-- describes for stratium/stratium_app) — so a down-then-up cycle that
-- dropped and recreated this role would silently leave stratium_pap_login a
-- member of nothing, without either script erroring, and this project's own
-- migration-boundary integration test
-- (TestEndToEnd/chain_verifies_across_the_migration_boundary,
-- store_integration_test.go) genuinely walks every migration's down script
-- in one run, including this one — unlike 000004's, which sits below that
-- test's own migration window and has never had this exercised against it.
-- Revoking every privilege here, without dropping the role that holds them,
-- gets the same "no leftover access" property a rollback needs without that
-- trap: the role persists, empty of privileges, and the up script's own
-- GRANTs (not its now-skipped CREATE ROLE) are what a re-apply relies on.
REVOKE SELECT, INSERT, UPDATE ON tenant_epoch FROM stratium_pap;
REVOKE USAGE ON SEQUENCE audit_chain_seq_seq FROM stratium_pap;
REVOKE INSERT, SELECT ON audit_chain FROM stratium_pap;
REVOKE SELECT, INSERT, UPDATE ON tool_catalog, approvals, delegations FROM stratium_pap;
REVOKE SELECT, INSERT, UPDATE, DELETE ON policies, agents, tier_overrides FROM stratium_pap;
