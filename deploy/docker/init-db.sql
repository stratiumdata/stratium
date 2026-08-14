-- Bootstraps the three login identities cmd/stratium-pdp/main.go and
-- cmd/stratium-pap use (stratium-pap's own connection lands in Task 3; this
-- role exists from Task 2 so the compose stack already has it to grant
-- membership to — see migrations/000016_stratium_pap_role's own doc comment
-- for why that migration never creates this LOGIN role itself). Runs once,
-- as the bootstrap superuser, before the PDP or PAP container (or anything
-- else) ever connects — see docker-entrypoint-initdb.d in the postgres
-- image.
--
-- migrations/000002_rls.up.sql FORCEs row-level security on every tenant
-- table, but Postgres exempts superusers from RLS unconditionally, FORCE or
-- not (see that migration's own doc comment). If a service connected as the
-- default "postgres" superuser, every query would silently see every
-- tenant's rows and this compose stack would prove nothing about tenant
-- isolation. None of the roles below is SUPERUSER or BYPASSRLS, so RLS is
-- actually live for all of them.
--
-- Three LOGIN roles, not one shared login, because main.go now opens two
-- separate connections (STRATIUM_MIGRATION_DATABASE_URL,
-- STRATIUM_DATABASE_URL) and closes the migration one before it ever serves
-- a request, and stratium-pap (Task 3 onward) needs a third identity holding
-- neither PDP role's privileges:
--
--   stratium_migrate — used only for migrations.Up(). Owns the database
--   (so it owns every table the embedded migrations create) and holds
--   standing membership in stratium_audit_owner, because
--   migrations/000004_audit_ownership.up.sql's ALTER TABLE audit_chain
--   OWNER TO stratium_audit_owner requires the role running it to already
--   be a member of the role it's handing ownership to (fails with "must be
--   able to SET ROLE" otherwise; verified against a real postgres:16
--   instance). This role is never used to serve a request.
--
--   stratium — the PDP's serving identity (STRATIUM_DATABASE_URL). Member
--   of stratium_app only, never of stratium_audit_owner. main.go's startup
--   check (checkNotAuditOwner) queries pg_has_role(current_user,
--   'stratium_audit_owner', 'member') on this connection and refuses to
--   start if that is ever true — so this role holding that membership is
--   no longer just a convention this file has to get right, it is
--   something the PDP itself verifies on every boot.
--
--   stratium_pap_login — the PAP's serving identity, member of stratium_pap
--   only (migrations/000016_stratium_pap_role). Mirrors stratium/
--   stratium_app's split rather than reusing "stratium" itself: the PAP
--   holds exactly the write credentials the PDP is deliberately denied
--   (spec §4.10, N3), so its login identity must carry a DIFFERENT
--   capability-role membership, never stratium_app's. Named with an
--   explicit _login suffix, unlike "stratium" — "stratium" was free to be
--   the terse, unqualified name because it was this file's first serving
--   identity; stratium_pap is already spoken for as this task's capability
--   role name (spec verbatim, and migrations/000016's own GRANT target), so
--   the login identity needed a name of its own.
CREATE ROLE stratium_audit_owner NOLOGIN;
CREATE ROLE stratium_app NOLOGIN;
CREATE ROLE stratium_pap NOLOGIN;

CREATE ROLE stratium_migrate LOGIN PASSWORD 'stratium_migrate_local_dev_only';
GRANT stratium_audit_owner TO stratium_migrate;

CREATE ROLE stratium LOGIN PASSWORD 'stratium_local_dev_only';
GRANT stratium_app TO stratium;

CREATE ROLE stratium_pap_login LOGIN PASSWORD 'stratium_pap_login_local_dev_only';
GRANT stratium_pap TO stratium_pap_login;

CREATE DATABASE stratium OWNER stratium_migrate;

-- Postgres 15+ no longer grants CREATE on a new database's public schema to
-- anyone but the database owner. audit_ownership's ALTER TABLE ... OWNER TO
-- requires the *new* owner (stratium_audit_owner) to hold CREATE on the
-- table's schema; stratium_migrate owns "stratium" and its public schema by
-- virtue of being the database owner, but stratium_audit_owner does not
-- inherit that and needs it granted explicitly (verified: migrations fail
-- with "permission denied for schema public" on migration 000004 without
-- this).
\connect stratium
GRANT CREATE ON SCHEMA public TO stratium_audit_owner;
