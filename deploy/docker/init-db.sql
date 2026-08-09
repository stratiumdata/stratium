-- Bootstraps the two login identities cmd/stratium-pdp/main.go uses. Runs
-- once, as the bootstrap superuser, before the PDP container (or anything
-- else) ever connects — see docker-entrypoint-initdb.d in the postgres
-- image.
--
-- migrations/000002_rls.up.sql FORCEs row-level security on every tenant
-- table, but Postgres exempts superusers from RLS unconditionally, FORCE or
-- not (see that migration's own doc comment). If the PDP connected as the
-- default "postgres" superuser, every query would silently see every
-- tenant's rows and this compose stack would prove nothing about tenant
-- isolation. Neither role below is SUPERUSER or BYPASSRLS, so RLS is
-- actually live for both.
--
-- Two LOGIN roles, not one, because main.go now opens two separate
-- connections (STRATIUM_MIGRATION_DATABASE_URL, STRATIUM_DATABASE_URL) and
-- closes the migration one before it ever serves a request:
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
--   stratium — the serving identity (STRATIUM_DATABASE_URL). Member of
--   stratium_app only, never of stratium_audit_owner. main.go's startup
--   check (checkNotAuditOwner) queries pg_has_role(current_user,
--   'stratium_audit_owner', 'member') on this connection and refuses to
--   start if that is ever true — so this role holding that membership is
--   no longer just a convention this file has to get right, it is
--   something the PDP itself verifies on every boot.
CREATE ROLE stratium_audit_owner NOLOGIN;
CREATE ROLE stratium_app NOLOGIN;

CREATE ROLE stratium_migrate LOGIN PASSWORD 'stratium_migrate_local_dev_only';
GRANT stratium_audit_owner TO stratium_migrate;

CREATE ROLE stratium LOGIN PASSWORD 'stratium_local_dev_only';
GRANT stratium_app TO stratium;

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
