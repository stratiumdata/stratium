-- Bootstraps the least-privileged role the PDP actually authenticates as.
-- Runs once, as the bootstrap superuser, before the PDP container (or
-- anything else) ever connects — see docker-entrypoint-initdb.d in the
-- postgres image.
--
-- migrations/000002_rls.up.sql FORCEs row-level security on every tenant
-- table, but Postgres exempts superusers from RLS unconditionally, FORCE or
-- not (see that migration's own doc comment). If the PDP connected as the
-- default "postgres" superuser, every query would silently see every
-- tenant's rows and this compose stack would prove nothing about tenant
-- isolation. "stratium" below is an ordinary login role — no SUPERUSER, no
-- BYPASSRLS — so RLS is actually live for it.
--
-- migrations/000004_audit_ownership.up.sql transfers audit_chain's
-- ownership to stratium_audit_owner and grants stratium_app INSERT/SELECT
-- on it, and its own doc comment expects the real login role to be granted
-- membership in stratium_app "outside this migration". Because main.go
-- opens a single *sql.DB and uses it for both migrations.Up() and every
-- Store query afterward, that same login role is also the one that has to
-- execute migration 000004's ALTER TABLE ... OWNER TO and GRANT statements
-- — which requires it to already hold both memberships *before* Up() runs,
-- not after (ALTER TABLE ... OWNER TO fails with "must be able to SET ROLE"
-- otherwise; verified against a real postgres:16 instance). Hence both
-- grants happen here, ahead of time, as the bootstrap superuser.
CREATE ROLE stratium_audit_owner NOLOGIN;
CREATE ROLE stratium_app NOLOGIN;
CREATE ROLE stratium LOGIN PASSWORD 'stratium_local_dev_only';
GRANT stratium_audit_owner TO stratium;
GRANT stratium_app TO stratium;

CREATE DATABASE stratium OWNER stratium;

-- Postgres 15+ no longer grants CREATE on a new database's public schema to
-- anyone but the database owner. audit_ownership's ALTER TABLE ... OWNER TO
-- requires the *new* owner (stratium_audit_owner) to hold CREATE on the
-- table's schema; stratium owns "stratium" and its public schema by virtue
-- of being the database owner, but stratium_audit_owner does not inherit
-- that and needs it granted explicitly (verified: migrations fail with
-- "permission denied for schema public" on migration 000004 without this).
\connect stratium
GRANT CREATE ON SCHEMA public TO stratium_audit_owner;
