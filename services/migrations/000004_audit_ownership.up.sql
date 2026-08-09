-- Ownership hardening for audit_chain. The DO INSTEAD NOTHING rules (Task 10)
-- and the BEFORE TRUNCATE trigger stop UPDATE, DELETE, and TRUNCATE for every
-- role that reaches them — but rules and triggers are just more objects on
-- the table, and whoever OWNS the table can DROP RULE or DROP TRIGGER at
-- will. Until now audit_chain was owned by whatever role ran the migrations,
-- which is also the role the application would authenticate as: immutability
-- rested on the convention that the app never issues those DROP statements,
-- not on anything the database enforces.
--
-- This migration gives audit_chain a dedicated owner role that holds no
-- login credentials, and cuts the application down to INSERT and SELECT on
-- it — never UPDATE, DELETE, TRUNCATE, and never ownership. The application
-- must NEVER authenticate as stratium_audit_owner; whatever login role the
-- service actually connects as should be GRANTed membership in stratium_app
-- instead (outside this migration, alongside its credentials). That
-- separation is what makes the append-only guarantee real rather than
-- conventional: a fully compromised application role still cannot rewrite or
-- erase history, because it does not own the table and cannot touch the
-- rules, the trigger, or the trigger function that enforce that.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'stratium_audit_owner') THEN
        CREATE ROLE stratium_audit_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'stratium_app') THEN
        CREATE ROLE stratium_app NOLOGIN;
    END IF;
END
$$;

ALTER TABLE audit_chain OWNER TO stratium_audit_owner;

GRANT INSERT, SELECT ON audit_chain TO stratium_app;
GRANT USAGE ON SEQUENCE audit_chain_seq_seq TO stratium_app;
