-- The PDP now deletes old sessions: a root delegation, the delegations made
-- under it and their approvals, once every one of them expired longer ago
-- than the deployment's retention period (STRATIUM_SESSION_RETENTION). The
-- audit chain is untouched and keeps the whole history.
--
-- 000016 withheld DELETE on both tables from the admin plane's role, and that
-- stands: revocation is still the only thing an operator can do to a
-- delegation. This grant is to the PDP's serving role, for the sweep alone.
GRANT DELETE ON delegations, approvals TO stratium_app;

-- The grant is wider than the sweep needs, so the database narrows it: the
-- serving role can delete only what has already expired. Deleting such a row
-- can lose a record, never change a decision, because an expired delegation
-- or approval already allows nothing. How long past expiry a row is kept is
-- the PDP's setting; that it has expired at all is enforced here.

-- Approvals are never deleted by a cascade, so a row-security policy is
-- enough.
CREATE POLICY serving_deletes_only_expired ON approvals
    AS RESTRICTIVE FOR DELETE TO stratium_app
    USING (expires_at < now());

-- Delegations are: deleting a parent cascades to its children, and a cascade
-- does not consult row security. A trigger fires for cascaded rows too. It
-- looks at session_user, the role that logged in, because a cascade runs as
-- the table's owner and current_user would name that instead.
--
-- pg_has_role, not a look at who was granted stratium_app directly: it
-- follows a grant through any roles in between, and it is true for
-- stratium_app itself. It is also true of every superuser, who is a member of
-- everything, so superusers are excepted by name: they bypass row security
-- already and are not what this guards against.
CREATE FUNCTION forbid_serving_delete_of_live_delegation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.expires_at >= now()
       AND pg_has_role(session_user, 'stratium_app', 'MEMBER')
       AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = session_user)
    THEN
        RAISE EXCEPTION 'delegation % has not expired; the serving role may delete only expired delegations', OLD.id
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER delegations_serving_delete_guard BEFORE DELETE ON delegations
    FOR EACH ROW EXECUTE FUNCTION forbid_serving_delete_of_live_delegation();
