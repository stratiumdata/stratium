REVOKE USAGE ON SEQUENCE audit_chain_seq_seq FROM stratium_app;
REVOKE INSERT, SELECT ON audit_chain FROM stratium_app;
ALTER TABLE IF EXISTS audit_chain OWNER TO CURRENT_USER;
DROP ROLE IF EXISTS stratium_app;
DROP ROLE IF EXISTS stratium_audit_owner;
