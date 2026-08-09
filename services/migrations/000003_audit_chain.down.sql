DROP TRIGGER IF EXISTS audit_chain_no_truncate ON audit_chain;
DROP FUNCTION IF EXISTS audit_chain_deny_truncate();
DROP RULE IF EXISTS audit_chain_no_delete ON audit_chain;
DROP RULE IF EXISTS audit_chain_no_update ON audit_chain;
DROP TABLE IF EXISTS audit_chain;
