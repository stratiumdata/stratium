DROP TRIGGER IF EXISTS delegations_serving_delete_guard ON delegations;
DROP FUNCTION IF EXISTS forbid_serving_delete_of_live_delegation();
DROP POLICY IF EXISTS serving_deletes_only_expired ON approvals;
REVOKE DELETE ON delegations, approvals FROM stratium_app;
