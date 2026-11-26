-- The admin plane lists approvals and delegations newest first, a page at a
-- time, and looks up one principal's live sessions. Without these each of
-- those sorts or scans the tenant's whole table.
CREATE INDEX idx_approvals_tenant_requested ON approvals(tenant_id, requested_at DESC, id DESC);
CREATE INDEX idx_delegations_tenant_created ON delegations(tenant_id, created_at DESC, id DESC);
CREATE INDEX idx_delegations_tenant_user ON delegations(tenant_id, user_id);
