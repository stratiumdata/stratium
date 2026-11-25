REVOKE UPDATE (used_at) ON approvals FROM stratium_app;
ALTER TABLE approvals DROP COLUMN IF EXISTS used_at;
