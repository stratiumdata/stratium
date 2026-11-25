-- An approval is good for one call. used_at is set by the PDP, in the same
-- statement that checks it is still NULL, when a call is allowed on the
-- strength of the approval. A second call offering the same approval finds
-- it set and is denied.
--
-- Approvals already used before this migration have no used_at and can be
-- used once more.
ALTER TABLE approvals ADD COLUMN used_at TIMESTAMPTZ;

-- The PDP may set this one column and no other: deciding an approval stays
-- the PAP's alone (000016).
GRANT UPDATE (used_at) ON approvals TO stratium_app;
