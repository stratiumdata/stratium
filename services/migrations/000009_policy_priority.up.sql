-- Gives policies the priority column that policy.StoredPolicy.Priority has
-- always declared.
--
-- The field was plumbed end to end in Phase 2c — StoredPolicy.Priority ->
-- cedar's policyMeta -> authz.PolicyVerdict.Priority -> the audit row's policy
-- provenance — but no migration ever created a column to load it from, so
-- LoadPolicies left it at Go's zero value and every audit row recorded
-- priority 0 for every policy. That is the same shape as the defect Phase 2b
-- fixed, where provenance was plumbed, hashed, and migrated but never
-- populated: a field that reaches an audit record looking like real data while
-- being structurally constant is worse than an absent one, because a reader
-- cannot tell the difference.
--
-- Priority is provenance only. Spec §3.3 Y7 removed priority as
-- security-relevant: the fold is deny-overrides with default-deny, and
-- authz.FoldVerdicts neither reads nor sorts by this value. It is stored so an
-- operator reading an audit row can locate the policy in their own authoring
-- model, and so tenants migrating from the predecessor — which ordered
-- policies by priority — do not silently lose the number they authored
-- against. Nothing may begin sorting, filtering, or short-circuiting by it;
-- TestFoldVerdicts_IgnoresPriority is the standing guard.
--
-- DEFAULT 0 backfills existing rows to exactly the value LoadPolicies has been
-- reporting for them, so this migration does not change any decision or any
-- audit value for policy sets authored before it.
--
-- No grant is needed: 000007 granted SELECT on the table, and table-level
-- grants cover columns added later.
ALTER TABLE policies ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN policies.priority IS
    'Provenance only (spec Y7). Recorded in audit rows; never consulted by the decision fold.';
