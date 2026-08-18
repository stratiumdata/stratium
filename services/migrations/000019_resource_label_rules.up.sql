-- Per-tenant resource labelling rules (spec §3.9.1, R4-R7). One row maps a
-- resource-id PREFIX to a classification hierarchy and a level;
-- internal/store.LoadResourceLabelRules reads a tenant's whole set on the
-- decision path and pkg/classification.Resolve picks the longest matching
-- prefix (R6). This is §4.4.2 T1's shape applied to resources, and
-- 000013_tool_catalog.up.sql is deliberately this file's template: the PAP
-- writes, the PDP reads, and what the GRANTs at the bottom do NOT name is the
-- enforcement.
--
-- R3 recorded that nothing anywhere supplied a resource's classification, so
-- R2 made every configured cap deny on every action. This table is what
-- supplies it. A row-per-resource table was rejected outright in §3.9.1: the
-- resource space is unbounded, and a scheme that requires enumerating every
-- file cannot be operated.
CREATE TABLE resource_label_rules (
    -- A surrogate handle, unlike 000018_spent_proofs.up.sql, which dropped one
    -- in favour of its natural key. The difference is that these rows are
    -- operator-facing configuration with an edit path (Task 4's PAP CRUD):
    -- prefix is exactly the field an operator corrects when a rule is wrong,
    -- so the natural key is the one thing that cannot serve as the stable
    -- handle an update-by-id or delete-by-id route names. Every other
    -- config table here (policies, agents, tool_catalog, tier_overrides)
    -- carries one for the same reason.
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id  TEXT NOT NULL,

    -- The resource-id prefix this rule labels. Matched with plain
    -- strings.HasPrefix, case-sensitively, and NOT at a path boundary: `/data`
    -- matches `/database/x`. See pkg/classification.Resolve's own doc comment
    -- for the three arguments behind that ruling; it is the case an operator
    -- will get wrong, so it is documented where their mental model forms
    -- rather than only here.
    --
    -- The empty string is a LEGAL, meaningful value: it is a prefix of every
    -- id, so a row with prefix '' is R7's catch-all, and R7 makes registering
    -- one the answer to "a tenant enabled a cap and now everything denies."
    -- That is why there is no `length(prefix) > 0` CHECK here and no
    -- required-field guard in internal/store.validateResourceLabelRule, while
    -- hierarchy and level get exactly that floor immediately below. An empty
    -- prefix means "everything"; an empty hierarchy or level means nothing at
    -- all.
    prefix     TEXT NOT NULL,

    -- The hierarchy this rule's level belongs to, and the level itself
    -- (`nato`/`SECRET`, `commercial`/`PUBLIC`). Stored verbatim, never
    -- case-folded on the way in: pkg/classification.Index and Resolve both
    -- fold when they compare, and normalising here would write back a level in
    -- casing the operator never typed -- the ruling resolve.go's longestMatch
    -- already records for the value it returns.
    hierarchy  TEXT NOT NULL,
    level      TEXT NOT NULL,

    -- The STRUCTURAL half of validity, and only that half. A row naming an
    -- empty hierarchy or an empty level can never match any cap and carries no
    -- information -- the same lower bound 000018_spent_proofs.up.sql puts on
    -- jti, and for the same reason: NOT NULL is satisfied by ''.
    --
    -- The SEMANTIC half -- is `level` actually a level of `hierarchy`? -- is
    -- deliberately NOT here, neither as a CHECK enumerating the pairs nor as
    -- an FK to a levels table this schema would then have to seed and keep in
    -- step. pkg/classification.Levels is the single source for what the
    -- hierarchies and their orderings ARE (R8 keeps them hardcoded in Go
    -- precisely because a tenant-defined hierarchy needs an ordering, which is
    -- its own subsystem), and a CHECK listing the ten (hierarchy, level) pairs
    -- would be a second copy of that table which no compiler, test, or
    -- migration links back to the first. Its two drift directions are both
    -- bad and both silent: stale-lax accepts exactly the row this validation
    -- exists to refuse, and stale-strict refuses a level Go considers
    -- perfectly valid, with only another migration able to correct it. This
    -- codebase already rules on the general form of that trade in
    -- internal/store's package doc -- "a second, divergent implementation ...
    -- is worse than none" -- about WHERE tenant_id versus RLS; the argument
    -- transfers unchanged. internal/store.validateResourceLabelRule holds the
    -- semantic half, in Go, against Levels itself.
    --
    -- What that check is worth is a good error at the point of the typo, and
    -- R9 is explicit that this is "a better error message, not the
    -- enforcement": the enforcement is that a label the system cannot rank
    -- never reaches a permissive branch, which is Task 3's to close in
    -- CheckCap. Nothing here makes an unrankable hierarchy impossible
    -- downstream, and no comment in this file should ever say it does.
    CONSTRAINT resource_label_rules_hierarchy_level_present
        CHECK (length(hierarchy) > 0 AND length(level) > 0),

    -- UNIQUE ON (tenant_id, prefix) -- NOT (tenant_id, prefix, hierarchy),
    -- which is what the phase plan originally called for and which Task 1
    -- showed to be wrong before this table was built.
    --
    -- CheckCap consumes exactly ONE classification and ONE hierarchy per
    -- resource (pkg/classification/classification.go), so a resource cannot
    -- carry a label in two hierarchies at once. Keying on the triple would let
    -- a tenant register `/data/` under both `nato` and `commercial` -- a pair
    -- no resource can satisfy. Resolve refuses to resolve it (two rules on one
    -- prefix carrying different answers is ambiguity, and ambiguity denies),
    -- so the ONLY symptom is total silent denial under that prefix with
    -- nothing naming the cause. A table must not be able to express a
    -- configuration the decision path cannot consume.
    --
    -- This is also what makes Task 1's "ties cannot happen" true rather than
    -- assumed. Resolve does not rely on it -- it refuses ambiguity
    -- deterministically at its own boundary, because a schema constraint is
    -- not a runtime one and a stale read or a store bug can still hand it a
    -- pair this key excludes -- but that is a safety net, not a licence to
    -- leave the schema loose.
    --
    -- ONE HAZARD THIS KEY DOES NOT CLOSE, carried to Task 3: rules at
    -- DIFFERENT prefix lengths in different hierarchies. A `commercial` PUBLIC
    -- carve-out beneath a `nato` TOP-SECRET rule makes the resource escape the
    -- nato cap entirely -- arguably worse than a lowering, but it is not one,
    -- and reporting it as a lowering would put a false claim in R6's operator
    -- log line. Task 3 owns that ruling; this key neither creates nor fixes it.
    UNIQUE (tenant_id, prefix)
);
CREATE INDEX idx_resource_label_rules_tenant ON resource_label_rules(tenant_id);

-- No index on prefix, and the omission is deliberate rather than forgotten.
-- The read path loads a tenant's ENTIRE rule set in one unfiltered SELECT and
-- matches in Go; there is no per-row filter, no ordering requirement beyond
-- determinism, and no closest-match query to serve. An index built for prefix
-- matching (text_pattern_ops, or a LIKE/^@ predicate to use it) would be a
-- SECOND implementation of R5/R6's matching rules living in SQL, next to the
-- one in pkg/classification that is tested and mutation-verified -- and the
-- two would be free to disagree about the case-sensitivity, the tie rule, and
-- the empty-prefix catch-all that Resolve's own doc comment settles. Rule sets
-- are operator-authored and small; whole-set loading is what the tool catalog
-- and the policy set already do (loadToolCatalogQuery, loadAllPoliciesQuery).
--
-- No created_at/created_by columns either, for the reason
-- 000013_tool_catalog.up.sql states as a general principle: a column nothing
-- reads is the plumbed-but-never-populated field this project's house style
-- rules out. Unlike that table, this one has a writer from day one -- but N4
-- makes every write of it append an audit_chain row in the SAME transaction,
-- and that row already carries the actor and the timestamp. Duplicating them
-- here would create a second record that can disagree with the first.

ALTER TABLE resource_label_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_label_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON resource_label_rules
    USING (tenant_id = current_tenant())
    WITH CHECK (tenant_id = current_tenant());

-- The revocation-epoch trigger (spec §4.8.1 V1), attached HERE because
-- 000015_tenant_epoch_trigger.up.sql could not name a table that did not yet
-- exist: its own list is policies, agents, tool_catalog, tier_overrides
-- (INSERT/UPDATE/DELETE) and delegations (UPDATE/DELETE), and it does not
-- cover this one. Checked against that migration's own table list rather than
-- assumed, the same way 000018_spent_proofs.up.sql checked before recording
-- the opposite answer for itself.
--
-- This table needs it, and 000018's reasoning is exactly what says so: a
-- trigger belongs on a table when a write to it changes what a cached decision
-- would evaluate to. Relabelling `/data/` from RESTRICTED to TOP-SECRET
-- changes the outcome of every capped decision under that prefix, so a PEP
-- holding a cached ALLOW from one second earlier must be made to re-ask. A
-- labelling change that did not invalidate a cached decision would be a stale
-- authorization decision -- which is the whole point of the epoch.
--
-- The function itself is reused, not redefined: bump_tenant_epoch() from
-- 000015 is table-agnostic (it branches on TG_OP for OLD/NEW and reads
-- tenant_id), which is why that migration attaches one shared function five
-- times rather than writing five copies. FOR EACH ROW and all three verbs,
-- matching the four config tables there: an UPDATE that corrects a level and a
-- DELETE that removes a rule change a decision exactly as much as an INSERT
-- that adds one.
--
-- No new tenant_epoch grant is needed for either writer: 000015 already grants
-- SELECT, INSERT, UPDATE on tenant_epoch to stratium_app and 000016 grants the
-- same to stratium_pap, and the trigger runs as whichever role performed the
-- governed write (SECURITY INVOKER). Were such a grant ever missing, the
-- trigger's own upsert would fail inside the writing transaction and take the
-- write down with it -- fail-closed by construction, per 000015's own comment.
CREATE TRIGGER tenant_epoch_bump AFTER INSERT OR UPDATE OR DELETE ON resource_label_rules
    FOR EACH ROW EXECUTE FUNCTION bump_tenant_epoch();

-- T6/T1 and E7 (§4.6.1), the same ruling 000013_tool_catalog.up.sql makes for
-- the tool catalog: the PDP authenticates no callers -- its tenant comes from
-- startup configuration, never a verified caller identity (internal/store's
-- package doc) -- so a PDP that could write this table would be writing the
-- authorization configuration it then reads, which is spec defect D1. A
-- resource label is configuration in the strongest sense available here: it
-- decides what a resource IS, and a PDP that could edit it could relabel any
-- capped resource down to PUBLIC and allow itself anything.
--
-- INSERT, UPDATE and DELETE are absent below completely rather than partially
-- -- unlike 000012_approvals.up.sql, whose serving role legitimately keeps
-- INSERT for CreateApproval, and unlike 000018_spent_proofs.up.sql, which
-- argues its own PDP write grant is replay state rather than configuration.
-- Nothing about either of those licenses a write here.
--
-- The absent grants ARE the enforcement, and this codebase backs that claim
-- with a live database rather than a comment: see
-- TestIntegration_ResourceLabelRules_ServingRoleCanReadAndCannotWrite
-- (internal/store/resource_label_integration_test.go), which probes all three
-- verbs as the real stratium_app identity and asserts SQLSTATE 42501 for each,
-- after first proving SELECT works -- because a role that could read nothing
-- would make the write probes meaningless.
GRANT SELECT ON resource_label_rules TO stratium_app;

-- stratium_pap gets the full CRUD set, including DELETE, and that is granted
-- ahead of its caller on purpose: Task 4's own brief is "create, read, update,
-- delete for the rules" and it changes only services/cmd/stratium-pap/, so
-- every privilege it needs has to exist by the end of this migration.
-- 000016_stratium_pap_role.up.sql made the identical call for policies,
-- agents, and tier_overrides ("Task 3's own brief text is explicit... so
-- DELETE is what that task depends on this migration having already granted").
--
-- DELETE is right for this table in a way it was not for tool_catalog, where
-- 000016 withheld it because "a tenant that no longer wants a tool specially
-- classified can already correct the row via UPDATE." There is no such
-- correcting write here: a rule that should never have existed cannot be
-- neutralised by editing it, because every row that exists MATCHES something
-- (the empty prefix matches everything), and there is no "off" level. Removing
-- the row is the only way to un-label a subtree.
--
-- SELECT is not optional alongside the writes: Postgres requires SELECT on any
-- column a DML statement READS, including the id in an UPDATE's or DELETE's
-- own WHERE clause, and including tenant_id in the RLS policy above -- the
-- rule 000015 and 000016 each found live rather than reasoned to.
GRANT SELECT, INSERT, UPDATE, DELETE ON resource_label_rules TO stratium_pap;
