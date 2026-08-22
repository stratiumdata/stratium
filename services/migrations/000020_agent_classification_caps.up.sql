-- 000020_agent_classification_caps.up.sql
--
-- classification_caps on the agent is the template a root delegation's own
-- classification_caps is copied from at issuance. Before this column, issuance
-- hardcoded an empty map (internal/pdpgrpc/delegation.go) and an empty map is
-- CheckCap's allow-everything case, so classification enforcement could not be
-- switched on through any supported interface.
--
-- The DEFAULT exists only to backfill existing rows and is dropped immediately
-- after, matching 000001_baseline.up.sql's refusal to give
-- delegations.approved_tools or delegations.classification_caps a default: an
-- INSERT must state its intent rather than inherit a silent one.
ALTER TABLE agents
    ADD COLUMN classification_caps JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE agents
    ALTER COLUMN classification_caps DROP DEFAULT;
