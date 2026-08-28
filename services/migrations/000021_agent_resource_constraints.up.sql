-- 000021_agent_resource_constraints.up.sql
--
-- resource_constraints on the agent is the template a root delegation's own
-- resource_constraints is copied from at issuance. Before this column,
-- issuance hardcoded an empty map (internal/pdpgrpc/delegation.go) and an
-- empty map is checkResourceConstraints' unrestricted case, so scope
-- enforcement could not be switched on through any supported interface --
-- exactly the shape 000020 fixed for classification_caps.
--
-- The DEFAULT exists only to backfill existing rows and is dropped
-- immediately after, matching 000020 and 000001_baseline's refusal to give
-- delegations.approved_tools a default: an INSERT must state its intent
-- rather than inherit a silent one.
ALTER TABLE agents
    ADD COLUMN resource_constraints JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE agents
    ALTER COLUMN resource_constraints DROP DEFAULT;
