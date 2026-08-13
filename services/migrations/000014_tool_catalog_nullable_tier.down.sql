ALTER TABLE tool_catalog DROP CONSTRAINT tool_catalog_tier_or_command_field;
ALTER TABLE tool_catalog ALTER COLUMN action_tier SET NOT NULL;
