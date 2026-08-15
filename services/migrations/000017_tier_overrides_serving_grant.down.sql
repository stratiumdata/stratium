-- Rolling this back leaves the PDP unable to read tier_overrides at all, at
-- which point LoadTierOverrides fails with insufficient_privilege and
-- pdpgrpc.Decide denies-and-audits rather than deciding without the tenant's
-- overrides — fail-closed, matching how a tool_catalog load failure already
-- behaves on that path. That is the correct direction for a rollback of a
-- read the decision path depends on: an override exists to RAISE a tier, so
-- silently proceeding without one would under-rate exactly the actions a
-- tenant took the trouble to mark as more sensitive.
REVOKE SELECT ON tier_overrides FROM stratium_app;
