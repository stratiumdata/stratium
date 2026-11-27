-- What a visitor finds in the demo tenant: one agent, the policy that lets the
-- shared demo login delegate to it, and a classification ceiling to run into.
-- The same shape deploy/stratium's quickstart builds locally, so
-- docs/quickstart.md and docs/demo.md show the same decisions.
--
-- Run by ./seed.sh after the tool catalog seeds, as the migration role, with
-- -v tenant_id=demo. Safe to run again: every statement skips what exists.
--
-- SQL and not the admin API, for one reason: the walkthrough needs the
-- agent's id, the admin UI does not show ids, and only an INSERT can choose
-- one. A fixed id stays true across every reset.
SELECT set_config('app.tenant_id', :'tenant_id', false);

-- The agent every visitor's session acts as. Capped at CONFIDENTIAL in the
-- "nato" hierarchy, which the label rules below give meaning to.
INSERT INTO agents (id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools, classification_caps, resource_constraints)
VALUES ('7d1f3c52-9a4e-4b0e-8c1d-5e2a6f0b9d31', :'tenant_id', 'demo-agent', 'anthropic', 'claude', 3, true, false, '[]', '{"nato": "CONFIDENTIAL"}', '{}')
ON CONFLICT (id) DO NOTHING;

-- Without a policy naming the principal, no delegation can be issued at all.
-- effect is the fixed placeholder a Rego policy carries (it can produce either
-- outcome per request). Protected, so a visitor cannot edit or disable the one
-- row every other visitor's session depends on.
INSERT INTO policies (tenant_id, name, description, language, effect, enabled, protected, policy_content)
VALUES (:'tenant_id', 'demo-grant', 'Lets the shared demo login hold tools and delegate them to an agent.', 'rego', 'deny', true, true,
E'package stratium.policy\n\nallow if {\n\tinput.principal.subject == "demo@example.com"\n}')
ON CONFLICT (tenant_id, name) DO NOTHING;

-- The catch-all first: once an agent has a cap, a resource with no label is
-- denied, so without it the cap above would deny nearly everything. /tmp and
-- /private/tmp are both listed because macOS resolves one to the other and
-- the match is on the path string the tool call carries.
INSERT INTO resource_label_rules (tenant_id, prefix, hierarchy, level) VALUES
    (:'tenant_id', '', 'nato', 'UNCLASSIFIED'),
    (:'tenant_id', '/tmp/secret-', 'nato', 'SECRET'),
    (:'tenant_id', '/private/tmp/secret-', 'nato', 'SECRET')
ON CONFLICT (tenant_id, prefix) DO NOTHING;
