-- Cedar Policy Language Integration
-- Migration: 001_cedar_tables

-- Add "cedar" to the policies table language constraint
ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_language_check;
ALTER TABLE policies ADD CONSTRAINT policies_language_check
    CHECK (language IN ('json', 'xacml', 'opa', 'cedar'));

-- Cedar schemas (admin-managed)
CREATE TABLE IF NOT EXISTS cedar_schemas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',
    schema_content TEXT NOT NULL,
    schema_format VARCHAR(10) NOT NULL CHECK (schema_format IN ('json', 'cedar')),
    version VARCHAR(50) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) DEFAULT '',
    updated_by VARCHAR(255) DEFAULT '',
    UNIQUE(namespace, name, version)
);

-- Cedar policy templates
CREATE TABLE IF NOT EXISTS cedar_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',
    template_content TEXT NOT NULL,
    schema_id UUID REFERENCES cedar_schemas(id) ON DELETE SET NULL,
    namespace VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) DEFAULT '',
    updated_by VARCHAR(255) DEFAULT ''
);

-- Template-linked policies (instantiated from templates)
CREATE TABLE IF NOT EXISTS cedar_linked_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES cedar_templates(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    principal_entity VARCHAR(512) DEFAULT '',
    resource_entity VARCHAR(512) DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) DEFAULT ''
);

-- Cached Cedar entities (static hierarchy data)
CREATE TABLE IF NOT EXISTS cedar_entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_uid VARCHAR(512) NOT NULL UNIQUE,
    entity_type VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}',
    parents JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add optional schema_id to policies table for Cedar policies
ALTER TABLE policies ADD COLUMN IF NOT EXISTS schema_id UUID REFERENCES cedar_schemas(id) ON DELETE SET NULL;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS template_id UUID REFERENCES cedar_templates(id) ON DELETE SET NULL;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cedar_entities_namespace ON cedar_entities(namespace);
CREATE INDEX IF NOT EXISTS idx_cedar_entities_type ON cedar_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_cedar_schemas_namespace ON cedar_schemas(namespace, is_active);
CREATE INDEX IF NOT EXISTS idx_cedar_templates_namespace ON cedar_templates(namespace);
CREATE INDEX IF NOT EXISTS idx_cedar_linked_policies_template ON cedar_linked_policies(template_id);
CREATE INDEX IF NOT EXISTS idx_policies_schema_id ON policies(schema_id) WHERE schema_id IS NOT NULL;
