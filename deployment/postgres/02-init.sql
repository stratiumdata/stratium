-- Stratium Policy Administration Point (PAP) Database Schema
-- This schema supports ABAC policies and entitlements

-- Connect to the stratium_pap database
\c stratium_pap

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Policies Table
-- Stores XACML and OPA policy definitions
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    language VARCHAR(10) NOT NULL CHECK (language IN ('json', 'xacml', 'opa')),
    policy_content TEXT NOT NULL,
    effect VARCHAR(10) NOT NULL CHECK (effect IN ('allow', 'deny')),
    priority INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255),
    updated_by VARCHAR(255)
);

-- Entitlements Table
-- Stores attribute-based entitlements (what users can access)
CREATE TABLE IF NOT EXISTS entitlements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    subject_attributes JSONB,
    resource_attributes JSONB,
    actions JSONB,
    conditions JSONB,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Audit Logs Table
-- Tracks all changes and evaluations for policies and entitlements
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(50) NOT NULL CHECK (entity_type IN ('policy', 'entitlement')),
    entity_id UUID,
    action VARCHAR(50) NOT NULL CHECK (action IN ('create', 'update', 'delete', 'evaluate', 'test')),
    actor VARCHAR(255) NOT NULL,
    changes JSONB,
    result JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
CREATE INDEX IF NOT EXISTS idx_policies_language ON policies(language);
CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority DESC);
CREATE INDEX IF NOT EXISTS idx_policies_created_at ON policies(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_entitlements_enabled ON entitlements(enabled);
CREATE INDEX IF NOT EXISTS idx_entitlements_subject_attrs ON entitlements USING GIN (subject_attributes);
CREATE INDEX IF NOT EXISTS idx_entitlements_resource_attrs ON entitlements USING GIN (resource_attributes);
CREATE INDEX IF NOT EXISTS idx_entitlements_created_at ON entitlements(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor);

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers to auto-update updated_at
CREATE TRIGGER update_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_entitlements_updated_at
    BEFORE UPDATE ON entitlements
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- SEED DATA FOR POLICIES AND ENTITLEMENTS
-- ============================================================================
-- This section contains the default policies and entitlements for the Stratium
-- platform, demonstrating ABAC (Attribute-Based Access Control)

-- ============================================================================
-- POLICIES
-- ============================================================================

INSERT INTO policies (name, description, language, policy_content, effect, priority, created_by) VALUES
    -- Admin Full Access Policy
    ('admin-full-access', 'Administrators have full access to all resources', 'opa',
     'package stratium.authz

default allow = false

allow {
    input.subject.role == "admin"
}', 'allow', 100, 'system'),

    -- Department Read Isolation Policy
    ('department-read-isolation', 'Users can read resources in their department', 'opa',
     'package stratium.authz

default allow = false

allow {
    input.action == "read"
    input.subject.department == input.resource.department
}', 'allow', 80, 'system'),

    -- Department Editor Access Policy
    ('department-editor-access', 'Editors can create and update resources in their department', 'opa',
     'package stratium.authz

default allow = false

allowed_actions = {"create", "update", "read"}

allow {
    input.subject.role == "editor"
    input.subject.department == input.resource.department
    allowed_actions[input.action]
}', 'allow', 85, 'system'),

    -- Owner Write Access Policy
    ('owner-write-access', 'Resource owners can update and delete their own resources', 'opa',
     'package stratium.authz

default allow = false

allowed_actions = {"update", "delete", "read"}

allow {
    input.subject.user_id == input.resource.owner_id
    allowed_actions[input.action]
}', 'allow', 90, 'system'),

    -- Classification-Based Access Policy
    ('classification-based-access', 'Users can only access resources at or below their classification level', 'opa',
     'package stratium.authz

default allow = false

classification_levels := {
    "unclassified": 0,
    "confidential": 1,
    "secret": 2,
    "top-secret": 3
}

allow {
    subject_level := classification_levels[input.subject.classification]
    resource_level := classification_levels[input.resource.classification]
    subject_level >= resource_level
}', 'allow', 70, 'system');

-- ============================================================================
-- ENTITLEMENTS
-- ============================================================================

INSERT INTO entitlements (name, description, subject_attributes, resource_attributes, actions, created_by) VALUES
    -- Admin Dataset Full Access
    ('admin-dataset-full-access', 'Admins have full access to all datasets',
     '{"role": "admin"}',
     '{"resource_type": "dataset"}',
     '["create", "read", "update", "delete", "list"]',
     'system'),

    -- Admin User Management
    ('admin-user-management', 'Admins can manage all users',
     '{"role": "admin"}',
     '{"resource_type": "user"}',
     '["create", "read", "update", "delete", "list"]',
     'system'),

    -- Engineering Department Read Access
    ('engineering-read-access', 'Engineering department members can read engineering datasets',
     '{"department": "engineering"}',
     '{"resource_type": "dataset", "department": "engineering"}',
     '["read", "list"]',
     'system'),

    -- Engineering Department Editor Access
    ('engineering-editor-access', 'Engineering editors can create and modify engineering datasets',
     '{"department": "engineering", "role": "editor"}',
     '{"resource_type": "dataset", "department": "engineering"}',
     '["create", "read", "update", "list"]',
     'system'),

    -- Biology Department Read Access
    ('biology-read-access', 'Biology department members can read biology datasets',
     '{"department": "biology"}',
     '{"resource_type": "dataset", "department": "biology"}',
     '["read", "list"]',
     'system'),

    -- Biology Department Editor Access
    ('biology-editor-access', 'Biology editors can create and modify biology datasets',
     '{"department": "biology", "role": "editor"}',
     '{"resource_type": "dataset", "department": "biology"}',
     '["create", "read", "update", "list"]',
     'system'),

    -- Physics Department Read Access
    ('physics-read-access', 'Physics department members can read physics datasets',
     '{"department": "physics"}',
     '{"resource_type": "dataset", "department": "physics"}',
     '["read", "list"]',
     'system'),

    -- Physics Department Editor Access
    ('physics-editor-access', 'Physics editors can create and modify physics datasets',
     '{"department": "physics", "role": "editor"}',
     '{"resource_type": "dataset", "department": "physics"}',
     '["create", "read", "update", "list"]',
     'system'),

    -- Chemistry Department Read Access
    ('chemistry-read-access', 'Chemistry department members can read chemistry datasets',
     '{"department": "chemistry"}',
     '{"resource_type": "dataset", "department": "chemistry"}',
     '["read", "list"]',
     'system'),

    -- Chemistry Department Editor Access
    ('chemistry-editor-access', 'Chemistry editors can create and modify chemistry datasets',
     '{"department": "chemistry", "role": "editor"}',
     '{"resource_type": "dataset", "department": "chemistry"}',
     '["create", "read", "update", "list"]',
     'system'),

    -- Data Science Department Read Access
    ('data-science-read-access', 'Data science department members can read data science datasets',
     '{"department": "data-science"}',
     '{"resource_type": "dataset", "department": "data-science"}',
     '["read", "list"]',
     'system'),

    -- Data Science Department Editor Access
    ('data-science-editor-access', 'Data science editors can create and modify data science datasets',
     '{"department": "data-science", "role": "editor"}',
     '{"resource_type": "dataset", "department": "data-science"}',
     '["create", "read", "update", "list"]',
     'system'),

    -- Cross-Department Viewer Access
    ('viewer-read-only', 'Viewers can only read resources in their department',
     '{"role": "viewer"}',
     '{"resource_type": "dataset"}',
     '["read", "list"]',
     'system');

-- Grant permissions to stratium user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO stratium;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO stratium;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO stratium;