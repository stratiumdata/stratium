export interface Policy {
  id: string;
  name: string;
  description: string;
  language: 'json' | 'opa' | 'xacml' | 'cedar';
  policy_content: string;
  effect: 'allow' | 'deny';
  priority: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
}

export interface Entitlement {
  id: string;
  name: string;
  description: string;
  subject_attributes: Record<string, any>;
  resource_attributes: Record<string, any>;
  actions: string[];
  conditions: Record<string, any>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
  expires_at?: string;
}

export interface CedarSchema {
  id: string;
  namespace: string;
  name: string;
  description: string;
  schema_content: string;
  schema_format: 'json' | 'cedar';
  version: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
}

export interface CedarTemplate {
  id: string;
  name: string;
  description: string;
  template_content: string;
  schema_id?: string;
  namespace: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
}

export interface CedarLinkedPolicy {
  id: string;
  template_id: string;
  policy_id: string;
  principal_entity: string;
  resource_entity: string;
  created_at: string;
  created_by: string;
}

export interface CedarTestResult {
  decision: 'allow' | 'deny' | 'error';
  reason: string;
  details: Record<string, any>;
  error?: string;
}

export interface AuditLog {
  id: string;
  entity_id: string;
  entity_type: string;
  action: string;
  actor: string;
  changes: Record<string, any>;
  result?: Record<string, any>;
  timestamp: string;
  ip_address?: string;
  user_agent?: string;
}
