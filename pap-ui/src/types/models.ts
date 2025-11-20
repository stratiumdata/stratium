export interface Policy {
  id: string;
  name: string;
  description: string;
  language: 'json' | 'opa' | 'xacml';
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
