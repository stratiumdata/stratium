/**
 * PAP API Client
 * Handles all HTTP requests to the PAP API with Keycloak authentication
 */

import Keycloak from 'keycloak-js';
import type { Policy, Entitlement, AuditLog, CedarSchema, CedarTemplate, CedarLinkedPolicy, CedarTestResult } from '@/types/models';

const API_BASE_URL = import.meta.env.VITE_PAP_API_URL || '';

export class ApiClient {
  private keycloak: Keycloak;

  constructor(keycloak: Keycloak) {
    this.keycloak = keycloak;
  }

  private async getAuthHeaders(): Promise<HeadersInit> {
    if (this.keycloak?.updateToken) {
      await this.keycloak.updateToken(30);
    }

    return {
      'Content-Type': 'application/json',
      ...(this.keycloak?.token ? { 'Authorization': `Bearer ${this.keycloak.token}` } : {}),
    };
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers = await this.getAuthHeaders();

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        ...headers,
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: response.statusText }));
      throw new Error(error.error || `HTTP ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }

  // ==================== Policies ====================

  async listPolicies(params?: {
    limit?: number;
    offset?: number;
    language?: string;
    enabled?: boolean;
    search?: string;
  }) {
    const query = new URLSearchParams();
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset) query.append('offset', params.offset.toString());
    if (params?.language) query.append('language', params.language);
    if (params?.enabled !== undefined) query.append('enabled', params.enabled.toString());
    if (params?.search) query.append('search', params.search);

    return this.request<{
      policies: Policy[];
      total: number;
      limit: number;
      offset: number;
    }>(`/api/v1/policies?${query}`);
  }

  async getPolicy(id: string) {
    return this.request<Policy>(`/api/v1/policies/${id}`);
  }

  async createPolicy(data: {
    name: string;
    description: string;
    language: 'json' | 'opa' | 'xacml' | 'cedar';
    policy_content: string;
    effect: 'allow' | 'deny';
    priority: number;
    enabled: boolean;
  }) {
    return this.request<Policy>('/api/v1/policies', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updatePolicy(id: string, data: Partial<{
    name: string;
    description: string;
    language: 'json' | 'opa' | 'xacml' | 'cedar';
    policy_content: string;
    effect: 'allow' | 'deny';
    priority: number;
    enabled: boolean;
  }>) {
    return this.request<Policy>(`/api/v1/policies/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deletePolicy(id: string) {
    return this.request<{ message: string }>(`/api/v1/policies/${id}`, {
      method: 'DELETE',
    });
  }

  async validatePolicy(language: string, policyContent: string) {
    return this.request<{
      valid: boolean;
      error?: string;
      syntax: string;
    }>('/api/v1/policies/validate', {
      method: 'POST',
      body: JSON.stringify({
        language,
        policy_content: policyContent,
      }),
    });
  }

  async testPolicy(data: {
    language: string;
    policy_content: string;
    subject_attributes: Record<string, any>;
    resource_attributes: Record<string, any>;
    action: string;
    environment?: Record<string, any>;
  }) {
    return this.request<{
      test_result: {
        allow: boolean;
        reason: string;
      };
      input: any;
    }>('/api/v1/policies/test', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // ==================== Entitlements ====================

  async listEntitlements(params?: {
    limit?: number;
    offset?: number;
    enabled?: boolean;
    search?: string;
  }) {
    const query = new URLSearchParams();
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset) query.append('offset', params.offset.toString());
    if (params?.enabled !== undefined) query.append('enabled', params.enabled.toString());
    if (params?.search) query.append('search', params.search);

    return this.request<{
      entitlements: Entitlement[];
      total: number;
      limit: number;
      offset: number;
    }>(`/api/v1/entitlements?${query}`);
  }

  async getEntitlement(id: string) {
    return this.request<Entitlement>(`/api/v1/entitlements/${id}`);
  }

  async createEntitlement(data: {
    name: string;
    description: string;
    subject_attributes: Record<string, any>;
    resource_attributes: Record<string, any>;
    actions: string[];
    conditions?: Record<string, any>;
    enabled: boolean;
    expires_at?: string;
  }) {
    return this.request<Entitlement>('/api/v1/entitlements', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateEntitlement(id: string, data: Partial<{
    name: string;
    description: string;
    subject_attributes: Record<string, any>;
    resource_attributes: Record<string, any>;
    actions: string[];
    conditions: Record<string, any>;
    enabled: boolean;
    expires_at: string;
  }>) {
    return this.request<Entitlement>(`/api/v1/entitlements/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteEntitlement(id: string) {
    return this.request<{ message: string }>(`/api/v1/entitlements/${id}`, {
      method: 'DELETE',
    });
  }

  // ==================== Audit Logs ====================

  async listAuditLogs(params?: {
    limit?: number;
    offset?: number;
    entity_type?: string;
    entity_id?: string;
    action?: string;
    actor?: string;
    start_date?: string;
    end_date?: string;
  }) {
    const query = new URLSearchParams();
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset) query.append('offset', params.offset.toString());
    if (params?.entity_type) query.append('entity_type', params.entity_type);
    if (params?.entity_id) query.append('entity_id', params.entity_id);
    if (params?.action) query.append('action', params.action);
    if (params?.actor) query.append('actor', params.actor);
    if (params?.start_date) query.append('start_date', params.start_date);
    if (params?.end_date) query.append('end_date', params.end_date);

    return this.request<{
      audit_logs: AuditLog[];
      total: number;
      limit: number;
      offset: number;
    }>(`/api/v1/audit-logs?${query}`);
  }

  async getAuditLog(id: string) {
    return this.request<AuditLog>(`/api/v1/audit-logs/${id}`);
  }
  // ==================== Cedar Schemas ====================

  async listCedarSchemas(namespace?: string) {
    const query = new URLSearchParams();
    if (namespace) query.append('namespace', namespace);

    return this.request<{
      schemas: CedarSchema[];
      total: number;
    }>(`/api/v1/cedar/schemas?${query}`);
  }

  async getCedarSchema(id: string) {
    return this.request<CedarSchema>(`/api/v1/cedar/schemas/${id}`);
  }

  async createCedarSchema(data: {
    namespace: string;
    name: string;
    description: string;
    schema_content: string;
    schema_format: 'json' | 'cedar';
    version: string;
  }) {
    return this.request<CedarSchema>('/api/v1/cedar/schemas', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateCedarSchema(id: string, data: Partial<{
    name: string;
    description: string;
    schema_content: string;
    schema_format: 'json' | 'cedar';
    version: string;
    is_active: boolean;
  }>) {
    return this.request<CedarSchema>(`/api/v1/cedar/schemas/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteCedarSchema(id: string) {
    return this.request<{ message: string }>(`/api/v1/cedar/schemas/${id}`, {
      method: 'DELETE',
    });
  }

  async validateAgainstSchema(schemaId: string, policyContent: string) {
    return this.request<{ valid: boolean; error?: string; schema_id: string }>(
      `/api/v1/cedar/schemas/${schemaId}/validate`,
      {
        method: 'POST',
        body: JSON.stringify({ policy_content: policyContent }),
      }
    );
  }

  // ==================== Cedar Templates ====================

  async listCedarTemplates(namespace?: string) {
    const query = new URLSearchParams();
    if (namespace) query.append('namespace', namespace);

    return this.request<{
      templates: CedarTemplate[];
      total: number;
    }>(`/api/v1/cedar/templates?${query}`);
  }

  async getCedarTemplate(id: string) {
    return this.request<CedarTemplate>(`/api/v1/cedar/templates/${id}`);
  }

  async createCedarTemplate(data: {
    name: string;
    description: string;
    template_content: string;
    schema_id?: string;
    namespace: string;
  }) {
    return this.request<CedarTemplate>('/api/v1/cedar/templates', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async deleteCedarTemplate(id: string) {
    return this.request<{ message: string }>(`/api/v1/cedar/templates/${id}`, {
      method: 'DELETE',
    });
  }

  async instantiateTemplate(templateId: string, data: {
    principal_entity: string;
    resource_entity: string;
  }) {
    return this.request<{
      linked_policy: CedarLinkedPolicy;
      policy: Policy;
    }>(`/api/v1/cedar/templates/${templateId}/instantiate`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async listLinkedPolicies(templateId: string) {
    return this.request<{
      linked_policies: CedarLinkedPolicy[];
      total: number;
    }>(`/api/v1/cedar/templates/${templateId}/linked`);
  }

  // ==================== Cedar Testing ====================

  async testCedarPolicy(data: {
    policy_content: string;
    subject_attributes: Record<string, any>;
    resource_attributes: Record<string, any>;
    action: string;
    environment?: Record<string, any>;
    namespace?: string;
  }) {
    return this.request<CedarTestResult>('/api/v1/cedar/test', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async batchTestCedarPolicy(data: {
    policy_content: string;
    requests: Array<{
      subject_attributes: Record<string, any>;
      resource_attributes: Record<string, any>;
      action: string;
      environment?: Record<string, any>;
      namespace?: string;
    }>;
  }) {
    return this.request<{
      results: CedarTestResult[];
      total: number;
    }>('/api/v1/cedar/batch-test', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }
}

// Create a singleton instance that will be initialized with Keycloak
let apiClientInstance: ApiClient | null = null;

export const initializeApiClient = (keycloak: Keycloak) => {
  apiClientInstance = new ApiClient(keycloak);
  return apiClientInstance;
};

export const getApiClient = (): ApiClient => {
  if (!apiClientInstance) {
    throw new Error('API client not initialized. Call initializeApiClient first.');
  }
  return apiClientInstance;
};