import { Policy, Entitlement, AuditLog } from '@/types/models';

const STORAGE_KEYS = {
  POLICIES: 'policyhub_policies',
  ENTITLEMENTS: 'policyhub_entitlements',
  AUDIT_LOGS: 'policyhub_audit_logs',
};

// Helper to create audit log
export const createAuditLog = (
  entityId: string,
  entityType: string,
  action: string,
  actor: string,
  changes: Record<string, any>,
  result?: Record<string, any>
): AuditLog => {
  return {
    id: crypto.randomUUID(),
    entity_id: entityId,
    entity_type: entityType,
    action,
    actor,
    changes,
    result,
    timestamp: new Date().toISOString(),
    ip_address: 'N/A',
    user_agent: navigator.userAgent,
  };
};

// Policies
export const getPolicies = (): Policy[] => {
  const data = localStorage.getItem(STORAGE_KEYS.POLICIES);
  return data ? JSON.parse(data) : [];
};

export const savePolicy = (policy: Policy, actor: string): void => {
  const policies = getPolicies();
  const existingIndex = policies.findIndex(p => p.id === policy.id);
  
  if (existingIndex >= 0) {
    const oldPolicy = policies[existingIndex];
    policies[existingIndex] = policy;
    addAuditLog(createAuditLog(policy.id, 'policy', 'update', actor, { old: oldPolicy, new: policy }));
  } else {
    policies.push(policy);
    addAuditLog(createAuditLog(policy.id, 'policy', 'create', actor, { new: policy }));
  }
  
  localStorage.setItem(STORAGE_KEYS.POLICIES, JSON.stringify(policies));
};

export const deletePolicy = (id: string, actor: string): void => {
  const policies = getPolicies();
  const policy = policies.find(p => p.id === id);
  const filtered = policies.filter(p => p.id !== id);
  localStorage.setItem(STORAGE_KEYS.POLICIES, JSON.stringify(filtered));
  
  if (policy) {
    addAuditLog(createAuditLog(id, 'policy', 'delete', actor, { deleted: policy }));
  }
};

// Entitlements
export const getEntitlements = (): Entitlement[] => {
  const data = localStorage.getItem(STORAGE_KEYS.ENTITLEMENTS);
  return data ? JSON.parse(data) : [];
};

export const saveEntitlement = (entitlement: Entitlement, actor: string): void => {
  const entitlements = getEntitlements();
  const existingIndex = entitlements.findIndex(e => e.id === entitlement.id);
  
  if (existingIndex >= 0) {
    const oldEntitlement = entitlements[existingIndex];
    entitlements[existingIndex] = entitlement;
    addAuditLog(createAuditLog(entitlement.id, 'entitlement', 'update', actor, { old: oldEntitlement, new: entitlement }));
  } else {
    entitlements.push(entitlement);
    addAuditLog(createAuditLog(entitlement.id, 'entitlement', 'create', actor, { new: entitlement }));
  }
  
  localStorage.setItem(STORAGE_KEYS.ENTITLEMENTS, JSON.stringify(entitlements));
};

export const deleteEntitlement = (id: string, actor: string): void => {
  const entitlements = getEntitlements();
  const entitlement = entitlements.find(e => e.id === id);
  const filtered = entitlements.filter(e => e.id !== id);
  localStorage.setItem(STORAGE_KEYS.ENTITLEMENTS, JSON.stringify(filtered));
  
  if (entitlement) {
    addAuditLog(createAuditLog(id, 'entitlement', 'delete', actor, { deleted: entitlement }));
  }
};

// Audit Logs
export const getAuditLogs = (): AuditLog[] => {
  const data = localStorage.getItem(STORAGE_KEYS.AUDIT_LOGS);
  return data ? JSON.parse(data) : [];
};

const addAuditLog = (log: AuditLog): void => {
  const logs = getAuditLogs();
  logs.unshift(log); // Add to beginning
  localStorage.setItem(STORAGE_KEYS.AUDIT_LOGS, JSON.stringify(logs));
};
