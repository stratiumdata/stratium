/**
 * React Query hooks for Audit Log management
 */

import { useQuery } from '@tanstack/react-query';
import { getApiClient } from '@/lib/api-client';

export const AUDIT_LOGS_QUERY_KEY = ['audit-logs'];

export const useAuditLogs = (params?: {
  limit?: number;
  offset?: number;
  entity_type?: string;
  entity_id?: string;
  action?: string;
  actor?: string;
  start_date?: string;
  end_date?: string;
}) => {
  return useQuery({
    queryKey: [...AUDIT_LOGS_QUERY_KEY, 'list', params],
    queryFn: () => getApiClient().listAuditLogs(params),
  });
};

export const useAuditLog = (id: string) => {
  return useQuery({
    queryKey: [...AUDIT_LOGS_QUERY_KEY, id],
    queryFn: () => getApiClient().getAuditLog(id),
    enabled: !!id,
  });
};