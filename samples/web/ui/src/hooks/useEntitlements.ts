import { useQuery } from '@tanstack/react-query';
import { useMemo, useCallback } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { platformClient, type EntitlementData } from '@/lib/platform-client';

type Entitlement = EntitlementData;

export interface EntitlementPermissions {
  canCreateDatasets: boolean;
  canDeleteDatasets: boolean;
  canUpdateDatasets: boolean;
  canReadDatasets: boolean;
  canManageUsers: boolean;
  canViewUsers: boolean;
  canViewFilters: boolean;
}

export const useEntitlements = () => {
  const { user, isAuthenticated } = useAuth();

  const { data: entitlements, isLoading, error } = useQuery<Entitlement[]>({
    queryKey: ['entitlements', user?.id],
    queryFn: async () => {
      if (!user) throw new Error('User not authenticated');

      return platformClient.getUserEntitlements(
        user.id,
        user.email,
        user.department || '',
        user.role || 'viewer'
      );
    },
    enabled: isAuthenticated && !!user,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  });

  // Parse entitlements into permissions - memoized to prevent unnecessary re-renders
  const permissions: EntitlementPermissions = useMemo(() => {
    const perms: EntitlementPermissions = {
      canCreateDatasets: false,
      canDeleteDatasets: false,
      canUpdateDatasets: false,
      canReadDatasets: false,
      canManageUsers: false,
      canViewUsers: false,
      canViewFilters: false,
    };

    if (entitlements) {
      entitlements.forEach((ent) => {
        // WORKAROUND: Platform service bug - active field is always false and resource field is empty
        // The Platform service returns "active entitlements" but sets active=false in protobuf
        // We'll check metadata for resource_type as a workaround

        // Try to get resource type from metadata or resource field
        const resourceType = ent.metadata?.resource_type || ent.resource;

        // Check for dataset permissions
        if (resourceType === 'dataset' || resourceType.includes('dataset')) {
          if (ent.actions.includes('create')) perms.canCreateDatasets = true;
          if (ent.actions.includes('delete')) perms.canDeleteDatasets = true;
          if (ent.actions.includes('update') || ent.actions.includes('write')) perms.canUpdateDatasets = true;
          if (ent.actions.includes('read')) perms.canReadDatasets = true;
          if (ent.actions.includes('filter')) perms.canViewFilters = true;
        }

        // Check for user permissions
        if (resourceType === 'user' || resourceType.includes('user')) {
          if (ent.actions.includes('create') || ent.actions.includes('update') || ent.actions.includes('delete')) {
            perms.canManageUsers = true;
          }
          if (ent.actions.includes('read')) perms.canViewUsers = true;
        }
      });
    }

    return perms;
  }, [entitlements]);

  const hasEntitlement = useCallback((resource: string, action: string) => {
    return entitlements?.some(
      (ent) => ent.active && ent.resource === resource && ent.actions.includes(action)
    ) || false;
  }, [entitlements]);

  return {
    entitlements: entitlements || [],
    permissions,
    isLoading,
    error,
    hasEntitlement,
  };
};