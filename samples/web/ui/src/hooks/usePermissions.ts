import { useMemo } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { useEntitlements } from './useEntitlements';
import type { Dataset, Permissions } from '@/types';

/**
 * Hook to determine user permissions for datasets based on dynamic entitlements from Platform service
 * Uses the Platform service to fetch real-time entitlements instead of static role checks
 */
export const usePermissions = (dataset?: Dataset): Permissions => {
  const { user } = useAuth();
  const { permissions, hasEntitlement } = useEntitlements();

  return useMemo(() => {
    if (!user) {
      return {
        canView: false,
        canEdit: false,
        canDelete: false,
        canCreate: false,
      };
    }

    // For general create permission (no specific dataset)
    if (!dataset) {
      return {
        canView: permissions.canReadDatasets,
        canEdit: false,
        canDelete: false,
        canCreate: permissions.canCreateDatasets,
      };
    }

    // For specific dataset, check entitlements
    const canViewDataset = hasEntitlement('dataset', 'read') || hasEntitlement(dataset.id, 'read');
    const canEditDataset = hasEntitlement('dataset', 'update') || hasEntitlement(dataset.id, 'update');
    const canDeleteDataset = hasEntitlement('dataset', 'delete') || hasEntitlement(dataset.id, 'delete');

    return {
      canView: canViewDataset,
      canEdit: canEditDataset,
      canDelete: canDeleteDataset,
      canCreate: permissions.canCreateDatasets,
    };
  }, [user, dataset, permissions, hasEntitlement]);
};

/**
 * Hook for general role-based permissions using dynamic entitlements
 */
export const useRolePermissions = () => {
  const { user } = useAuth();
  const { permissions } = useEntitlements();

  return useMemo(() => ({
    isAdmin: user?.role === 'admin',
    isEditor: user?.role === 'editor' || user?.role === 'admin',
    isViewer: !!user,
    canManageUsers: permissions.canManageUsers,
    canCreateDatasets: permissions.canCreateDatasets,
    canUseFilters: permissions.canViewFilters,
  }), [user, permissions]);
};