/**
 * React Query hooks for Entitlement management
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getApiClient } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';

export const ENTITLEMENTS_QUERY_KEY = ['entitlements'];

export const useEntitlements = (params?: {
  limit?: number;
  offset?: number;
  enabled?: boolean;
  search?: string;
}) => {
  return useQuery({
    queryKey: [...ENTITLEMENTS_QUERY_KEY, 'list', params],
    queryFn: () => getApiClient().listEntitlements(params),
  });
};

export const useEntitlement = (id: string) => {
  return useQuery({
    queryKey: [...ENTITLEMENTS_QUERY_KEY, id],
    queryFn: () => getApiClient().getEntitlement(id),
    enabled: !!id && id !== 'new',
  });
};

export const useCreateEntitlement = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (data: {
      name: string;
      description: string;
      subject_attributes: Record<string, any>;
      resource_attributes: Record<string, any>;
      actions: string[];
      conditions?: Record<string, any>;
      enabled: boolean;
      expires_at?: string;
    }) => getApiClient().createEntitlement(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ENTITLEMENTS_QUERY_KEY });
      toast({
        title: 'Entitlement created',
        description: 'The entitlement has been successfully created.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to create entitlement',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

export const useUpdateEntitlement = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: ({ id, data }: {
      id: string;
      data: Partial<{
        name: string;
        description: string;
        subject_attributes: Record<string, any>;
        resource_attributes: Record<string, any>;
        actions: string[];
        conditions: Record<string, any>;
        enabled: boolean;
        expires_at: string;
      }>;
    }) => getApiClient().updateEntitlement(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ENTITLEMENTS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: [...ENTITLEMENTS_QUERY_KEY, variables.id] });
      toast({
        title: 'Entitlement updated',
        description: 'The entitlement has been successfully updated.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to update entitlement',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

export const useDeleteEntitlement = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (id: string) => getApiClient().deleteEntitlement(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ENTITLEMENTS_QUERY_KEY });
      toast({
        title: 'Entitlement deleted',
        description: 'The entitlement has been successfully deleted.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to delete entitlement',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};