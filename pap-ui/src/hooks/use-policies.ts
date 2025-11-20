/**
 * React Query hooks for Policy management
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getApiClient } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';
import type { Policy } from '@/types/models';

export const POLICIES_QUERY_KEY = ['policies'];

// List policies
export const usePolicies = (params?: {
  limit?: number;
  offset?: number;
  language?: string;
  enabled?: boolean;
  search?: string;
}) => {
  return useQuery({
    queryKey: [...POLICIES_QUERY_KEY, 'list', params],
    queryFn: () => getApiClient().listPolicies(params),
  });
};

// Get single policy
export const usePolicy = (id: string) => {
  return useQuery({
    queryKey: [...POLICIES_QUERY_KEY, id],
    queryFn: () => getApiClient().getPolicy(id),
    enabled: !!id && id !== 'new',
  });
};

// Create policy
export const useCreatePolicy = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (data: {
      name: string;
      description: string;
      language: 'json' | 'opa' | 'xacml';
      policy_content: string;
      effect: 'allow' | 'deny';
      priority: number;
      enabled: boolean;
    }) => getApiClient().createPolicy(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: POLICIES_QUERY_KEY });
      toast({
        title: 'Policy created',
        description: 'The policy has been successfully created.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to create policy',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

// Update policy
export const useUpdatePolicy = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: ({ id, data }: {
      id: string;
      data: Partial<{
        name: string;
        description: string;
        language: 'json' | 'opa' | 'xacml';
        policy_content: string;
        effect: 'allow' | 'deny';
        priority: number;
        enabled: boolean;
      }>;
    }) => getApiClient().updatePolicy(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: POLICIES_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: [...POLICIES_QUERY_KEY, variables.id] });
      toast({
        title: 'Policy updated',
        description: 'The policy has been successfully updated.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to update policy',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

// Delete policy
export const useDeletePolicy = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (id: string) => getApiClient().deletePolicy(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: POLICIES_QUERY_KEY });
      toast({
        title: 'Policy deleted',
        description: 'The policy has been successfully deleted.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to delete policy',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

// Validate policy
export const useValidatePolicy = () => {
  const { toast } = useToast();

  return useMutation({
    mutationFn: ({ language, policyContent }: { language: string; policyContent: string }) =>
      getApiClient().validatePolicy(language, policyContent),
    onError: (error: Error) => {
      toast({
        title: 'Validation failed',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

// Test policy
export const useTestPolicy = () => {
  const { toast } = useToast();

  return useMutation({
    mutationFn: (data: {
      language: string;
      policy_content: string;
      subject_attributes: Record<string, any>;
      resource_attributes: Record<string, any>;
      action: string;
      environment?: Record<string, any>;
    }) => getApiClient().testPolicy(data),
    onError: (error: Error) => {
      toast({
        title: 'Test failed',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};