/**
 * React Query hooks for Cedar Schema management
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getApiClient } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';

export const CEDAR_SCHEMAS_QUERY_KEY = ['cedar-schemas'];

export const useCedarSchemas = (namespace?: string) => {
  return useQuery({
    queryKey: [...CEDAR_SCHEMAS_QUERY_KEY, 'list', namespace],
    queryFn: () => getApiClient().listCedarSchemas(namespace),
  });
};

export const useCedarSchema = (id: string) => {
  return useQuery({
    queryKey: [...CEDAR_SCHEMAS_QUERY_KEY, id],
    queryFn: () => getApiClient().getCedarSchema(id),
    enabled: !!id && id !== 'new',
  });
};

export const useCreateCedarSchema = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (data: {
      namespace: string;
      name: string;
      description: string;
      schema_content: string;
      schema_format: 'json' | 'cedar';
      version: string;
    }) => getApiClient().createCedarSchema(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CEDAR_SCHEMAS_QUERY_KEY });
      toast({
        title: 'Schema created',
        description: 'The Cedar schema has been successfully created.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to create schema',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

export const useUpdateCedarSchema = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: ({ id, data }: {
      id: string;
      data: Partial<{
        name: string;
        description: string;
        schema_content: string;
        schema_format: 'json' | 'cedar';
        version: string;
        is_active: boolean;
      }>;
    }) => getApiClient().updateCedarSchema(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: CEDAR_SCHEMAS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: [...CEDAR_SCHEMAS_QUERY_KEY, variables.id] });
      toast({
        title: 'Schema updated',
        description: 'The Cedar schema has been successfully updated.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to update schema',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

export const useDeleteCedarSchema = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (id: string) => getApiClient().deleteCedarSchema(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CEDAR_SCHEMAS_QUERY_KEY });
      toast({
        title: 'Schema deleted',
        description: 'The Cedar schema has been successfully deleted.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to delete schema',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};
