/**
 * React Query hooks for Cedar Template management
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getApiClient } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';
import { CEDAR_SCHEMAS_QUERY_KEY } from '@/hooks/use-cedar-schemas';

export const CEDAR_TEMPLATES_QUERY_KEY = ['cedar-templates'];

export const useCedarTemplates = (namespace?: string) => {
  return useQuery({
    queryKey: [...CEDAR_TEMPLATES_QUERY_KEY, 'list', namespace],
    queryFn: () => getApiClient().listCedarTemplates(namespace),
  });
};

export const useCedarTemplate = (id: string) => {
  return useQuery({
    queryKey: [...CEDAR_TEMPLATES_QUERY_KEY, id],
    queryFn: () => getApiClient().getCedarTemplate(id),
    enabled: !!id && id !== 'new',
  });
};

export const useCreateCedarTemplate = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (data: {
      name: string;
      description: string;
      template_content: string;
      schema_id?: string;
      namespace: string;
    }) => getApiClient().createCedarTemplate(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CEDAR_TEMPLATES_QUERY_KEY });
      toast({
        title: 'Template created',
        description: 'The Cedar template has been successfully created.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to create template',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

export const useDeleteCedarTemplate = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (id: string) => getApiClient().deleteCedarTemplate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CEDAR_TEMPLATES_QUERY_KEY });
      toast({
        title: 'Template deleted',
        description: 'The Cedar template has been successfully deleted.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to delete template',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

export const useInstantiateTemplate = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: ({ templateId, data }: {
      templateId: string;
      data: { principal_entity: string; resource_entity: string };
    }) => getApiClient().instantiateTemplate(templateId, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: CEDAR_TEMPLATES_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: [...CEDAR_TEMPLATES_QUERY_KEY, variables.templateId, 'linked'] });
      toast({
        title: 'Template instantiated',
        description: 'A linked policy has been created from the template.',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to instantiate template',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};

export const useLinkedPolicies = (templateId: string) => {
  return useQuery({
    queryKey: [...CEDAR_TEMPLATES_QUERY_KEY, templateId, 'linked'],
    queryFn: () => getApiClient().listLinkedPolicies(templateId),
    enabled: !!templateId && templateId !== 'new',
  });
};

export const useTestCedarPolicy = () => {
  const { toast } = useToast();

  return useMutation({
    mutationFn: (data: {
      policy_content: string;
      subject_attributes: Record<string, any>;
      resource_attributes: Record<string, any>;
      action: string;
      environment?: Record<string, any>;
      namespace?: string;
    }) => getApiClient().testCedarPolicy(data),
    onError: (error: Error) => {
      toast({
        title: 'Test failed',
        description: error.message,
        variant: 'destructive',
      });
    },
  });
};
