import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { ArrowLeft, Loader2, Plus } from 'lucide-react';
import { CedarTemplate } from '@/types/models';
import {
  useCedarTemplate,
  useCreateCedarTemplate,
  useInstantiateTemplate,
  useLinkedPolicies,
} from '@/hooks/use-cedar-templates';

const CedarTemplateForm = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const isEditing = id !== 'new';

  const { data: template, isLoading } = useCedarTemplate(id && id !== 'new' ? id : '');
  const { data: linkedData } = useLinkedPolicies(id && id !== 'new' ? id : '');
  const createMutation = useCreateCedarTemplate();
  const instantiateMutation = useInstantiateTemplate();

  const [formData, setFormData] = useState<Partial<CedarTemplate>>({
    name: '',
    description: '',
    template_content: '',
    namespace: 'Stratium',
  });

  const [instantiateData, setInstantiateData] = useState({
    principal_entity: '',
    resource_entity: '',
  });

  useEffect(() => {
    if (template) {
      setFormData(template);
    }
  }, [template]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      await createMutation.mutateAsync({
        name: formData.name || '',
        description: formData.description || '',
        template_content: formData.template_content || '',
        namespace: formData.namespace || 'Stratium',
      });
      navigate('/cedar/templates');
    } catch (error) {
      console.error('Failed to save template:', error);
    }
  };

  const handleInstantiate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id || id === 'new') return;

    try {
      await instantiateMutation.mutateAsync({
        templateId: id,
        data: instantiateData,
      });
      setInstantiateData({ principal_entity: '', resource_entity: '' });
    } catch (error) {
      console.error('Failed to instantiate template:', error);
    }
  };

  const isSubmitting = createMutation.isPending;

  if (isLoading && isEditing) {
    return (
      <Layout>
        <div className="flex justify-center items-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate('/cedar/templates')}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {isEditing ? template?.name || 'Template' : 'New Cedar Template'}
            </h1>
            <p className="text-muted-foreground mt-2">
              {isEditing ? 'View template details and instantiate linked policies' : 'Create a reusable policy template with ?principal/?resource placeholders'}
            </p>
          </div>
        </div>

        {/* Template Details / Create Form */}
        <Card>
          <CardHeader>
            <CardTitle>{isEditing ? 'Template Details' : 'Template Content'}</CardTitle>
            <CardDescription>
              {isEditing
                ? 'Template content and metadata'
                : 'Use ?principal and ?resource as placeholders in your Cedar policy'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isEditing ? (
              <div className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div>
                    <Label className="text-muted-foreground">Namespace</Label>
                    <p className="mt-1"><Badge variant="outline">{template?.namespace}</Badge></p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Created</Label>
                    <p className="mt-1 text-sm">{template?.created_at ? new Date(template.created_at).toLocaleString() : '-'}</p>
                  </div>
                </div>
                {template?.description && (
                  <div>
                    <Label className="text-muted-foreground">Description</Label>
                    <p className="mt-1 text-sm">{template.description}</p>
                  </div>
                )}
                <div>
                  <Label className="text-muted-foreground">Template Content</Label>
                  <pre className="mt-1 rounded-md border bg-muted p-4 font-mono text-sm overflow-x-auto">
                    {template?.template_content}
                  </pre>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="grid gap-6 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="name">Name *</Label>
                    <Input
                      id="name"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      disabled={isSubmitting}
                      placeholder="e.g., user-resource-access"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="namespace">Namespace *</Label>
                    <Input
                      id="namespace"
                      value={formData.namespace}
                      onChange={(e) => setFormData({ ...formData, namespace: e.target.value })}
                      disabled={isSubmitting}
                      placeholder="e.g., Stratium"
                      required
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Textarea
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    disabled={isSubmitting}
                    rows={2}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="template_content">Template Content *</Label>
                  <Textarea
                    id="template_content"
                    value={formData.template_content}
                    onChange={(e) => setFormData({ ...formData, template_content: e.target.value })}
                    disabled={isSubmitting}
                    rows={10}
                    className="font-mono text-sm"
                    placeholder={'permit(\n  principal == ?principal,\n  action in [Action::"WrapDEK", Action::"UnwrapDEK"],\n  resource == ?resource\n);'}
                    required
                  />
                </div>

                <div className="flex gap-4">
                  <Button type="submit" disabled={isSubmitting}>
                    {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Create Template
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => navigate('/cedar/templates')}
                    disabled={isSubmitting}
                  >
                    Cancel
                  </Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>

        {/* Instantiate Template (edit mode only) */}
        {isEditing && (
          <Card>
            <CardHeader>
              <CardTitle>Instantiate Template</CardTitle>
              <CardDescription>
                Create a linked policy by binding concrete entities to the template placeholders
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleInstantiate} className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="principal_entity">Principal Entity</Label>
                    <Input
                      id="principal_entity"
                      value={instantiateData.principal_entity}
                      onChange={(e) => setInstantiateData({ ...instantiateData, principal_entity: e.target.value })}
                      placeholder='Stratium::User::"alice"'
                      disabled={instantiateMutation.isPending}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="resource_entity">Resource Entity</Label>
                    <Input
                      id="resource_entity"
                      value={instantiateData.resource_entity}
                      onChange={(e) => setInstantiateData({ ...instantiateData, resource_entity: e.target.value })}
                      placeholder='Stratium::Resource::"doc-123"'
                      disabled={instantiateMutation.isPending}
                    />
                  </div>
                </div>
                <Button type="submit" disabled={instantiateMutation.isPending}>
                  {instantiateMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  <Plus className="mr-2 h-4 w-4" />
                  Instantiate
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Linked Policies (edit mode only) */}
        {isEditing && linkedData && (
          <Card>
            <CardHeader>
              <CardTitle>Linked Policies</CardTitle>
              <CardDescription>
                Policies instantiated from this template ({linkedData.total} total)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Policy ID</TableHead>
                      <TableHead>Principal</TableHead>
                      <TableHead>Resource</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {linkedData.linked_policies.length > 0 ? (
                      linkedData.linked_policies.map((link) => (
                        <TableRow key={link.id}>
                          <TableCell className="font-mono text-sm">{link.policy_id.slice(0, 8)}...</TableCell>
                          <TableCell className="font-mono text-sm">{link.principal_entity || '-'}</TableCell>
                          <TableCell className="font-mono text-sm">{link.resource_entity || '-'}</TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {new Date(link.created_at).toLocaleDateString()}
                          </TableCell>
                        </TableRow>
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={4} className="text-center text-muted-foreground">
                          No linked policies yet
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
};

export default CedarTemplateForm;
