import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowLeft, Loader2 } from 'lucide-react';
import { CedarSchema } from '@/types/models';
import { useCedarSchema, useCreateCedarSchema, useUpdateCedarSchema } from '@/hooks/use-cedar-schemas';

const CedarSchemaForm = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const isEditing = id !== 'new';

  const { data: schema, isLoading } = useCedarSchema(id && id !== 'new' ? id : '');
  const createMutation = useCreateCedarSchema();
  const updateMutation = useUpdateCedarSchema();

  const [formData, setFormData] = useState<Partial<CedarSchema>>({
    namespace: 'Stratium',
    name: '',
    description: '',
    schema_content: '',
    schema_format: 'json',
    version: '1.0',
    is_active: true,
  });

  useEffect(() => {
    if (schema) {
      setFormData(schema);
    }
  }, [schema]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      if (isEditing && id) {
        await updateMutation.mutateAsync({
          id,
          data: {
            name: formData.name,
            description: formData.description,
            schema_content: formData.schema_content,
            schema_format: formData.schema_format as 'json' | 'cedar',
            version: formData.version,
            is_active: formData.is_active,
          },
        });
      } else {
        await createMutation.mutateAsync({
          namespace: formData.namespace || 'Stratium',
          name: formData.name || '',
          description: formData.description || '',
          schema_content: formData.schema_content || '',
          schema_format: (formData.schema_format as 'json' | 'cedar') || 'json',
          version: formData.version || '1.0',
        });
      }
      navigate('/cedar/schemas');
    } catch (error) {
      console.error('Failed to save schema:', error);
    }
  };

  const isSubmitting = createMutation.isPending || updateMutation.isPending;

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
            onClick={() => navigate('/cedar/schemas')}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {isEditing ? 'Edit Schema' : 'New Cedar Schema'}
            </h1>
            <p className="text-muted-foreground mt-2">
              {isEditing ? 'Update schema details' : 'Define entity types and actions for Cedar policy validation'}
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Schema Details</CardTitle>
            <CardDescription>
              Configure the Cedar schema namespace, format, and content
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="name">Name *</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    disabled={isSubmitting}
                    placeholder="e.g., ztdf-base"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="namespace">Namespace *</Label>
                  <Input
                    id="namespace"
                    value={formData.namespace}
                    onChange={(e) => setFormData({ ...formData, namespace: e.target.value })}
                    disabled={isSubmitting || isEditing}
                    placeholder="e.g., Stratium"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="schema_format">Format *</Label>
                  <Select
                    value={formData.schema_format}
                    onValueChange={(value) => setFormData({ ...formData, schema_format: value as any })}
                    disabled={isSubmitting}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="cedar">Cedar</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="version">Version *</Label>
                  <Input
                    id="version"
                    value={formData.version}
                    onChange={(e) => setFormData({ ...formData, version: e.target.value })}
                    disabled={isSubmitting}
                    placeholder="e.g., 1.0"
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
                  rows={3}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="schema_content">Schema Content *</Label>
                <Textarea
                  id="schema_content"
                  value={formData.schema_content}
                  onChange={(e) => setFormData({ ...formData, schema_content: e.target.value })}
                  disabled={isSubmitting}
                  rows={15}
                  className="font-mono text-sm"
                  placeholder='{"Stratium": {"entityTypes": {...}, "actions": {...}}}'
                  required
                />
              </div>

              {isEditing && (
                <div className="flex items-center space-x-2">
                  <Switch
                    id="is_active"
                    checked={formData.is_active}
                    onCheckedChange={(checked) => setFormData({ ...formData, is_active: checked })}
                    disabled={isSubmitting}
                  />
                  <Label htmlFor="is_active">Active</Label>
                </div>
              )}

              <div className="flex gap-4">
                <Button type="submit" disabled={isSubmitting}>
                  {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {isEditing ? 'Update Schema' : 'Create Schema'}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate('/cedar/schemas')}
                  disabled={isSubmitting}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </Layout>
  );
};

export default CedarSchemaForm;
