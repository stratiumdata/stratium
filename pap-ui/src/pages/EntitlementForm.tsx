import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowLeft, Loader2 } from 'lucide-react';
import { Entitlement } from '@/types/models';
import { useEntitlement, useCreateEntitlement, useUpdateEntitlement } from '@/hooks/use-entitlements';
import { useToast } from '@/hooks/use-toast';

const EntitlementForm = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  const isEditing = id !== 'new';

  const { data: entitlement, isLoading } = useEntitlement(id && id !== 'new' ? id : '');
  const createMutation = useCreateEntitlement();
  const updateMutation = useUpdateEntitlement();

  const [formData, setFormData] = useState<Partial<Entitlement>>({
    name: '',
    description: '',
    subject_attributes: {},
    resource_attributes: {},
    actions: [],
    conditions: {},
    enabled: true,
  });

  const [actionsInput, setActionsInput] = useState('');
  const [subjectAttrsInput, setSubjectAttrsInput] = useState('{}');
  const [resourceAttrsInput, setResourceAttrsInput] = useState('{}');
  const [conditionsInput, setConditionsInput] = useState('{}');

  useEffect(() => {
    if (entitlement) {
      setFormData(entitlement);
      setActionsInput(entitlement.actions.join(', '));
      setSubjectAttrsInput(JSON.stringify(entitlement.subject_attributes, null, 2));
      setResourceAttrsInput(JSON.stringify(entitlement.resource_attributes, null, 2));
      setConditionsInput(JSON.stringify(entitlement.conditions, null, 2));
    }
  }, [entitlement]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const entitlementData = {
        name: formData.name || '',
        description: formData.description || '',
        subject_attributes: JSON.parse(subjectAttrsInput),
        resource_attributes: JSON.parse(resourceAttrsInput),
        actions: actionsInput.split(',').map(a => a.trim()).filter(Boolean),
        conditions: JSON.parse(conditionsInput),
        enabled: formData.enabled || false,
        expires_at: formData.expires_at,
      };

      if (isEditing && id) {
        await updateMutation.mutateAsync({ id, data: entitlementData });
      } else {
        await createMutation.mutateAsync(entitlementData);
      }
      navigate('/entitlements');
    } catch (error) {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Invalid JSON in one of the fields. Please check your input.',
        variant: 'destructive',
      });
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
            onClick={() => navigate('/entitlements')}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {isEditing ? 'Edit Entitlement' : 'New Entitlement'}
            </h1>
            <p className="text-muted-foreground mt-2">
              {isEditing ? 'Update entitlement details' : 'Create a new user entitlement'}
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Entitlement Details</CardTitle>
            <CardDescription>
              Configure the entitlement settings and permissions
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
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="expires_at">Expires At</Label>
                  <Input
                    id="expires_at"
                    type="datetime-local"
                    value={formData.expires_at?.slice(0, 16) || ''}
                    onChange={(e) => setFormData({ ...formData, expires_at: e.target.value ? new Date(e.target.value).toISOString() : undefined })}
                    disabled={isSubmitting}
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
                <Label htmlFor="actions">Actions (comma-separated) *</Label>
                <Input
                  id="actions"
                  value={actionsInput}
                  onChange={(e) => setActionsInput(e.target.value)}
                  placeholder="read, write, delete"
                  disabled={isSubmitting}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="subject_attributes">Subject Attributes (JSON)</Label>
                <Textarea
                  id="subject_attributes"
                  value={subjectAttrsInput}
                  onChange={(e) => setSubjectAttrsInput(e.target.value)}
                  disabled={isSubmitting}
                  rows={4}
                  className="font-mono text-sm"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="resource_attributes">Resource Attributes (JSON)</Label>
                <Textarea
                  id="resource_attributes"
                  value={resourceAttrsInput}
                  onChange={(e) => setResourceAttrsInput(e.target.value)}
                  disabled={isSubmitting}
                  rows={4}
                  className="font-mono text-sm"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="conditions">Conditions (JSON)</Label>
                <Textarea
                  id="conditions"
                  value={conditionsInput}
                  onChange={(e) => setConditionsInput(e.target.value)}
                  disabled={isSubmitting}
                  rows={4}
                  className="font-mono text-sm"
                />
              </div>

              <div className="flex items-center space-x-2">
                <Switch
                  id="enabled"
                  checked={formData.enabled}
                  onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
                  disabled={isSubmitting}
                />
                <Label htmlFor="enabled">Enable this entitlement</Label>
              </div>

              <div className="flex gap-4">
                <Button type="submit" disabled={isSubmitting}>
                  {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {isEditing ? 'Update Entitlement' : 'Create Entitlement'}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate('/entitlements')}
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

export default EntitlementForm;
