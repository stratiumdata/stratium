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
import { Policy } from '@/types/models';
import { usePolicy, useCreatePolicy, useUpdatePolicy } from '@/hooks/use-policies';

const PolicyForm = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const isEditing = id !== 'new';

  const { data: policy, isLoading } = usePolicy(id && id !== 'new' ? id : '');
  const createMutation = useCreatePolicy();
  const updateMutation = useUpdatePolicy();

  const [formData, setFormData] = useState<Partial<Policy>>({
    name: '',
    description: '',
    language: 'json',
    policy_content: '',
    effect: 'allow',
    priority: 0,
    enabled: true,
  });

  useEffect(() => {
    if (policy) {
      setFormData(policy);
    }
  }, [policy]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const policyData = {
      name: formData.name || '',
      description: formData.description || '',
      language: formData.language as 'json' | 'opa' | 'xacml',
      policy_content: formData.policy_content || '',
      effect: formData.effect as 'allow' | 'deny',
      priority: formData.priority || 0,
      enabled: formData.enabled || false,
    };

    try {
      if (isEditing && id) {
        await updateMutation.mutateAsync({ id, data: policyData });
      } else {
        await createMutation.mutateAsync(policyData);
      }
      navigate('/policies');
    } catch (error) {
      // Error handling is done in the mutation hooks
      console.error('Failed to save policy:', error);
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
            onClick={() => navigate('/policies')}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {isEditing ? 'Edit Policy' : 'New Policy'}
            </h1>
            <p className="text-muted-foreground mt-2">
              {isEditing ? 'Update policy details' : 'Create a new authorization policy'}
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Policy Details</CardTitle>
            <CardDescription>
              Configure the policy settings and content
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
                  <Label htmlFor="language">Language *</Label>
                  <Select
                    value={formData.language}
                    onValueChange={(value) => setFormData({ ...formData, language: value as any })}
                    disabled={isSubmitting}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="opa">OPA</SelectItem>
                      <SelectItem value="xacml">XACML</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="effect">Effect *</Label>
                  <Select
                    value={formData.effect}
                    onValueChange={(value) => setFormData({ ...formData, effect: value as any })}
                    disabled={isSubmitting}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="allow">Allow</SelectItem>
                      <SelectItem value="deny">Deny</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="priority">Priority *</Label>
                  <Input
                    id="priority"
                    type="number"
                    value={formData.priority}
                    onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) })}
                    disabled={isSubmitting}
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
                <Label htmlFor="policy_content">Policy Content *</Label>
                <Textarea
                  id="policy_content"
                  value={formData.policy_content}
                  onChange={(e) => setFormData({ ...formData, policy_content: e.target.value })}
                  disabled={isSubmitting}
                  rows={10}
                  className="font-mono text-sm"
                  required
                />
              </div>

              <div className="flex items-center space-x-2">
                <Switch
                  id="enabled"
                  checked={formData.enabled}
                  onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
                  disabled={isSubmitting}
                />
                <Label htmlFor="enabled">Enable this policy</Label>
              </div>

              <div className="flex gap-4">
                <Button type="submit" disabled={isSubmitting}>
                  {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {isEditing ? 'Update Policy' : 'Create Policy'}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate('/policies')}
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

export default PolicyForm;
