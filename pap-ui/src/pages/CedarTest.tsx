import { useState } from 'react';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Loader2, Play } from 'lucide-react';
import { useTestCedarPolicy } from '@/hooks/use-cedar-templates';
import type { CedarTestResult } from '@/types/models';

const CedarTest = () => {
  const testMutation = useTestCedarPolicy();

  const [policyContent, setPolicyContent] = useState(
    'permit(\n  principal,\n  action == Action::"UnwrapDEK",\n  resource\n);'
  );
  const [subjectAttrs, setSubjectAttrs] = useState('{\n  "type": "User",\n  "id": "alice"\n}');
  const [resourceAttrs, setResourceAttrs] = useState('{\n  "type": "Resource",\n  "id": "doc-123"\n}');
  const [action, setAction] = useState('UnwrapDEK');
  const [namespace, setNamespace] = useState('');
  const [result, setResult] = useState<CedarTestResult | null>(null);
  const [parseError, setParseError] = useState('');

  const handleTest = async (e: React.FormEvent) => {
    e.preventDefault();
    setParseError('');
    setResult(null);

    let subject: Record<string, any>;
    let resource: Record<string, any>;

    try {
      subject = JSON.parse(subjectAttrs);
    } catch {
      setParseError('Invalid JSON in subject attributes');
      return;
    }

    try {
      resource = JSON.parse(resourceAttrs);
    } catch {
      setParseError('Invalid JSON in resource attributes');
      return;
    }

    try {
      const res = await testMutation.mutateAsync({
        policy_content: policyContent,
        subject_attributes: subject,
        resource_attributes: resource,
        action,
        namespace: namespace || undefined,
      });
      setResult(res);
    } catch (error) {
      console.error('Test failed:', error);
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cedar Policy Tester</h1>
          <p className="text-muted-foreground mt-2">
            Test Cedar policies against sample requests without persisting
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          {/* Input */}
          <Card>
            <CardHeader>
              <CardTitle>Policy Input</CardTitle>
              <CardDescription>
                Enter a Cedar policy and test data
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleTest} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="policy_content">Cedar Policy *</Label>
                  <Textarea
                    id="policy_content"
                    value={policyContent}
                    onChange={(e) => setPolicyContent(e.target.value)}
                    rows={8}
                    className="font-mono text-sm"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="action">Action *</Label>
                  <Input
                    id="action"
                    value={action}
                    onChange={(e) => setAction(e.target.value)}
                    placeholder="e.g., UnwrapDEK"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="namespace">Namespace</Label>
                  <Input
                    id="namespace"
                    value={namespace}
                    onChange={(e) => setNamespace(e.target.value)}
                    placeholder="Leave empty for un-namespaced policies"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="subject">Subject Attributes (JSON) *</Label>
                  <Textarea
                    id="subject"
                    value={subjectAttrs}
                    onChange={(e) => setSubjectAttrs(e.target.value)}
                    rows={4}
                    className="font-mono text-sm"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="resource">Resource Attributes (JSON) *</Label>
                  <Textarea
                    id="resource"
                    value={resourceAttrs}
                    onChange={(e) => setResourceAttrs(e.target.value)}
                    rows={4}
                    className="font-mono text-sm"
                    required
                  />
                </div>

                {parseError && (
                  <p className="text-sm text-destructive">{parseError}</p>
                )}

                <Button type="submit" disabled={testMutation.isPending} className="w-full">
                  {testMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="mr-2 h-4 w-4" />
                  )}
                  Run Test
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Result */}
          <Card>
            <CardHeader>
              <CardTitle>Test Result</CardTitle>
              <CardDescription>
                Authorization decision from the Cedar engine
              </CardDescription>
            </CardHeader>
            <CardContent>
              {result ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-medium">Decision:</span>
                    <Badge
                      variant={result.decision === 'allow' ? 'default' : 'destructive'}
                      className="text-lg px-4 py-1"
                    >
                      {result.decision.toUpperCase()}
                    </Badge>
                  </div>

                  <div>
                    <Label className="text-muted-foreground">Reason</Label>
                    <p className="mt-1 text-sm">{result.reason}</p>
                  </div>

                  {result.details && Object.keys(result.details).length > 0 && (
                    <div>
                      <Label className="text-muted-foreground">Details</Label>
                      <pre className="mt-1 rounded-md border bg-muted p-4 font-mono text-sm overflow-x-auto">
                        {JSON.stringify(result.details, null, 2)}
                      </pre>
                    </div>
                  )}

                  {result.error && (
                    <div>
                      <Label className="text-destructive">Error</Label>
                      <p className="mt-1 text-sm text-destructive">{result.error}</p>
                    </div>
                  )}
                </div>
              ) : testMutation.isPending ? (
                <div className="flex justify-center items-center py-12">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  <p>Run a test to see results here</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </Layout>
  );
};

export default CedarTest;
