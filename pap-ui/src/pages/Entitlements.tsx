import { useState } from 'react';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Plus, Search, Edit, Trash2, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useEntitlements, useDeleteEntitlement } from '@/hooks/use-entitlements';

const Entitlements = () => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');

  const { data, isLoading, error } = useEntitlements({ search: searchTerm || undefined });
  const deleteMutation = useDeleteEntitlement();

  const handleDelete = (id: string) => {
    if (window.confirm('Are you sure you want to delete this entitlement?')) {
      deleteMutation.mutate(id);
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Entitlements</h1>
            <p className="text-muted-foreground mt-2">
              Manage user entitlements and permissions
            </p>
          </div>
          <Button onClick={() => navigate('/entitlements/new')}>
            <Plus className="mr-2 h-4 w-4" />
            New Entitlement
          </Button>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>All Entitlements</CardTitle>
            <CardDescription>
              View and manage all user entitlements
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="mb-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search entitlements..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>

            {isLoading ? (
              <div className="flex justify-center items-center py-12">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : error ? (
              <div className="text-center py-12 text-destructive">
                <p>Failed to load entitlements: {error.message}</p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Actions</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data && data.entitlements.length > 0 ? (
                      data.entitlements.map((entitlement) => (
                        <TableRow key={entitlement.id}>
                          <TableCell>
                            <div>
                              <div className="font-medium">{entitlement.name}</div>
                              <div className="text-sm text-muted-foreground">
                                {entitlement.description}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex gap-1">
                              {entitlement.actions.slice(0, 3).map((action, i) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  {action}
                                </Badge>
                              ))}
                              {entitlement.actions.length > 3 && (
                                <Badge variant="outline" className="text-xs">
                                  +{entitlement.actions.length - 3}
                                </Badge>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            {entitlement.expires_at ? (
                              <span className="text-sm">
                                {new Date(entitlement.expires_at).toLocaleDateString()}
                              </span>
                            ) : (
                              <span className="text-sm text-muted-foreground">Never</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant={entitlement.enabled ? 'default' : 'secondary'}>
                              {entitlement.enabled ? 'Enabled' : 'Disabled'}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => navigate(`/entitlements/${entitlement.id}`)}
                              >
                                <Edit className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDelete(entitlement.id)}
                                disabled={deleteMutation.isPending}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={5} className="text-center text-muted-foreground">
                          No entitlements found
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </Layout>
  );
};

export default Entitlements;
