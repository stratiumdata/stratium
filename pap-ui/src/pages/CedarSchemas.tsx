import { useState } from 'react';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Plus, Search, Edit, Trash2, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useCedarSchemas, useDeleteCedarSchema } from '@/hooks/use-cedar-schemas';

const CedarSchemas = () => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');

  const { data, isLoading, error } = useCedarSchemas();
  const deleteMutation = useDeleteCedarSchema();

  const handleDelete = (id: string) => {
    if (window.confirm('Are you sure you want to delete this schema?')) {
      deleteMutation.mutate(id);
    }
  };

  const filteredSchemas = data?.schemas.filter((schema) =>
    !searchTerm ||
    schema.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    schema.namespace.toLowerCase().includes(searchTerm.toLowerCase())
  ) ?? [];

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Cedar Schemas</h1>
            <p className="text-muted-foreground mt-2">
              Manage Cedar authorization schemas for policy validation
            </p>
          </div>
          <Button onClick={() => navigate('/cedar/schemas/new')}>
            <Plus className="mr-2 h-4 w-4" />
            New Schema
          </Button>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>All Schemas</CardTitle>
            <CardDescription>
              Cedar schemas define entity types, actions, and validation rules
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="mb-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search schemas..."
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
                <p>Failed to load schemas: {error.message}</p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Namespace</TableHead>
                      <TableHead>Format</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredSchemas.length > 0 ? (
                      filteredSchemas.map((schema) => (
                        <TableRow key={schema.id}>
                          <TableCell>
                            <div>
                              <div className="font-medium">{schema.name}</div>
                              <div className="text-sm text-muted-foreground">
                                {schema.description}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline">{schema.namespace}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant="secondary">{schema.schema_format.toUpperCase()}</Badge>
                          </TableCell>
                          <TableCell>{schema.version}</TableCell>
                          <TableCell>
                            <Badge variant={schema.is_active ? 'default' : 'secondary'}>
                              {schema.is_active ? 'Active' : 'Inactive'}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => navigate(`/cedar/schemas/${schema.id}`)}
                              >
                                <Edit className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDelete(schema.id)}
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
                        <TableCell colSpan={6} className="text-center text-muted-foreground">
                          No schemas found
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

export default CedarSchemas;
