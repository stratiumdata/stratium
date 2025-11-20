import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { apiClient } from '@/api/client';
import { usePermissions } from '@/hooks/usePermissions';

export const DatasetDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const { data: dataset, isLoading, error } = useQuery({
    queryKey: ['dataset', id],
    queryFn: () => apiClient.getDataset(id!),
    enabled: !!id,
  });

  const permissions = usePermissions(dataset);

  const deleteMutation = useMutation({
    mutationFn: () => apiClient.deleteDataset(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['datasets'] });
      navigate('/datasets');
    },
  });

  const handleDelete = () => {
    if (permissions.canDelete) {
      deleteMutation.mutate();
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-lg text-muted-foreground">Loading dataset...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-4 sm:px-6 lg:px-8">
        <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-4">
          <h3 className="text-destructive font-medium">Error loading dataset</h3>
          <p className="text-destructive/80 text-sm mt-1">
            {(error as any).response?.data?.error || (error as Error).message}
          </p>
          {(error as any).response?.status === 403 && (
            <p className="text-destructive/80 text-sm mt-2">
              You don't have permission to view this dataset. It may belong to a different department.
            </p>
          )}
          <Link
            to="/datasets"
            className="mt-4 inline-flex items-center text-sm text-destructive hover:opacity-80"
          >
            ← Back to datasets
          </Link>
        </div>
      </div>
    );
  }

  if (!dataset) {
    return (
      <div className="px-4 sm:px-6 lg:px-8">
        <div className="text-center py-12">
          <h3 className="text-lg font-medium text-foreground">Dataset not found</h3>
          <Link
            to="/datasets"
            className="mt-4 inline-flex items-center text-sm text-primary hover:opacity-80"
          >
            ← Back to datasets
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="px-4 sm:px-6 lg:px-8">
      <div className="mb-6">
        <Link
          to="/datasets"
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          ← Back to datasets
        </Link>
      </div>

      <div className="bg-card shadow-elegant overflow-hidden sm:rounded-lg border border-border">
        <div className="px-4 py-5 sm:px-6 flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-foreground">{dataset.title}</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
              Created {new Date(dataset.created_at).toLocaleDateString()}
            </p>
          </div>
          <div className="flex space-x-3">
            {permissions.canEdit && (
              <Link
                to={`/datasets/${dataset.id}/edit`}
                className="inline-flex items-center px-4 py-2 border border-border rounded-md shadow-sm text-sm font-medium text-foreground bg-card hover:bg-muted"
              >
                Edit
              </Link>
            )}
            {permissions.canDelete && (
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="inline-flex items-center px-4 py-2 border border-destructive/30 rounded-md shadow-sm text-sm font-medium text-destructive bg-card hover:bg-destructive/10"
              >
                Delete
              </button>
            )}
          </div>
        </div>
        <div className="border-t border-border px-4 py-5 sm:p-0">
          <dl className="sm:divide-y sm:divide-border">
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-muted-foreground">Description</dt>
              <dd className="mt-1 text-sm text-foreground sm:mt-0 sm:col-span-2">
                {dataset.description}
              </dd>
            </div>
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-muted-foreground">Department</dt>
              <dd className="mt-1 text-sm text-foreground sm:mt-0 sm:col-span-2">
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-accent/20 text-accent-foreground">
                  {dataset.department}
                </span>
              </dd>
            </div>
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-muted-foreground">Data URL</dt>
              <dd className="mt-1 text-sm text-foreground sm:mt-0 sm:col-span-2">
                <a
                  href={dataset.data_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:opacity-80"
                >
                  {dataset.data_url}
                </a>
              </dd>
            </div>
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-muted-foreground">Tags</dt>
              <dd className="mt-1 text-sm text-foreground sm:mt-0 sm:col-span-2">
                <div className="flex flex-wrap gap-2">
                  {dataset.tags && dataset.tags.length > 0 ? (
                    dataset.tags.map((tag) => (
                      <span
                        key={tag}
                        className="inline-flex items-center px-2.5 py-0.5 rounded-md text-sm font-medium bg-muted text-muted-foreground"
                      >
                        {tag}
                      </span>
                    ))
                  ) : (
                    <span className="text-muted-foreground">No tags</span>
                  )}
                </div>
              </dd>
            </div>
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-muted-foreground">Owner ID</dt>
              <dd className="mt-1 text-sm text-foreground sm:mt-0 sm:col-span-2 font-mono">
                {dataset.owner_id}
              </dd>
            </div>
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-muted-foreground">Dataset ID</dt>
              <dd className="mt-1 text-sm text-foreground sm:mt-0 sm:col-span-2 font-mono">
                {dataset.id}
              </dd>
            </div>
          </dl>
        </div>

        {/* Permissions info */}
        <div className="border-t border-border px-4 py-4 sm:px-6 bg-muted/30">
          <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
            Your Permissions
          </h4>
          <div className="flex flex-wrap gap-2 text-xs">
            <PermissionBadge allowed={permissions.canView} label="View" />
            <PermissionBadge allowed={permissions.canEdit} label="Edit" />
            <PermissionBadge allowed={permissions.canDelete} label="Delete" />
          </div>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="fixed z-10 inset-0 overflow-y-auto">
          <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 bg-background/80 backdrop-blur-sm transition-opacity" onClick={() => setShowDeleteConfirm(false)} />
            <div className="inline-block align-bottom bg-card rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6 border border-border">
              <div className="sm:flex sm:items-start">
                <div className="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-destructive/10 sm:mx-0 sm:h-10 sm:w-10">
                  <svg className="h-6 w-6 text-destructive" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                  <h3 className="text-lg leading-6 font-medium text-foreground">Delete Dataset</h3>
                  <div className="mt-2">
                    <p className="text-sm text-muted-foreground">
                      Are you sure you want to delete "{dataset.title}"? This action cannot be undone.
                    </p>
                  </div>
                </div>
              </div>
              <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  disabled={deleteMutation.isPending}
                  onClick={handleDelete}
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-destructive text-base font-medium text-destructive-foreground hover:opacity-90 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
                >
                  {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowDeleteConfirm(false)}
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-border shadow-sm px-4 py-2 bg-card text-base font-medium text-foreground hover:bg-muted focus:outline-none sm:mt-0 sm:w-auto sm:text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const PermissionBadge: React.FC<{ allowed: boolean; label: string }> = ({ allowed, label }) => (
  <span
    className={`inline-flex items-center px-2.5 py-0.5 rounded-full font-medium ${
      allowed
        ? 'bg-accent/20 text-accent-foreground'
        : 'bg-muted text-muted-foreground'
    }`}
  >
    {allowed ? '✓' : '✗'} {label}
  </span>
);