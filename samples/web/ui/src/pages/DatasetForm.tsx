import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { apiClient } from '@/api/client';
import { useAuth } from '@/contexts/AuthContext';
import type { CreateDatasetRequest } from '@/types';

export const DatasetForm: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isEditMode = !!id;

  const [formData, setFormData] = useState<CreateDatasetRequest>({
    title: '',
    description: '',
    data_url: '',
    department: user?.department || '',
    tags: [],
  });

  const [tagInput, setTagInput] = useState('');
  const [error, setError] = useState('');

  // Load existing dataset for edit mode
  const { data: existingDataset } = useQuery({
    queryKey: ['dataset', id],
    queryFn: () => apiClient.getDataset(id!),
    enabled: isEditMode,
  });

  useEffect(() => {
    if (existingDataset) {
      setFormData({
        title: existingDataset.title,
        description: existingDataset.description,
        data_url: existingDataset.data_url,
        department: existingDataset.department,
        tags: existingDataset.tags || [],
      });
    }
  }, [existingDataset]);

  const createMutation = useMutation({
    mutationFn: (data: CreateDatasetRequest) => apiClient.createDataset(data),
    onSuccess: (dataset) => {
      queryClient.invalidateQueries({ queryKey: ['datasets'] });
      navigate(`/datasets/${dataset.id}`);
    },
    onError: (error: any) => {
      setError(error.response?.data?.error || 'Failed to create dataset');
    },
  });

  const updateMutation = useMutation({
    mutationFn: (data: CreateDatasetRequest) => apiClient.updateDataset(id!, data),
    onSuccess: (dataset) => {
      queryClient.invalidateQueries({ queryKey: ['datasets'] });
      queryClient.invalidateQueries({ queryKey: ['dataset', id] });
      navigate(`/datasets/${dataset.id}`);
    },
    onError: (error: any) => {
      setError(error.response?.data?.error || 'Failed to update dataset');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!formData.title.trim()) {
      setError('Title is required');
      return;
    }
    if (!formData.description.trim()) {
      setError('Description is required');
      return;
    }
    if (!formData.data_url.trim()) {
      setError('Data URL is required');
      return;
    }
    if (!formData.department.trim()) {
      setError('Department is required');
      return;
    }

    if (isEditMode) {
      updateMutation.mutate(formData);
    } else {
      createMutation.mutate(formData);
    }
  };

  const handleAddTag = () => {
    const trimmedTag = tagInput.trim();
    if (trimmedTag && !formData.tags.includes(trimmedTag)) {
      setFormData({
        ...formData,
        tags: [...formData.tags, trimmedTag],
      });
      setTagInput('');
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    setFormData({
      ...formData,
      tags: formData.tags.filter((tag) => tag !== tagToRemove),
    });
  };

  const isPending = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="px-4 sm:px-6 lg:px-8">
      <div className="mb-6">
        <Link
          to={isEditMode ? `/datasets/${id}` : '/datasets'}
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          ← Back
        </Link>
      </div>

      <div className="max-w-2xl">
        <h1 className="text-3xl font-bold text-foreground mb-6">
          {isEditMode ? 'Edit Dataset' : 'Create New Dataset'}
        </h1>

        {error && (
          <div className="mb-6 bg-destructive/10 border border-destructive/30 rounded-lg p-4">
            <p className="text-destructive text-sm">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="title" className="block text-sm font-medium text-foreground">
              Title *
            </label>
            <input
              type="text"
              id="title"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="mt-1 block w-full rounded-md border-input shadow-sm focus:border-ring focus:ring-ring sm:text-sm px-3 py-2 border bg-background text-foreground"
              required
            />
          </div>

          <div>
            <label htmlFor="description" className="block text-sm font-medium text-foreground">
              Description *
            </label>
            <textarea
              id="description"
              rows={4}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="mt-1 block w-full rounded-md border-input shadow-sm focus:border-ring focus:ring-ring sm:text-sm px-3 py-2 border bg-background text-foreground"
              required
            />
          </div>

          <div>
            <label htmlFor="data_url" className="block text-sm font-medium text-foreground">
              Data URL *
            </label>
            <input
              type="url"
              id="data_url"
              value={formData.data_url}
              onChange={(e) => setFormData({ ...formData, data_url: e.target.value })}
              placeholder="https://example.com/dataset.csv"
              className="mt-1 block w-full rounded-md border-input shadow-sm focus:border-ring focus:ring-ring sm:text-sm px-3 py-2 border bg-background text-foreground"
              required
            />
          </div>

          <div>
            <label htmlFor="department" className="block text-sm font-medium text-foreground">
              Department *
            </label>
            <input
              type="text"
              id="department"
              value={formData.department}
              onChange={(e) => setFormData({ ...formData, department: e.target.value })}
              className="mt-1 block w-full rounded-md border-input shadow-sm focus:border-ring focus:ring-ring sm:text-sm px-3 py-2 border bg-background text-foreground"
              required
            />
            <p className="mt-1 text-sm text-muted-foreground">
              Datasets are subject to department-based access control
            </p>
          </div>

          <div>
            <label htmlFor="tags" className="block text-sm font-medium text-foreground">
              Tags
            </label>
            <div className="mt-1 flex gap-2">
              <input
                type="text"
                id="tags"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyPress={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddTag();
                  }
                }}
                placeholder="Add a tag..."
                className="block w-full rounded-md border-input shadow-sm focus:border-ring focus:ring-ring sm:text-sm px-3 py-2 border bg-background text-foreground"
              />
              <button
                type="button"
                onClick={handleAddTag}
                className="inline-flex items-center px-4 py-2 border border-border rounded-md shadow-sm text-sm font-medium text-foreground bg-card hover:bg-muted"
              >
                Add
              </button>
            </div>
            {formData.tags.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {formData.tags.map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center px-2.5 py-0.5 rounded-md text-sm font-medium bg-accent/20 text-accent-foreground"
                  >
                    {tag}
                    <button
                      type="button"
                      onClick={() => handleRemoveTag(tag)}
                      className="ml-1 inline-flex items-center p-0.5 text-accent-foreground hover:opacity-80"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end space-x-3 pt-6 border-t border-border">
            <Link
              to={isEditMode ? `/datasets/${id}` : '/datasets'}
              className="inline-flex items-center px-4 py-2 border border-border rounded-md shadow-sm text-sm font-medium text-foreground bg-card hover:bg-muted"
            >
              Cancel
            </Link>
            <button
              type="submit"
              disabled={isPending}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-primary-foreground bg-primary hover:opacity-90 disabled:opacity-50 transition-all shadow-elegant"
            >
              {isPending ? 'Saving...' : isEditMode ? 'Update Dataset' : 'Create Dataset'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};