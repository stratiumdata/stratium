import React, { useState, useRef, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { apiClient } from '@/api/client';
import { useRolePermissions } from '@/hooks/usePermissions';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { Dataset } from '@/types';

const DatasetCard = React.memo<{ dataset: Dataset }>(({ dataset }) => {
  return (
    <Link
      to={`/datasets/${dataset.id}`}
      className="bg-white overflow-hidden shadow rounded-lg hover:shadow-md transition-shadow"
    >
      <div className="px-4 py-5 sm:p-6">
        <h3 className="text-lg font-medium text-gray-900 truncate">
          {dataset.title}
        </h3>
        <p className="mt-2 text-sm text-gray-500 line-clamp-2">
          {dataset.description}
        </p>
        <div className="mt-4 flex items-center text-sm text-gray-500">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-primary-foreground bg-primary/60">
            {dataset.department}
          </span>
        </div>
        {dataset.tags && dataset.tags.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {dataset.tags.slice(0, 3).map((tag) => (
              <span
                key={tag}
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-700"
              >
                {tag}
              </span>
            ))}
            {dataset.tags.length > 3 && (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-700">
                +{dataset.tags.length - 3} more
              </span>
            )}
          </div>
        )}
      </div>
    </Link>
  );
});

DatasetCard.displayName = 'DatasetCard';

export const DatasetsList = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('');
  const [tagsFilter, setTagsFilter] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [debouncedDept, setDebouncedDept] = useState('');
  const [debouncedTags, setDebouncedTags] = useState('');
  const { canCreateDatasets, canUseFilters } = useRolePermissions();
  
  const searchTimerRef = useRef<NodeJS.Timeout>();
  const deptTimerRef = useRef<NodeJS.Timeout>();
  const tagsTimerRef = useRef<NodeJS.Timeout>();

  useEffect(() => {
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => setDebouncedSearch(searchQuery), 500);
    return () => { if (searchTimerRef.current) clearTimeout(searchTimerRef.current); };
  }, [searchQuery]);

  useEffect(() => {
    if (deptTimerRef.current) clearTimeout(deptTimerRef.current);
    deptTimerRef.current = setTimeout(() => setDebouncedDept(departmentFilter), 500);
    return () => { if (deptTimerRef.current) clearTimeout(deptTimerRef.current); };
  }, [departmentFilter]);

  useEffect(() => {
    if (tagsTimerRef.current) clearTimeout(tagsTimerRef.current);
    tagsTimerRef.current = setTimeout(() => setDebouncedTags(tagsFilter), 500);
    return () => { if (tagsTimerRef.current) clearTimeout(tagsTimerRef.current); };
  }, [tagsFilter]);

  const { data, isLoading, error } = useQuery({
    queryKey: ['datasets', debouncedSearch, debouncedDept, debouncedTags],
    queryFn: () => {
      if (debouncedSearch || debouncedDept || debouncedTags) {
        return apiClient.searchDatasets({
          q: debouncedSearch || undefined,
          department: debouncedDept || undefined,
          tags: debouncedTags || undefined,
          limit: 100,
        });
      }
      return apiClient.getDatasets({ limit: 100 });
    },
    staleTime: 30000, // 30 seconds
    refetchOnWindowFocus: false,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-lg text-gray-600">Loading datasets...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <h3 className="text-red-800 font-medium">Error loading datasets</h3>
        <p className="text-red-600 text-sm mt-1">{(error as Error).message}</p>
      </div>
    );
  }

  const datasets = data?.data || [];

  return (
    <div className="px-4 sm:px-6 lg:px-8">
      <div className="sm:flex sm:items-center">
        <div className="sm:flex-auto">
          <h1 className="text-3xl font-semibold text-gray-900">Datasets</h1>
          <p className="mt-2 text-sm text-gray-700">
            Browse and manage research datasets. Results are filtered based on your department access.
          </p>
        </div>
        {canCreateDatasets && (
          <div className="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
            <Link
              to="/datasets/new"
              className="inline-flex items-center justify-center rounded-md border border-transparent text-primary-foreground bg-primary hover:opacity-90 px-4 py-2 text-sm font-medium shadow-sm"
            >
              Create Dataset
            </Link>
          </div>
        )}
      </div>

      {/* Filters */}
      {canUseFilters && (<div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div>
          <Label htmlFor="search">Search</Label>
          <Input
            type="text"
            id="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search datasets..."
            className="mt-1"
          />
        </div>
        <div>
          <Label htmlFor="department">Department</Label>
          <Input
            type="text"
            id="department"
            value={departmentFilter}
            onChange={(e) => setDepartmentFilter(e.target.value)}
            placeholder="Filter by department..."
            className="mt-1"
          />
        </div>
        <div>
          <Label htmlFor="tags">Tags</Label>
          <Input
            type="text"
            id="tags"
            value={tagsFilter}
            onChange={(e) => setTagsFilter(e.target.value)}
            placeholder="Filter by tags..."
            className="mt-1"
          />
        </div>
      </div>)}

      {/* Results */}
      <div className="mt-8 flex flex-col">
        <div className="text-sm text-gray-500 mb-4">
          {datasets.length} dataset{datasets.length !== 1 ? 's' : ''} found
        </div>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {datasets.map((dataset: Dataset) => (
            <DatasetCard key={dataset.id} dataset={dataset} />
          ))}
        </div>
        {datasets.length === 0 && (
          <div className="text-center py-12">
            <svg
              className="mx-auto h-12 w-12 text-gray-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"
              />
            </svg>
            <h3 className="mt-2 text-sm font-medium text-gray-900">No datasets found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {searchQuery || departmentFilter || tagsFilter
                ? 'Try adjusting your filters'
                : 'Get started by creating a new dataset'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};