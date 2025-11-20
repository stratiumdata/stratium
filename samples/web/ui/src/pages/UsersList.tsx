import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/api/client';
import type { User } from '@/types';

export const UsersList: React.FC = () => {
  const { data: users, isLoading, error } = useQuery({
    queryKey: ['users'],
    queryFn: () => apiClient.getUsers(),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-lg text-muted-foreground">Loading users...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-4 sm:px-6 lg:px-8">
        <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-4">
          <h3 className="text-destructive font-medium">Error loading users</h3>
          <p className="text-destructive/80 text-sm mt-1">{(error as Error).message}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="px-4 sm:px-6 lg:px-8">
      <div className="sm:flex sm:items-center">
        <div className="sm:flex-auto">
          <h1 className="text-3xl font-semibold text-foreground">Users</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Manage users across all departments. Admin access required.
          </p>
        </div>
      </div>

      <div className="mt-8 flex flex-col">
        <div className="text-sm text-muted-foreground mb-4">
          {users?.length || 0} user{users?.length !== 1 ? 's' : ''} found
        </div>
        <div className="-my-2 -mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div className="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
            <div className="overflow-hidden shadow-elegant ring-1 ring-border md:rounded-lg">
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-foreground sm:pl-6">
                      Name
                    </th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-foreground">
                      Email
                    </th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-foreground">
                      Title
                    </th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-foreground">
                      Created
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border bg-card">
                  {users?.map((user: User) => (
                    <tr key={user.id} className="hover:bg-muted/20">
                      <td className="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-foreground sm:pl-6">
                        {user.name}
                      </td>
                      <td className="whitespace-nowrap px-3 py-4 text-sm text-muted-foreground">
                        {user.email}
                      </td>
                      <td className="whitespace-nowrap px-3 py-4 text-sm text-muted-foreground">
                        {user.title}
                      </td>
                      <td className="whitespace-nowrap px-3 py-4 text-sm text-muted-foreground">
                        {new Date(user.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const RoleBadge: React.FC<{ role: string }> = ({ role }) => {
  const colors = {
    admin: 'bg-primary/20 text-primary-foreground',
    editor: 'bg-accent/20 text-accent-foreground',
    viewer: 'bg-muted text-muted-foreground',
  };

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
        colors[role as keyof typeof colors] || colors.viewer
      }`}
    >
      {role}
    </span>
  );
};