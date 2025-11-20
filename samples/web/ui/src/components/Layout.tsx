import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { useRolePermissions } from '@/hooks/usePermissions';

interface LayoutProps {
  children: React.ReactNode;
}

export const Layout = React.memo<LayoutProps>(({ children }) => {
  const { user, logout } = useAuth();
  const { canManageUsers } = useRolePermissions();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-background">
      <nav className="bg-card shadow-sm border-b border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center">
                <Link to="/" className="text-xl font-bold text-primary">
                  Stratium Research
                </Link>
              </div>
              <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
                <Link
                  to="/datasets"
                  className="inline-flex items-center px-1 pt-1 text-sm font-medium text-foreground border-b-2 border-transparent hover:border-border"
                >
                  Datasets
                </Link>
                {canManageUsers && (
                  <Link
                    to="/users"
                    className="inline-flex items-center px-1 pt-1 text-sm font-medium text-foreground border-b-2 border-transparent hover:border-border"
                  >
                    Users
                  </Link>
                )}
              </div>
            </div>
            <div className="flex items-center">
              {user && (
                <div className="flex items-center space-x-4">
                  <div className="text-sm">
                    <div className="font-medium text-foreground">{user.name}</div>
                    <div className="text-muted-foreground">
                      {user.department} • {user.role}
                    </div>
                  </div>
                  <button
                    onClick={handleLogout}
                    className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-primary-foreground bg-primary hover:opacity-90 transition-all shadow-elegant"
                  >
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  );
});

Layout.displayName = 'Layout';