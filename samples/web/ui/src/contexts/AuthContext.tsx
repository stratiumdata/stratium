import React, { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react';
import keycloak from '@/config/keycloak';
import type { AuthUser } from '@/types';

interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: AuthUser | null;
  token: string | null;
  login: () => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState<string | null>(null);

  const updateUserFromToken = useCallback(() => {
    if (keycloak.tokenParsed) {
      const tokenData = keycloak.tokenParsed as any;
      setUser({
        id: tokenData.sub || '',
        email: tokenData.email || '',
        name: tokenData.name || tokenData.preferred_username || '',
        department: tokenData.department || '',
        role: tokenData.role || 'viewer',
      });
    }
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    setToken(null);
    setIsAuthenticated(false);
    keycloak.logout();
  }, []);

  const initKeycloak = useCallback(async () => {
    try {
      const authenticated = await keycloak.init({
        onLoad: 'check-sso',
        silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
        pkceMethod: 'S256',
      });

      setIsAuthenticated(authenticated);

      if (authenticated) {
        updateUserFromToken();
        setToken(keycloak.token || null);

        // Setup token refresh
        keycloak.onTokenExpired = () => {
          keycloak.updateToken(30).then((refreshed) => {
            if (refreshed) {
              setToken(keycloak.token || null);
              console.log('Token refreshed');
            }
          }).catch(() => {
            console.error('Failed to refresh token');
            logout();
          });
        };
      }
    } catch (error) {
      console.error('Failed to initialize Keycloak:', error);
    } finally {
      setIsLoading(false);
    }
  }, [updateUserFromToken, logout]);

  useEffect(() => {
    initKeycloak();
  }, [initKeycloak]);

  const login = useCallback(() => {
    keycloak.login();
  }, []);

  const contextValue = useMemo(() => ({
    isAuthenticated,
    isLoading,
    user,
    token,
    login,
    logout,
  }), [isAuthenticated, isLoading, user, token, login, logout]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};