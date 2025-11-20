import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import Keycloak from 'keycloak-js';
import { keycloakConfig } from '@/config/keycloak';
import { useToast } from '@/hooks/use-toast';
import { initializeApiClient } from '@/lib/api-client';

const resolvePkceMethod = () => {
  if (typeof window === 'undefined') {
    return 'S256' as const;
  }

  const hasSubtleCrypto = Boolean(window.crypto?.subtle);
  const secureContext = typeof window.isSecureContext === 'boolean' ? window.isSecureContext : true;

  return hasSubtleCrypto && secureContext ? ('S256' as const) : ('plain' as const);
};

interface AuthContextType {
  keycloak: Keycloak | null;
  authenticated: boolean;
  loading: boolean;
  login: () => void;
  logout: () => void;
  getUsername: () => string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [keycloak, setKeycloak] = useState<Keycloak | null>(null);
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    const initKeycloak = async () => {
      const keycloakInstance = new Keycloak(keycloakConfig);
      const pkceMethod = resolvePkceMethod();

      if (pkceMethod === 'plain') {
        console.warn(
          'Web Crypto API not available. Falling back to PKCE "plain" challenge. ' +
            'Serve the PAP UI over HTTPS or localhost to restore S256.',
        );
        toast({
          title: 'Insecure Context Detected',
          description:
            'The PAP UI is running without Web Crypto support. Switch to HTTPS or localhost to enable secure PKCE (S256).',
          variant: 'destructive',
        });
      }

      try {
        const authenticated = await keycloakInstance.init({
          onLoad: 'check-sso',
          checkLoginIframe: false,
          pkceMethod,
        });

        setKeycloak(keycloakInstance);
        setAuthenticated(authenticated);

        // Initialize API client when Keycloak is authenticated
        if (authenticated) {
          initializeApiClient(keycloakInstance);
        }
      } catch (error) {
        console.error('Keycloak initialization failed:', error);
        toast({
          title: 'Authentication Error',
          description: 'Failed to initialize authentication. Please check Keycloak configuration.',
          variant: 'destructive',
        });
      } finally {
        setLoading(false);
      }
    };

    initKeycloak();
  }, [toast]);

  const login = () => {
    keycloak?.login();
  };

  const logout = () => {
    keycloak?.logout();
  };

  const getUsername = () => {
    return keycloak?.tokenParsed?.preferred_username || 'Unknown User';
  };

  return (
    <AuthContext.Provider
      value={{
        keycloak,
        authenticated,
        loading,
        login,
        logout,
        getUsername,
      }}
    >
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
