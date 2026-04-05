import { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { AuthContext } from '../../src/contexts/AuthContext';
import { initializeApiClient } from '../../src/lib/api-client';

// Initialize the API client with a minimal stub so getApiClient() doesn't throw.
// The actual HTTP requests will be intercepted by cy.intercept().
const stubKeycloak = { updateToken: () => Promise.resolve(true), token: 'test-token' } as any;
initializeApiClient(stubKeycloak);

const mockAuth = {
  keycloak: stubKeycloak,
  authenticated: true,
  loading: false,
  login: () => {},
  logout: () => {},
  getUsername: () => 'test-user',
};

export const TestProviders = ({
  children,
  initialRoute = '/',
}: {
  children: ReactNode;
  initialRoute?: string;
}) => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  return (
    <QueryClientProvider client={queryClient}>
      <AuthContext.Provider value={mockAuth}>
        <MemoryRouter initialEntries={[initialRoute]}>
          {children}
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>
  );
};
