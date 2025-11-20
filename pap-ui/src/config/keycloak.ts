// Keycloak Configuration
// Note: Update these values with your actual Keycloak instance details
export const keycloakConfig = {
    url: import.meta.env.VITE_KEYCLOAK_URL,
    realm: import.meta.env.VITE_KEYCLOAK_REALM,
    clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
};

// Note: Client secrets should NEVER be exposed in frontend code
// This is handled by Keycloak's public client configuration
