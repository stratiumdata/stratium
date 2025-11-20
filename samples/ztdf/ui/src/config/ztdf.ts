export const ztdfConfig = {
  keyAccessUrl: import.meta.env.VITE_KEY_ACCESS_URL || "http://localhost:8081",
  keyManagerUrl: import.meta.env.VITE_KEY_MANAGER_URL || "http://localhost:8081",
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || "ztdf-viewer",
  clientKeyExpirationMs: parseInt(
    import.meta.env.VITE_CLIENT_KEY_EXPIRATION_MS || '86400000' // 24 hours
  ),
};
