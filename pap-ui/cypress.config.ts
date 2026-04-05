import { defineConfig } from 'cypress';

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    specPattern: 'cypress/e2e/**/*.cy.ts',
    supportFile: 'cypress/support/e2e.ts',
    viewportWidth: 1280,
    viewportHeight: 720,
    defaultCommandTimeout: 10000,
    env: {
      KEYCLOAK_URL: 'http://localhost:8080',
      KEYCLOAK_REALM: 'stratium',
      KEYCLOAK_CLIENT_ID: 'stratium-pap',
      KEYCLOAK_CLIENT_SECRET: 'stratium-pap-secret',
      TEST_USERNAME: 'admin456',
      TEST_PASSWORD: 'admin123',
    },
  },
  component: {
    devServer: {
      framework: 'react',
      bundler: 'vite',
    },
    specPattern: 'cypress/component/**/*.cy.tsx',
    supportFile: 'cypress/support/component.ts',
    indexHtmlFile: 'cypress/support/component-index.html',
  },
});
