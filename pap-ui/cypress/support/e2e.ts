/// <reference types="cypress" />

import './commands';

// Prevent uncaught exceptions from failing tests (Keycloak SSO check can throw)
Cypress.on('uncaught:exception', (err) => {
  if (err.message.includes('keycloak') || err.message.includes('SSO')) {
    return false;
  }
  return true;
});
