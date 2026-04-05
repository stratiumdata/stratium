/// <reference types="cypress" />

declare global {
  namespace Cypress {
    interface Chainable {
      /**
       * Authenticate with Keycloak by performing the full OAuth2 login flow
       * programmatically, establishing session cookies so check-sso succeeds.
       */
      login(username?: string, password?: string): Chainable<void>;
    }
  }
}

/**
 * Performs the Keycloak OAuth2 authorization code flow programmatically:
 * 1. Visit the Keycloak auth endpoint to get the login form
 * 2. POST credentials to the login form action URL
 * 3. Follow redirects back to the app with the auth code
 * This establishes session cookies so the app's check-sso works.
 */
Cypress.Commands.add('login', (
  username = Cypress.env('TEST_USERNAME'),
  password = Cypress.env('TEST_PASSWORD'),
) => {
  const keycloakUrl = Cypress.env('KEYCLOAK_URL');
  const realm = Cypress.env('KEYCLOAK_REALM');
  const clientId = Cypress.env('KEYCLOAK_CLIENT_ID');

  // Step 1: Hit the Keycloak authorization endpoint.
  // This returns the login page HTML with the form action URL.
  cy.request({
    url: `${keycloakUrl}/realms/${realm}/protocol/openid-connect/auth`,
    qs: {
      client_id: clientId,
      redirect_uri: `${Cypress.config('baseUrl')}/`,
      response_type: 'code',
      scope: 'openid',
    },
    followRedirect: false,
  }).then((response) => {
    // Extract the form action URL from the login page HTML
    const html = response.body;
    const actionMatch = html.match(/action="([^"]+)"/);
    if (!actionMatch) {
      throw new Error('Could not find login form action URL in Keycloak response');
    }
    const loginUrl = actionMatch[1].replace(/&amp;/g, '&');

    // Step 2: POST credentials to the login form
    cy.request({
      method: 'POST',
      url: loginUrl,
      form: true,
      body: {
        username,
        password,
      },
      followRedirect: false,
    }).then((loginResponse) => {
      // Step 3: Follow the redirect back to the app.
      // Keycloak redirects to our app with ?code=... and session cookies are set.
      const redirectUrl = loginResponse.headers['location'] as string;
      if (redirectUrl) {
        cy.visit(redirectUrl);
      }
    });
  });
});

export {};
