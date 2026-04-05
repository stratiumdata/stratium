describe('Cedar Schemas', () => {
  beforeEach(() => {
    cy.login();
    // After login, we're on the dashboard. Wait for app to be ready.
    cy.contains('Dashboard', { timeout: 15000 }).should('be.visible');
  });

  it('navigates to Cedar Schemas page from sidebar', () => {
    cy.contains('Cedar Schemas').click();
    cy.url().should('include', '/cedar/schemas');
    cy.contains('h1', 'Cedar Schemas').should('be.visible');
  });

  it('creates a new Cedar schema', () => {
    cy.visit('/cedar/schemas');
    cy.contains('New Schema').click();
    cy.url().should('include', '/cedar/schemas/new');

    cy.get('#name').type('test-schema');
    cy.get('#namespace').clear().type('TestNS');
    cy.get('#version').clear().type('1.0');
    cy.get('#description').type('Test schema for Cypress E2E');
    cy.get('#schema_content').type(
      '{"TestNS":{"entityTypes":{"User":{},"Resource":{}},"actions":{"Read":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["Resource"]}}}}}',
      { parseSpecialCharSequences: false }
    );

    cy.contains('button', 'Create Schema').click();

    cy.url().should('include', '/cedar/schemas');
    cy.url().should('not.include', '/new');
    cy.contains('test-schema').should('be.visible');
  });

  it('searches schemas by name', () => {
    cy.visit('/cedar/schemas');
    cy.get('input[placeholder="Search schemas..."]').type('test-schema');
    cy.contains('test-schema').should('be.visible');

    cy.get('input[placeholder="Search schemas..."]').clear().type('nonexistent');
    cy.contains('No schemas found').should('be.visible');
  });

  it('edits an existing schema', () => {
    cy.visit('/cedar/schemas');

    cy.get('table tbody tr').first().within(() => {
      cy.get('button').first().click();
    });

    cy.url().should('match', /\/cedar\/schemas\/[0-9a-f-]+/);
    cy.get('#version').clear().type('1.1');
    cy.contains('button', 'Update Schema').click();
    cy.url().should('eq', Cypress.config().baseUrl + '/cedar/schemas');
  });

  it('deletes a schema with confirmation', () => {
    cy.visit('/cedar/schemas');
    cy.on('window:confirm', () => true);

    cy.get('table tbody tr').first().within(() => {
      cy.get('button').last().click();
    });

    cy.contains('No schemas found', { timeout: 10000 }).should('be.visible');
  });

  it('cancels schema creation', () => {
    cy.visit('/cedar/schemas/new');
    cy.get('#name').type('will-be-cancelled');
    cy.contains('button', 'Cancel').click();
    cy.url().should('include', '/cedar/schemas');
    cy.url().should('not.include', '/new');
  });
});
