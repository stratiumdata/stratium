describe('Cedar Templates', () => {
  beforeEach(() => {
    cy.login();
    cy.contains('Dashboard', { timeout: 15000 }).should('be.visible');
  });

  it('navigates to Cedar Templates page from sidebar', () => {
    cy.contains('Cedar Templates').click();
    cy.url().should('include', '/cedar/templates');
    cy.contains('h1', 'Cedar Templates').should('be.visible');
  });

  it('creates a new Cedar template', () => {
    cy.visit('/cedar/templates/new');

    cy.get('#name').type('user-resource-access');
    cy.get('#namespace').clear().type('TestNS');
    cy.get('#description').type('Grant a specific user access to a specific resource');
    cy.get('#template_content').type(
      'permit(\n  principal == ?principal,\n  action in [Action::"Read"],\n  resource == ?resource\n);',
      { parseSpecialCharSequences: false }
    );

    cy.contains('button', 'Create Template').click();

    cy.url().should('include', '/cedar/templates');
    cy.url().should('not.include', '/new');
    cy.contains('user-resource-access').should('be.visible');
  });

  it('views template details', () => {
    cy.visit('/cedar/templates');

    cy.get('table tbody tr').first().within(() => {
      cy.get('button').first().click();
    });

    cy.url().should('match', /\/cedar\/templates\/[0-9a-f-]+/);
    cy.contains('Template Details').should('be.visible');
    cy.get('pre').should('contain.text', 'permit');
  });

  it('instantiates a template with entity bindings', () => {
    cy.visit('/cedar/templates');

    cy.get('table tbody tr').first().within(() => {
      cy.get('button').first().click();
    });

    cy.contains('Instantiate Template').should('be.visible');
    cy.get('#principal_entity').type('TestNS::User::"alice"', { parseSpecialCharSequences: false });
    cy.get('#resource_entity').type('TestNS::Resource::"doc-1"', { parseSpecialCharSequences: false });

    cy.contains('button', 'Instantiate').click();
    cy.contains('Linked Policies').should('be.visible');
  });

  it('deletes a template with confirmation', () => {
    cy.visit('/cedar/templates');
    cy.on('window:confirm', () => true);

    cy.get('table tbody tr').first().within(() => {
      cy.get('button').last().click();
    });

    cy.contains('No templates found', { timeout: 10000 }).should('be.visible');
  });

  it('cancels template creation', () => {
    cy.visit('/cedar/templates/new');
    cy.get('#name').type('will-be-cancelled');
    cy.contains('button', 'Cancel').click();
    cy.url().should('include', '/cedar/templates');
    cy.url().should('not.include', '/new');
  });
});
