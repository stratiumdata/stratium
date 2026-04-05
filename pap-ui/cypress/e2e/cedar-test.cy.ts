describe('Cedar Policy Tester', () => {
  beforeEach(() => {
    cy.login();
    cy.contains('Dashboard', { timeout: 15000 }).should('be.visible');
    cy.visit('/cedar/test');
    cy.contains('Cedar Policy Tester').should('be.visible');
  });

  it('navigates to Cedar Tester page from sidebar', () => {
    cy.visit('/');
    cy.contains('Cedar Tester').click();
    cy.url().should('include', '/cedar/test');
    cy.contains('h1', 'Cedar Policy Tester').should('be.visible');
  });

  it('shows the input form and empty result pane', () => {
    cy.contains('Policy Input').should('be.visible');
    cy.contains('Test Result').should('be.visible');
    cy.contains('Run a test to see results here').should('be.visible');
  });

  it('runs a test that results in ALLOW', () => {
    cy.get('#policy_content').should('contain.value', 'permit');
    cy.get('#action').should('have.value', 'UnwrapDEK');

    cy.contains('button', 'Run Test').click();
    cy.contains('ALLOW', { timeout: 10000 }).should('be.visible');
  });

  it('runs a test that results in DENY', () => {
    cy.get('#policy_content').clear().type(
      'forbid(\n  principal,\n  action,\n  resource\n);',
      { parseSpecialCharSequences: false }
    );

    cy.contains('button', 'Run Test').click();
    cy.contains('DENY', { timeout: 10000 }).should('be.visible');
  });

  it('runs a test with mismatched action (default deny)', () => {
    cy.get('#action').clear().type('WrapDEK');
    cy.contains('button', 'Run Test').click();
    cy.contains('DENY', { timeout: 10000 }).should('be.visible');
    cy.contains('No matching Cedar policy').should('be.visible');
  });

  it('shows error for invalid JSON in subject attributes', () => {
    cy.get('#subject').clear().type('not valid json');
    cy.contains('button', 'Run Test').click();
    cy.contains('Invalid JSON in subject attributes').should('be.visible');
  });

  it('shows error for invalid JSON in resource attributes', () => {
    cy.get('#resource').clear().type('not valid json');
    cy.contains('button', 'Run Test').click();
    cy.contains('Invalid JSON in resource attributes').should('be.visible');
  });

  it('preserves form state between test runs', () => {
    const customPolicy = 'permit(principal, action, resource);';
    cy.get('#policy_content').clear().type(customPolicy, { parseSpecialCharSequences: false });
    cy.get('#action').clear().type('CustomAction');

    cy.contains('button', 'Run Test').click();
    cy.contains('ALLOW', { timeout: 10000 }).should('be.visible');

    cy.get('#policy_content').should('contain.value', customPolicy);
    cy.get('#action').should('have.value', 'CustomAction');
  });
});
