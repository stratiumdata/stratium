import { TestProviders } from '../support/test-providers';
import CedarTest from '../../src/pages/CedarTest';

describe('CedarTest Component', () => {
  it('renders the page title and both panels', () => {
    cy.mount(
      <TestProviders initialRoute="/cedar/test">
        <CedarTest />
      </TestProviders>
    );

    cy.contains('h1', 'Cedar Policy Tester').should('be.visible');
    cy.contains('Policy Input').should('be.visible');
    cy.contains('Test Result').should('be.visible');
    cy.contains('Run a test to see results here').should('be.visible');
  });

  it('shows default form values', () => {
    cy.mount(
      <TestProviders initialRoute="/cedar/test">
        <CedarTest />
      </TestProviders>
    );

    cy.get('#policy_content').should('contain.value', 'permit');
    cy.get('#action').should('have.value', 'UnwrapDEK');
  });

  it('validates JSON before submitting', () => {
    cy.mount(
      <TestProviders initialRoute="/cedar/test">
        <CedarTest />
      </TestProviders>
    );

    cy.get('#subject').clear().type('not json');
    cy.contains('button', 'Run Test').click();
    cy.contains('Invalid JSON in subject attributes').should('be.visible');
  });

  it('displays ALLOW result on successful test', () => {
    cy.intercept('POST', '**/api/v1/cedar/test', {
      body: {
        decision: 'allow',
        reason: 'Access allowed by Cedar policies: policy',
        details: { determining_policies: ['policy'] },
      },
    });

    cy.mount(
      <TestProviders initialRoute="/cedar/test">
        <CedarTest />
      </TestProviders>
    );

    cy.contains('button', 'Run Test').click();
    cy.contains('ALLOW').should('be.visible');
    cy.contains('Access allowed').should('be.visible');
  });

  it('displays DENY result', () => {
    cy.intercept('POST', '**/api/v1/cedar/test', {
      body: {
        decision: 'deny',
        reason: 'No matching Cedar policy found',
        details: {},
      },
    });

    cy.mount(
      <TestProviders initialRoute="/cedar/test">
        <CedarTest />
      </TestProviders>
    );

    cy.contains('button', 'Run Test').click();
    cy.contains('DENY').should('be.visible');
  });

  it('sends correct payload to API', () => {
    cy.intercept('POST', '**/api/v1/cedar/test', (req) => {
      expect(req.body).to.have.property('policy_content');
      expect(req.body).to.have.property('action', 'UnwrapDEK');
      expect(req.body.subject_attributes).to.have.property('id', 'alice');
      expect(req.body.resource_attributes).to.have.property('id', 'doc-123');
      req.reply({ body: { decision: 'allow', reason: 'test', details: {} } });
    });

    cy.mount(
      <TestProviders initialRoute="/cedar/test">
        <CedarTest />
      </TestProviders>
    );

    cy.contains('button', 'Run Test').click();
    cy.contains('ALLOW').should('be.visible');
  });

  it('includes namespace in request when provided', () => {
    cy.intercept('POST', '**/api/v1/cedar/test', (req) => {
      expect(req.body).to.have.property('namespace', 'MyNS');
      req.reply({ body: { decision: 'allow', reason: 'test', details: {} } });
    });

    cy.mount(
      <TestProviders initialRoute="/cedar/test">
        <CedarTest />
      </TestProviders>
    );

    cy.get('#namespace').type('MyNS');
    cy.contains('button', 'Run Test').click();
    cy.contains('ALLOW').should('be.visible');
  });
});
