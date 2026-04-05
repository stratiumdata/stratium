import { TestProviders } from '../support/test-providers';
import CedarSchemas from '../../src/pages/CedarSchemas';

describe('CedarSchemas Component', () => {
  it('renders the page title and New Schema button', () => {
    cy.intercept('GET', '**/api/v1/cedar/schemas*', {
      body: { schemas: [], total: 0 },
    });

    cy.mount(
      <TestProviders initialRoute="/cedar/schemas">
        <CedarSchemas />
      </TestProviders>
    );

    cy.contains('h1', 'Cedar Schemas').should('be.visible');
    cy.contains('button', 'New Schema').should('be.visible');
  });

  it('shows empty state when no schemas exist', () => {
    cy.intercept('GET', '**/api/v1/cedar/schemas*', {
      body: { schemas: [], total: 0 },
    });

    cy.mount(
      <TestProviders initialRoute="/cedar/schemas">
        <CedarSchemas />
      </TestProviders>
    );

    cy.contains('No schemas found').should('be.visible');
  });

  it('displays schemas in a table', () => {
    cy.intercept('GET', '**/api/v1/cedar/schemas*', {
      body: {
        schemas: [
          {
            id: '123', namespace: 'Stratium', name: 'ztdf-base', description: 'Base schema',
            schema_content: '{}', schema_format: 'json', version: '1.0', is_active: true,
            created_at: '2026-04-04T00:00:00Z', updated_at: '2026-04-04T00:00:00Z',
            created_by: 'admin', updated_by: 'admin',
          },
        ],
        total: 1,
      },
    });

    cy.mount(
      <TestProviders initialRoute="/cedar/schemas">
        <CedarSchemas />
      </TestProviders>
    );

    cy.contains('ztdf-base').should('be.visible');
    cy.contains('Stratium').should('exist');
    cy.contains('JSON').should('exist');
    cy.contains('Active').should('exist');
  });

  it('filters schemas by search term', () => {
    cy.intercept('GET', '**/api/v1/cedar/schemas*', {
      body: {
        schemas: [
          {
            id: '1', namespace: 'Stratium', name: 'ztdf-base', description: '',
            schema_content: '{}', schema_format: 'json', version: '1.0', is_active: true,
            created_at: '', updated_at: '', created_by: '', updated_by: '',
          },
          {
            id: '2', namespace: 'Acme', name: 'acme-schema', description: '',
            schema_content: '{}', schema_format: 'cedar', version: '2.0', is_active: false,
            created_at: '', updated_at: '', created_by: '', updated_by: '',
          },
        ],
        total: 2,
      },
    });

    cy.mount(
      <TestProviders initialRoute="/cedar/schemas">
        <CedarSchemas />
      </TestProviders>
    );

    cy.contains('ztdf-base').should('be.visible');
    cy.contains('acme-schema').should('be.visible');

    cy.get('input[placeholder="Search schemas..."]').type('acme');
    cy.contains('ztdf-base').should('not.exist');
    cy.contains('acme-schema').should('be.visible');
  });
});
