/// <reference types="cypress" />

import { mount } from 'cypress/react';
import './commands';
import '../../src/index.css';

declare global {
  namespace Cypress {
    interface Chainable {
      mount: typeof mount;
    }
  }
}

Cypress.Commands.add('mount', mount);
