# Patent Draft Package: Agent Authorization

This directory contains a working patent draft package for Stratium's agent authorization workflow, tailored to the double-hop delegation model described in `docs/PRD_AGENT_AUTHORIZATION.md`.

## Documents

- `docs/patent/01-patent-specification-draft.md` — patent-style specification draft
- `docs/patent/02-claim-set.md` — independent and dependent claims
- `docs/patent/03-figure-descriptions.md` — figure list and drawing narratives
- `docs/patent/04-invention-disclosure-form.md` — attorney-ready invention disclosure form
- `docs/patent/05-provisional-ready-package.md` — provisional-oriented filing package and checklist
- `docs/patent/06-nonprovisional-attorney-package.md` — nonprovisional assembly and attorney handoff package
- `docs/patent/figures/README.md` — draft Mermaid figure set for all six patent figures
- `docs/patent/figures/*.svg` — cleaner black-and-white SVG drafts for illustrator or counsel review

## Notes

- These documents are a technical drafting starting point, not legal advice.
- The specification and claims are written in nonprovisional style so they can be adapted for a provisional filing or expanded for a later nonprovisional application.
- For U.S. filing practice, provisional applications generally do not require claims, while nonprovisional applications do. See the USPTO guidance:
  - https://www.uspto.gov/patents/basics/apply/provisional-application
  - https://www.uspto.gov/patents/basics/types-patent-applications

## Drafting Assumptions

- The invention centers on task-bound authorization for autonomous or semi-autonomous agents.
- The implementation context is Stratium's delegated authorization architecture, including agent registration, delegation tokens, compound policy evaluation, trust tiers, scope narrowing, and audit lineage.
- Novelty emphasis is placed on runtime enforcement, derivative delegated scope, cryptographic delegation artifacts, and provenance across agent chains.
