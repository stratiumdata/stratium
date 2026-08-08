# Stratium

Multi-tenant authorization platform for AI agents. Decides, per action, whether a
specific agent — acting under a specific person's delegated authority, at a
specific point in a delegation chain — may perform a specific action.

## Layout

- `services/` — the Go module (`module stratium`). PDP, PAP, and PEP.
- `clients/` — Python SDK and admin UI.
- `deploy/` — Docker and Postgres setup.
- `proto/` — service contracts.
- `docs/` — design specs and implementation plans.

## Development

    make build      # compile
    make test       # tests with -race
    make lint       # golangci-lint
    make conformance  # authorization conformance properties

Design of record: `docs/superpowers/specs/2026-08-08-agent-authorization-redesign-design.md`
