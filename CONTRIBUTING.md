# Contributing

Thanks for helping. Start with [`docs/concepts.md`](docs/concepts.md) — most
review feedback comes back to it.

## The one rule

**The component being policed never classifies its own actions.** Before
sending a change, ask: *could a hostile enforcement point (PEP) get a better
answer by lying?* If yes, the logic is in the wrong process. Changes that move
judgement into the PEP will not be merged.

## Setup

Needs Go 1.25+, Node 22+, and Docker (for `make integration` only).

    make build        # builds the admin UI, then the Go binaries
    make test         # Go tests with -race, plus the UI's lint and tests
    make lint
    make conformance  # authorization conformance properties

Use `make`, not bare `go build` — see the README for why.

## Pull requests

- One logical change per PR, with tests. A bug fix starts with a failing test.
- Commit messages: `<type>: <description>` (`feat`, `fix`, `docs`, `test`,
  `refactor`, `chore`, `perf`, `ci`).
- `make test` and `make lint` must pass; CI runs the same targets.

## Security issues

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).
