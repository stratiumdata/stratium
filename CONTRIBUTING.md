# Contributing

Thanks for helping. Start with [`docs/concepts.md`](docs/concepts.md) — most
review feedback comes back to it.

## The one rule

**The component being policed never classifies its own actions.** Before
sending a change, ask: *could a hostile enforcement point (PEP) get a better
answer by lying?* If yes, the logic is in the wrong process. Changes that move
judgement into the PEP will not be merged.

## Setup

Needs Go 1.26+, Node 22+, and Docker (for `make integration` only).

    make build        # builds the admin UI, then the Go binaries
    make test         # Go tests with -race, plus the UI's lint and tests
    make lint
    make conformance  # authorization conformance properties

**Use `make`, not `go build` directly.** The admin console (`clients/ui`) is
embedded into the `stratium-pap` binary with `//go:embed dist`, and `dist/` is
a git-ignored build output. On a fresh checkout every Go command that compiles
`cmd/stratium-pap` (`go build`, `go vet`, `go test`, `golangci-lint`) fails
with:

    pattern dist: no matching files found

until the console has been built. `make build`, `make test`, `make vet` and
`make lint` each depend on the `ui` target, which runs `npm ci` and the Vite
build only when the console's own inputs have changed. `make ui` alone is
enough to unblock bare `go` commands afterwards.

Two things follow:

- `go install github.com/stratiumdata/stratium/services/cmd/stratium-pap@…`
  can never work. Building `stratium-pap` means cloning this repository and
  running `make`.
- `dist/` is deliberately never committed. A checked-in build output would
  make the embed test (`services/cmd/stratium-pap/ui_test.go`) pass whether or
  not anyone rebuilt the console, which is the only thing that test detects.

### `make integration`

It brings up the whole stack in Docker (24 services: Postgres, ten PDP
instances, two PEPs, a real Envoy and its upstream, a real gRPC target, three
`stratium-pap` instances, a real Keycloak, and two real LiteLLM proxies), runs
the integration-tagged tests against it, and tears it down again with its
volumes, always. CI runs it on every pull request.

It needs Docker and, on a cold machine, network access to pull `postgres`,
`envoyproxy/envoy`, `quay.io/keycloak/keycloak` and `ghcr.io/berriai/litellm`.
The Keycloak realm is imported from
`deploy/docker/keycloak/stratium-realm.json`; nothing in it is a credential to
anything outside this stack.

## Pull requests

- One logical change per PR, with tests. A bug fix starts with a failing test.
- Commit messages: `<type>: <description>` (`feat`, `fix`, `docs`, `test`,
  `refactor`, `chore`, `perf`, `ci`).
- `make test` and `make lint` must pass; CI runs the same targets.

## Security issues

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).
