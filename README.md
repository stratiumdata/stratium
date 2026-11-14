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

    make build      # compile (builds the admin UI first — see below)
    make test       # Go tests with -race, plus the admin UI's lint and tests
    make lint       # golangci-lint
    make conformance  # authorization conformance properties
    make integration  # the live-stack proofs (see below)

`make integration` brings up the whole stack in Docker — 17 services:
Postgres, eight PDP instances, two PEPs, a real Envoy and its upstream, a real
gRPC target, two `stratium-pap` instances, and a real Keycloak — runs the
integration-tagged tests against it, and tears it down
again with its volumes, always. It therefore needs Docker and, on a cold
machine, network access to pull `postgres`, `envoyproxy/envoy`, and
`quay.io/keycloak/keycloak`. The Keycloak realm is imported from
`deploy/docker/keycloak/stratium-realm.json`; nothing in it is a credential
to anything outside this stack.

**Use `make`, not `go build` directly.** The admin UI (`clients/ui`) is
embedded into the `stratium-pap` binary with `//go:embed dist`, and `dist/` is
a git-ignored build output. On a fresh checkout every Go command that compiles
`cmd/stratium-pap` — `go build`, `go vet`, `go test`, `golangci-lint` — fails
with:

    pattern dist: no matching files found

until the UI has been built. `make build`, `make test`, `make vet`, and
`make lint` each depend on the `ui` target, which runs `npm ci` and the Vite
build only when the UI's own inputs have changed. Node is therefore a build
dependency of this repository, not only of the UI. `make ui` on its own is
enough to unblock bare `go` commands afterwards.

One consequence of this: `go install stratium/cmd/stratium-pap@…` can never
work. There is no `make ui` step in a module install, and `dist/` — git-ignored
for the reason above — is never part of the module's source either way.
Building `stratium-pap` means cloning this repository and running `make`.

`dist/` is deliberately never committed: a checked-in build output would make
the embed test (`services/cmd/stratium-pap/ui_test.go`) pass forever whether or
not anyone rebuilt the UI, which is the only thing that test exists to detect.

New here? [`docs/concepts.md`](docs/concepts.md) explains what the system
decides and why it holds, in concepts rather than code.
[`docs/validation-journeys.md`](docs/validation-journeys.md) is the pre-launch
validation list and an honest account of where the model is too tight.
[`docs/default-posture.md`](docs/default-posture.md) answers "what should I
actually set?" for a first real agent.

Design of record: `docs/superpowers/specs/2026-08-08-agent-authorization-redesign-design.md`

## Installing the enforcement surfaces

`services/cmd/stratium-pep` is the client-side binary that gates a real
agent's tool calls against the PDP, as a Claude Code `PreToolUse` hook or as
an MCP proxy. See [`docs/pep.md`](docs/pep.md) for the `.claude/settings.json`
hook entry, launching the MCP proxy in place of a real server, required
environment variables, and how to start a session — **every tool call is
denied until a session is started and a policy permits it.**

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports: [`SECURITY.md`](SECURITY.md).
