# Stratium User Guide

For someone who has never touched this system before. It assumes you can use a
terminal, Docker, and an HTTP client, and nothing else.

Read §1 once for orientation. Everything after it is reference you can jump into.

**Contents**

1. [What Stratium is](#1-what-stratium-is)
2. [Install](#2-install)
3. [Setup — every environment variable](#3-setup--every-environment-variable)
4. [Connecting to an existing OIDC provider](#4-connecting-to-an-existing-oidc-provider)
5. [PAP capabilities — the admin plane](#5-pap-capabilities--the-admin-plane)
6. [PEP capabilities — putting an agent behind Stratium](#6-pep-capabilities--putting-an-agent-behind-stratium)
7. [Troubleshooting](#7-troubleshooting)

Deeper references: [`docs/architecture.md`](architecture.md) for how the system
works internally, [`docs/pep.md`](pep.md) for the enforcement-surface operator
manual, and the two plans under [`docs/testing/`](testing/) for hands-on
walkthroughs with verified output.

---

## 1. What Stratium is

Stratium answers one question, per action, for AI agents:

> May **this agent**, acting under **this person's** delegated authority, perform
> **this action** on **this resource**, right now?

It is three programs:

| Binary | Name | What you do with it |
|---|---|---|
| `stratium-pdp` | Policy **Decision** Point | Runs as a service. Answers `Decide` over gRPC. You configure it and otherwise leave it alone. |
| `stratium-pap` | Policy **Administration** Point | Runs as a service with a web UI and a REST API. Where you write policies, register agents, and approve escalations. |
| `stratium-pep` | Policy **Enforcement** Point | Runs *beside the agent*, on the agent's machine. Intercepts tool calls and blocks the ones the PDP refuses. |

The single most important thing to understand before you configure anything:

> **The PEP does not decide. It forwards the tool call's arguments to the PDP
> verbatim and enforces the answer.** All classification — how dangerous an
> action is, what resource it touches, how that resource is classified — happens
> server-side, in the PDP, from data the PDP itself trusts.

The practical consequence you will meet on day one:

> **Every tool call is denied until a session has been started and a policy
> permits it.** If you install a PEP and everything is denied, that is almost
> always correct behaviour, not a bug. Work through §6 in order.

### Key terms

| Term | Meaning |
|---|---|
| **Tenant** | Your isolation boundary. Fixed at process startup, never sent in a request. One PDP process serves exactly one tenant, for its whole life. |
| **Agent** | A registered actor — a name, a provider, a trust tier, an on/off switch, and an optional tool allowlist. |
| **Delegation** | A time-boxed grant from a person to an agent: which tools, up to which action tier, under which classification caps. Delegations chain, and a child can only ever narrow its parent. |
| **Action tier** | How dangerous an action is, 0–4, derived by the PDP. |
| **Trust tier** | How much an agent is trusted, 0–3. |
| **Policy** | A rule about the *principal* (the human), written in Cedar, Rego, XACML, or JSON. |
| **Session** | One `session-start` call that creates a delegation and writes a session file the PEP reads on every tool call. |

**Action tiers** — what the PDP derives, and what a delegation caps:

| Value | Name | Meaning | Example |
|---|---|---|---|
| `0` | `REASONING` | no side effects | thinking, planning |
| `1` | `READ_ONLY` | reads data | `cat`, `ls`, `git log`, `Read` |
| `2` | `INTERNAL_MODIFY` | mutates internal state | `Write`, `Edit`, `git commit` |
| `3` | `EXTERNAL_COMMS` | reaches outside your boundary | `curl`, `git push`, `aws` |
| `4` | `DESTRUCTIVE` | irreversible or financially binding | `rm -rf`, `DROP TABLE`, `terraform destroy` |

**Agent trust tiers** — and the minimum trust each action tier requires:

| Value | Name | Can attempt up to |
|---|---|---|
| `0` | `UNVERIFIED` | `READ_ONLY` |
| `1` | `REGISTERED` | `INTERNAL_MODIFY` |
| `2` | `CERTIFIED` | `EXTERNAL_COMMS` |
| `3` | `PLATFORM_TRUSTED` | `DESTRUCTIVE` |

An agent below the required trust tier is denied regardless of what its
delegation allows. Both checks apply; neither substitutes for the other.

---

## 2. Install

### 2.1 Prerequisites

| Requirement | Version | Needed for |
|---|---|---|
| **Go** | 1.26+ | building any binary |
| **Node + npm** | any current LTS | building the admin UI, which is embedded into `stratium-pap` |
| **Docker + Compose** | any current | the local evaluation stack, and `make integration` |
| **PostgreSQL** | 16 | the database (supplied by Docker in the local stack) |
| **OpenSSL** | any | generating the PDP's token-signing key |
| **An OIDC provider** | — | operators signing in to the PAP (§4) |

### 2.2 Fastest path: the local evaluation stack

This brings up everything — Postgres, PDPs, PEPs, Envoy, Keycloak, and two PAPs
— in one command, applies migrations, generates a signing key, and imports a
ready-made Keycloak realm with three operator accounts.

```bash
git clone https://github.com/stratiumdata/stratium.git
cd stratium
docker compose -f deploy/docker/docker-compose.yml up -d --build --wait --wait-timeout 300
```

**Expected:** every service reaches `Healthy`, ending with lines like

```
 ✔ Container docker-keycloak-1      Healthy
 ✔ Container docker-pdp-pap-1       Healthy
 ✔ Container docker-stratium-pap-1  Healthy
```

**The stack publishes on ephemeral host ports.** Read them, never assume them,
and re-read them after every `up`, `down`, or restart:

```bash
dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }   # a function, not a variable
export PAP="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"
export PDP="localhost:$(dc port pdp-pap 50051  | sed -E 's/.*://')"
export KC="localhost:$(dc port keycloak 8080   | sed -E 's/.*://')"
export TENANT=tenant-pap-e2e-integration
echo "PAP=$PAP  PDP=$PDP  KC=$KC"
```

> `dc` must be a shell **function**. Putting the command in a variable and
> calling `$C port …` fails — the shell looks for a single command whose name is
> the entire string.

Open `http://$PAP/` in a browser for the admin UI. Sign in with one of the
seeded accounts:

| Username | Password | Role |
|---|---|---|
| `pap-admin` | `pap_admin_local_dev_only` | admin |
| `pap-editor` | `pap_editor_local_dev_only` | editor |
| `pap-viewer` | `pap_viewer_local_dev_only` | viewer |

These credentials exist only inside this compose stack and are not a credential
to anything outside it.

**To tear down**, including the database volume:

```bash
docker compose -f deploy/docker/docker-compose.yml down -v --remove-orphans
```

### 2.3 Building from source

```bash
make build      # compile everything (builds the admin UI first)
make test       # Go tests with -race, plus the UI's lint and tests
make lint       # golangci-lint
make vet
make fmt
make proto      # regenerate protobuf stubs
make conformance   # authorization conformance properties
make integration   # full Docker stack, integration tests, guaranteed teardown
make ui            # build only the admin UI
```

> **Use `make`, never bare `go build`.** The admin UI is compiled into
> `stratium-pap` with `//go:embed dist`, and `dist/` is a git-ignored build
> output. On a fresh checkout every Go command that compiles `cmd/stratium-pap`
> — `go build`, `go vet`, `go test`, `golangci-lint` — fails with:
>
> ```
> pattern dist: no matching files found
> ```
>
> `make ui` on its own is enough to unblock bare `go` commands afterwards. A
> consequence worth knowing: `go install github.com/stratiumdata/stratium/services/cmd/stratium-pap@…` can never
> work. Building the PAP means cloning the repository.

`stratium-pep` has no such dependency and builds on its own:

```bash
cd services && go build -o /usr/local/bin/stratium-pep ./cmd/stratium-pep
```

Cross-compiling a PEP for the machines your agents run on:

```bash
cd services
GOOS=linux  GOARCH=amd64 go build -o dist/stratium-pep-linux-amd64  ./cmd/stratium-pep
GOOS=darwin GOARCH=arm64 go build -o dist/stratium-pep-darwin-arm64 ./cmd/stratium-pep
GOOS=windows GOARCH=amd64 go build -o dist/stratium-pep.exe         ./cmd/stratium-pep
```

### 2.4 Container images

Three Dockerfiles under `deploy/docker/`, all producing distroless,
non-root images:

| Dockerfile | Builds | Entrypoint |
|---|---|---|
| `Dockerfile` | `stratium-pdp` | `/stratium-pdp` |
| `Dockerfile.pap` | `stratium-pap` | `/stratium-pap` |
| `Dockerfile.pep` | `stratium-pep` | `/stratium-pep` (no subcommand baked in — pass it as the container's `command`) |

```yaml
# the PEP's mode is a deployment choice, not an image choice
services:
  pep:
    image: your-registry/stratium-pep:latest
    command: ["extauthz"]        # or "proxy", "mcp", "hook", "session-start"
```

> The PDP Dockerfile generates a **throwaway** EC signing key at build time and
> bakes it in at `/etc/stratium/keys/current.pem`. That is for local evaluation
> only: anyone with the image has the key. A PDP running on it logs a warning
> at start-up. A real deployment mounts an operator-managed key file — see §2.6.

### 2.5 Database setup

Stratium needs **three login roles**, none of which may be a superuser or hold
`BYPASSRLS`. Postgres exempts superusers from row-level security
unconditionally, so a service connecting as `postgres` would silently see every
tenant's rows and your tenant isolation would be worth nothing.

| Login role | Member of | Used by | Purpose |
|---|---|---|---|
| `stratium_migrate` | `stratium_audit_owner` | the PDP, at startup only | owns the database; applies migrations. The connection is closed before serving begins. |
| `stratium` | `stratium_app` | the PDP, serving | reads decisions data, appends audit rows. **Must not** be a member of `stratium_audit_owner` — the PDP checks this on every boot and refuses to start otherwise. |
| `stratium_pap_login` | `stratium_pap` | the PAP | holds exactly the write privileges the PDP is deliberately denied. |

```sql
-- run once, as the bootstrap superuser, before any service connects
CREATE ROLE stratium_audit_owner NOLOGIN;
CREATE ROLE stratium_app         NOLOGIN;
CREATE ROLE stratium_pap         NOLOGIN;

CREATE ROLE stratium_migrate   LOGIN PASSWORD '<secret>';
GRANT stratium_audit_owner TO stratium_migrate;

CREATE ROLE stratium          LOGIN PASSWORD '<secret>';
GRANT stratium_app TO stratium;

CREATE ROLE stratium_pap_login LOGIN PASSWORD '<secret>';
GRANT stratium_pap TO stratium_pap_login;

CREATE DATABASE stratium OWNER stratium_migrate;

-- then, connected to the new database
\connect stratium
GRANT CREATE ON SCHEMA public TO stratium_audit_owner;
```

The PDP and the PAP each check their own role when they start, and stop if it
is a superuser or has `BYPASSRLS`.

The complete, commented version is `deploy/docker/init-db.sql` — read it before
adapting it, because each grant has a reason recorded next to it.

**Migrations** are embedded in the PDP binary and applied at startup when
`STRATIUM_MIGRATION_DATABASE_URL` is set. Leave it unset and the PDP skips
migrations and assumes an already-migrated schema, saying so in its logs.

Twenty-five migrations ship. `000002_rls` is the one to know about: it enables
**and forces** row-level security on every tenant table.

### 2.6 Token signing keys

The PDP signs delegation tokens with ES256. Generate a P-256 EC private key:

```bash
mkdir -p /etc/stratium/keys
openssl ecparam -name prime256v1 -genkey -noout -out /etc/stratium/keys/current.pem
chmod 0400 /etc/stratium/keys/current.pem
chown <pdp-user> /etc/stratium/keys/current.pem
```

`STRATIUM_TOKEN_SIGNING_KEY_PATH` holds the **path**, never the key material, so
a leaked environment dump or crash report never leaks a signing key.

**Rotating a key** — no in-flight token breaks:

1. Generate `next.pem`.
2. Set `STRATIUM_TOKEN_PREVIOUS_KEY_PATH` to the *outgoing* `current.pem`.
3. Point `STRATIUM_TOKEN_SIGNING_KEY_PATH` at `next.pem`.
4. Restart the PDP.
5. Once every token issued under the old key has expired, unset
   `STRATIUM_TOKEN_PREVIOUS_KEY_PATH` and restart again.

The previous key **verifies but structurally cannot sign** — that is enforced by
the type, not by convention.

There is no JWKS endpoint and there does not need to be: the PDP verifies its
own tokens, so key distribution is never on the enforcement path.

### 2.7 Verifying the install

```bash
# 1. the PDP is up
grpcurl -plaintext "$PDP" list        # or check the container's health status

# 2. the schema is migrated — 11 application tables, all with RLS forced
psql -c "SELECT relname, relrowsecurity, relforcerowsecurity
         FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'
         ORDER BY 1;"

# 3. the PAP answers, and refuses an unauthenticated caller
curl -sS -w '\n%{http_code}\n' "http://$PAP/v1/policies"     # → unauthorized, 401

# 4. the PAP's public UI config is readable without a token
curl -sS "http://$PAP/ui-config"
```

Expected tables: `agents`, `approvals`, `audit_chain`, `delegations`,
`entitlements`, `policies`, `resource_label_rules`, `spent_proofs`,
`tenant_epoch`, `tier_overrides`, `tool_catalog` — every one with
`rowsecurity = t` and `rowforcesecurity = t`.

---

## 3. Setup — every environment variable

Three rules run through all three binaries:

1. **A value with no safe guess is required and has no default.** A process that
   starts against a guessed database, tenant, or IdP is worse than one that
   refuses to start.
2. **Every missing variable is reported at once.** You will not fix one, restart,
   and discover the next.
3. **Durations use Go syntax** — `5s`, `30s`, `2m`, `1h30m`. Every duration below
   must be **positive**; zero or negative fails at startup with a message naming
   the variable.

### 3.1 `stratium-pdp` — the decision service

**Required, no default:**

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_DATABASE_URL` | `postgres://stratium:pw@db:5432/stratium?sslmode=require` | The serving connection. Must authenticate as a member of `stratium_app` and **must not** be a superuser, hold `BYPASSRLS`, or be a member of `stratium_audit_owner`. The PDP verifies the last of these at boot and refuses to serve if it fails. Connections identify as `stratium-pdp` (`application_name`, visible in `pg_stat_activity`) unless the URL sets its own. |
| `STRATIUM_TENANT_ID` | `acme-prod` | Any non-empty string. Fixed for the process's lifetime; **no request can carry one**. Serving a second tenant means running a second PDP process. |
| `STRATIUM_TOKEN_SIGNING_KEY_PATH` | `/etc/stratium/keys/current.pem` | Path to a PEM-encoded EC private key. Presence is checked here; readability and key validity are checked when the file is loaded, moments later. |
| `STRATIUM_DPOP_FRESHNESS_WINDOW` | `30s` | How far a DPoP proof's `iat` may sit from the PDP's clock, in either direction. **No default on purpose:** too small denies an honest fleet with ordinary NTP drift; too large widens the window a stolen token and captured proof stay replayable in. `30s` suits containers sharing a host clock; tune to your own NTP discipline. |

**Optional, with defaults:**

| Variable | Default | Options / range | Notes |
|---|---|---|---|
| `STRATIUM_MIGRATION_DATABASE_URL` | unset | a Postgres URL | Set it to apply embedded migrations at startup on a connection closed before serving. Unset means "skip migrations, assume an already-migrated schema", logged plainly. Use `stratium_migrate`. |
| `STRATIUM_TOKEN_PREVIOUS_KEY_PATH` | unset | a file path | Verify-only key, for a rotation window. Unset is the steady state. |
| `STRATIUM_LISTEN_ADDR` | `:50051` | `host:port` | gRPC listen address. |
| `STRATIUM_TLS_CERT_FILE` | unset | a file path | PEM certificate chain the PDP serves. Set together with `STRATIUM_TLS_KEY_FILE`. **Required unless `STRATIUM_GRPC_INSECURE=true`:** with neither set, the PDP refuses to start. Loaded once at startup; rotating the certificate needs a restart. |
| `STRATIUM_TLS_KEY_FILE` | unset | a file path | PEM private key for `STRATIUM_TLS_CERT_FILE`. Setting only one of the two is a startup failure. |
| `STRATIUM_GRPC_INSECURE` | `false` | `true`, `false` | `true` serves plaintext gRPC. **Local development only**; the PDP logs a warning on every start. Setting it alongside the certificate variables is a startup failure. |
| `STRATIUM_PRINCIPAL_OIDC_ISSUER` | unset | an issuer URL | OIDC issuer of the identity provider that signs principals' tokens. Discovered at startup; an unreachable or wrong issuer stops the PDP from starting. **Required, with the audience and claim below, unless `STRATIUM_PRINCIPAL_AUTH_INSECURE=true`:** with none of them set, the PDP refuses to start. |
| `STRATIUM_PRINCIPAL_OIDC_AUDIENCE` | unset | a client id | The audience a principal's token must be issued for. Must **not** be the PAP's `STRATIUM_PAP_OIDC_AUDIENCE`: see "Principal authentication" below. |
| `STRATIUM_PRINCIPAL_CLAIM` | unset | a claim name, for example `email` | The token claim that names the person. With `email`, the token must also carry `email_verified: true`. Must be the same claim, from the same identity provider, as the PAP's `STRATIUM_PAP_APPROVER_CLAIM` (§4.4). Prefer an immutable, provider-verified claim. |
| `STRATIUM_PRINCIPAL_OIDC_TIMEOUT` | `5s` | duration > 0 | Deadline for issuer discovery at startup and for the provider calls that verifying a token needs. |
| `STRATIUM_PRINCIPAL_OIDC_KEY_REFRESH_INTERVAL` | `30s` | duration > 0 | Least time between two fetches of the identity provider's signing keys. The PDP fetches them again when a principal token's signature does not verify, which is how a rotated key is picked up; this spaces those fetches out however many such tokens arrive. A token signed with a key the PDP has not fetched yet is refused until the next fetch, so this is also the longest a newly rotated key can go unrecognised. |
| `STRATIUM_PRINCIPAL_AUTH_INSECURE` | `false` | `true`, `false` | `true` turns principal verification off: the PDP believes the `subject` a caller sends. **Local development only**; the PDP logs a warning on every start. Setting it alongside any of the issuer, audience, or claim variables is a startup failure. |
| `STRATIUM_MAX_DELEGATION_DEPTH` | `5` | integer ≥ 1 | Longest delegation chain permitted. A chain deeper than this denies. |
| `STRATIUM_DB_TIMEOUT` | `5s` | duration > 0 | Database connect/ping deadline. |
| `STRATIUM_DB_MAX_OPEN_CONNS` | `20` | integer ≥ 1 | Most database connections this PDP holds at once. A call that needs one while all are in use waits for it until the caller's own deadline. Add up this value for every PDP, plus `STRATIUM_PAP_DB_MAX_OPEN_CONNS` for every PAP, and keep the total under Postgres's `max_connections` (100 unless you changed it). |
| `STRATIUM_APPROVAL_TTL` | `24h` | duration > 0 | How long an approval stays valid, from the moment it is requested: the time a person has to answer, plus the time the agent has to use the answer. An approval allows one call. |
| `STRATIUM_MAX_PENDING_APPROVALS` | `20` | integer ≥ 1 | Most approvals one session may have waiting for an answer at once. A session is a root delegation and every delegation made under it, since all of their approvals go to the same person. A call that would need one more is denied, and the denial says so; the session can ask again once an approval is answered or expires. Asking again for a call that already has an approval waiting does not count: the PDP returns that approval. |
| `STRATIUM_MAX_DELEGATION_TTL` | `24h` | duration > 0 | Longest lifetime a delegation may be created with. `CreateDelegation` refuses a longer `ttl_seconds` and names this maximum. Raise it if your sessions legitimately run longer. |
| `STRATIUM_POLICY_EVAL_TIMEOUT` | `2s` | duration > 0 | Deadline on one evaluation of the tenant's policies. A policy still running at the deadline is stopped and the call is denied. |
| `STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND` | `5` | number > 0 | How many audit rows a second `Decide` writes for calls whose token does not authenticate. A call past this rate and the burst below is still denied; it is logged instead of audited, and the next such row says how many were left out. Fractions are accepted (`0.5` is one row every two seconds). Counted per PDP process. |
| `STRATIUM_FAILED_TOKEN_AUDIT_BURST` | `20` | integer ≥ 1 | How many of those rows may be written at once before the per-second rate applies. |
| `STRATIUM_REQUEST_TIMEOUT` | `10s` | duration > 0 | Longest one call to the PDP may run, start to finish. A call still running then fails with `DEADLINE_EXCEEDED`, which a PEP treats as a denial. A caller's own shorter deadline still applies, so with the PEP's default `STRATIUM_PEP_CONNECT_TIMEOUT` of `5s` this only decides for a caller that set a longer deadline or none. Keep it above `STRATIUM_POLICY_EVAL_TIMEOUT`. |
| `STRATIUM_MAX_REQUEST_BYTES` | `4194304` (4 MiB) | integer ≥ 1 | Largest request the PDP reads; a larger one is refused with `RESOURCE_EXHAUSTED`. This is what bounds `raw_input`, the tool call itself, so it must stay above the largest file an agent writes or patch it applies in one call. Every other request field has its own limit, listed under "Request field limits" below. |
| `STRATIUM_SPENT_PROOF_REAP_INTERVAL` | `5m` | duration > 0 | How often the PDP sweeps its own tenant's expired `spent_proofs` rows. A longer interval cannot shorten replay protection — rows only become reapable once past the freshness window — it only delays cleanup. |
| `STRATIUM_POLICY_LANGUAGES` | `cedar,json,rego,xacml` | any comma-separated subset of those four | Which engines this PDP will evaluate. **A name with no matching engine is a startup failure.** A stray comma (`cedar,,rego`) is rejected rather than silently dropped. A tenant policy in a language this PDP does not run produces an honest deny naming the language — never a silent skip. |

#### Request field limits

The PDP refuses a request with a field longer than these. Each default is far above what a PEP sends. Every value is an integer of at least 1; anything else stops the PDP at start-up with an error naming the variable.

| Variable | Default | Applies to |
|---|---|---|
| `STRATIUM_MAX_TOOL_BYTES` | `8192` | `tool`, and each entry of `requested_scope.tools`. On the `ext_authz` surface the tool is the request's path and query string, so keep this above the longest URL you serve. |
| `STRATIUM_MAX_SUBJECT_BYTES` | `512` | `subject` |
| `STRATIUM_MAX_PURPOSE_BYTES` | `1024` | `purpose` |
| `STRATIUM_MAX_PATH_BYTES` | `4096` | `cwd`, and each `resource` value |
| `STRATIUM_MAX_NAME_BYTES` | `256` | `harness`, `observed_method`, and each `resource` key |
| `STRATIUM_MAX_URI_BYTES` | `16384` | `observed_uri` |
| `STRATIUM_MAX_CREDENTIAL_BYTES` | `16384` | `token`, `parent_token`, `principal_token`, `dpop_proof`, `dpop_jwk`. Raise it if your identity provider's tokens list enough groups to exceed it. |
| `STRATIUM_MAX_REQUESTED_TOOLS` | `1024` | the number of entries in `requested_scope.tools` |
| `STRATIUM_MAX_RESOURCE_ENTRIES` | `64` | the number of entries in `resource` |

`raw_input` has no limit of its own; `STRATIUM_MAX_REQUEST_BYTES` bounds it.

How a refusal looks depends on the call. `Decide` answers `DENY` and names the field; the denial is in the audit trail like any other, with the tool and subject cut to 256 bytes in that row. An over-long `token` is treated as a token that does not authenticate. `CreateDelegation`, `IssueToken` and `ReportToolUse` fail with `INVALID_ARGUMENT` naming the field.

```bash
# a minimal production PDP
STRATIUM_DATABASE_URL=postgres://stratium:...@db:5432/stratium?sslmode=require
STRATIUM_MIGRATION_DATABASE_URL=postgres://stratium_migrate:...@db:5432/stratium?sslmode=require
STRATIUM_TENANT_ID=acme-prod
STRATIUM_TOKEN_SIGNING_KEY_PATH=/etc/stratium/keys/current.pem
STRATIUM_DPOP_FRESHNESS_WINDOW=30s
STRATIUM_LISTEN_ADDR=:50051
STRATIUM_TLS_CERT_FILE=/etc/stratium/tls/pdp.crt
STRATIUM_TLS_KEY_FILE=/etc/stratium/tls/pdp.key
STRATIUM_PRINCIPAL_OIDC_ISSUER=https://idp.example.com/realms/acme
STRATIUM_PRINCIPAL_OIDC_AUDIENCE=stratium
STRATIUM_PRINCIPAL_CLAIM=email
```

**Transport security.** gRPC between Stratium components is TLS by default
(TLS 1.2 or later). The PDP serves the certificate above, and every PEP
subcommand verifies it against the system roots, or against a private CA
bundle named by `STRATIUM_PEP_PDP_CA_FILE` (§3.3). Plaintext needs an explicit
opt-in on both sides (`STRATIUM_GRPC_INSECURE=true` on the PDP,
`STRATIUM_PEP_PDP_INSECURE=true` on the PEP) and is for the local evaluation
stack only, which sets both for you: delegation tokens are bearer credentials,
and plaintext exposes them to anyone on the path. A PEP that cannot complete
the handshake denies, like any other unreachable PDP.

**Principal authentication.** By default the PDP authenticates who a new
session is for. A root delegation (a session) must carry the principal's OIDC
token, which `session-start` reads from the file named by
`STRATIUM_PEP_PRINCIPAL_TOKEN_FILE` (§3.3). The PDP verifies the token's
signature, issuer, audience, and expiry, and reads the principal from
`STRATIUM_PRINCIPAL_CLAIM` in the token, not from the request. A `subject` in
the request is optional, and if sent it must equal the token's identity. A
child delegation takes no principal token: its parent's own token authorizes
it, and it always acts for the root principal of its chain.
`STRATIUM_PRINCIPAL_CLAIM` must name the same claim, from the same identity
provider, as the PAP's `STRATIUM_PAP_APPROVER_CLAIM`, because an approval is
valid only when the approver the PAP identifies equals the principal the PDP
recorded (§4.4). `STRATIUM_PRINCIPAL_OIDC_AUDIENCE` must be a different value
from the PAP's `STRATIUM_PAP_OIDC_AUDIENCE`, with a separate client at the
identity provider: the PEP keeps the principal's token in a file the agent's
user can usually read, and a token the PAP also accepts would let the agent
sign in to the admin plane as that person and approve its own requests. The
two services cannot check this for each other. The opt-out, `STRATIUM_PRINCIPAL_AUTH_INSECURE=true`, is for
the local evaluation stack only, which sets it for you.

For an unattended agent (CI, a scheduled job), use a token for a service
identity from the same identity provider (client credentials or workload
identity), and write policy for that identity. If that token has no suitable
`email` claim, set `STRATIUM_PRINCIPAL_CLAIM` to a claim it does have, and set
the PAP's approver claim to match.

### 3.2 `stratium-pap` — the admin plane

**Required, no default:**

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_PAP_TENANT_ID` | `acme-prod` | Must match the PDP's `STRATIUM_TENANT_ID` for the tenant you are administering. One PAP process serves one tenant. |
| `STRATIUM_PAP_DATABASE_URL` | `postgres://stratium_pap_login:pw@db:5432/stratium?sslmode=require` | Must authenticate as a member of `stratium_pap` — **not** `stratium_app`. A URL naming the wrong role fails closed on the first write. Connections identify as `stratium-pap` unless the URL sets its own `application_name`. |
| `STRATIUM_PAP_OIDC_ISSUER` | `https://login.example.com/realms/acme` | Your IdP's issuer URL. The PAP performs real OIDC discovery against `<issuer>/.well-known/openid-configuration` at startup and refuses to serve if it fails. |
| `STRATIUM_PAP_OIDC_AUDIENCE` | `stratium-pap` | What this deployment accepts as its own `aud`. Tokens whose audience does not match are rejected. |
| `STRATIUM_PAP_OIDC_CLIENT_ID` | `stratium-pap` | The public client the **admin UI** authenticates as, served to the browser at `GET /ui-config`. The PAP never uses it itself, and holds no client secret. |
| `STRATIUM_PAP_ROLE_CLAIM` | `groups` | Which claim carries role/group membership. **Never guessed** — a wrong guess would not fail loudly, it would silently refuse every operator. |
| `STRATIUM_PAP_APPROVER_CLAIM` | `email` | Which claim identifies the operator for **approval** purposes. A second, independent claim from the role claim — see §4.4. The PAP logs a warning at start-up when this names a claim a person can change, such as `preferred_username` or `name`; the PDP does the same for `STRATIUM_PRINCIPAL_CLAIM`. |
| `STRATIUM_PAP_ADMIN_GROUPS` | `stratium-admins` | Comma-separated claim values mapped to the `admin` role. |
| `STRATIUM_PAP_EDITOR_GROUPS` | `stratium-editors` | → `editor`. |
| `STRATIUM_PAP_VIEWER_GROUPS` | `stratium-viewers,all-staff` | → `viewer`. |

A group name listed under **two** roles is a startup failure, not a silent
last-wins. A stray comma is rejected the same way — a dropped admin group name
means an intended administrator is refused entirely.

**Optional, with defaults:**

| Variable | Default | Notes |
|---|---|---|
| `STRATIUM_PAP_LISTEN_ADDR` | `:8080` | The PAP serves plain HTTP. **Terminate TLS upstream** — an ingress or reverse proxy. This is the only internet-facing component. |
| `STRATIUM_PAP_OIDC_SCOPE` | `openid profile email` | The scope string the UI requests. Add your IdP's group scope here if it needs one (Okta's `groups`, for instance). **Do not add `offline_access`** — it mints a refresh token, a longer-lived credential the browser has nowhere safe to keep. |
| `STRATIUM_PAP_OIDC_TIMEOUT` | `5s` | Bounds **every** HTTP call the OIDC library makes for the life of the process, including background JWKS refreshes — not just the initial discovery. |
| `STRATIUM_PAP_OIDC_KEY_REFRESH_INTERVAL` | `30s` | Least time between two fetches of the identity provider's signing keys; a duration above zero. Same meaning as the PDP's `STRATIUM_PRINCIPAL_OIDC_KEY_REFRESH_INTERVAL`: it is also the longest a newly rotated key can go unrecognised. |
| `STRATIUM_PAP_DB_TIMEOUT` | `5s` | Database connect/ping deadline. |
| `STRATIUM_PAP_DB_MAX_OPEN_CONNS` | `10` | Most database connections the PAP holds at once; an integer of at least 1. A request that needs one while all are in use waits. See `STRATIUM_DB_MAX_OPEN_CONNS` for how to size it against Postgres. |

The PAP refuses a request body over 1 MiB (`413`), and closes a connection that takes more than 30 seconds to send a request or sits idle for two minutes. A policy tried through the policy test endpoint is stopped after 2 seconds. These are fixed.

```bash
STRATIUM_PAP_TENANT_ID=acme-prod
STRATIUM_PAP_DATABASE_URL=postgres://stratium_pap_login:...@db:5432/stratium?sslmode=require
STRATIUM_PAP_OIDC_ISSUER=https://login.example.com/realms/acme
STRATIUM_PAP_OIDC_AUDIENCE=stratium-pap
STRATIUM_PAP_OIDC_CLIENT_ID=stratium-pap
STRATIUM_PAP_ROLE_CLAIM=groups
STRATIUM_PAP_APPROVER_CLAIM=email
STRATIUM_PAP_ADMIN_GROUPS=stratium-admins
STRATIUM_PAP_EDITOR_GROUPS=stratium-editors
STRATIUM_PAP_VIEWER_GROUPS=stratium-viewers,all-staff
STRATIUM_PAP_LISTEN_ADDR=:8080
```

### 3.3 `stratium-pep` — the enforcement point

`stratium-pep` is one binary with five subcommands. **Each subcommand requires a
different set of variables**, and each fails at startup naming every one it is
missing.

```
stratium-pep <hook|session-start|mcp|extauthz|proxy>
```

#### Shared identity variables

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_PEP_PDP_ADDR` | `pdp.internal:50051` | `host:port` of the PDP. |
| `STRATIUM_PEP_AGENT_ID` | `50bdd8cc-377f-4135-818d-cfd30b206ce5` | The UUID returned when you created the agent (§5.4). |
| `STRATIUM_PEP_SUBJECT` | `alice@example.com` | The **person** on whose behalf the agent acts. Must match what your policies condition on. At `session-start` it must equal the identity in the principal's OIDC token (`STRATIUM_PEP_PRINCIPAL_TOKEN_FILE`, below). The PDP holds every later call to it: a `Decide` whose subject is not the person the session's delegation was issued for is denied, and so is a child delegation requested under another subject. |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | `5s` | Bounds every PDP call. Duration > 0. |
| `STRATIUM_PEP_PDP_CA_FILE` | `/etc/stratium/pdp-ca.pem` | Optional. PEM CA bundle to verify the PDP's certificate with, instead of the system roots. Use it when a private CA issued the PDP's certificate. |
| `STRATIUM_PEP_PDP_INSECURE` | `true` | Optional. Plaintext connection to the PDP, for the local evaluation stack only. Setting it alongside `STRATIUM_PEP_PDP_CA_FILE` is an error, and the PEP denies. |

#### Which subcommand needs what

| Variable | `session-start` | `hook` | `mcp` | `extauthz` | `proxy` |
|---|:--:|:--:|:--:|:--:|:--:|
| `STRATIUM_PEP_PDP_ADDR` | ● | ● | ● | ● | ● |
| `STRATIUM_PEP_AGENT_ID` | ● | ● | ● | ● | ● |
| `STRATIUM_PEP_SUBJECT` | ● | ● | ● | ● | ● |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | ● | ● | ● | ● | ● |
| `STRATIUM_PEP_PDP_CA_FILE` | ○ | ○ | ○ | ○ | ○ |
| `STRATIUM_PEP_PDP_INSECURE` | ○ | ○ | ○ | ○ | ○ |
| `STRATIUM_PEP_SESSION_FILE` | ● | ● | ● | — | — |
| `STRATIUM_PEP_REQUESTED_TOOLS` | ● | — | — | — | — |
| `STRATIUM_PEP_REQUESTED_TIER` | ● | — | — | — | — |
| `STRATIUM_PEP_TTL_SECONDS` | ● | — | — | — | — |
| `STRATIUM_PEP_PRINCIPAL_TOKEN_FILE` | ○ | — | — | — | — |
| `STRATIUM_PEP_PURPOSE` | ○ | — | — | — | — |
| `STRATIUM_PEP_ESCALATE_AT` | ○ | — | — | — | — |
| `STRATIUM_PEP_APPROVAL_POLL_INTERVAL` | — | ● | ● | — | ● |
| `STRATIUM_PEP_APPROVAL_TIMEOUT` | — | ● | ● | — | ● |
| `STRATIUM_PEP_CACHE_STALENESS_WINDOW` | — | — | ● | — | — |
| `STRATIUM_PEP_MCP_UPSTREAM_COMMAND` | — | — | ● | — | — |
| `STRATIUM_PEP_MCP_UPSTREAM_ARGS` | — | — | ○ | — | — |
| `STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR` | — | — | — | ● | — |
| `STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS` | — | — | — | ● | — |
| `STRATIUM_PEP_PROXY_LISTEN_ADDR` | — | — | — | — | ● |
| `STRATIUM_PEP_PROXY_TARGET_ADDR` | — | — | — | — | ● |
| `STRATIUM_PEP_PROXY_PUBLIC_URI` | — | — | — | — | ● |

● required ○ optional — not read

> `extauthz` and `proxy` take **no session file and no cache window**, and that
> is structural, not an omission. On those two surfaces the caller *is* the
> party being policed, so it must re-authenticate on every call and can never be
> served a cached decision.

#### Every PEP variable in detail

| Variable | Used by | Example | Notes |
|---|---|---|---|
| `STRATIUM_PEP_SESSION_FILE` | session-start, hook, mcp | `/run/stratium/session.json` | Where `session-start` writes, and where `hook`/`mcp` read **fresh on every call**. Created `0600`. Deleting it ends the session immediately — the next tool call denies. This file is bearer authority: anyone who can read it can act as the agent. |
| `STRATIUM_PEP_REQUESTED_TOOLS` | session-start | `Read,Write,Bash` | Comma-separated. What you are *asking* for. The PDP clamps this to what the principal actually holds; the session file records what was **granted**, which may be narrower. An empty list is a missing-configuration error. |
| `STRATIUM_PEP_REQUESTED_TIER` | session-start | `3` | Integer 0–4. Requested `max_action_tier`. Clamped downward if policy does not permit it. Range is validated by the PDP, not locally. |
| `STRATIUM_PEP_TTL_SECONDS` | session-start | `3600` | Delegation lifetime in seconds. Must be positive, and no more than the PDP's `STRATIUM_MAX_DELEGATION_TTL` (default 24h), or `session-start` is refused. |
| `STRATIUM_PEP_PRINCIPAL_TOKEN_FILE` | session-start | `/run/secrets/principal.jwt` | Optional. Path to a file holding the principal's OIDC token; surrounding whitespace is trimmed. `session-start` sends it to the PDP as `principal_token`. Needed whenever the PDP verifies principals (the default, §3.1 "Principal authentication"); a PDP running with `STRATIUM_PRINCIPAL_AUTH_INSECURE=true` ignores it. A file, not a variable, so the token is not copied into child processes' environments. An unreadable or empty file fails `session-start`. The token is needed only at session start: it is typically short-lived, and that does not shorten the session, whose lifetime is `STRATIUM_PEP_TTL_SECONDS`. |
| `STRATIUM_PEP_PURPOSE` | session-start | `nightly refactor` | Free text, recorded on the delegation and visible to policy. Optional. |
| `STRATIUM_PEP_ESCALATE_AT` | session-start | `3` | Optional. Asks for a **lower** escalation threshold than the agent's (§5.5). It can never raise or remove the agent's threshold, so leaving it unset changes nothing. |
| `STRATIUM_PEP_APPROVAL_POLL_INTERVAL` | hook, mcp, proxy | `2s` | How often to poll for a human's answer while an escalation is pending. |
| `STRATIUM_PEP_APPROVAL_TIMEOUT` | hook, mcp, proxy | `5m` | How long to wait before an unanswered escalation denies. **No safe default:** too short denies escalations no human could clear in time; too long leaves a tool call silently blocked. |
| `STRATIUM_PEP_CACHE_STALENESS_WINDOW` | mcp | `30s` | Upper bound on how old a decision `mcp` replays from its in-memory cache may be. `hook` has no cache and ignores it. See [`docs/pep.md`](pep.md) § "The decision cache". |
| `STRATIUM_PEP_MCP_UPSTREAM_COMMAND` | mcp | `npx` | The real MCP server's executable. Must not be blank. |
| `STRATIUM_PEP_MCP_UPSTREAM_ARGS` | mcp | `-y,@modelcontextprotocol/server-filesystem,/srv/data` | **Comma-separated**, not shell-quoted. Optional. |
| `STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR` | extauthz | `:9191` | Where Envoy's `ext_authz` filter reaches this server. |
| `STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS` | extauthz | `api.example.com,api.eu.example.com` | The authorities this surface answers for. Envoy reports the *caller's own* `Host`/`:authority`, so without this list a DPoP proof captured in flight to one gateway replays at another. Use **stable public hostnames**, not the address anything happens to dial. |
| `STRATIUM_PEP_PROXY_LISTEN_ADDR` | proxy | `:9292` | Bind address. |
| `STRATIUM_PEP_PROXY_TARGET_ADDR` | proxy | `payments.internal:50051` | The real gRPC service being fronted. |
| `STRATIUM_PEP_PROXY_PUBLIC_URI` | proxy | `https://tools.example.com` | This proxy's own stable public identity, and the whole of a DPoP proof's `htu` authority. Deliberately **not** the target address (a proof for one target would replay at any other behind the same proxy), **not** the caller's `:authority`, and **not** the listen address (`:9292` carries no host at all). |

---

## 4. Connecting to an existing OIDC provider

Only the **PAP** talks to your IdP, and only to verify tokens that operators
(humans) present. The PDP and the PEP never touch it. Agents are never OIDC
identities — they are rows in the `agents` table.

### 4.1 What the PAP does with a token

1. Reads the `Authorization: Bearer <token>` header.
2. Verifies the signature against your IdP's published JWKS, discovered at
   `<issuer>/.well-known/openid-configuration`.
3. Checks `iss`, `aud`, and `exp`.
4. Reads `sub` — the identity every write is attributed to in the audit trail.
5. Reads `STRATIUM_PAP_ROLE_CLAIM` and maps it through your group configuration
   to exactly one of `viewer`, `editor`, `admin`.
6. Reads `STRATIUM_PAP_APPROVER_CLAIM` — used only when deciding approvals.

**There is no bundled IdP, no mock mode, and no fallback.** Discovery happens at
startup and the process refuses to serve if it fails.

### 4.2 What your IdP must provide

| Requirement | Why |
|---|---|
| A standard OIDC discovery document | The PAP fetches it at startup; there is no manual JWKS configuration. |
| A **public** client with PKCE and the authorization-code flow | The admin UI runs in a browser and can keep no secret. |
| Redirect URIs covering wherever the UI is served | `https://stratium.example.com/*` |
| A claim carrying group or role membership, **in the access token** | Group membership is commonly in the ID token only by default; you usually have to add an access-token mapper. |
| The PAP's own audience in `aud` | Many IdPs need an explicit audience mapper or an API-identifier configuration. |
| A verified email claim, if you use `email` as the approver claim | See §4.4. |

The role claim may be **a single string or an array of strings**. Real IdPs
issue group membership as an array far more often. Among an array's matches the
**highest-ranked role wins**: an operator in both `all-staff` (viewer) and
`stratium-admins` (admin) is an admin, never shadowed by the broader group. An
array entry that is not a string is skipped. A claim that is neither a string
nor an array of strings is refused.

An **absent** role claim and an **unrecognised** one are both refusals. There is
no default role: the PAP never guesses `viewer`.

### 4.3 Provider recipes

#### Keycloak

The reference realm at `deploy/docker/keycloak/stratium-realm.json` is a working
example. The essential parts:

```jsonc
// Client
{
  "clientId": "stratium-pap",
  "publicClient": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,      // for scripted/CI token minting
  "redirectUris": ["https://stratium.example.com/*"],
  "protocolMappers": [
    { "name": "groups",
      "protocolMapper": "oidc-group-membership-mapper",
      "config": { "full.path": "false", "claim.name": "groups",
                  "access.token.claim": "true", "id.token.claim": "true",
                  "multivalued": "true" } },
    { "name": "stratium-pap-audience",
      "protocolMapper": "oidc-audience-mapper",
      "config": { "included.client.audience": "stratium-pap",
                  "access.token.claim": "true" } }
  ]
}
```

```bash
STRATIUM_PAP_OIDC_ISSUER=https://kc.example.com/realms/acme
STRATIUM_PAP_OIDC_AUDIENCE=stratium-pap
STRATIUM_PAP_OIDC_CLIENT_ID=stratium-pap
STRATIUM_PAP_ROLE_CLAIM=groups
STRATIUM_PAP_APPROVER_CLAIM=email
```

> `"full.path": "false"` matters. With it `true`, the claim carries
> `/stratium-admins`, and your `STRATIUM_PAP_ADMIN_GROUPS` must include the
> leading slash to match. Pick one and be consistent.

#### Okta

Create an OIDC **Single-Page Application**, add a **groups claim** to the access
token (Security → API → Authorization Servers → Claims), and add `groups` to the
requested scopes.

```bash
STRATIUM_PAP_OIDC_ISSUER=https://acme.okta.com/oauth2/default
STRATIUM_PAP_OIDC_AUDIENCE=api://default          # the authorization server's audience
STRATIUM_PAP_OIDC_CLIENT_ID=0oa1example
STRATIUM_PAP_ROLE_CLAIM=groups
STRATIUM_PAP_APPROVER_CLAIM=email
STRATIUM_PAP_OIDC_SCOPE="openid profile email groups"
```

#### Microsoft Entra ID (Azure AD)

Register an SPA, set **Token configuration → Add groups claim**, and expose an
API so tokens carry your application ID URI as `aud`.

```bash
STRATIUM_PAP_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-guid>/v2.0
STRATIUM_PAP_OIDC_AUDIENCE=api://<application-client-id>
STRATIUM_PAP_OIDC_CLIENT_ID=<application-client-id>
STRATIUM_PAP_ROLE_CLAIM=groups     # or "roles" for app roles
STRATIUM_PAP_APPROVER_CLAIM=oid
```

> Use `oid`, the user's object ID, to identify an approver. Entra documents
> `preferred_username` and `email` as changeable, so neither should decide who
> may approve. `STRATIUM_PRINCIPAL_CLAIM` on the PDP must be `oid` too, and
> policies then name people by object ID.

> Entra emits group **object IDs**, not display names, unless you enable group
> name emission for groups synced from on-prem AD. Your
> `STRATIUM_PAP_*_GROUPS` values must be whatever the claim actually contains —
> GUIDs are fine. Entra also replaces the groups claim with a `_claim_names`
> overage indirection past ~200 groups; if you hit that, use **app roles**
> (`STRATIUM_PAP_ROLE_CLAIM=roles`) instead.

#### Auth0

Add a post-login Action that copies roles into a namespaced custom claim, and
set an API audience.

```javascript
exports.onExecutePostLogin = async (event, api) => {
  api.accessToken.setCustomClaim('https://stratium.example.com/groups',
                                 event.authorization?.roles ?? []);
};
```

```bash
STRATIUM_PAP_OIDC_ISSUER=https://acme.eu.auth0.com/
STRATIUM_PAP_OIDC_AUDIENCE=https://stratium.example.com/api
STRATIUM_PAP_OIDC_CLIENT_ID=<spa-client-id>
STRATIUM_PAP_ROLE_CLAIM=https://stratium.example.com/groups
STRATIUM_PAP_APPROVER_CLAIM=email
```

> Auth0 requires custom claims to be namespaced URIs. The claim **name** is that
> whole URI — put it in `STRATIUM_PAP_ROLE_CLAIM` verbatim. Note the trailing
> slash on the Auth0 issuer; it is part of the issuer.

#### Google Workspace

Workable but awkward: Google does not emit group membership in ID tokens. You
will need a claim your own middleware adds, or a different IdP for the PAP.

Note that Google issues tokens from `accounts.google.com` and exchanges the code
at `oauth2.googleapis.com` — the PAP handles this automatically by capturing
both endpoints from the discovery document for the UI's Content-Security-Policy.

### 4.4 The approver claim, and why it is separate

Approving an escalation requires **two** things, and a role is only one of them:

1. The `admin` role — enforced by the route.
2. The operator's approver identity must **equal the approval's root
   principal**: the person the PDP identified from the principal's OIDC token
   when the session started (§3.1). On a PDP running with
   `STRATIUM_PRINCIPAL_AUTH_INSECURE=true` it is the `STRATIUM_PEP_SUBJECT`
   the PEP sent.

That second check is why `STRATIUM_PAP_APPROVER_CLAIM` exists and is configured
independently of `STRATIUM_PAP_ROLE_CLAIM`. The role claim answers "what may this
operator do"; the approver claim answers "is this operator the person the agent
is acting for". An IdP's opaque `sub` was never going to match an email address
recorded by a PEP, so a second claim has to be nominated.

> **`email` gets a special rule.** When `STRATIUM_PAP_APPROVER_CLAIM=email`, the
> PAP additionally requires `email_verified: true`. Some IdPs let a caller
> self-assert an email with no verification behind it — without this check an
> operator could name themselves any root principal and approve their own
> escalations, with an audit row that looks entirely legitimate. A missing or
> malformed `email_verified` reads as **not verified**.

Practical consequence: set `STRATIUM_PEP_SUBJECT` on each PEP to the exact
string your approver claim will contain for the person who owns that agent
session. If they do not match, escalations can never be approved by anyone.

The PDP's `STRATIUM_PRINCIPAL_CLAIM` (§3.1) must name the same claim, from the
same identity provider. The PDP records a session's root principal from that
claim of the principal's token, and the PAP compares the approver claim against
the recorded value, so two different claims never match.

### 4.5 Getting a token for scripting

For CI or command-line use, if your IdP allows the password grant on a public
client:

```bash
tok() {
  curl -sS -X POST "$ISSUER/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=stratium-pap \
    -d "username=$1" -d "password=$2" -d 'scope=openid email' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
export ADMIN=$(tok alice 's3cret')
curl -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/policies"
```

> **Operator tokens are short-lived** — five minutes in the reference Keycloak
> realm. Re-mint rather than debugging a sudden `401`.
>
> Also: `export EDITOR=<jwt>` shadows your shell's `$EDITOR` variable. A later
> bare `git commit` will try to launch a JWT as your text editor.

### 4.6 OIDC troubleshooting

| Symptom | Likely cause |
|---|---|
| PAP exits at startup: `discover OIDC provider …` | Issuer URL wrong, unreachable, or missing a trailing/leading path segment. Verify `curl $ISSUER/.well-known/openid-configuration`. |
| PAP exits: `role groups: group "x" is mapped to both admin and editor` | The same claim value appears in two `*_GROUPS` variables. |
| PAP exits: `STRATIUM_PAP_ADMIN_GROUPS: empty group name` | A leading, trailing, or doubled comma. |
| Every request `401 unauthorized` | Token expired, wrong `aud`, or wrong issuer. The PAP deliberately returns a fixed, detail-free error — inspect the token yourself at your IdP. |
| Authenticated but every request `403` | The role claim is absent from the **access token** (it is often only in the ID token), or its values match no configured group. |
| Reads work, writes `403` | The operator resolved to `viewer`. Check which group list their claim value is in. |
| Approve returns `401` | The approver claim is absent, empty, or — with `email` — not verified. |
| Approve returns `403` | The operator is an admin, but their approver identity is not this approval's root principal. |
| Key rotation broke verification | Ensure `STRATIUM_PAP_OIDC_TIMEOUT` is set sensibly; it bounds background JWKS refreshes as well as discovery. |

---

## 5. PAP capabilities — the admin plane

`stratium-pap` serves a REST API at `/v1/...` and an embedded admin UI at `/`.
Everything below is reachable either way; the API is documented because it is
what the UI itself calls and what you will script against.

**The console has one screen per resource**, and every screen is a thin
wrapper over the routes below:

| Screen | What it does |
|---|---|
| Policies | full CRUD, plus **Validate** and **Test** against sample input — §5.4 |
| Agents | full CRUD, plus a classification-caps panel — edited separately from the agent, once one exists, at a higher role floor — §5.5, §5.7 |
| Tier overrides | full CRUD — §5.8 |
| Tool catalog | create, read, update — **no delete**, because the API has none — §5.6 |
| Label rules | full CRUD — §5.7 |
| Approvals | approve or deny a pending, unexpired request; a decided or expired one offers neither — §5.9 |
| Delegations | read-only, plus revoke — §5.10 |

Policy text is authored in a plain textarea — no syntax highlighting — and
**Validate** and **Test** are both round trips to the server, never
client-side checks.

**Every action is offered to every signed-in operator, whatever their role.**
The console never hides, greys, or pre-flights a button based on a guess about
what an operator may do — that is the server's answer to give, not the UI's.
A viewer sees every Save and Delete button and, on submitting one, gets back
the server's own `403` text verbatim. The console is not role-aware by design;
treat the route table below as the actual authority on who can do what.

### 5.1 Authentication and roles

Every `/v1` route requires `Authorization: Bearer <oidc-token>`. Roles are
resolved from claims (§4), never from a table — there is no "who creates the
first admin" bootstrap problem because your IdP already knows.

| Role | Can do |
|---|---|
| `viewer` | every `GET` |
| `editor` | every `GET`, plus `POST` and `PUT` (create and update), except the writes below |
| `admin` | everything, plus `DELETE` and the action endpoints (approve, deny, revoke) |

Roles are ranked, so an admin satisfies every editor and viewer route.

An editor can tighten what an admin's ceilings are measured against, never
relax it. These need `admin`, and an editor who tries gets a `403` that says
why:

- **Creating** a resource label rule or a tool catalog entry, or an agent
  above the lowest trust tier (`trust_tier` 0).
- **Changing or disabling a protected policy**, and protecting or
  unprotecting one (§5.4).
- **Updating a label rule** in any way except raising its level: lowering the
  level, or changing the prefix or hierarchy.
- **Updating a catalog entry** in any way except raising its `action_tier`:
  lowering or clearing the tier, or changing the tool name, verb, or the input
  fields.
- **Updating an agent** so that its `trust_tier` goes up, or `suspended` goes
  from `true` to `false`, or `enabled` goes from `false` to `true`. An editor
  can still suspend or disable an agent, lower its trust tier, and change its
  allowed tools.

### 5.2 Complete route table

| Method & path | Min role | What it does |
|---|---|---|
| `GET /v1/policies` | viewer | list policies, ordered by name |
| `POST /v1/policies` | editor | create a policy |
| `GET /v1/policies/{id}` | viewer | fetch one policy, including its full text |
| `PUT /v1/policies/{id}` | editor | full replace; a protected policy needs **admin** (§5.4) |
| `PUT /v1/policies/{id}/protection` | **admin** | protect or unprotect a policy |
| `DELETE /v1/policies/{id}` | **admin** | delete |
| `POST /v1/policies/validate` | editor | syntax/semantic check, persists nothing |
| `POST /v1/policies/test` | editor | evaluate a candidate against sample input |
| `GET /v1/agents` | viewer | list agents |
| `POST /v1/agents` | editor | register an agent; above `trust_tier` 0 needs **admin** (§5.1) |
| `GET /v1/agents/{id}` | viewer | fetch one agent |
| `PUT /v1/agents/{id}` | editor | full replace; raising the trust tier or resuming needs **admin** (§5.1) |
| `DELETE /v1/agents/{id}` | **admin** | delete |
| `GET /v1/agents/{id}/escalation` | viewer | read the agent's escalation threshold |
| `PUT /v1/agents/{id}/escalation` | **admin** | set it |
| `DELETE /v1/agents/{id}/escalation` | **admin** | remove it |
| `GET /v1/tool-catalog` | viewer | list catalog entries |
| `POST /v1/tool-catalog` | **admin** | register a tool |
| `GET /v1/tool-catalog/{id}` | viewer | fetch one entry |
| `PUT /v1/tool-catalog/{id}` | editor | full replace; anything but raising the tier needs **admin** (§5.1) |
| `GET /v1/resource-label-rules` | viewer | list label rules |
| `POST /v1/resource-label-rules` | **admin** | create a label rule |
| `GET /v1/resource-label-rules/{id}` | viewer | fetch one rule |
| `PUT /v1/resource-label-rules/{id}` | editor | full replace; anything but raising the level needs **admin** (§5.1) |
| `DELETE /v1/resource-label-rules/{id}` | **admin** | delete |
| `GET /v1/tier-overrides` | viewer | list overrides |
| `POST /v1/tier-overrides` | editor | create an override |
| `GET /v1/tier-overrides/{id}` | viewer | fetch one override |
| `PUT /v1/tier-overrides/{id}` | editor | full replace |
| `DELETE /v1/tier-overrides/{id}` | **admin** | delete |
| `GET /v1/approvals` | viewer | list approvals, every status |
| `POST /v1/approvals/{id}/approve` | **admin** + identity | approve a pending escalation |
| `POST /v1/approvals/{id}/deny` | **admin** + identity | deny it |
| `GET /v1/delegations` | viewer | list delegations |
| `POST /v1/delegations/{id}/revoke` | **admin** | revoke a delegation |
| `POST /v1/containment` | editor | does a candidate permission set allow anything a baseline forbids? Persists nothing |
| `GET /v1/principals/{id}/effective` | viewer | the union of one principal's live root delegations |
| `GET /v1/audit` | viewer | read the hash-chained audit log, newest first; filter by `event_type` and `agent_id` |
| `GET /ui-config` | *none* | public UI configuration — `issuer`, `client_id`, `audience`, `scope`. Carries no secret; it is the one route reachable without a token, because a browser cannot present one before being told where to get it. |

**Three resources deliberately lack routes you might expect:**

- **`tool-catalog` has no `DELETE`.** The database role deliberately withholds
  `DELETE` on that table, and a route with no grant behind it could only ever
  answer `insufficient_privilege`. Retire a tool by updating it, or remove the
  row with a direct database write if you truly must.
- **`approvals` has no create, update, or delete.** The PDP creates a pending
  approval when a decision escalates. Approve and deny *are* the sanctioned
  mutations.
- **`delegations` has no create, update, or delete.** Delegations are created
  over gRPC by `stratium-pep session-start`. Revoke is this table's sanctioned
  "delete" — it sets `revoked`/`revoked_at` rather than removing the row, so the
  audit trail stays intact.

### 5.3 Common conventions

**Every `PUT` is a full replace.** There is no partial patch. The body must
carry every field the matching `POST` accepts; omitted fields become their zero
values.

**Server-owned fields are ignored on input** and set authoritatively:
`id`, `tenant_id`, `created_at`, `updated_at`, `version`. Send them or don't —
they are overwritten either way.

**Status codes:**

| Code | Meaning |
|---|---|
| `200` | success (GET, PUT, action endpoints) |
| `201` | created (POST) |
| `204` | deleted (DELETE) |
| `400` | your request is wrong — malformed JSON, a bad UUID, a failed field validation, a policy that does not compile, an override that would lower a tier |
| `401` | no token, an invalid token, or (on approvals) no usable approver identity |
| `403` | authenticated, but your role is insufficient — or, on approvals, you are not the root principal |
| `404` | no such row **in your tenant**. Row-level security makes "belongs to another tenant" and "does not exist" indistinguishable, by design. |
| `409` | conflicts with what already exists — a duplicate name or prefix, an agent still referenced by a live delegation, an approval that is no longer pending |
| `500` | something unanticipated. The body deliberately does **not** echo the underlying error, to avoid leaking schema or connection detail. |

**Every write is audited** into the hash-chained `audit_chain` table, attributed
to the `sub` claim of the token that made it, inside the same transaction as the
write itself. `GET`s are not audited.

**Every write bumps the tenant epoch**, which invalidates every cached decision
across your fleet. That is what makes a policy change take effect on the next
tool call rather than whenever a cache happens to expire.

### 5.4 CRUD: Policies

A policy decides the **principal leg** — a rule about the human the agent acts
for. It can never widen what a delegation or an agent's own record allows.

**Fields**

| Field | Type | Notes |
|---|---|---|
| `name` | string | **required**, non-empty, unique within the tenant |
| `description` | string | free text |
| `language` | string | **required**, one of `cedar`, `rego`, `xacml`, `json` |
| `policy_content` | string | **required**, the policy text; validated by its own engine before anything is written |
| `effect` | string | **required**, `allow` or `deny` — see the rule below |
| `enabled` | bool | disabled policies are not evaluated |
| `protected` | bool | server-owned; set through `PUT /v1/policies/{id}/protection`. Sending it on create or update has no effect |
| `version` | int64 | server-owned; incremented on every update |
| `id`, `tenant_id`, `created_at`, `updated_at` | — | server-owned |

> ### The `effect` rule — read this before your first `400`
>
> `effect` is **not** "what I want this policy to do". It is a declaration that
> must agree with what the policy text itself says, and two of the four
> languages cannot make that declaration at all.
>
> | Language | `effect` must be |
> |---|---|
> | `cedar` | whatever the text declares (`permit` → `allow`, `forbid` → `deny`) — a mismatch is a `400` |
> | `json` | whatever the text declares — a mismatch is a `400` |
> | `rego` | **always `"deny"`** |
> | `xacml` | **always `"deny"`** |
>
> A Rego or XACML policy can produce either outcome depending on the request, so
> a single stored effect could never describe it. The column holds a fixed
> placeholder that a display screen must not read as behaviour. Sending
> `"allow"` for one of those two returns a `400` saying exactly this.

**Create**

```bash
curl -sS -X POST "http://$PAP/v1/policies" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{
    "name": "engineers-may-act",
    "description": "engineering staff may delegate to agents",
    "language": "rego",
    "effect": "deny",
    "enabled": true,
    "policy_content": "package stratium.policy\n\nallow if {\n\tinput.principal.subject == \"alice@example.com\"\n}"
  }'
```

`201`, echoing the stored policy with its `id`, `version: 1`, and timestamps.

**Read**

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/policies"
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/policies/$ID"
```

**Update** — full replace; `version` increments server-side.

```bash
curl -X PUT "http://$PAP/v1/policies/$ID" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"engineers-may-act","description":"widened to the team",
       "language":"rego","effect":"deny","enabled":true,
       "policy_content":"package stratium.policy\n\nallow if {\n\tinput.principal.attributes.team == \"platform\"\n}"}'
```

**Delete** — admin only.

```bash
curl -X DELETE -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/policies/$ID"   # 204
```

**Protecting a policy** — admin only.

Editors write policy, which means an editor can rewrite or disable any rule,
including a `forbid` an admin depends on. Protecting a policy takes that away
for that one policy:

```bash
curl -X PUT "http://$PAP/v1/policies/$ID/protection" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"protected":true}'
```

While a policy is protected, an editor's `PUT` on it returns `403`; an admin
can still change it, and it stays protected. Only this route sets or clears
the flag: `{"protected":false}` lifts it. A protected `forbid` holds whatever
editors add, because a deny from any policy overrides every allow. Protecting
or unprotecting writes a `policy_protected` or `policy_unprotected` audit
entry.

**Validate without saving** — editor.

```bash
curl -X POST "http://$PAP/v1/policies/validate" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"language":"cedar","policy_content":"permit(principal, action, resource);"}'
```

`200 {"valid": true}` on success. On failure, a `400` carrying **the engine's own
error text**, unwrapped — it already names the offending construct.

Validation is strict about policies that are syntactically fine but can never
fire: a Rego module with a typo'd package, a JSON `"in": []`, a Cedar `in []`
scope, an XACML document naming an out-of-vocabulary tier. Storing a policy that
can never fire is exactly the failure the PAP exists to prevent.

> **Rego policies must declare `package stratium.policy`.** Anything else is
> refused, because a module in another package can never be reached:
>
> ```
> rego: validate: policy declares package data.wrong.name, want data.stratium.policy
> (every policy's module must declare `package stratium.policy`)
> ```

> **Rego policies cannot reach outside the process.** A policy decides from
> the request it is given. The built-ins `http.send`, `net.lookup_ip_addr`,
> and `opa.runtime` are not available, so a policy cannot make network calls,
> do DNS lookups, or read the host's environment. Using one is refused when
> the policy is validated, saved, or loaded:
>
> ```
> rego: validate: 1 error occurred: validate:3: rego_type_error: undefined function http.send
> ```
>
> Everything else in Rego's standard library works, including `time.now_ns`
> for time-based rules. If a decision needs outside data, put it in the
> request (resource labels, principal attributes) or in the policy itself.

**Test against sample input** — editor. Evaluates a **candidate** policy (stored
or not) against a hypothetical request.

```bash
curl -X POST "http://$PAP/v1/policies/test" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{
    "language": "cedar",
    "policy_content": "permit(principal, action, resource);",
    "principal": { "subject": "alice@example.com",
                   "attributes": { "team": "platform" } },
    "action":    { "tool": "Bash", "raw_input": "{\"command\":\"rm -rf /tmp/x\"}" },
    "resource":  { "id": "/tmp/x" },
    "agent":     { "trust_tier": 3, "enabled": true, "suspended": false,
                   "allowed_tools": [] },
    "delegation":{ "depth": 0, "max_action_tier": 3,
                   "classification_caps": {"nato":"CONFIDENTIAL"},
                   "purpose": "cleanup" }
  }'
```

Response:

```json
{
  "isolated":               { "effect": "ALLOW", "reason": "...", "source": "cedar", "policy_id": "..." },
  "with_existing_policies": { "effect": "DENY",  "reason": "...", "source": "cedar", "policy_id": "..." },
  "tier":          { "value": 4, "source": "derived" },
  "legs_evaluated":{ "principal": true, "agent": false, "delegation": false }
}
```

- `isolated` — what your candidate alone decides.
- `with_existing_policies` — what it decides folded together with everything
  already stored. A candidate that allows can still lose to an existing deny.
- `tier` — the derived action tier, and whether it was derived or declared. Add
  `"declared_tier": 4` to the request to force a hypothetical without crafting
  input that derives there.
- `legs_evaluated` — **always `principal: true, agent: false, delegation: false`**.
  This endpoint runs only the policy leg. It is not a decision and must never be
  read as one; the other two legs are what actually cap an agent.

### 5.5 CRUD: Agents

An agent is the actor. Registering one gives you the UUID a PEP is configured
with.

**Fields**

| Field | Type | Notes |
|---|---|---|
| `name` | string | **required**, non-empty, unique within the tenant |
| `provider` | string | **required** — `anthropic`, `openai`, whatever you use |
| `model_id` | string | free text |
| `trust_tier` | int | **required**, `0`–`3`. Out of range is a `400`. |
| `enabled` | bool | `false` denies every call by this agent |
| `suspended` | bool | `true` denies every call by this agent |
| `allowed_tools` | array of strings | **required — must be present, even if empty.** A missing key is a `400`. |
| `id`, `tenant_id`, `created_at`, `updated_at` | — | server-owned |

> **`"allowed_tools": []` means UNRESTRICTED, not "no tools".** An empty list
> places no per-agent restriction, leaving the delegation's own `approved_tools`
> as the only tool gate. A non-empty list is an allowlist: a tool not in it is
> denied regardless of the delegation. This is the single most commonly
> misread field on this API.

**Create**

```bash
export AGENT=$(curl -sS -X POST "http://$PAP/v1/agents" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"alice-claude-code","provider":"anthropic","model_id":"claude",
       "trust_tier":3,"enabled":true,"suspended":false,"allowed_tools":[]}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "AGENT=$AGENT"
```

**Read / Update / Delete**

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/agents"
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/agents/$AGENT"

# suspend without deleting — the reversible kill switch; resuming needs an admin
curl -X PUT "http://$PAP/v1/agents/$AGENT" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"alice-claude-code","provider":"anthropic","model_id":"claude",
       "trust_tier":3,"enabled":true,"suspended":true,"allowed_tools":[]}'

curl -X DELETE -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/agents/$AGENT"
```

> **Deleting an agent still referenced by a live delegation or approval returns
> `409`**, naming what still refers to it. Suspend instead — it takes effect on
> the very next tool call across your whole fleet, because the write bumps the
> tenant epoch and invalidates every cached decision.

**Resource constraints — scoping an agent to a path prefix.** Three routes,
admin-only, on `/v1/agents/{id}/resource-constraints`:

```bash
curl -sS -X PUT "http://$PAP/v1/agents/$AGENT/resource-constraints" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"resource_constraints": {"id_prefix": "/workspace/"}}'
```

The response is the same advisory shape classification caps return:

```json
{
  "agent_id": "...",
  "resource_constraints": {"id_prefix": "/workspace/"},
  "unsatisfiable_tools": ["Glob", "Grep", "TodoWrite", "WebFetch", "WebSearch"],
  "live_delegations": 2
}
```

`GET` on the same route returns the identical shape without writing anything.
`DELETE` clears the scope for delegations issued from now on. `PUT` requires
the `resource_constraints` key to be present — an OMITTED key (or an explicit
JSON `null`) is refused with a `400` naming `DELETE` as the alternative, so a
typo'd field name or a bare `{}`-less body can never silently wipe the
agent's scope. An explicitly supplied `{}` is different from an omitted key
and is accepted: that is an operator deliberately setting "no constraints,"
the same nil-vs-present-empty distinction `allowed_tools` uses (§5.5 above).
`DELETE` remains the deliberate way to turn enforcement off outright, the
same split classification caps use.

`id_prefix` is currently the only key with defined semantics: every resource
identity a call resolves to must fall under the prefix. Six things to know
before you use it:

1. **It applies at the next issuance**, exactly like classification caps: a
   root delegation copies the agent's scope when `CreateDelegation` mints it,
   and never reads it live. To make a new scope bite immediately, revoke the
   live delegation (§5.9) and let the agent re-issue.
2. **The prefix must end in `/`.** `"/workspace"` is refused with a `400`
   naming what it should be — without the trailing slash it would also match
   a sibling directory such as `/workspace-evil/`.
3. **A tool resolving no resource identity denies under any configured
   scope, permanently** — the same trap classification caps set (§4a of
   [`default-posture.md`](default-posture.md)), and the same five tools ship
   that way: `Glob`, `Grep`, `WebFetch`, `WebSearch`, `TodoWrite`. A shell
   command naming no path (`npm test`) is denied for the identical reason:
   nothing to check, and unevaluable must not read as satisfied.
4. **A shell command is checked on every path it names, not just one.** `cat
   /workspace/a.txt; cat /etc/shadow` denies on the second path even though
   the first is in scope — a benign path cannot buy scope for a command that
   still reaches outside it.
5. **The scope root itself is outside its own scope.** Under
   `id_prefix=/workspace/`, `ls /workspace` (no trailing slash) denies: the
   path this call resolves to is `/workspace`, which does not satisfy
   `HasPrefix` against `/workspace/` — the same trailing-slash requirement
   item 2 states, now working against the root directory itself. This is
   fail-closed, not a bug, but it will surprise operators: naming the scope
   root as a bare argument is denied, and only paths strictly under it
   succeed.
6. **On a shell tool it is not a boundary.** The PDP reads a command's text
   and does not run a shell. It checks every word that looks like a path: one
   with a `/`, one starting with `~`, a bare `..`, or a name with a file
   extension. Under an `id_prefix` it also checks two things more:

    - **Bare names that a file command or a redirection uses.** For `cat`,
      `ls`, `cd`, `pushd`, `rm`, `rmdir`, `cp`, `mv`, `ln`, `touch`, `mkdir`,
      `head`, `tail`, `less`, `more`, `tac`, `nl`, `stat`, `du`, `wc`, `file`,
      `tee`, `readlink`, `realpath` or `source`, wherever it stands in a
      command (`sudo cat notes` too), every later word that is not a flag or
      a number counts as a path, and so does the word after `<` or `>`.
      `cat /workspace/a.txt; cat notes`, `cd build` and `echo x > out` are
      denied: write the full path. A bare `cd` counts as `~`. This also
      refuses one of those names used as plain text, as in `echo cat notes`.
    - **Whether the text can be read at all.** A command that uses `$`, a
      backtick, or an unquoted `*`, `?`, `[` or `{` is denied with `command
      uses … cannot be evaluated`, because the shell would change its words
      after the check. `$` inside single quotes and a glob inside any quotes
      are fine: `awk '{print $1}' /workspace/a.txt` is allowed.

   What still gets through: a bare name given to a command outside that
   list (`python script`, `make -C dir`), a script or interpreter that opens
   files itself, and a symlink inside the prefix that points out of it. Use
   `id_prefix` to keep a well-behaved agent in its lane. To confine a shell,
   run it where the files outside its scope are not reachable.

A child delegation may narrow `id_prefix` further (`/workspace/service-a/`
under a parent's `/workspace/`) but may not widen it or drop it — see
[`concepts.md`](concepts.md) §7.

**Escalation threshold: when a human must approve.** Admin-only, on
`/v1/agents/{id}/escalation`. At or above this tier, a call waits for a human
(§5.9) instead of being allowed outright.

```bash
curl -sS -X PUT "http://$PAP/v1/agents/$AGENT/escalation" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"escalate_at": 4}'
```

```json
{"agent_id": "...", "escalate_at": 4, "live_delegations": 1, "applies": "at next issuance"}
```

1. **It applies at the next issuance,** like caps and scope. A root delegation
   copies the agent's threshold when it is minted. Revoke live delegations to
   apply a change now.
2. **A session can only make it stricter.** `STRATIUM_PEP_ESCALATE_AT`, or the
   SDK's `escalate_at=`, asks for a *lower* threshold. Asking for a higher one,
   or for none, leaves the agent's in place: the caller is the party being
   policed.
3. **A threshold above the session's ceiling is dropped.** If policy clamps the
   ceiling to `EXTERNAL_COMMS` and the threshold is `DESTRUCTIVE`, it could
   never fire. The response names it in `removed` with reason `unreachable`.
4. **Removing or raising it is audited as a widening** (§5.11): the agent can
   now act unattended where a human was asked before.
5. **A missing or `null` value is a `400`.** Neither may silently mean tier 0
   (escalate on everything) or "no threshold". `DELETE` removes it.
6. **Sub-agents inherit it** and may lower it. A child whose own ceiling sits
   below the threshold may drop it, since it could never reach it.

Escalation needs a person to approve, so it fits `hook`, `mcp`, and the SDK,
which wait. `extauthz` and `proxy` turn an escalation into a denial naming the
approval id (§6.1).

#### Reserving an agent for particular people

Whoever starts a session names the agent it runs through, and an agent's
ceilings (classification caps, resource constraints, escalation threshold,
trust tier, allowed tools) are whatever that agent's record says. Unless
policy says otherwise, any principal who holds a tool may start a session
through any agent. If your agents carry different ceilings, say who may use
which one.

Policy sees the agent by id, both when a session starts and on every call, as
`context.agent.id` in Cedar and `input.agent.id` in Rego. A `forbid` reserves
the agent:

```cedar
// only alice may act through this agent
forbid(principal, action, resource)
when {
  context.agent.id == "50bdd8cc-377f-4135-818d-cfd30b206ce5" &&
  principal != User::"alice@example.com"
};
```

```rego
package stratium.policy

deny if {
	input.agent.id == "50bdd8cc-377f-4135-818d-cfd30b206ce5"
	input.principal.subject != "alice@example.com"
}
```

Then protect the policy, so that an editor cannot rewrite or disable it
(§5.4, "Protecting a policy").

Anyone else who tries to start a session through that agent is refused
(`none of the requested tools are held by this principal`), and a session
that already exists is denied on its next call. Use the id, not the name: an
editor can rename an agent. The `json` and `xacml` languages cannot name an
agent's id; write this rule in Cedar or Rego.

A `permit` or `forbid` that reads any other `context.agent` field
(`trust_tier`, `enabled`, `suspended`, `allowed_tools`) is likewise evaluated
against the real agent at session start.

### 5.6 CRUD: Tools (the tool catalog)

The tool catalog tells the PDP **how to read a tool's arguments**: which JSON
field holds the resource it acts on, which holds the command, what verb to
record, and what tier to assign. Without a catalog row for a tool, the PDP falls
back to a built-in table and the tool's arguments contribute no resource
identity — which means it can never be resource-labelled.

**Fields**

| Field | Type | Notes |
|---|---|---|
| `tool_name` | string | **required**, unique within the tenant. The exact name the harness sends. |
| `action_tier` | int or `null` | `0`–`4`, or `null` meaning "derive per call from the command". |
| `verb` | string | recorded on the decision and visible to policy — `read`, `write`, `execute`, `search`… |
| `resource_field` | string or `null` | which raw-input JSON field holds the resource identity |
| `command_field` | string or `null` | which raw-input JSON field holds the command text |
| `id`, `tenant_id` | — | server-owned |

> **Validation rule:** an entry must set an `action_tier`, a `command_field`, or
> both. Setting neither is a `400` — such a row could never produce a tier.

Two shapes, and the difference matters:

```jsonc
// A fixed-tier tool. Reading a file is always READ_ONLY.
{ "tool_name": "Read", "action_tier": 1, "verb": "read",
  "resource_field": "file_path", "command_field": null }

// A shell tool. NO fixed tier — the tier is derived per call from the command.
{ "tool_name": "Bash", "action_tier": null, "verb": "execute",
  "resource_field": null, "command_field": "command" }
```

The `Bash` shape is the important one. A single fixed tier can never describe a
shell command: `ls -la` is `READ_ONLY` and `rm -rf /` is `DESTRUCTIVE`, through
the same tool. `action_tier: null` plus `command_field` is what tells the PDP to
classify the command text on every call, server-side.

**Create / read / update**

```bash
curl -X POST "http://$PAP/v1/tool-catalog" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"tool_name":"Read","action_tier":1,"verb":"read","resource_field":"file_path"}'

curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/tool-catalog"
# an editor may raise the tier; any other change needs an admin
curl -X PUT "http://$PAP/v1/tool-catalog/$ID" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"tool_name":"Read","action_tier":2,"verb":"read","resource_field":"file_path"}'
```

There is **no `DELETE`** — see §5.2.

**Bulk seeding.** Two ready-made seeds ship for the harnesses this project has
run against:

```bash
psql -v tenant_id="$TENANT" -f deploy/seed/tool-catalog-claude-code.sql
psql -v tenant_id="$TENANT" -f deploy/seed/tool-catalog-mcp-filesystem.sql
```

The Claude Code seed registers twelve tools. Three details in it that will
surprise you:

- `Read` uses `file_path`, **not** `path`.
- `Glob`, `Grep`, `WebFetch`, `WebSearch` and `TodoWrite` have **no**
  `resource_field`, deliberately — they cannot be resource-labelled at all, and
  under a classification cap they **deny outright**. Test this before enabling a
  cap on a session that needs them.
- `Bash` has no tier and a `command_field`, as above.

**Registering a tool of your own.** Do not guess the field names. Capture a real
payload first — the PEP's `hook` surface receives the harness's exact JSON, and
[`docs/pep.md`](pep.md) § "Adding a tool of your own" walks through it.

### 5.7 CRUD: Labels (resource label rules)

A label rule maps a **resource-id prefix** to a `(hierarchy, level)`
classification. At decision time the PDP resolves a resource by **longest
matching prefix** and compares the result against the delegation's cap.

**Fields**

| Field | Type | Notes |
|---|---|---|
| `prefix` | string | **required** (an empty string is valid and means "catch-all"). Unique within the tenant. |
| `hierarchy` | string | **required**, `nato` or `commercial` |
| `level` | string | **required**, a level of that hierarchy |
| `id`, `tenant_id` | — | server-owned |

**The two shipped hierarchies**, low to high:

| Hierarchy | Levels |
|---|---|
| `nato` | `UNCLASSIFIED`, `RESTRICTED`, `CONFIDENTIAL`, `SECRET`, `TOP-SECRET` |
| `commercial` | `PUBLIC`, `INTERNAL`, `CONFIDENTIAL-COMMERCIAL`, `RESTRICTED-COMMERCIAL`, `HIGHLY-CONFIDENTIAL` |

An unknown hierarchy or a level that is not part of the named hierarchy is a
`400` listing what is valid.

```bash
# the catch-all first — see the warning below
curl -X POST "http://$PAP/v1/resource-label-rules" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"prefix":"","hierarchy":"nato","level":"UNCLASSIFIED"}'

# then the carve-outs
curl -X POST "http://$PAP/v1/resource-label-rules" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"prefix":"/srv/secret/","hierarchy":"nato","level":"SECRET"}'

curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/resource-label-rules"
curl -X DELETE -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/resource-label-rules/$ID"
```

> **Four traps, all of which deny rather than leak — but all of which will
> surprise you:**
>
> 1. **A cap with no catch-all denies every unmatched resource.** There is no
>    default level. An unmatched resource is *unlabelled*, and an unlabelled
>    resource under any configured cap denies with "cannot be evaluated". Write
>    the empty-prefix rule before enabling caps.
> 2. **Deleting the empty-prefix rule un-labels the whole tenant.** That is why
>    `DELETE` here is admin-only: every other delete on this API removes
>    something permissive; this one removes something that makes things work.
> 3. **Write the trailing separator.** `"/srv/secret"` also matches
>    `/srv/secret-notes.txt`. Use `"/srv/secret/"`.
> 4. **The uniqueness key is the prefix alone, not `(prefix, hierarchy, level)`.**
>    A second rule on the same prefix in a *different* hierarchy collides
>    (`409`) exactly like an identical one. One prefix carries one answer.
>
> [`docs/pep.md`](pep.md) § "Labelling resources for classification caps" covers
> each of these with worked examples.

**Setting the cap.** A ceiling lives on the *agent*, and a root delegation copies
it at issuance. The route is admin-only, because a classification ceiling is not
ordinary agent configuration:

```bash
curl -sS -X PUT "http://$PAP/v1/agents/$AGENT/classification-caps" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"classification_caps": {"nato": "CONFIDENTIAL"}}'
```

The response reports the consequences, not just the value — the catch-all rule
in force per capped hierarchy, the tools that can never satisfy *any* cap, and
how many live delegations the change does **not** affect:

```json
{
  "classification_caps": {"nato": "CONFIDENTIAL"},
  "catch_all": {"nato": "UNCLASSIFIED"},
  "unsatisfiable_tools": ["Glob", "Grep", "TodoWrite", "WebFetch", "WebSearch"],
  "live_delegations": 2,
  "applies": "at next issuance"
}
```

Four things to know before you use it:

1. **It applies at the next issuance.** A delegation already minted keeps the
   caps it was issued with — that is what `live_delegations` is counting. To make
   a ceiling bite now, revoke the delegation (§5.9) and let the agent re-issue.
2. **A cap with no catch-all rule is refused** with `409`. Register the
   empty-prefix rule first, or pass `?allow_uncovered=true` if a deny-by-default
   posture is genuinely what you want. The override is recorded in the audit
   entry.
3. **`PUT` will not clear a cap.** An empty or absent map is a `400`. Turning
   enforcement off is `DELETE` on the same route — a separate, deliberate verb,
   so it cannot happen by omitting a field from a request body.
4. **A cap naming two hierarchies is currently unreachable without the
   override**, because `resource_label_rules` is unique on the prefix alone
   (point 4 above), so only one empty-prefix rule can exist per tenant.

`GET` on the same route returns the same body, so you can read the consequences
before committing to them.

### 5.8 CRUD: Overrides (tier overrides)

An override corrects the tier the PDP assigns to a tool or verb — **upward
only**.

**Fields**

| Field | Type | Notes |
|---|---|---|
| `tool_or_verb` | string | **required**. A tool name (`Bash`), a `Tool:verb` pair (`Bash:execute`), or a bare verb (`delete`). |
| `action_tier` | int | **required**, `0`–`4`. The tier to assign. |
| `builtin_tier` | int | server-owned — the baseline computed when the row was written |
| `created_by` | string | server-owned — the `sub` of the operator who wrote it |
| `id`, `tenant_id`, `created_at` | — | server-owned |

Lookup is **most specific first**: `Tool:verb`, then `Tool`, then the bare verb.

> ### Raise-only, enforced at both ends
>
> An override may name a tier **at or above** what the tool would otherwise
> resolve to, never below. A lowering override is refused at write time with a
> `400` naming both tiers:
>
> ```
> tier override may not lower the resolution beneath it: baseline is READ_ONLY, override is REASONING
> ```
>
> It is checked **again** at decision time, against the catalog loaded for that
> very decision. That second check is the one that cannot be bypassed — the
> stored baseline is a snapshot, and a tenant that catalogs a tool as
> `DESTRUCTIVE` *after* writing a `WRITE` override on it has left a row that was
> valid when written and is a lowering now.
>
> A row that fails the read-time check is **dropped, not fatal**: resolution
> falls through to the higher tier beneath it and a log line names the key. One
> bad row costs you that override, never every decision.

```bash
# treat every psql invocation as destructive, whatever the command text says
curl -X POST "http://$PAP/v1/tier-overrides" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"tool_or_verb":"psql","action_tier":4}'

# raise a single verb across every tool
curl -X POST "http://$PAP/v1/tier-overrides" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"tool_or_verb":"delete","action_tier":4}'

curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/tier-overrides"
curl -X DELETE -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/tier-overrides/$ID"
```

> You cannot use an override to make something *safer*. If a tool is being
> classified too harshly, fix its catalog row — that is what the catalog is for.

### 5.9 Approvals

An approval is created **by the PDP**, not by you, whenever a decision comes back
`ESCALATE` — which happens when a delegation's `escalate_at` tier is reached and
nothing denied. The agent's tool call blocks (on `hook` and `mcp`) while a human
decides.

**Fields you will see**

| Field | Notes |
|---|---|
| `id` | what you approve or deny |
| `agent_id`, `delegation_id`, `root_delegation_id` | which chain asked |
| `subject` | the principal the agent is acting for |
| `root_principal` | **who is allowed to decide this** — see below |
| `tool_name`, `action`, `derived_tier` | what was attempted |
| `input_digest` | a hash. Raw tool input is never stored. |
| `status` | `pending`, `approved`, or `denied` |
| `requested_at`, `expires_at` | expiry comes from `STRATIUM_APPROVAL_TTL`, default 24h |
| `approved_by`, `approved_at` | populated once decided |

```bash
# find pending work
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/approvals" \
  | python3 -c 'import json,sys; [print(a["id"], a["status"], a["tool_name"], a["root_principal"]) for a in json.load(sys.stdin)]'

curl -X POST -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/approvals/$ID/approve"
curl -X POST -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/approvals/$ID/deny"
```

**An approval allows one call.** It covers the exact call it was requested
for: the same agent, delegation, tool and input. The PDP marks it used when
it allows that call, and a second call offering the same approval is denied
with `approval … has already been used`. Running the same command again
needs a new approval. `GET /v1/approvals` returns the time as `used_at`, and
the approvals screen shows such an approval as **used**.

> ### A role is necessary and never sufficient
>
> Approving requires **both**:
>
> 1. the `admin` role, and
> 2. your approver identity (§4.4) **equal to this approval's `root_principal`**.
>
> An admin who is not the root principal gets a `403`. An admin whose approver
> claim is absent, empty, or unverified gets a `401`. There is no override and
> no path that skips either check — including for the person who deployed the
> system.
>
> **Revoking** a delegation, by contrast, needs only the admin role. Taking
> authority away is not the same kind of act as granting it.

Three more things worth knowing:

- **Deciding a non-pending approval returns `409`.** Approvals are decided once.
- **An expired approval denies on retry**, whatever its status says.
- **An approval can never resurrect a request the three legs would refuse.** By
  the time an approval is consulted, all three legs have re-run fresh on the
  retry. A delegation revoked between the escalation and the approval denies
  regardless of what you clicked.

### 5.10 Delegations

Read-only, plus revoke. Delegations are created over gRPC by
`stratium-pep session-start` (§6).

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/delegations"

# the kill switch for one agent session
curl -X POST -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/delegations/$ID/revoke"
```

Revocation sets `revoked`/`revoked_at` rather than deleting the row, so the
audit trail survives, and it takes effect **on the very next tool call** — the
PEP re-reads its session file on every call and the write bumps the tenant epoch,
invalidating every cached decision fleet-wide.

---

### 5.11 Containment — what a change widens

Every other question in this section is a **point query**: you hand it one
sample and it tells you what happens to that sample. These two answer the
universal one — *does this allow anything that was not allowed before?*

**`POST /v1/containment`** compares two permission sets. It writes nothing; it
is `editor` because every POST here is, not because it changes anything.

```bash
curl -X POST -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  "http://$PAP/v1/containment" -d '{
    "baseline":  {"approved_tools":["Read","Write"],"max_action_tier":3,"expires_at":"2026-12-01T00:00:00Z"},
    "candidate": {"approved_tools":["Read","Bash"],"max_action_tier":3,"expires_at":"2026-12-01T00:00:00Z"}
  }'
```

```json
{"contained":false,"reason":"child tool Bash not in parent approved_tools"}
```

`reason` is the counterexample: the **first** dimension on which the candidate
exceeds the baseline, worded exactly as a refused delegation would word it. A
contained candidate returns `{"contained":true,"reason":""}`.

**Two questions, and they are not the same question.** Add `"question"` to
select one:

```bash
# did this agent's grant get WIDER?  (an absent cap means unrestricted,
# so adding the first one NARROWS)
curl -X POST -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  "http://$PAP/v1/containment" -d '{
    "question": "grant",
    "baseline":  {"approved_tools":["Read"],"max_action_tier":1,"classification_caps":{},"expires_at":"2026-12-01T00:00:00Z"},
    "candidate": {"approved_tools":["Read"],"max_action_tier":1,"classification_caps":{"nato":"SECRET"},"expires_at":"2026-12-01T00:00:00Z"}
  }'
```

```json
{"question":"grant","contained":true,"reason":""}
```

The identical bodies with `"question": "delegation"` — the default, and what
an omitted field means — answer the opposite way:

```json
{"question":"delegation","contained":false,"reason":"child caps hierarchy nato which parent does not cap"}
```

Neither answer is wrong. `delegation` asks *may a child hold this?*, and a
child may not invent a dimension its parent never had — a deliberate shape
rule. `grant` asks *did this get wider?*, which is a pure lattice question, and
introducing a restriction narrows. Ask the one you mean; an unrecognised value
is a 400 rather than a silent fallback, because guessing between two answers
that differ is the one thing this endpoint must not do.

The fields are the six that bound a grant — `approved_tools`,
`max_action_tier`, `escalate_at`, `classification_caps`, `resource_constraints`,
`expires_at`. Omitted fields take their zero value, which is not the same as
"unrestricted" for every dimension, so send the whole set rather than a patch.

**`GET /v1/principals/{id}/effective`** answers the question the delegation
chain cannot. Every hop is checked against its parent, exhaustively — but
nothing compares **siblings**. Two live root delegations under one person, one
reaching `/secret` and one reaching the internet, are each within bounds and
together are an exfiltration path.

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/principals/alice@example.com/effective"
```

```json
{
  "principal_id": "alice@example.com",
  "union": {"approved_tools":["Bash","Read"],"max_action_tier":3,"classification_caps":{},"resource_constraints":{},"expires_at":"2026-12-01T00:00:00Z"},
  "delegations_counted": 2,
  "imprecision": ["resource constraint id_prefix differs across members (/workspace/ vs /tmp/), so the union is unconstrained for it"]
}
```

The `{id}` is the principal's OIDC subject, not a UUID. Revoked, expired and
non-root delegations contribute nothing.

Two fields are easy to skim past and shouldn't be:

- **`delegations_counted`** is what distinguishes "this principal holds nothing"
  from "this principal holds everything." An empty `approved_tools` means
  *unrestricted* everywhere else in Stratium, so a zero-value union and a
  genuinely unrestricted one serialize identically. The count tells them apart.
- **`imprecision`** names every dimension the union had to widen beyond an exact
  join. The union deliberately errs upward — a report that quietly lost
  precision would be worse than no report — and this is where it admits it.

**This route reports; it enforces nothing.** There is no principal ceiling to
check the union against yet.

---

### 5.12 Reading the audit log

`audit_chain` is append-only and hash-linked: every entry commits to its
predecessor's hash, so a mutation or a deletion breaks verification. Everything
the admin plane does lands there — every decision, every delegation, every CRUD
write, and a `containment` row whenever a write widens an agent's grant (§5.11).

```bash
# the containment verdicts, newest first
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/audit?event_type=containment"

# everything that happened to one agent
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/audit?agent_id=$AGENT&limit=200"
```

```json
{
  "entries": [{
    "seq": 1287,
    "prev_hash": "3q2+7w==", "entry_hash": "kR4x9A==",
    "occurred_at": "2026-09-16T23:58:35Z",
    "event_type": "containment",
    "actor": "f2cc233c-acbe-4c41-916d-80fd94daed3f",
    "agent_id": "5359f7c0-d5b3-46de-add4-8f94147dde23",
    "decision": "ALLOW",
    "reason": "agent grant widened: child tool Write not in parent approved_tools"
  }],
  "next_before_seq": 1240
}
```

`event_type`, `agent_id`, `limit` (default 50, max 500) and `before_seq` all
combine. Paging is by `seq`, which is the primary key and insertion-ordered, so
a cursor cannot skip or repeat a row even while new entries are being appended.
**`next_before_seq` is present only when the page was full** — no cursor means
you have reached the end, which saves a round trip to discover an empty page.

**Two things this route does not do.**

It does not verify the chain. `pkg/audit.Verify` requires its first entry to
link to the zero hash, so it can only run over a *contiguous* range starting at
a tenant's very first row — and a filtered read is by construction not
contiguous. Rather than ship a check that quietly means something weaker than
it sounds, every row carries `prev_hash` and `entry_hash` and a caller who has
read a contiguous range can re-walk it themselves.

It does not return raw tool inputs, because they were never stored — only
`input_digest`. Writing raw shell commands into an undeletable table before
per-tenant key management exists would be worse than not storing them
([`architecture.md`](architecture.md) §14).

**On the role.** This is `viewer`, like every other read here. Worth knowing
what that includes: `reason` strings name the resource identities a call
resolved to, which is more than `GET /v1/delegations` reveals. There is no
secret material in it, but "who gets viewer" is a slightly bigger question once
the audit log is readable.

---

## 6. PEP capabilities — putting an agent behind Stratium

A **PEP** is the piece that actually stops something. It runs on the machine
where the agent's tool calls execute, intercepts each one, asks the PDP, and
enforces the answer.

It classifies nothing. A tool call's arguments cross this process as opaque
bytes.

### 6.1 Choosing a surface

`stratium-pep` offers four enforcement surfaces. Pick by **what kind of harness
you are policing**, not by vendor.

| Surface | Use it when | Intercepts | Can block on a human? |
|---|---|---|---|
| `hook` | the harness has a pre-tool-use hook — **Claude Code, Codex** | every tool call, including shell | **yes** |
| `mcp` | the harness launches local stdio MCP servers — **Claude Desktop, ChatGPT desktop, Claude Code, Codex** | `tools/call`, resource reads and prompts on the server you wrap | **yes** |
| `extauthz` | the tool is an HTTP API you control, behind Envoy | every HTTP request | no — degrades to a denial naming the approval |
| `proxy` | the tool is a gRPC service you control | every gRPC stream, at open | no — same degrade |

Two rules that decide the rest of your design:

> **A surface may block on a human only while the credential it would wait with
> outlives the wait.** A bearer token does; a single-use, short-lived DPoP proof
> does not. `extauthz` and `proxy` require sender-constrained tokens, so they
> degrade an escalation to a denial that names the approval id, and the client
> retries once it is approved.

> **Only `mcp` may serve a cached decision.** Its cache lives in the `mcp`
> process's memory, so only decisions that process received from the PDP are
> ever replayed. `hook` asks the PDP on every call. On `extauthz` and `proxy`
> the caller *is* the party being policed, so every call goes to the PDP.

### 6.2 Creating a PEP for an agent — the complete recipe

Seven steps. Do them in order; each one's failure mode is different and step 2
is the one everybody skips.

#### Step 0 — Have the PDP reachable and the binary in place

```bash
export PDP=pdp.internal:50051
export STRATIUM_PEP_PDP_CA_FILE=/etc/stratium/pdp-ca.pem   # only if a private CA issued the PDP's certificate
which stratium-pep
```

Against the local evaluation stack (§2.2), use its `$PDP` and
`export STRATIUM_PEP_PDP_INSECURE=true` instead: that stack serves plaintext.

#### Step 1 — Register the agent (PAP, §5.5)

```bash
export AGENT=$(curl -sS -X POST "http://$PAP/v1/agents" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"alice-claude-code","provider":"anthropic","model_id":"claude",
       "trust_tier":3,"enabled":true,"suspended":false,"allowed_tools":[]}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
```

The agent's **trust tier caps what it can ever attempt**, independent of any
delegation. A `REGISTERED` (1) agent can never perform an `EXTERNAL_COMMS`
action even under a delegation that permits tier 3.

#### Step 2 — Write a policy that lets your principal delegate

**Without this, nothing else works.** `session-start` calls `CreateDelegation`,
which is clamped by what the *principal* is permitted to delegate. With no policy
it fails with:

```
none of the requested tools are held by this principal
```

```bash
curl -sS -X POST "http://$PAP/v1/policies" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"alice-may-delegate","description":"grant for alice",
       "language":"rego","effect":"deny","enabled":true,
       "policy_content":"package stratium.policy\n\nallow if {\n\tinput.principal.subject == \"alice@example.com\"\n}"}'
```

The subject in the policy **must match** the `STRATIUM_PEP_SUBJECT` you will
configure in step 4.

#### Step 3 — Seed the tool catalog for this harness (§5.6)

```bash
psql -v tenant_id="$TENANT" -f deploy/seed/tool-catalog-claude-code.sql
```

Skip this and `Bash` arrives as an opaque JSON envelope, never gets its command
extracted, and a harmless `ls -la` rates `INTERNAL_MODIFY` instead of
`READ_ONLY`. The catalog is not optional for shell tools.

#### Step 4 — Start a session

This is the call that creates the delegation and writes the session file.

```bash
export SESSION=/run/stratium/session.json

STRATIUM_PEP_PDP_ADDR="$PDP" \
STRATIUM_PEP_AGENT_ID="$AGENT" \
STRATIUM_PEP_SUBJECT="alice@example.com" \
STRATIUM_PEP_SESSION_FILE="$SESSION" \
STRATIUM_PEP_CONNECT_TIMEOUT=5s \
STRATIUM_PEP_PRINCIPAL_TOKEN_FILE=/run/secrets/principal.jwt \
STRATIUM_PEP_REQUESTED_TOOLS="Read,Write,Bash" \
STRATIUM_PEP_REQUESTED_TIER=3 \
STRATIUM_PEP_PURPOSE="daily engineering session" \
STRATIUM_PEP_TTL_SECONDS=3600 \
stratium-pep session-start; echo "exit=$?"
```

`STRATIUM_PEP_PRINCIPAL_TOKEN_FILE` names a file holding alice's OIDC token.
Get it from your identity provider: Stratium does not log in for you. The PDP
reads the principal from it, and `STRATIUM_PEP_SUBJECT` must equal that
identity.
Against the local evaluation stack, leave the variable out: that stack's PDPs
run with principal verification off.

**Expected** — `exit=0` and a session file holding what was **granted**, which
may be narrower than what you asked for:

```json
{
  "delegation_id": "0ac6d617-2fe0-47d2-97a1-401c8651baa0",
  "granted_scope": { "max_action_tier": 3,
                     "tools": ["Read", "Write", "Bash"] },
  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "epoch": 77
}
```

**Check `granted_scope`, do not assume it.** An empty `tools` list, or
`none of the requested tools are held by this principal`, means step 2's policy
is missing or its subject does not match.

> **The session file is bearer authority, not a label.** Anyone who can read it
> can act as this agent for the delegation's lifetime. It is created `0600`; keep
> it that way, keep it off shared volumes, and delete it when the session ends —
> deleting it denies the very next tool call.

> **Ask for what you need, including discovery tools.** `Glob` and `Grep` are how
> an agent finds the file it then reads. A session granted only `Read` will
> frustrate everyone. See [`docs/pep.md`](pep.md) § "Grant discovery tools, not
> just access tools".

#### Step 5 — Prove enforcement by hand before wiring it in

Do not install a hook into a live session before you have seen it work.

```bash
hook() {
  printf '%s' "$1" | \
  STRATIUM_PEP_PDP_ADDR="$PDP" STRATIUM_PEP_AGENT_ID="$AGENT" \
  STRATIUM_PEP_SUBJECT="alice@example.com" STRATIUM_PEP_SESSION_FILE="$SESSION" \
  STRATIUM_PEP_CONNECT_TIMEOUT=5s \
  STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s STRATIUM_PEP_APPROVAL_TIMEOUT=5m \
  stratium-pep hook
  echo "  exit=$?"
}

hook '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
hook '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}'
hook '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
hook '{"tool_name":"Grep","tool_input":{"pattern":"x"}}'
```

**Observed**, against a session capped at tier 3 with tools `Read, Write, Bash`:

```
  exit=0                                            # ls -la      → READ_ONLY
  exit=0                                            # curl        → EXTERNAL_COMMS, at the ceiling
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"action tier DESTRUCTIVE exceeds delegation max_action_tier EXTERNAL_COMMS at depth 0"}}
  exit=2                                            # rm -rf /    → DESTRUCTIVE, refused
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"tool \"Grep\" not in delegation approved_tools at depth 0"}}
  exit=2                                            # Grep        → outside the granted scope
```

**PASS if** the first three differ from each other. Those are the *same tool*
with the *same delegation* — only the command text changed, and the tier was
computed in the PDP.

> **If every call denies with `missing required configuration: …`**, add the
> variables it names. The `hook` surface needs **seven**, and a missing one
> **fails closed with the reason on stdout** rather than allowing. That is
> correct behaviour, and it is why the reason text matters.

#### Step 6 — Wire it into the harness

**Claude Code** — `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "stratium-pep hook", "timeout": 330, "onFailure": "block" }
        ]
      }
    ],
    "PostToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command", "command": "stratium-pep report", "timeout": 15 } ] }
    ],
    "PostToolUseFailure": [
      { "matcher": "*",
        "hooks": [ { "type": "command", "command": "stratium-pep report", "timeout": 15 } ] }
    ]
  }
}
```

The seven variables must be exported in the shell that launches Claude Code.
**Keep the `timeout` above the hook's time budget.** The hook answers within
`STRATIUM_PEP_APPROVAL_TIMEOUT` + 4 × `STRATIUM_PEP_CONNECT_TIMEOUT` (320s with
the values on this page: 5m + 4 × 5s) and denies at that point. A harness that gives up on a
hook sooner runs the tool call, so the `timeout` must be the larger number.
**Start with a narrow `matcher`** (`"Read"`) on a session you care about.

**Codex** — `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command",
                     "command": "/usr/local/bin/stratium-pep session-start",
                     "timeout": 15 } ] }
    ],
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/usr/local/bin/stratium-pep hook --harness codex",
                     "timeout": 330 } ] }
    ],
    "PostToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/usr/local/bin/stratium-pep report",
                     "timeout": 15 } ] }
    ]
  }
}
```

`--harness codex` makes the hook answer the way Codex reads (exit `2`, reason on
stderr) and tells the PDP the tool names are Codex's, so a file edit from Codex
(`apply_patch`) is decided as an `Edit` of each file the patch names. See
[`stratium-pep hook`](pep/harnesses/codex.md).

Two Codex-specific gotchas, both of which fail **open**:

- Install at `~/.codex/hooks.json`, not `<repo>/.codex/hooks.json` — project-local
  hooks are silently disabled until the project is trusted.
- Codex content-hashes every hook and will not run one you have not reviewed.
  A freshly installed hook reports `trustStatus: untrusted` and **is not
  enforcing**. Approve each one in the `/hooks` browser, or use the
  [system install](pep/harnesses/codex.md#the-system-install), whose hooks need
  no review.

Full detail: [`docs/testing/2026-08-20-agent-integration-test.md`](testing/2026-08-20-agent-integration-test.md).

**MCP harnesses** (Claude Desktop, ChatGPT desktop, any client running local
stdio MCP) — replace the real server's command with `stratium-pep mcp` and move
the original into the upstream variables:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/local/bin/stratium-pep",
      "args": ["mcp"],
      "env": {
        "STRATIUM_PEP_MCP_UPSTREAM_COMMAND": "npx",
        "STRATIUM_PEP_MCP_UPSTREAM_ARGS": "-y,@modelcontextprotocol/server-filesystem,/srv/data",
        "STRATIUM_PEP_PDP_ADDR": "pdp.internal:50051",
        "STRATIUM_PEP_PDP_CA_FILE": "/etc/stratium/pdp-ca.pem",
        "STRATIUM_PEP_AGENT_ID": "…",
        "STRATIUM_PEP_SUBJECT": "alice@example.com",
        "STRATIUM_PEP_SESSION_FILE": "/run/stratium/mcp-session.json",
        "STRATIUM_PEP_CONNECT_TIMEOUT": "5s",
        "STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "2s",
        "STRATIUM_PEP_APPROVAL_TIMEOUT": "5m",
        "STRATIUM_PEP_CACHE_STALENESS_WINDOW": "30s"
      }
    }
  }
}
```

The **tool names are the upstream server's**, not the harness's — request
`read_text_file,write_file,list_directory` in step 4, not `Read,Write,LS`, and
catalog those names in step 3.

> `tools/list` is **not** filtered. An agent can see a tool it cannot call and
> finds out at call time. That is deliberate: filtering the list would mean this
> proxy deciding what a tool *is*, which is exactly the job it must not do.

**HTTP APIs behind Envoy:**

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc: { cluster_name: stratium_pep }
        timeout: 5s
```

```bash
STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR=:9191
STRATIUM_PEP_PDP_ADDR=pdp.internal:50051
STRATIUM_PEP_PDP_CA_FILE=/etc/stratium/pdp-ca.pem
STRATIUM_PEP_AGENT_ID=…
STRATIUM_PEP_SUBJECT=alice@example.com
STRATIUM_PEP_CONNECT_TIMEOUT=5s
STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS=api.example.com,api.eu.example.com
```

`deploy/docker/envoy.yaml` is the worked example. Catalog each endpoint as a
"tool" and choose its `resource_field` deliberately — the PDP sees an HTTP
request, not a tool call with named arguments.

**gRPC services:**

```bash
STRATIUM_PEP_PROXY_LISTEN_ADDR=:9292
STRATIUM_PEP_PROXY_TARGET_ADDR=payments.internal:50051
STRATIUM_PEP_PROXY_PUBLIC_URI=https://tools.example.com
STRATIUM_PEP_PDP_ADDR=pdp.internal:50051
STRATIUM_PEP_PDP_CA_FILE=/etc/stratium/pdp-ca.pem
STRATIUM_PEP_AGENT_ID=…
STRATIUM_PEP_SUBJECT=alice@example.com
STRATIUM_PEP_CONNECT_TIMEOUT=5s
STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s
STRATIUM_PEP_APPROVAL_TIMEOUT=5m
```

The tool name is the **full gRPC method** (`/pkg.Service/Method`), catalogable
per tenant like any other. Note its limits: a stream is authorized **once, at
open**, message bodies are never inspected, and there is no command text for the
evidence rule to scan. [`docs/pep.md`](pep.md) § "The `proxy` surface's limits"
covers all four consequences.

#### Step 7 — Verify in the real harness

Ask the agent to do something it should be refused. The harness surfaces
`permissionDecisionReason` as the reason it could not proceed.

### 6.3 Session lifecycle

| Event | Effect |
|---|---|
| `session-start` | creates the delegation, writes the session file |
| every tool call | the session file is re-read **fresh**; there is no in-memory cache of it |
| token expires mid-session | the PEP silently re-issues once and retries — you see nothing |
| `POST /v1/delegations/{id}/revoke` | the **next** tool call denies |
| agent suspended or disabled | the next tool call denies |
| any PAP write | the tenant epoch bumps, invalidating every cached decision fleet-wide |
| `mcp` restarts | its decision cache starts empty; the next call asks the PDP |
| session file deleted | the next tool call denies |
| delegation TTL elapses | denies |

Re-run `session-start` to begin a new session. There is no renew.

### 6.4 Reading a denial

Every denial carries a reason. Learning to read four shapes saves hours:

| Reason begins with | Means | Fix |
|---|---|---|
| `stratium-pep: missing required configuration:` | the PEP is misconfigured — **not** a policy denial | add the named variables |
| `stratium-pep: could not reach PDP` / `PDP did not respond in time` | network or PDP outage, or a TLS mismatch; the PEP failed closed | check the PDP; for a TLS handshake error, see §3.1 "Transport security" |
| `action tier X exceeds delegation max_action_tier Y at depth N` | the delegation's ceiling | raise `STRATIUM_PEP_REQUESTED_TIER` and restart the session, if policy permits it |
| `tool "X" not in delegation approved_tools at depth N` | outside the granted scope | add it to `STRATIUM_PEP_REQUESTED_TOOLS` and restart the session |
| `tool "X" not in agent allowed_tools` | the **agent record**, not the delegation | edit the agent (§5.5) |
| `delegation chain is not well-formed: request subject is not the principal root delegation … was issued for` | `STRATIUM_PEP_SUBJECT` differs from the subject the session was started with | use the same subject for `session-start` and every later call, or start a new session |
| `principal_token is required` | `session-start` sent no principal token to a PDP that verifies principals | set `STRATIUM_PEP_PRINCIPAL_TOKEN_FILE` to a file holding the person's OIDC token (§3.3) |
| `principal_token does not identify a principal` | the token failed verification: expired, wrong audience or issuer, or an unverified email | get a fresh token from the identity provider and audience the PDP is configured for (§3.1 "Principal authentication") |
| `subject is not the principal that principal_token identifies` | `STRATIUM_PEP_SUBJECT` differs from the identity in the token | set `STRATIUM_PEP_SUBJECT` to the value of the token's `STRATIUM_PRINCIPAL_CLAIM` claim |
| `agent trust tier X insufficient for action tier Y (requires Z)` | the agent's trust tier | raise it, deliberately |
| `resource classification X exceeds delegation cap Y in hierarchy "h"` | a classification cap | §5.7 |
| `resource declares no classification; … cannot be evaluated` | a cap is set and nothing labelled the resource | write a catch-all label rule |
| `action tier X at or above delegation escalate_at Y` | **not a denial:** the call is waiting for a human approval (§5.9) | approve it, or lower the work's tier |
| `default deny: no policy verdict allowed` | no policy allowed the principal | §5.4 |
| `delegation … is revoked` / `expired at …` | exactly what it says | new session |

A **configuration failure and a policy denial look different on purpose.** If the
reason names a variable, it is yours to fix; if it names a tier, a tool, or a
classification, the system is working.

### 6.5 Operational notes

- **Every tool call is a synchronous PDP round trip.** Size the PDP for your
  fleet's tool-call rate, not its user count.
- **A denial costs two round trips and writes two audit rows.** On a first denial
  the PEP re-issues its token once and retries, because "the token expired" and
  "policy denied" arrive as the same wire shape. An allow costs one of each.
- **The decision cache is what buys outage tolerance** on `mcp`. It lives in
  the `mcp` process's memory for the life of that process; nothing is ever read
  from a cache file. An entry is used only if the epoch still matches, the
  delegation and token have not expired, and it is inside your staleness window.
  Everything else is a miss.
- **`hook` has no decision cache.** It asks the PDP on every call, so a PDP
  outage denies every hooked tool call immediately.
- **The PEP never logs a token or key material**, on any path.
- **A per-project hook install can be undone by the agent it governs.** The
  hook entry, the binary and the hook's environment all sit where the agent
  can write. `sudo -E deploy/stratium --claude install --system` (or
  `--codex`) puts them out of its reach; see
  [What the install protects](pep/hook.md#what-the-install-protects).
- **Uninstalling:** remove the hook from `.claude/settings.json` or
  `~/.codex/hooks.json`, restore the real MCP command, and delete the session
  file. A hook left installed against a stopped PDP denies every tool call.

---

## 7. Troubleshooting

### Startup

| Symptom | Cause | Fix |
|---|---|---|
| `missing required configuration: A, B, C` | required variables unset | set all named — the list is complete, you will not discover more |
| PDP: `serving identity holds membership in stratium_audit_owner` | the serving role has DDL rights over `audit_chain` | use a role that is a member of `stratium_app` only |
| PDP: `stratium_audit_owner role does not exist` | migration `000004` was never applied | apply migrations (set `STRATIUM_MIGRATION_DATABASE_URL`) |
| PDP: `STRATIUM_POLICY_LANGUAGES: …` | a name matching no engine, or a stray comma | use a subset of `cedar,json,rego,xacml` |
| PDP: `STRATIUM_TLS_CERT_FILE and STRATIUM_TLS_KEY_FILE are required …` | no certificate configured | set both, or `STRATIUM_GRPC_INSECURE=true` for local development only |
| PDP: `missing principal authentication settings: …` | the issuer, audience, or claim for principal verification is unset | set `STRATIUM_PRINCIPAL_OIDC_ISSUER`, `STRATIUM_PRINCIPAL_OIDC_AUDIENCE`, and `STRATIUM_PRINCIPAL_CLAIM`, or `STRATIUM_PRINCIPAL_AUTH_INSECURE=true` for local development only |
| PDP: `must be positive, got 0s` | a zero or negative duration | every duration must be > 0 |
| PDP: `pattern dist: no matching files found` | you ran `go build` for the PAP without the UI | `make ui`, then use `make` |
| PAP: `discover OIDC provider …` | issuer wrong or unreachable | `curl $ISSUER/.well-known/openid-configuration` |
| PAP: `group "x" is mapped to both …` | one group in two role lists | pick one |

### Runtime

| Symptom | Cause |
|---|---|
| Every tool call denied, reason names a variable | PEP misconfigured, failing closed. Correct behaviour. |
| Every tool call denied, no session file | run `session-start` |
| `none of the requested tools are held by this principal` | no policy grants your `STRATIUM_PEP_SUBJECT` (§6.2 step 2), or the subject does not match |
| `granted_scope.tools` empty | same |
| `ls -la` rates `INTERNAL_MODIFY` | the tool catalog is not seeded — `Bash` has no `command_field` (§6.2 step 3) |
| `Glob`/`Grep` deny under a cap | fieldless tools cannot be labelled and deny outright under any cap (§5.6) |
| A cap seems to deny everything | no empty-prefix catch-all label rule (§5.7) |
| A cap seems to do nothing | the agent's caps are empty, or the acting delegation predates the change — caps apply at next issuance, so revoke and re-issue (§5.7) |
| A tier override is ignored | it failed read-time re-validation and was dropped; check the PDP's logs for the key |
| Policy change had no effect | the policy is `enabled: false`, or its `language` is not in this PDP's `STRATIUM_POLICY_LANGUAGES` |
| `409` deleting an agent | a live delegation or approval still names it — suspend instead |
| `403` approving as an admin | your approver identity is not the approval's `root_principal` (§4.4) |
| Duplicate audit rows for one denial | expected — the re-issue retry (§6.5) |
| Everything broke after `docker compose up` | the ports changed; re-read them (§2.2) |

### Where to look next

| Question | Document |
|---|---|
| How does the decision actually work? | [`docs/architecture.md`](architecture.md) |
| Everything about the enforcement surfaces | [`docs/pep.md`](pep.md) |
| A step-by-step run with verified output | [`docs/testing/2026-08-19-resource-labelling-manual-test.md`](testing/2026-08-19-resource-labelling-manual-test.md) |
| Wiring a real agent (Claude Code, Codex, MCP, Envoy) | [`docs/testing/2026-08-20-agent-integration-test.md`](testing/2026-08-20-agent-integration-test.md) |
| The design of record | `docs/superpowers/specs/2026-08-08-agent-authorization-redesign-design.md` |
