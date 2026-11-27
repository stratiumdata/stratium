# Hosted demo

One tenant of Stratium on a single host, reachable on port 443: Postgres, one
PDP, one `stratium-pap` (the admin UI is embedded in it), Keycloak, and Caddy
in front holding the certificate. It is separate from `../docker/`, which is
the test stack with committed development credentials; nothing here changes
that one.

Every visitor shares the one tenant and the one `demo` login (editor role).
Treat the host as disposable: it holds no real data and is rebuilt from
scratch by a reset.

## The host

`terraform/` creates one that meets everything below on AWS: `terraform init
&& terraform apply` there, then point the hostname's A record at the
`public_ip` output and connect with the `connect` output.

- Inbound: 443 and 80 only (80 redirects and answers the certificate
  challenge). No SSH; use AWS Systems Manager Session Manager.
- Outbound: 443 (image pulls, certificate issuance) and DNS.
- Instance role: Session Manager and nothing else.
- Instance metadata: IMDSv2 required, hop limit 1, so a container cannot read
  the instance's credentials.
- A DNS record for the demo's hostname pointing at the instance, in place
  before the first start. Caddy needs it to obtain the certificate.
- Docker with the compose plugin. About 4 GB of memory.

## Bring it up

    git clone https://github.com/stratiumdata/stratium && cd stratium
    docker run --rm -v "$PWD":/src -w /src node:22 make ui   # the admin UI, without Node on the host
    cd deploy/demo
    ./setup.sh demo.example.com        # writes .env and secrets/signing.pem
    docker compose up -d --build --wait
    ./smoke-test.sh --live

`setup.sh` generates every password. The two a person needs are in `.env`:
`DEMO_USER_PASSWORD` (shared, meant to be published) and
`DEMO_ADMIN_PASSWORD` (yours).

## Reset

    docker compose down -v && docker compose up -d --wait

This drops every policy, agent and session, and re-imports the realm. Keep
`.env`: the new database is initialised with the same passwords. If the first
start fails partway through database initialisation, reset before retrying;
Postgres does not re-run its initialisation against an existing volume.

## What is and is not exposed

| Path | Goes to |
|---|---|
| gRPC (`Content-Type: application/grpc`) | the PDP |
| `/realms/stratium/*`, `/resources/*` | Keycloak sign-in |
| `/realms/stratium/account*` | not routed: a visitor must not change the shared password |
| everything else | the admin plane |

Keycloak's admin console and master realm are not routed, and no Keycloak
administrator account exists. Postgres publishes no port.

## Testing a change locally

    mkdir -p secrets/local && cd secrets/local
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout ca.key -out ca.pem -subj "/CN=stratium demo local test" -days 30
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout key.pem -out csr.pem -subj "/CN=demo.stratium.test"
    printf 'subjectAltName=DNS:demo.stratium.test\n' > ext
    openssl x509 -req -in csr.pem -CA ca.pem -CAkey ca.key -CAcreateserial \
      -out cert.pem -days 30 -extfile ext
    chmod 644 key.pem && cd ../..

    ./setup.sh demo.stratium.test
    docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build --wait
    ./smoke-test.sh
    docker compose -f docker-compose.yml -f docker-compose.local.yml down -v

The local stack listens on `127.0.0.1:443` and needs no hosts-file entry; the
smoke test tells curl where the name resolves.
