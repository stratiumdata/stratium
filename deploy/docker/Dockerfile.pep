# syntax=docker/dockerfile:1

# Builds stratium-pep for the Task 4 real-Envoy proof: a container running
# `stratium-pep extauthz`, the ext_authz service Envoy's own compose service
# points at (see docker-compose.yml's pep-extauthz and envoy.yaml). A
# separate Dockerfile from this directory's own Dockerfile (which builds
# stratium-pdp), not a shared one parameterized by build target: the two
# binaries need genuinely different runtime inputs, not just a different
# entrypoint. stratium-pdp needs an ES256 signing key generated into the
# image (that Dockerfile's own comment on STRATIUM_TOKEN_SIGNING_KEY_PATH);
# stratium-pep's extauthz mode reads no key at all -- it forwards whatever
# token arrives on the request Envoy is fronting (extauthz.go's own package
# doc, "NO SESSION FILE") -- so folding the two into one parameterized file
# would carry pdp-only steps (openssl, key generation) into an image that
# has no use for either.
FROM golang:1.26-alpine AS builder

WORKDIR /src/services
COPY services/go.mod services/go.sum ./
RUN go mod download

COPY services/ ./

# CGO_ENABLED=0: same reasoning as this directory's own Dockerfile -- every
# dependency here is pure Go, so distroless "static" below needs no libc.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/stratium-pep ./cmd/stratium-pep

# Distroless, not golang:alpine -- same reasoning as this directory's own
# Dockerfile: nothing to build or fetch with, no shell to get a foothold in,
# running as the pre-created nonroot uid/gid by default.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/stratium-pep /stratium-pep

USER nonroot:nonroot
ENTRYPOINT ["/stratium-pep"]
