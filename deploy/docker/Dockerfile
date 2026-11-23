# syntax=docker/dockerfile:1

# Builder: compiles a static stratium-pdp binary. Needs the full Go
# toolchain, so nothing from this stage ships — only /out/stratium-pdp is
# copied into the runtime stage below.
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

WORKDIR /src/services
COPY services/go.mod services/go.sum ./
RUN go mod download

COPY services/ ./

# CGO_ENABLED=0: every dependency here (lib/pq, grpc, golang-migrate) is
# pure Go, so the binary needs no libc at all — that's what lets the runtime
# stage below be distroless "static" instead of needing glibc or musl.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/stratium-pdp ./cmd/stratium-pdp

# A throwaway ES256 (P-256) signing key for STRATIUM_TOKEN_SIGNING_KEY_PATH,
# generated fresh on every image build, here, not committed to the repo —
# main.go now calls internal/token.Load at startup (Phase 9 Task 2), so a
# real, readable EC key is required or the container fails to start. openssl
# runs only in this builder stage, which ships nothing (see the runtime
# stage's own comment on why it is distroless static): the key file is the
# only thing COPY'd forward below, never the tool that made it. Regenerated
# on every build, with no persistence between builds or containers — this is
# `make integration`'s own key, not a production secret; a real deployment's
# key comes from an operator-mounted file, per K1, never from a Dockerfile.
RUN apk add --no-cache openssl && \
    mkdir -p /out/keys && \
    openssl ecparam -name prime256v1 -genkey -noout -out /out/keys/current.pem && \
    chmod 0400 /out/keys/current.pem

# Runtime: distroless, not golang:alpine. The predecessor shipped a full Go
# toolchain — plus a shell and a package manager — as its production
# runtime, and that was flagged in review. This image has none of that:
# nothing to build with, nothing to fetch with, no shell to get a foothold
# in. Just the binary and its CA certs.
#
# "nonroot" is the distroless variant with a pre-created, unprivileged
# uid/gid 65532 baked in — running as non-root is what this image does by
# default, not a step the Dockerfile has to remember. USER is set
# explicitly below anyway so it isn't left implicit.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

COPY --from=builder /out/stratium-pdp /stratium-pdp
# --chown, deliberately with no --chmod alongside it: --chmod on a COPY
# whose destination directory does not exist yet applies to the
# IMPLICITLY CREATED parent directories too, not just the file — stripping
# their own execute (traverse) bit left /etc/stratium/keys/ unreadable to
# its own owner, "permission denied" opening a file that was itself
# correctly mode 0400, found by actually starting this container rather
# than trusting the Dockerfile read correctly. Mode 0400 is instead set on
# the file alone, in the builder stage above (chmod 0400, right after
# openssl writes it) — chown here only changes ownership to nonroot, so the
# implicitly created /etc/stratium/ and /etc/stratium/keys/ keep Docker's
# ordinary default directory mode (traversable), and only the key file
# itself is owner-read-only.
COPY --from=builder --chown=nonroot:nonroot /out/keys/current.pem /etc/stratium/keys/current.pem

USER nonroot:nonroot
ENTRYPOINT ["/stratium-pdp"]
