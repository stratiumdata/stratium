# syntax=docker/dockerfile:1

# Builder: compiles a static stratium-pdp binary. Needs the full Go
# toolchain, so nothing from this stage ships — only /out/stratium-pdp is
# copied into the runtime stage below.
FROM golang:1.25-alpine AS builder

WORKDIR /src/services
COPY services/go.mod services/go.sum ./
RUN go mod download

COPY services/ ./

# CGO_ENABLED=0: every dependency here (lib/pq, grpc, golang-migrate) is
# pure Go, so the binary needs no libc at all — that's what lets the runtime
# stage below be distroless "static" instead of needing glibc or musl.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/stratium-pdp ./cmd/stratium-pdp

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
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/stratium-pdp /stratium-pdp

USER nonroot:nonroot
ENTRYPOINT ["/stratium-pdp"]
