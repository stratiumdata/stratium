# Multi-stage build for Stratium gRPC services
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go/go.mod go/go.sum ./go/

# Download dependencies
WORKDIR /app/go
RUN go mod download

# Copy the entire project
WORKDIR /app
COPY . .

# Build arguments to specify which service to build
ARG SERVICE_NAME
ARG SERVICE_PORT

# Build arguments for feature flags (passed via ldflags)
ARG BUILD_MODE=production
ARG BUILD_FEATURES=""
ARG BUILD_VERSION=dev
ARG BUILD_TIME

# Set build time if not provided
RUN if [ -z "$BUILD_TIME" ]; then BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ"); fi

# Build the specified service with ldflags for feature flag injection
WORKDIR /app/go
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags="-w -s \
    -X 'stratium/features.BuildMode=${BUILD_MODE}' \
    -X 'stratium/features.BuildFeatures=${BUILD_FEATURES}' \
    -X 'stratium/features.BuildVersion=${BUILD_VERSION}' \
    -X 'stratium/features.BuildTime=$(date -u +"%Y-%m-%dT%H:%M:%SZ")'" \
    -o /app/bin/${SERVICE_NAME} \
    ./cmd/${SERVICE_NAME}

# Final stage - minimal runtime image
# FROM cgr.dev/chainguard/wolfi-base:latest
FROM golang:1.25-alpine

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates netcat-openbsd

# Create non-root user
RUN addgroup -g 1000 stratium && \
    adduser -D -u 1000 -G stratium stratium

WORKDIR /home/stratium

# Copy the binary from builder
ARG SERVICE_NAME
COPY --from=builder /app/bin/${SERVICE_NAME} /usr/local/bin/server

# Change ownership
RUN chown -R stratium:stratium /home/stratium

# Switch to non-root user
USER stratium

# Set default port (can be overridden)
ARG SERVICE_PORT
ENV PORT=${SERVICE_PORT}

# Expose the service port
EXPOSE ${PORT}

# Run the service
CMD ["server"]
