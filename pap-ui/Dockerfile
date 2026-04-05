# Build stage
FROM --platform=$BUILDPLATFORM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application (use .env.docker by default)
ARG VITE_MODE=docker
RUN npm run build -- --mode ${VITE_MODE}

# Production stage
FROM nginx:alpine

# Copy built files from builder stage
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx template (envsubst will render it at startup)
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Expose port 8080
EXPOSE 8080

# Default PAP API URL (protocol + host)
ENV PAP_API_URL=https://pap:8090
# Only substitute PAP_API_URL — leave nginx variables ($host, $remote_addr, etc.) untouched
ENV NGINX_ENVSUBST_FILTER=PAP_API_URL

# Health check (using curl which is available in nginx:alpine)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
