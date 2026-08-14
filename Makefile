.DEFAULT_GOAL := help
GO_DIR := services
PROTO_DIR := proto
COMPOSE := docker compose -f deploy/docker/docker-compose.yml

help: ## Show available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build all binaries
	cd $(GO_DIR) && go build ./...

test: ## Run tests with the race detector
	cd $(GO_DIR) && go test -race ./...

vet: ## Run go vet
	cd $(GO_DIR) && go vet ./...

fmt: ## Format Go code
	cd $(GO_DIR) && go fmt ./...

lint: ## Lint (requires golangci-lint)
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found: https://golangci-lint.run/welcome/install/"; exit 1; }
	cd $(GO_DIR) && golangci-lint run ./...

proto: ## Generate Go code from proto/ (requires protoc, protoc-gen-go, protoc-gen-go-grpc)
	@command -v protoc >/dev/null 2>&1 || { \
		echo "protoc not found: https://protobuf.dev/installation/"; exit 1; }
	@command -v protoc-gen-go >/dev/null 2>&1 || { \
		echo "protoc-gen-go not found: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; exit 1; }
	@command -v protoc-gen-go-grpc >/dev/null 2>&1 || { \
		echo "protoc-gen-go-grpc not found: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"; exit 1; }
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GO_DIR) --go_opt=module=stratium \
		--go-grpc_out=$(GO_DIR) --go-grpc_opt=module=stratium \
		$(PROTO_DIR)/pdp/v1/pdp.proto \
		$(PROTO_DIR)/target/v1/target.proto

CONFORMANCE_PROPERTIES := 25

conformance: ## Run the authorization conformance suite (spec §7)
	@# The count assertion lives HERE, not in Go. A completeness test inside
	@# conformance_test.go cannot detect that file being deleted — it goes with it,
	@# `go test -run` then matches nothing, and the job exits 0. Verified.
	@out=$$(cd $(GO_DIR) && go test ./internal/authz/ -run "TestC[0-9]|TestConformanceSuiteIsComplete" -v 2>&1); \
	echo "$$out"; \
	ran=$$(echo "$$out" | grep -cE "^=== RUN   TestC[0-9]+_[^/]*$$" || true); \
	if [ "$$ran" -ne $(CONFORMANCE_PROPERTIES) ]; then \
		echo "CONFORMANCE GATE FAILED: expected $(CONFORMANCE_PROPERTIES) properties, $$ran ran."; \
		echo "A property was deleted or renamed, or the suite file is missing."; \
		exit 1; \
	fi; \
	echo "$$ran/$(CONFORMANCE_PROPERTIES) conformance properties executed."

integration: ## Run the end-to-end proof: fresh compose volumes -> integration tests -> torn down, always
	@command -v docker >/dev/null 2>&1 || { \
		echo "docker not found: https://docs.docker.com/get-docker/"; exit 1; }
	@$(COMPOSE) down -v --remove-orphans >/dev/null 2>&1 || true
	trap '$(COMPOSE) down -v --remove-orphans' EXIT; \
	set -e; \
	$(COMPOSE) up -d --build --wait --wait-timeout 120; \
	pg_port=$$($(COMPOSE) port postgres 5432 | sed -E 's/.*://'); \
	pdp_port=$$($(COMPOSE) port pdp 50051 | sed -E 's/.*://'); \
	pdp_narrow_port=$$($(COMPOSE) port pdp-narrow 50051 | sed -E 's/.*://'); \
	pdp_resource_port=$$($(COMPOSE) port pdp-resource 50051 | sed -E 's/.*://'); \
	pdp_extauthz_port=$$($(COMPOSE) port pdp-extauthz 50051 | sed -E 's/.*://'); \
	envoy_port=$$($(COMPOSE) port envoy 10000 | sed -E 's/.*://'); \
	pdp_proxy_port=$$($(COMPOSE) port pdp-proxy 50051 | sed -E 's/.*://'); \
	grpc_target_port=$$($(COMPOSE) port grpc-target 50051 | sed -E 's/.*://'); \
	pep_proxy_port=$$($(COMPOSE) port pep-proxy 9292 | sed -E 's/.*://'); \
	pdp_epoch_port=$$($(COMPOSE) port pdp-epoch 50051 | sed -E 's/.*://'); \
	pdp_cache_port=$$($(COMPOSE) port pdp-cache 50051 | sed -E 's/.*://'); \
	echo "postgres -> localhost:$$pg_port   pdp -> localhost:$$pdp_port   pdp-narrow -> localhost:$$pdp_narrow_port   pdp-resource -> localhost:$$pdp_resource_port   pdp-extauthz -> localhost:$$pdp_extauthz_port   envoy -> localhost:$$envoy_port   pdp-proxy -> localhost:$$pdp_proxy_port   grpc-target -> localhost:$$grpc_target_port   pep-proxy -> localhost:$$pep_proxy_port   pdp-epoch -> localhost:$$pdp_epoch_port   pdp-cache -> localhost:$$pdp_cache_port"; \
	STRATIUM_IT_DATABASE_URL="postgres://stratium_migrate:stratium_migrate_local_dev_only@localhost:$$pg_port/stratium?sslmode=disable" \
	STRATIUM_IT_SERVING_DATABASE_URL="postgres://stratium:stratium_local_dev_only@localhost:$$pg_port/stratium?sslmode=disable" \
	STRATIUM_IT_PDP_ADDR="localhost:$$pdp_port" \
	STRATIUM_IT_TENANT_ID="tenant-one" \
	STRATIUM_IT_PDP_NARROW_ADDR="localhost:$$pdp_narrow_port" \
	STRATIUM_IT_NARROW_TENANT_ID="tenant-narrow-registry-integration" \
	STRATIUM_IT_PDP_RESOURCE_ADDR="localhost:$$pdp_resource_port" \
	STRATIUM_IT_RESOURCE_TENANT_ID="tenant-resource-identity-integration" \
	STRATIUM_IT_PDP_EXTAUTHZ_ADDR="localhost:$$pdp_extauthz_port" \
	STRATIUM_IT_EXTAUTHZ_TENANT_ID="tenant-extauthz-integration" \
	STRATIUM_IT_ENVOY_ADDR="localhost:$$envoy_port" \
	STRATIUM_IT_PDP_PROXY_ADDR="localhost:$$pdp_proxy_port" \
	STRATIUM_IT_PROXY_TENANT_ID="tenant-proxy-integration" \
	STRATIUM_IT_PDP_EPOCH_ADDR="localhost:$$pdp_epoch_port" \
	STRATIUM_IT_EPOCH_TENANT_ID="tenant-epoch-e2e-integration" \
	STRATIUM_IT_PDP_CACHE_ADDR="localhost:$$pdp_cache_port" \
	STRATIUM_IT_CACHE_TENANT_ID="tenant-cache-integration" \
	STRATIUM_IT_GRPC_TARGET_ADDR="localhost:$$grpc_target_port" \
	STRATIUM_IT_PEP_PROXY_ADDR="localhost:$$pep_proxy_port" \
	go -C $(GO_DIR) test -tags=integration -race -v -count=1 ./internal/store/...

.PHONY: help build test vet fmt lint proto conformance integration
