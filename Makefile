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
		$(PROTO_DIR)/pdp/v1/pdp.proto

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
	echo "postgres -> localhost:$$pg_port   pdp -> localhost:$$pdp_port"; \
	STRATIUM_IT_DATABASE_URL="postgres://stratium_migrate:stratium_migrate_local_dev_only@localhost:$$pg_port/stratium?sslmode=disable" \
	STRATIUM_IT_PDP_ADDR="localhost:$$pdp_port" \
	STRATIUM_IT_TENANT_ID="tenant-one" \
	go -C $(GO_DIR) test -tags=integration -race -v -count=1 ./internal/store/...

.PHONY: help build test vet fmt lint proto conformance integration
