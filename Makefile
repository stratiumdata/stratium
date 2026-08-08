.DEFAULT_GOAL := help
GO_DIR := services

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

conformance: ## Run the authorization conformance suite (spec §7)
	cd $(GO_DIR) && go test ./internal/authz/ -run "TestC[0-9]" -v

.PHONY: help build test vet fmt lint conformance
