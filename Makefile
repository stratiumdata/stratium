# Stratium Platform gRPC Services Makefile

.PHONY: help build test run-server run-client generate clean
.PHONY: build-platform test-platform run-platform-server run-platform-client build-license-signer generate-license-bundle
.PHONY: build-key-manager test-key-manager run-key-manager-server run-key-manager-client
.PHONY: build-key-access test-key-access run-key-access-server run-key-access-client
.PHONY: build-pap test-pap run-pap-server build-pap-cli install-pap-cli
.PHONY: docker-build docker-up docker-down docker-logs test-integration test-cedar test-agent-gateway test-ui test-ui-e2e test-ui-component
.PHONY: build-demo build-demo-platform build-demo-key-manager build-demo-key-access build-demo-pap
.PHONY: docker-demo-up docker-demo-down docker-demo-logs verify-demo test-features
.PHONY: build-customer build-customer-platform build-customer-key-manager build-customer-key-access build-customer-pap
.PHONY: docker-customer-up docker-customer-down docker-customer-logs verify-customer
.PHONY: push-customer push-customer-platform push-customer-key-manager push-customer-key-access push-customer-pap
.PHONY: setup-buildx build-customer-multiplatform build-customer-multiplatform-platform build-customer-multiplatform-key-manager build-customer-multiplatform-key-access build-customer-multiplatform-agent-gateway
.PHONY: build-postgres push-postgres fmt-all tests-unit tests-integration tests-e2e tests-all fips-validate build-all docker-build-images docker-push-images \
	docker-compose-up docker-compose-down docker-compose-logs helm-minikube helm-eks eks-create eks-delete aws-ecr-login

# Default target
help: ## Shows available Makefile commands with descriptions
	@echo "Stratium Platform Help"
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  - CUSTOMER_VERSION=eval-1.0.1 && make build-customer-multiplatform"
	@echo "  - CUSTOMER_FEATURES=full-logging,metrics && make build-customer-multiplatform"
	@echo "  - CUSTOMER_VERSION=eval-1.0.1 && CUSTOMER_FEATURES=full-logging,metrics && make build-customer-multiplatform"
	@echo "  - BUILD_MODE=demo && make build-customer-multiplatform"

PLATFORMS ?= linux/amd64,linux/arm64
DOCKER_HUB_ORG := stratiumdata
CUSTOMER_VERSION ?= eval-0.0.1
CUSTOMER_FEATURES := ## full-logging | metrics | observability | rate-limiting | caching | short-timeouts
BUILD_MODE := ## production | development | demo
BUILD_VERSION :=
DOCKER_REGISTRY ?= $(DOCKER_HUB_ORG)
DOCKER_VERSION ?= $(shell git rev-parse --short HEAD)
DEPLOY_ENV ?= production
COMPOSE_FILE ?= deployment/docker/docker-compose.yml
COMPOSE_PROJECT_NAME ?= $(notdir $(CURDIR))
COMPOSE_SERVICE_TAGS := platform:platform-server key-manager:key-manager-server key-access:key-access-server pap:pap-server pap-ui:pap-ui agent-gateway:agent-gateway-server
DOCKER_SERVICES := key-manager-server:50052 key-access-server:50053 pap-server:8090
AWS_REGION ?= us-east-2
AWS_ACCOUNT_ID ?= 
PUSH_TO_ECR ?= true
HELM_RELEASE ?= stratium
HELM_NAMESPACE ?= stratium
export COMPOSE_PROJECT_NAME

FIPS ?= 1
GOFIPS140 ?= v1.0.0
ifeq ($(FIPS),1)
GO_BUILD_ENV := GOFIPS140=$(GOFIPS140)
GO_BUILD_TAGS := -tags fips
GO_BUILD_TAGS_RAW := fips
else
GO_BUILD_ENV :=
GO_BUILD_TAGS :=
GO_BUILD_TAGS_RAW :=
endif

build: build-platform build-key-manager build-key-access build-pap build-agent-gateway build-mcp build-audit ## Build all binaries

build-platform: ## Build platform service binaries
	@echo "Building platform server..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/platform-server ./cmd/platform-server
	@echo "Building platform client..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/platform-client ./cmd/platform-client
	@echo "Platform build complete!"

build-key-manager: ## Build key manager service binaries
	@echo "Building key manager server..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/key-manager-server ./cmd/key-manager-server
	@echo "Building key manager client..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/key-manager-client ./cmd/key-manager-client
	@echo "Key manager build complete!"

build-key-access: ## Build key access service binaries
	@echo "Building key access server..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/key-access-server ./cmd/key-access-server
	@echo "Building key access client..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/key-access-client ./cmd/key-access-client
	@echo "Key access build complete!"

build-pap: ## Build PAP service binary
	@echo "Building PAP server..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/pap-server ./cmd/pap-server
	@echo "PAP build complete!"

build-pap-cli: ## Build PAP CLI client
	@echo "Building PAP CLI client..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/pap-cli ./cmd/pap-cli
	@echo "PAP CLI build complete!"

build-agent-gateway: ## Build agent gateway service binary
	@echo "Building agent gateway server..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) \
		-ldflags "-X stratium/features.BuildFeatures=agent-auth" \
		-o ../bin/agent-gateway-server ./cmd/agent-gateway-server
	@echo "Agent gateway build complete!"

build-mcp: ## Build Stratium MCP server for Claude Code integration
	@echo "Building stratium-mcp server..."
	cd go && go build -o ../bin/stratium-mcp ./cmd/stratium-mcp
	@echo "stratium-mcp build complete!"

build-audit: ## Build Stratium audit CLI for admin audit trail access
	@echo "Building stratium-audit CLI..."
	cd go && go build -o ../bin/stratium-audit ./cmd/stratium-audit
	@echo "stratium-audit build complete!"

seed-demo: ## Seed demo data for MCP agent auth demo
	@./demos/mcp/seed-demo-data.sh

build-license-signer: ## Build license signer CLI
	@echo "Building license signer CLI..."
	cd go && $(GO_BUILD_ENV) go build $(GO_BUILD_TAGS) -o ../bin/license-signer ./cmd/license-signer
	@echo "License signer CLI build complete!"

generate-license-bundle: build-license-signer ## Generate a customer license bundle (uses scripts/generate-license-bundle.sh)
	@./scripts/generate-license-bundle.sh

install-pap-cli: build-pap-cli ## Install PAP CLI to system PATH
	@echo "Installing PAP CLI to /usr/local/bin..."
	@sudo cp bin/pap-cli /usr/local/bin/
	@sudo chmod +x /usr/local/bin/pap-cli
	@echo "PAP CLI installed successfully!"
	@echo "You can now run 'pap-cli' from anywhere."

tests-all: tests-unit tests-integration tests-e2e ## Run unit, integration, and e2e tests

tests-unit: ## Run unit tests (short mode)
	@echo "Running unit tests..."
	cd go && go test -short ./...

test-platform: ## Run platform service tests
	@echo "Running platform service tests..."
	cd go && go test -v ./services/platform

test-key-manager: ## Run key manager service tests
	@echo "Running key manager service tests..."
	cd go && go test -v ./services/key-manager

test-key-access: ## Run key access service tests
	@echo "Running key access service tests..."
	cd go && go test -v ./services/key-access

test-pap: ## Run PAP service tests
	@echo "Running PAP service tests..."
	cd go && go test -v ./services/pap ./pkg/...

test-cedar: ## Run Cedar policy engine tests
	@echo "Running Cedar policy engine tests..."
	cd go && go test -v ./pkg/cedar ./pkg/policy_engine -run Cedar

test-agent-gateway: ## Run agent gateway tests
	@echo "Running agent gateway tests..."
	cd go && go test -v ./services/agent-gateway/...

tests-integration: ## Run integration tests for services and SDK
	@echo "Running integration tests..."
	cd go && go test ./services/...
	cd sdk/go && go test ./...

test-ui: test-ui-component test-ui-e2e ## Run all PAP UI Cypress tests

test-ui-e2e: ## Run PAP UI E2E tests (requires running services + dev server)
	@echo "Running PAP UI E2E tests..."
	cd pap-ui && npx cypress run --e2e

test-ui-component: ## Run PAP UI component tests
	@echo "Running PAP UI component tests..."
	cd pap-ui && npx cypress run --component

tests-e2e: test-platform-pdp test-pap-auth ## Run end-to-end shell-based tests

test-platform-pdp: ## Run PDP integration tests
	@echo "Running platform PDP integration test..."
	./scripts/test_platform_pdp.sh

test-pap-auth: ## Run PAP authentication tests
	@echo "Running PAP authentication test..."
	./scripts/test_pap_auth.sh

fips-validate: ## Validate runtime FIPS crypto modules (STRICT=1 to fail on skips)
	@echo "Validating FIPS runtime crypto modules..."
	@STRICT=$(STRICT) GO_BIN_PATH=$(GO_BIN_PATH) \
	PYTHON_BIN=$(PYTHON_BIN) OPENSSL_CONF=$(OPENSSL_CONF) OPENSSL_MODULES=$(OPENSSL_MODULES) OPENSSL_BIN=$(OPENSSL_BIN) \
	JAVA_SECURITY_PROPERTIES=$(JAVA_SECURITY_PROPERTIES) JAVA_FIPS_CLASSPATH=$(JAVA_FIPS_CLASSPATH) \
	./scripts/validate_fips_runtime.sh

docker-migrate: ## Apply database migrations (safe to re-run)
	@echo "Applying database migrations..."
	docker exec -i stratium-postgres psql -U keycloak -d stratium_pap < deployment/postgres/04-init-agent-auth.sql
	@echo "Applying Cedar policy tables migration..."
	docker exec -i stratium-postgres psql -U keycloak -d stratium_pap < go/migrations/001_cedar_tables.sql
	@echo "Migrations applied!"

full: generate build docker-down docker-build docker-up docker-migrate ## Rebuilds artifacts, docker images, and runs migrations
	@echo ""
	@echo "✓ Rebuild complete!"
	@echo ""
	@echo "You can now test the system:"
	@echo "  ./scripts/test_agent_auth.sh"

bench: ## Run all benchmarks
	@echo "Running platform benchmarks..."
	cd go && go test -bench=. ./services/platform
	@echo "Running key manager benchmarks..."
	cd go && go test -bench=. ./services/key-manager
	@echo "Running Cedar policy engine benchmarks..."
	cd go && go test -bench=. -benchmem ./pkg/cedar

# Docker commands
docker-build: ## Build all Docker images (production)
	@set -eu; \
	for entry in $(DOCKER_SERVICES); do \
		svc=$${entry%%:*}; port=$${entry##*:}; \
		printf 'Building %s image (port %s)...\n' "$$svc" "$$port"; \
		docker build \
			--build-arg SERVICE_NAME=$$svc \
			--build-arg SERVICE_PORT=$$port \
			--build-arg BUILD_MODE=$(DEPLOY_ENV) \
			--build-arg BUILD_VERSION=$(DOCKER_VERSION) \
			--build-arg GOFIPS140=$(GOFIPS140) \
			--build-arg BUILD_TAGS=$(GO_BUILD_TAGS_RAW) \
			-f deployment/docker/Dockerfile \
			-t $(DOCKER_REGISTRY)/$$svc:$(DOCKER_VERSION) \
			-t local/$$svc:latest \
			.; \
	done; \
	echo "Building platform-server image with agent-auth feature..."; \
	docker build \
		--build-arg SERVICE_NAME=platform-server \
		--build-arg SERVICE_PORT=50051 \
		--build-arg BUILD_MODE=$(DEPLOY_ENV) \
		--build-arg BUILD_VERSION=$(DOCKER_VERSION) \
		--build-arg GOFIPS140=$(GOFIPS140) \
		--build-arg BUILD_TAGS=$(GO_BUILD_TAGS_RAW) \
		--build-arg BUILD_FEATURES=metrics,observability,caching,rate-limiting,agent-auth \
		-f deployment/docker/Dockerfile \
		-t $(DOCKER_REGISTRY)/platform-server:$(DOCKER_VERSION) \
		-t local/platform-server:latest \
		.; \
	echo "Building pap-server image with agent-auth feature..."; \
	docker build \
		--build-arg GOFIPS140=$(GOFIPS140) \
		--build-arg BUILD_TAGS=$(GO_BUILD_TAGS_RAW) \
		--build-arg BUILD_FEATURES=agent-auth \
		-f deployment/docker/Dockerfile.pap \
		-t $(DOCKER_REGISTRY)/pap-server:$(DOCKER_VERSION) \
		-t local/pap-server:latest \
		.; \
	echo "Building agent-gateway-server image..."; \
	docker build \
		--build-arg SERVICE_NAME=agent-gateway-server \
		--build-arg GOFIPS140=$(GOFIPS140) \
		--build-arg BUILD_TAGS=$(GO_BUILD_TAGS_RAW) \
		--build-arg BUILD_FEATURES=agent-auth \
		-f deployment/docker/Dockerfile \
		-t $(DOCKER_REGISTRY)/agent-gateway-server:$(DOCKER_VERSION) \
		-t local/agent-gateway-server:latest \
		.; \
	echo "Building pap-ui image..."; \
	docker build \
		-f pap-ui/Dockerfile \
		-t $(DOCKER_REGISTRY)/pap-ui:$(DOCKER_VERSION) \
		-t local/pap-ui:latest \
		pap-ui

docker-push: ## Push Docker images to registry/ECR
	@set -eu; \
	REGISTRY=$(DOCKER_REGISTRY); \
	REPO_PREFIX=stratiumdata-; \
	if [ "$(PUSH_TO_ECR)" = "true" ]; then \
		REGISTRY=$$(AWS_REGION=$(AWS_REGION) AWS_ACCOUNT_ID=$(AWS_ACCOUNT_ID) ./deployment/aws/ecr/ecr_login.sh); \
		echo \"Publishing images to $$REGISTRY\"; \
	else \
		echo \"Publishing images to $(DOCKER_REGISTRY)\"; \
	fi; \
	for entry in $(DOCKER_SERVICES); do \
		svc=$${entry%%:*}; \
		repo_name=$${REPO_PREFIX}$$svc; \
		if [ "$(PUSH_TO_ECR)" = "true" ]; then \
			if ! aws ecr describe-repositories --region $(AWS_REGION) --repository-name $$repo_name >/dev/null 2>&1; then \
				echo \"Creating ECR repository $$repo_name\"; \
				aws ecr create-repository --region $(AWS_REGION) --repository-name $$repo_name >/dev/null; \
			fi; \
		fi; \
		docker tag $(DOCKER_REGISTRY)/$$svc:$(DOCKER_VERSION) $$REGISTRY/$$repo_name:$(DOCKER_VERSION); \
		docker push $$REGISTRY/$$repo_name:$(DOCKER_VERSION); \
	done; \
	for extra_svc in platform-server agent-gateway-server pap-ui; do \
		repo_name=$${REPO_PREFIX}$$extra_svc; \
		if [ "$(PUSH_TO_ECR)" = "true" ]; then \
			if ! aws ecr describe-repositories --region $(AWS_REGION) --repository-name $$repo_name >/dev/null 2>&1; then \
				echo "Creating ECR repository $$repo_name"; \
				aws ecr create-repository --region $(AWS_REGION) --repository-name $$repo_name >/dev/null; \
			fi; \
		fi; \
		docker tag $(DOCKER_REGISTRY)/$$extra_svc:$(DOCKER_VERSION) $$REGISTRY/$$repo_name:$(DOCKER_VERSION); \
		docker push $$REGISTRY/$$repo_name:$(DOCKER_VERSION); \
	done

docker-up: ## Start all services with Docker Compose (including agent-gateway)
	@echo "Starting all services with Docker Compose..."
	docker-compose -f deployment/docker/docker-compose.yml --profile agent-auth up -d
	@echo "Services started!"
	@echo ""
	@echo "Enabling HTTPS on Keycloak"
	docker exec stratium-keycloak /opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE --server http://localhost:8080 --realm master --user admin --password admin
	@echo ""
	@echo "Services available at:"
	@echo "  Platform:       localhost:50051 (gRPC)"
	@echo "  Key Manager:    localhost:50052 (gRPC)"
	@echo "  Key Access:     localhost:50053 (gRPC)"
	@echo "  Agent Gateway:  localhost:50054 (gRPC)"
	@echo "  PAP API:        https://localhost:8090"
	@echo "  PAP UI:         http://localhost:3000"
	@echo "  Keycloak:       http://localhost:8080"
	@echo "  PostgreSQL:     localhost:5432"
	@echo "  Redis:          localhost:6379"
	@echo "  Prometheus:     http://localhost:9095"
	@echo "  Grafana:        http://localhost:3001"

docker-down: ## Stop all services
	@echo "Stopping all services..."
	docker-compose -f deployment/docker/docker-compose.yml --profile agent-auth down
	@echo "Services stopped!"

docker-down-volumes: ## Stop all services and remove volumes
	@echo "Stopping all services and removing volumes..."
	docker-compose -f deployment/docker/docker-compose.yml --profile agent-auth down -v
	@echo "Services stopped and volumes removed!"

docker-logs: ## View logs from all services
	docker-compose -f deployment/docker/docker-compose.yml logs -f

docker-ps: ## List all containers from the Stratium deployment
	docker-compose -f deployment/docker/docker-compose.yml ps

# Helm Deployment
helm-minikube: ## Install Stratium via Helm on Minikube
	helm upgrade --install $(HELM_RELEASE) deployment/helm/stratium \
		--namespace $(HELM_NAMESPACE) --create-namespace \
		-f deployment/helm/stratium/values-local.yaml \
		-f deployment/helm/stratium/values-local-ingress.yaml

	deployment/helm/setup-minikube-ingress.sh

# Multi-platform builds using buildx (for both ARM64 and AMD64)
build-customer-multiplatform: setup-buildx build-customer-multiplatform-platform build-customer-multiplatform-key-manager build-customer-multiplatform-key-access build-customer-multiplatform-agent-gateway ## Build and push all images for ARM64+AMD64
	@echo ""
	@echo "✓ All multi-platform customer images built and pushed!"
	@echo ""
	@echo "Images support both:"
	@echo "  - linux/amd64 (Windows, Linux x86_64)"
	@echo "  - linux/arm64 (Mac Apple Silicon, ARM servers)"

setup-buildx: ## Set up Docker Buildx for multi-platform
	@echo "Setting up Docker Buildx for multi-platform builds..."
	@docker buildx create --name multiplatform --use --bootstrap 2>/dev/null || docker buildx use multiplatform 2>/dev/null || echo "Buildx already configured"
	@docker buildx inspect --bootstrap
	@echo "✓ Buildx ready for multi-platform builds"

build-customer-multiplatform-platform: ## Build and push platform (ARM64+AMD64)
	@echo "Building multi-platform platform-server customer image..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg SERVICE_NAME=platform-server \
		--build-arg SERVICE_PORT=50051 \
		--build-arg BUILD_MODE=$(BUILD_MODE) \
		--build-arg BUILD_FEATURES=$(CUSTOMER_FEATURES) \
		--build-arg BUILD_VERSION=$(CUSTOMER_VERSION) \
		-t stratiumdata/platform:customer \
		-t stratiumdata/platform:eval \
		-t stratiumdata/platform:$(CUSTOMER_VERSION) \
		-f deployment/docker/Dockerfile \
		--push \
		.
	@echo "✓ Multi-platform platform-server customer image built and pushed"

build-customer-multiplatform-key-manager: ## Build and push key-manager (ARM64+AMD64)
	@echo "Building multi-platform key-manager-server customer image..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg SERVICE_NAME=key-manager-server \
		--build-arg SERVICE_PORT=50052 \
		--build-arg BUILD_MODE=$(BUILD_MODE) \
		--build-arg BUILD_FEATURES=$(CUSTOMER_FEATURES) \
		--build-arg BUILD_VERSION=$(CUSTOMER_VERSION) \
		-t stratiumdata/key-manager:customer \
		-t stratiumdata/key-manager:eval \
		-t stratiumdata/key-manager:$(CUSTOMER_VERSION) \
		-f deployment/docker/Dockerfile \
		--push \
		.
	@echo "✓ Multi-platform key-manager-server customer image built and pushed"

build-customer-multiplatform-key-access: ## Build and push key-access (ARM64+AMD64)
	@echo "Building multi-platform key-access-server customer image..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg SERVICE_NAME=key-access-server \
		--build-arg SERVICE_PORT=50053 \
		--build-arg BUILD_MODE=$(BUILD_MODE) \
		--build-arg BUILD_FEATURES=$(CUSTOMER_FEATURES) \
		--build-arg BUILD_VERSION=$(CUSTOMER_VERSION) \
		-t stratiumdata/key-access:customer \
		-t stratiumdata/key-access:eval \
		-t stratiumdata/key-access:$(CUSTOMER_VERSION) \
		-f deployment/docker/Dockerfile \
		--push \
		.
	@echo "✓ Multi-platform key-access-server customer image built and pushed"

build-customer-multiplatform-agent-gateway: ## Build and push agent-gateway (ARM64+AMD64)
	@echo "Building multi-platform agent-gateway-server customer image..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg SERVICE_NAME=agent-gateway-server \
		--build-arg SERVICE_PORT=50054 \
		--build-arg BUILD_MODE=$(BUILD_MODE) \
		--build-arg BUILD_FEATURES=agent-auth \
		--build-arg BUILD_VERSION=$(CUSTOMER_VERSION) \
		-t stratiumdata/agent-gateway:customer \
		-t stratiumdata/agent-gateway:eval \
		-t stratiumdata/agent-gateway:$(CUSTOMER_VERSION) \
		-f deployment/docker/Dockerfile \
		--push \
		.
	@echo "✓ Multi-platform agent-gateway-server customer image built and pushed"

# Quick start
quickstart: docker-down docker-build docker-up ## Rebuilds and restarts docker containers
	@echo ""
	@echo "✓ Quickstart complete!"
	@echo ""
	@echo "Waiting for services to be healthy..."
	@sleep 10
	@echo ""
	@echo "You can now test the system:"
	@echo "  make test-platform-pdp"
	@echo "  make test-pap-auth"

# Development helpers
mod-tidy: ## Tidy up Go dependencies
	@echo "Tidying dependencies..."
	cd go && go mod tidy
	@echo "Dependencies tidied!"

mod-download: ## Download Go dependencies
	@echo "Downloading dependencies..."
	cd go && go mod download
	@echo "Dependencies downloaded!"

fmt: ## Format Go code files
	@echo "Formatting code..."
	cd go && go fmt ./...
	@echo "Code formatted!"

vet: ## Vets all Go code
	@echo "Running go vet..."
	cd go && go vet ./...
	@echo "Vet complete!"

generate: ## Generate all protobuf code
	@echo "Generating platform protobuf code..."
	protoc --go_out=go --go_opt=module=stratium \
	       --go-grpc_out=go --go-grpc_opt=module=stratium \
	       proto/services/platform/platform.proto
	@echo "Generating key manager protobuf code..."
	protoc --go_out=go --go_opt=module=stratium \
	       --go-grpc_out=go --go-grpc_opt=module=stratium \
	       proto/services/key-manager/key-manager.proto
	@echo "Generating key access protobuf code..."
	protoc -I. -I./proto/services/key-manager \
		   --go_out=go --go_opt=module=stratium \
	       --go-grpc_out=go --go-grpc_opt=module=stratium \
	       proto/services/key-access/key-access.proto
	@echo "Generating agent gateway protobuf code..."
	protoc --go_out=go --go_opt=module=stratium \
	       --go-grpc_out=go --go-grpc_opt=module=stratium \
	       proto/services/agent-gateway/agent-gateway.proto
	@echo "Generating ZTDF protobuf models..."
	protoc --go_out=go/pkg --go_opt=module=stratium \
           --go-grpc_out=go/pkg --go-grpc_opt=module=stratium \
           proto/models/ztdf.proto
	@echo "Generating STANAG4774 protobuf models..."
	protoc --go_out=go/pkg --go_opt=module=stratium \
           --go-grpc_out=go/pkg --go-grpc_opt=module=stratium \
           proto/models/stanag4774.proto
	@echo "Code generation complete!"

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f go/cmd/platform-server/platform-server
	rm -f go/cmd/platform-client/platform-client
	rm -f go/cmd/key-manager-server/key-manager-server
	rm -f go/cmd/key-manager-client/key-manager-client
	rm -f go/cmd/key-access-server/key-access-server
	rm -f go/cmd/key-access-client/key-access-client
	rm -f go/cmd/pap-server/pap-server
	rm -f go/cmd/pap-cli/pap-cli
	rm -f go/cmd/agent-gateway-server/agent-gateway-server
	@echo "Clean complete!"
