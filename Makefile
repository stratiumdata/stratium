.DEFAULT_GOAL := help
GO_DIR := services
PROTO_DIR := proto
UI_DIR := clients/ui
COMPOSE := docker compose -f deploy/docker/docker-compose.yml

# UI_DIST is where the admin UI is built TO -- inside the Go package that
# embeds it (services/cmd/stratium-pap/ui.go). //go:embed cannot name a path
# containing "..", so the build output has to land in the package directory;
# clients/ui/vite.config.ts sets outDir to exactly this.
#
# It is git-ignored (root .gitignore's bare `dist/`, which matches at any
# depth) and must stay that way. A committed dist would make the Go-side
# embed test pass forever regardless of whether the UI was ever rebuilt,
# which is the only thing that test exists to detect.
UI_DIST := $(GO_DIR)/cmd/stratium-pap/dist
UI_SRC := $(shell find $(UI_DIR)/src -type f 2>/dev/null) \
	$(UI_DIR)/index.html $(UI_DIR)/callback.html $(UI_DIR)/vite.config.ts $(UI_DIR)/package.json

help: ## Show available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# --- The admin UI (Phase 14 Task 6, N13) --------------------------------
#
# Every Go target below depends on `ui`, and that is not belt-and-braces: it
# is the whole answer to the build-order problem //go:embed creates. `go
# build`, `go vet`, `go test`, and golangci-lint ALL compile
# cmd/stratium-pap, and every one of them fails with
#
#     pattern dist: no matching files found
#
# on a clean checkout where the UI has never been built. Making the ordering
# a Make prerequisite puts it in one place, visible, rather than in a README
# nobody reads twice. CI calls these same targets so there is exactly one
# definition of it.
#
# The two file targets below make repeat runs cheap: npm ci re-runs only when
# package-lock.json changes, and the Vite build only when a UI source file
# does. A `make test` that rebuilt the UI unconditionally would be a tax on
# every Go test run.
$(UI_DIR)/node_modules: $(UI_DIR)/package-lock.json
	@command -v npm >/dev/null 2>&1 || { \
		echo "npm not found -- the admin UI is part of this build: https://nodejs.org/"; exit 1; }
	cd $(UI_DIR) && npm ci
	@touch $@

$(UI_DIST)/index.html: $(UI_DIR)/node_modules $(UI_SRC)
	cd $(UI_DIR) && npm run build

ui: $(UI_DIST)/index.html ## Build the admin UI into the PAP's embed directory

ui-test: $(UI_DIR)/node_modules ## Lint and test the admin UI
	cd $(UI_DIR) && npm run lint && npm run test

ui-clean: ## Remove the built admin UI
	rm -rf $(UI_DIST)

build: ui ## Build all binaries (builds the admin UI first -- see the `ui` target)
	cd $(GO_DIR) && go build ./...

test: ui ui-test ## Run Go tests with the race detector, plus the admin UI's lint and tests
	cd $(GO_DIR) && go test -race ./...

vet: ui ## Run go vet
	cd $(GO_DIR) && go vet ./...
	cd $(GO_DIR) && go vet -tags integration ./...

fmt: ## Format Go code
	cd $(GO_DIR) && go fmt ./...

lint: ui ## Lint (requires golangci-lint)
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
		--go_out=$(GO_DIR) --go_opt=module=github.com/stratiumdata/stratium \
		--go-grpc_out=$(GO_DIR) --go-grpc_opt=module=github.com/stratiumdata/stratium \
		$(PROTO_DIR)/pdp/v1/pdp.proto \
		$(PROTO_DIR)/target/v1/target.proto

PYTHON_PDP_DIR := sdk/python/stratium/_pdp

proto-python: ## Generate Python stubs into the SDK (requires grpcio-tools)
	@python3 -c 'import grpc_tools' 2>/dev/null || { \
		echo "grpcio-tools not found: pip install grpcio-tools"; exit 1; }
	python3 -m grpc_tools.protoc \
		--proto_path=$(PROTO_DIR) \
		--python_out=$(PYTHON_PDP_DIR) \
		--grpc_python_out=$(PYTHON_PDP_DIR) \
		$(PROTO_DIR)/pdp/v1/pdp.proto
	@# protoc nests output under pdp/v1/ (the proto's path relative to
	@# --proto_path, not its package). Flatten so the stubs live directly in
	@# _pdp/ and import as stratium._pdp.*, then remove the now-empty tree.
	@if [ -d $(PYTHON_PDP_DIR)/pdp/v1 ]; then \
		mv $(PYTHON_PDP_DIR)/pdp/v1/*.py $(PYTHON_PDP_DIR)/; \
		rm -rf $(PYTHON_PDP_DIR)/pdp; \
	fi
	@# grpc_tools emits `from pdp.v1 import ...`, which only resolves if the
	@# generated directory is on sys.path. Rewriting to a relative import keeps
	@# the stubs importable as stratium._pdp.* without touching sys.path.
	@python3 -c "import pathlib, re; p = pathlib.Path('$(PYTHON_PDP_DIR)'); [f.write_text(re.sub(r'^from pdp\.v1 import', 'from . import', f.read_text(), flags=re.M)) for f in p.glob('*_pb2*.py')]"

proto-python-check: proto-python ## Fail if the committed stubs are stale
	@git diff --quiet -- $(PYTHON_PDP_DIR) || { \
		echo "generated Python stubs are stale; run 'make proto-python' and commit"; \
		git diff --stat -- $(PYTHON_PDP_DIR); exit 1; }

CONFORMANCE_PROPERTIES := 25

conformance: ## Run the authorization conformance suite (spec §7)
	@# The count assertion lives HERE, not in Go. A completeness test inside
	@# conformance_test.go cannot detect that file being deleted — it goes with it,
	@# `go test -run` then matches nothing, and the job exits 0. Verified.
	@# go test's own exit status is captured and re-asserted below, and that
	@# is not belt-and-braces either. `out=$$(go test ...)` is an ASSIGNMENT:
	@# a failing go test leaves this recipe running, and the recipe's exit
	@# status is whatever its LAST command returns — the trailing echo, which
	@# always succeeds. Until Phase 14 Task 8 this target therefore exited 0
	@# on a conformance property that FAILED, and only ever failed on a
	@# miscount. Measured, not reasoned about: a pointed-to test was renamed,
	@# TestC5 fatalled on the stale pointer, and `make conformance; echo $$?`
	@# printed 0 while `make test` printed 2. The whole gate still caught it
	@# because `go test -race ./...` runs this package too — but the target
	@# NAMED conformance was not, on its own, the gate it looked like.
	@out=$$(cd $(GO_DIR) && go test ./internal/authz/ -run "TestC[0-9]|TestConformanceSuiteIsComplete" -v 2>&1); status=$$?; \
	echo "$$out"; \
	ran=$$(echo "$$out" | grep -cE "^=== RUN   TestC[0-9]+_[^/]*$$" || true); \
	if [ "$$ran" -ne $(CONFORMANCE_PROPERTIES) ]; then \
		echo "CONFORMANCE GATE FAILED: expected $(CONFORMANCE_PROPERTIES) properties, $$ran ran."; \
		echo "A property was deleted or renamed, or the suite file is missing."; \
		exit 1; \
	fi; \
	if [ "$$status" -ne 0 ]; then \
		echo "CONFORMANCE GATE FAILED: all $(CONFORMANCE_PROPERTIES) properties ran, but go test exited $$status."; \
		echo "A property failed its assertions, or a proven-elsewhere pointer named a test that no longer exists."; \
		exit 1; \
	fi; \
	echo "$$ran/$(CONFORMANCE_PROPERTIES) conformance properties executed."

# Named sdk-conformance, not conformance: that name is already the spec §7
# property gate above. This runs a different suite -- sdk/conformance/cases,
# shared with every Stratium SDK -- against cmd/stratium-pep's own
# cacheEntryUsable and resolveApproval, so a divergence between an SDK and
# the Go reference shows up here instead of only in whichever SDK's own test
# suite happens to run it.
sdk-conformance: ## Run the SDK conformance cases against the Go reference
	cd $(GO_DIR) && go test ./cmd/stratium-pep/ -run TestConformanceCases -v

integration: ui ## Run the end-to-end proof: fresh compose volumes -> integration tests -> torn down, always
	@command -v docker >/dev/null 2>&1 || { \
		echo "docker not found: https://docs.docker.com/get-docker/"; exit 1; }
	@$(COMPOSE) down -v --remove-orphans >/dev/null 2>&1 || true
	key_dir=$$(mktemp -d); \
	trap '$(COMPOSE) down -v --remove-orphans; rm -rf "$$key_dir"' EXIT; \
	set -e; \
	$(COMPOSE) up -d --build --wait --wait-timeout 300; \
	$(COMPOSE) cp pdp:/etc/stratium/keys/current.pem "$$key_dir/token-signing.pem" >/dev/null; \
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
	pdp_mcp_port=$$($(COMPOSE) port pdp-mcp 50051 | sed -E 's/.*://'); \
	pdp_pap_port=$$($(COMPOSE) port pdp-pap 50051 | sed -E 's/.*://'); \
	pap_port=$$($(COMPOSE) port stratium-pap 8080 | sed -E 's/.*://'); \
	pap_extauthz_port=$$($(COMPOSE) port pap-extauthz 8080 | sed -E 's/.*://'); \
	keycloak_port=$$($(COMPOSE) port keycloak 8080 | sed -E 's/.*://'); \
	echo "postgres -> localhost:$$pg_port  pdp -> localhost:$$pdp_port   pdp-narrow -> localhost:$$pdp_narrow_port   pdp-resource -> localhost:$$pdp_resource_port   pdp-extauthz -> localhost:$$pdp_extauthz_port   envoy -> localhost:$$envoy_port   pdp-proxy -> localhost:$$pdp_proxy_port   grpc-target -> localhost:$$grpc_target_port   pep-proxy -> localhost:$$pep_proxy_port   pdp-epoch -> localhost:$$pdp_epoch_port   pdp-cache -> localhost:$$pdp_cache_port   pdp-mcp -> localhost:$$pdp_mcp_port   pdp-pap -> localhost:$$pdp_pap_port   stratium-pap -> localhost:$$pap_port   pap-extauthz -> localhost:$$pap_extauthz_port   keycloak -> localhost:$$keycloak_port"; \
	STRATIUM_IT_DATABASE_URL="postgres://stratium_migrate:stratium_migrate_local_dev_only@localhost:$$pg_port/stratium?sslmode=disable" \
	STRATIUM_IT_SERVING_DATABASE_URL="postgres://stratium:stratium_local_dev_only@localhost:$$pg_port/stratium?sslmode=disable" \
	STRATIUM_IT_PAP_DATABASE_URL="postgres://stratium_pap_login:stratium_pap_login_local_dev_only@localhost:$$pg_port/stratium?sslmode=disable" \
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
	STRATIUM_IT_PDP_MCP_ADDR="localhost:$$pdp_mcp_port" \
	STRATIUM_IT_MCP_TENANT_ID="tenant-mcp-integration" \
	STRATIUM_IT_GRPC_TARGET_ADDR="localhost:$$grpc_target_port" \
	STRATIUM_IT_PEP_PROXY_ADDR="localhost:$$pep_proxy_port" \
	STRATIUM_IT_PDP_PAP_ADDR="localhost:$$pdp_pap_port" \
	STRATIUM_IT_PAP_TENANT_ID="tenant-pap-e2e-integration" \
	STRATIUM_IT_PAP_ADDR="localhost:$$pap_port" \
	STRATIUM_IT_PAP_EXTAUTHZ_ADDR="localhost:$$pap_extauthz_port" \
	STRATIUM_IT_KEYCLOAK_ADDR="localhost:$$keycloak_port" \
	STRATIUM_IT_TOKEN_SIGNING_KEY_PATH="$$key_dir/token-signing.pem" \
	go -C $(GO_DIR) test -tags=integration -race -v -count=1 ./internal/store/...

.PHONY: help build test vet fmt lint proto proto-python proto-python-check conformance sdk-conformance integration ui ui-test ui-clean
