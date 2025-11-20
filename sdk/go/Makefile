# Stratium SDK Makefile

# Path to the main Stratium project proto directory
PROTO_SOURCE_DIR := ../../proto

.PHONY: help generate-proto copy-proto test lint clean clean-gen fmt tidy build-examples publish-prepare

# Publish directory
PUBLISH_DIR := $(HOME)/stratium-sdk

help:
	@echo "Stratium Go SDK - Make Commands"
	@echo ""
	@echo "Development:"
	@echo "  make copy-proto      - Copy proto files from main project"
	@echo "  make generate-proto  - Copy proto files and generate gRPC stubs"
	@echo "  make test            - Run tests"
	@echo "  make lint            - Run linters"
	@echo "  make fmt             - Format code"
	@echo "  make tidy            - Run go mod tidy"
	@echo ""
	@echo "Publishing:"
	@echo "  make publish-prepare - Copy SDK to ~/stratium-sdk for publishing"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean           - Clean generated files and copied protos"
	@echo "  make clean-gen       - Clean only generated files (keep protos)"
	@echo ""
	@echo "Tools:"
	@echo "  make install-tools   - Install required tools"
	@echo "  make build-examples  - Build example programs"
	@echo ""

# Install required tools
install-tools:
	@echo "Installing protobuf compiler tools..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "✓ Tools installed"

# Copy proto files from main project
copy-proto:
	@echo "Copying proto files from main project..."
	@mkdir -p proto/services/platform
	@mkdir -p proto/services/key-manager
	@mkdir -p proto/services/key-access
	@mkdir -p proto/models

	@echo "  - Copying platform service protos..."
	@cp -r $(PROTO_SOURCE_DIR)/services/platform/*.proto proto/services/platform/ 2>/dev/null || true

	@echo "  - Copying key-manager service protos..."
	@cp -r $(PROTO_SOURCE_DIR)/services/key-manager/*.proto proto/services/key-manager/ 2>/dev/null || true

	@echo "  - Copying key-access service protos..."
	@cp -r $(PROTO_SOURCE_DIR)/services/key-access/*.proto proto/services/key-access/ 2>/dev/null || true

	@echo "  - Copying model protos..."
	@cp -r $(PROTO_SOURCE_DIR)/models/*.proto proto/models/ 2>/dev/null || true

	@echo "✓ Proto files copied"

# Generate gRPC stubs from proto files
generate-proto: copy-proto
	@echo "Generating gRPC stubs from proto files..."
	@mkdir -p gen

	@echo "Generating Platform service..."
	protoc --go_out=gen --go_opt=module=stratium \
		--go-grpc_out=gen --go-grpc_opt=module=stratium \
		proto/services/platform/platform.proto

	@echo "Generating Key Manager service..."
	protoc --go_out=gen --go_opt=module=stratium \
		--go-grpc_out=gen --go-grpc_opt=module=stratium \
		proto/services/key-manager/key-manager.proto

	@echo "Generating Key Access service..."
	protoc --go_out=gen --go_opt=module=stratium \
		--go-grpc_out=gen --go-grpc_opt=module=stratium \
		proto/services/key-access/key-access.proto

	@echo "Generating model protos..."
	protoc --go_out=gen --go_opt=module=stratium \
		proto/models/*.proto

	@echo "✓ gRPC stubs generated in gen/"

# Run tests
test:
	@echo "Running tests..."
	go test ./... -v

# Run linters
lint:
	@echo "Running linters..."
	go vet ./...
	gofmt -l .

# Clean generated files
clean:
	@echo "Cleaning generated files and copied protos..."
	rm -rf gen/
	rm -rf proto/
	@echo "✓ Clean complete"

# Clean only generated code (keep proto files)
clean-gen:
	@echo "Cleaning generated files..."
	rm -rf gen/
	@echo "✓ Generated files cleaned"

# Format code
fmt:
	@echo "Formatting code..."
	gofmt -w .
	@echo "✓ Format complete"

# Run go mod tidy
tidy:
	@echo "Running go mod tidy..."
	go mod tidy
	@echo "✓ Tidy complete"

# Build examples
build-examples:
	@echo "Building examples..."
	cd examples && go build -o ../bin/basic_usage basic_usage.go
	@echo "✓ Examples built in bin/"

# Prepare SDK for publishing
publish-prepare: fmt tidy generate-proto
	@echo "==========================================="
	@echo "Preparing SDK for publishing..."
	@echo "==========================================="
	@echo ""

	@echo "Step 1: Cleaning destination directory..."
	@rm -rf $(PUBLISH_DIR)
	@mkdir -p $(PUBLISH_DIR)
	@echo "✓ Destination cleaned: $(PUBLISH_DIR)"
	@echo ""

	@echo "Step 2: Copying SDK files..."
	@rsync -av --progress \
		--exclude='.git' \
		--exclude='.gitignore' \
		--exclude='proto/' \
		--exclude='bin/' \
		--exclude='*.log' \
		--exclude='.DS_Store' \
		--exclude='*.swp' \
		--exclude='*.swo' \
		--exclude='*~' \
		. $(PUBLISH_DIR)/
	@echo "✓ SDK files copied"
	@echo ""

	@echo "Step 3: Running go mod tidy in publish directory..."
	@cd $(PUBLISH_DIR) && go mod tidy
	@echo "✓ Dependencies updated"
	@echo ""

	@echo "Step 4: Verifying SDK structure..."
	@echo "Files in $(PUBLISH_DIR):"
	@ls -la $(PUBLISH_DIR) | head -20
	@echo ""
	@echo "Generated proto stubs:"
	@ls -la $(PUBLISH_DIR)/gen 2>/dev/null || echo "  (no generated stubs yet - run 'make generate-proto' first)"
	@echo ""

	@echo "==========================================="
	@echo "✓ SDK ready for publishing!"
	@echo "==========================================="
	@echo ""
	@echo "Location: $(PUBLISH_DIR)"
	@echo ""
	@echo "Next steps:"
	@echo "  cd $(PUBLISH_DIR)"
	@echo "  git init"
	@echo "  git add ."
	@echo "  git commit -m 'Initial commit: Stratium Go SDK'"
	@echo "  git remote add origin https://github.com/stratiumdata/go-sdk.git"
	@echo "  git push -u origin main"
	@echo "  git tag v0.1.0"
	@echo "  git push origin v0.1.0"
	@echo ""