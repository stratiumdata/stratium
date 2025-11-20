#!/bin/bash

# Script to generate TypeScript gRPC-Web client code from proto files

set -e

PROTO_DIR="../../../proto/services/platform"
OUT_DIR="src/generated"

# Create output directory if it doesn't exist
mkdir -p $OUT_DIR

# Generate TypeScript code
# Note: You need protoc and protoc-gen-grpc-web installed
# Install with: npm install -g grpc-tools grpc_tools_node_protoc_ts

protoc \
  --plugin=protoc-gen-ts=./node_modules/.bin/protoc-gen-ts \
  --js_out=import_style=commonjs,binary:$OUT_DIR \
  --ts_out=service=grpc-web:$OUT_DIR \
  --grpc-web_out=import_style=typescript,mode=grpcwebtext:$OUT_DIR \
  --proto_path=$PROTO_DIR \
  $PROTO_DIR/platform.proto

echo "gRPC-Web TypeScript client generated successfully in $OUT_DIR"