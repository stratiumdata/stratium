# Building a Stratium Golang Client - Step-by-Step Guide

This guide walks you through building a complete Golang CLI client that integrates with Stratium for zero-trust data encryption and access control using ZTDF (Zero Trust Data Format).

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Project Setup](#project-setup)
- [Keycloak Configuration](#keycloak-configuration)
- [Policy and Entitlement Configuration](#policy-and-entitlement-configuration)
- [Building the Client](#building-the-client)
  - [OIDC Authentication](#oidc-authentication)
  - [Key Manager Integration](#key-manager-integration)
  - [ZTDF Encryption](#ztdf-encryption)
  - [ZTDF Decryption](#ztdf-decryption)
- [Complete Working Example](#complete-working-example)
- [Running the Sample](#running-the-sample)
- [Troubleshooting](#troubleshooting)

## Overview

This sample demonstrates:

1. **OIDC Authentication**: Authenticate users via Keycloak
2. **Client Key Registration**: Register public keys with Key Manager
3. **ZTDF Encryption**: Encrypt files with attribute-based access control
4. **ZTDF Decryption**: Decrypt files with policy enforcement
5. **Policy Evaluation**: Enforce fine-grained access control

## Prerequisites

Before starting, ensure you have:

- **Go 1.21+** installed
- **Stratium services** running:
  - Key Manager (default: `localhost:50052`)
  - Policy Decision Point (default: `localhost:50051`)
- **Keycloak** running (default: `http://localhost:8080`)
- **grpcurl** installed (for testing)
- **openssl** for key generation

## Project Setup

### 1. Create Project Directory

```bash
mkdir stratium-client-sample
cd stratium-client-sample
```

### 2. Initialize Go Module

```bash
go mod init github.com/yourusername/stratium-client-sample
```

### 3. Install Dependencies

```bash
# gRPC and Protocol Buffers
go get google.golang.org/grpc
go get google.golang.org/protobuf/proto

# OIDC client
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2

# CLI framework
go get github.com/spf13/cobra
go get github.com/spf13/viper
```

Note: All cryptographic operations use Go's standard library (`crypto/*` packages).

### 4. Project Structure

```
stratium-client-sample/
├── cmd/
│   └── main.go                 # CLI entry point
├── internal/
│   ├── auth/
│   │   └── oidc.go            # OIDC authentication
│   ├── keymanager/
│   │   └── client.go          # Key Manager client
│   ├── ztdf/
│   │   ├── encrypt.go         # Encryption logic
│   │   └── decrypt.go         # Decryption logic
│   └── config/
│       └── config.go          # Configuration
├── proto/                      # Generated proto files
├── keys/                       # Client key storage
├── config.yaml                 # Configuration file
└── go.mod
```

### 5. Copy Protocol Buffer Files

Copy the Stratium proto files to your project:

```bash
# From Stratium repository
cp -r /path/to/stratium/proto ./proto
```

### 6. Generate gRPC Code

```bash
# Install protoc plugins if not already installed
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code from proto files
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/services/key-manager/key-manager.proto
```

## Keycloak Configuration

### Step 1: Create a New Realm (Optional)

If you want to use a dedicated realm:

1. Login to Keycloak Admin Console: `http://localhost:8080`
2. Hover over the realm dropdown (top left)
3. Click **"Create Realm"**
4. Set realm name to `stratium`
5. Click **"Create"**

### Step 2: Create a Client

1. Navigate to **Clients** → **Create client**
2. Configure the client:
   - **Client ID**: `stratium-cli-client`
   - **Client Protocol**: `openid-connect`
   - **Client authentication**: `ON` (for confidential client)
   - **Authorization**: `OFF` (not needed for this sample)
   - **Valid redirect URIs**: `http://localhost:8888/callback`
   - **Web origins**: `http://localhost:8888`

3. Click **Save**

### Step 3: Get Client Credentials

1. Go to the **Credentials** tab
2. Copy the **Client Secret** (you'll need this)

### Step 4: Create Client Scopes

Create custom client scopes for attribute-based access control:

#### Create "department" scope:

1. Navigate to **Client Scopes** → **Create client scope**
2. Set:
   - **Name**: `department`
   - **Protocol**: `openid-connect`
   - **Display on consent screen**: `OFF`
3. Click **Save**
4. Go to **Mappers** tab → **Add mapper** → **By configuration** → **User Attribute**
5. Configure:
   - **Name**: `department`
   - **User Attribute**: `department`
   - **Token Claim Name**: `department`
   - **Claim JSON Type**: `String`
   - **Add to ID token**: `ON`
   - **Add to access token**: `ON`
   - **Add to userinfo**: `ON`
6. Click **Save**

#### Create "clearance" scope:

1. Navigate to **Client Scopes** → **Create client scope**
2. Set:
   - **Name**: `clearance`
   - **Protocol**: `openid-connect`
3. Click **Save**
4. Go to **Mappers** tab → **Add mapper** → **User Attribute**
5. Configure:
   - **Name**: `clearance`
   - **User Attribute**: `clearance`
   - **Token Claim Name**: `clearance`
   - **Claim JSON Type**: `String`
   - **Add to ID token**: `ON`
   - **Add to access token**: `ON`
   - **Add to userinfo**: `ON`
6. Click **Save**

#### Create "role" scope:

1. Navigate to **Client Scopes** → **Create client scope**
2. Set:
   - **Name**: `role`
   - **Protocol**: `openid-connect`
3. Click **Save**
4. Go to **Mappers** tab → **Add mapper** → **User Realm Role**
5. Configure:
   - **Name**: `realm-roles`
   - **Token Claim Name**: `roles`
   - **Claim JSON Type**: `String`
   - **Add to ID token**: `ON`
   - **Add to access token**: `ON`
6. Click **Save**

### Step 5: Assign Scopes to Client

1. Go back to **Clients** → `stratium-cli-client`
2. Click **Client scopes** tab
3. Click **Add client scope**
4. Select `department`, `clearance`, and `role`
5. Add them as **Default** scopes
6. Click **Add**

### Step 6: Create Test Users

#### Create engineering user:

1. Navigate to **Users** → **Add user**
2. Set:
   - **Username**: `engineer1`
   - **Email**: `engineer1@example.com`
   - **First name**: `John`
   - **Last name**: `Engineer`
3. Click **Create**
4. Go to **Credentials** tab
5. Set password: `password123`
6. Set **Temporary**: `OFF`
7. Click **Set password**
8. Go to **Attributes** tab
9. Add attributes:
   - **department**: `engineering`
   - **clearance**: `SECRET`
10. Click **Save**
11. Go to **Role mapping** tab
12. Click **Assign role** → Select `engineer` role

#### Create finance user:

1. Navigate to **Users** → **Add user**
2. Set:
   - **Username**: `finance1`
   - **Email**: `finance1@example.com`
3. Click **Create**
4. Set password: `password123`
5. Add attributes:
   - **department**: `finance`
   - **clearance**: `CONFIDENTIAL`
6. Assign `analyst` role

### Step 7: Verify Token Claims

Test that tokens include custom claims:

```bash
# Get access token
curl -X POST "http://localhost:8080/realms/stratium/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=stratium-cli-client" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "username=engineer1" \
  -d "password=password123" \
  -d "grant_type=password"

# Decode the access token at https://jwt.io to verify claims
```

Expected claims in token:
```json
{
  "sub": "user-uuid",
  "department": "engineering",
  "clearance": "SECRET",
  "roles": ["engineer"],
  "email": "engineer1@example.com"
}
```

## Policy and Entitlement Configuration

### Step 1: Create Policies

Create policies to control access to encrypted data.

#### Policy 1: Department-Based Access

```bash
curl -X POST "http://localhost:3000/api/v1/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering Department Access",
    "description": "Allow engineering department to access engineering resources",
    "effect": "allow",
    "enabled": true,
    "priority": 4000,
    "language": "opa",
    "policy_content": {
      "rego": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.department == \"engineering\"\n    input.resource.owner == \"engineering\"\n}"
    }
  }'
```

#### Policy 2: Clearance-Based Access

```bash
curl -X POST "http://localhost:3000/api/v1/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Clearance Check",
    "description": "Verify user clearance level matches or exceeds resource classification",
    "effect": "allow",
    "enabled": true,
    "priority": 7500,
    "language": "opa",
    "policy_content": {
      "rego": "package stratium.authz\n\ndefault allow = false\n\nclearance_levels = {\n    \"PUBLIC\": 0,\n    \"CONFIDENTIAL\": 1,\n    \"SECRET\": 2,\n    \"TOP_SECRET\": 3\n}\n\nallow {\n    user_level := clearance_levels[input.subject.clearance]\n    resource_level := clearance_levels[input.resource.classification]\n    user_level >= resource_level\n}"
    }
  }'
```

#### Policy 3: Role-Based Access

```bash
curl -X POST "http://localhost:3000/api/v1/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineer Role Access",
    "description": "Allow engineers read/write access to technical documents",
    "effect": "allow",
    "enabled": true,
    "priority": 3500,
    "language": "json",
    "policy_content": {
      "conditions": {
        "subject": {
          "roles": {"$contains": "engineer"}
        },
        "resource": {
          "resource_type": {"$eq": "technical-document"}
        },
        "action": {
          "action_name": {"$in": ["read", "write"]}
        }
      }
    }
  }'
```

### Step 2: Create Entitlements

Entitlements grant specific users or groups access to resources.

#### Entitlement 1: Engineering Team Access

```bash
curl -X POST "http://localhost:3000/api/v1/entitlements" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering Team - Engineering Resources",
    "description": "Grant engineering team access to engineering owned resources",
    "subject": {
      "type": "group",
      "id": "engineering"
    },
    "resource": {
      "type": "resource",
      "attributes": {
        "owner": "engineering"
      }
    },
    "actions": ["read", "write", "delete"],
    "enabled": true
  }'
```

#### Entitlement 2: User-Specific Entitlement

```bash
curl -X POST "http://localhost:3000/api/v1/entitlements" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineer1 - Project Alpha Access",
    "description": "Grant engineer1 access to project-alpha resources",
    "subject": {
      "type": "user",
      "id": "engineer1"
    },
    "resource": {
      "type": "resource",
      "attributes": {
        "project": "alpha",
        "classification": "SECRET"
      }
    },
    "actions": ["read", "write"],
    "enabled": true
  }'
```

### Step 3: Test Policy Evaluation

Test that policies work correctly:

```bash
curl -X POST "http://localhost:3000/api/v1/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {
      "user_id": "engineer1",
      "department": "engineering",
      "clearance": "SECRET",
      "roles": ["engineer"]
    },
    "resource": {
      "resource_id": "doc-123",
      "owner": "engineering",
      "classification": "SECRET",
      "resource_type": "technical-document"
    },
    "action": {
      "action_name": "read"
    }
  }'
```

Expected response:
```json
{
  "decision": "ALLOW",
  "policies_evaluated": [
    {
      "policy_id": "policy-xyz",
      "policy_name": "Engineering Department Access",
      "effect": "allow",
      "matched": true
    },
    {
      "policy_id": "policy-abc",
      "policy_name": "Clearance Check",
      "effect": "allow",
      "matched": true
    }
  ]
}
```

## Building the Client

### OIDC Authentication

Create `internal/auth/oidc.go`:

```go
package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	ProviderURL  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

type OIDCClient struct {
	config   OIDCConfig
	provider *oidc.Provider
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewOIDCClient(ctx context.Context, config OIDCConfig) (*OIDCClient, error) {
	provider, err := oidc.NewProvider(ctx, config.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID}, config.Scopes...),
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &OIDCClient{
		config:   config,
		provider: provider,
		oauth2:   oauth2Config,
		verifier: verifier,
	}, nil
}

// AuthenticatePasswordGrant uses Resource Owner Password Credentials grant
func (c *OIDCClient) AuthenticatePasswordGrant(ctx context.Context, username, password string) (*oauth2.Token, error) {
	token, err := c.oauth2.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("password authentication failed: %w", err)
	}
	return token, nil
}

// AuthenticateDeviceFlow uses Device Authorization Grant (better for CLI)
func (c *OIDCClient) AuthenticateDeviceFlow(ctx context.Context) (*oauth2.Token, error) {
	// This requires device flow support in Keycloak
	// For simplicity, we'll use password flow in this example
	return nil, fmt.Errorf("device flow not implemented")
}

// GetUserInfo retrieves user information from the ID token
func (c *OIDCClient) GetUserInfo(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims, nil
}

// RefreshToken refreshes an expired token
func (c *OIDCClient) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	tokenSource := c.oauth2.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	return newToken, nil
}

// CreateAuthenticatedContext creates a context with the access token
func (c *OIDCClient) CreateAuthenticatedContext(ctx context.Context, token *oauth2.Token) context.Context {
	return context.WithValue(ctx, "access_token", token.AccessToken)
}
```

### Key Manager Integration

Create `internal/keymanager/client.go`:

```go
package keymanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/yourusername/stratium-client-sample/proto/services/key-manager"
)

type KeyManagerClient struct {
	conn   *grpc.ClientConn
	client pb.KeyManagerServiceClient
}

func NewKeyManagerClient(address string) (*KeyManagerClient, error) {
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Key Manager: %w", err)
	}

	return &KeyManagerClient{
		conn:   conn,
		client: pb.NewKeyManagerServiceClient(conn),
	}, nil
}

func (c *KeyManagerClient) Close() error {
	return c.conn.Close()
}

// GenerateKeyPair generates an RSA key pair for the client
func GenerateKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return privateKey, nil
}

// SavePrivateKey saves private key to file
func SavePrivateKey(privateKey *rsa.PrivateKey, filename string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return os.WriteFile(filename, privateKeyPEM, 0600)
}

// PublicKeyToPEM converts public key to PEM format
func PublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM), nil
}

// RegisterClientKey registers the client's public key with Key Manager
func (c *KeyManagerClient) RegisterClientKey(ctx context.Context, clientID string, publicKeyPEM string, accessToken string) (*pb.RegisterClientKeyResponse, error) {
	// Add access token to gRPC metadata for authentication
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)

	req := &pb.RegisterClientKeyRequest{
		ClientId:     clientID,
		PublicKeyPem: publicKeyPEM,
		KeyType:      pb.KeyType_KEY_TYPE_RSA_2048,
		Metadata: map[string]string{
			"purpose":       "ztdf-encryption",
			"generated_by":  "cli-client",
		},
	}

	resp, err := c.client.RegisterClientKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to register client key: %w", err)
	}

	return resp, nil
}

// GetClientKey retrieves the active client key
func (c *KeyManagerClient) GetClientKey(ctx context.Context, clientID string, accessToken string) (*pb.GetClientKeyResponse, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)

	req := &pb.GetClientKeyRequest{
		ClientId: clientID,
	}

	resp, err := c.client.GetClientKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get client key: %w", err)
	}

	return resp, nil
}

// CreateKey creates a server-managed encryption key
func (c *KeyManagerClient) CreateKey(ctx context.Context, name string, accessToken string) (*pb.CreateKeyResponse, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)

	req := &pb.CreateKeyRequest{
		Name:                 name,
		KeyType:              pb.KeyType_KEY_TYPE_RSA_2048,
		ProviderType:         pb.KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		RotationPolicy:       pb.RotationPolicy_ROTATION_POLICY_TIME_BASED,
		RotationIntervalDays: 90,
	}

	resp, err := c.client.CreateKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}

	return resp, nil
}
```

### ZTDF Encryption

Create `internal/ztdf/encrypt.go`:

```go
package ztdf

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type ZTDFManifest struct {
	Version            string                 `json:"version"`
	EncryptedPayload   []byte                 `json:"encrypted_payload"`
	EncryptedDEK       []byte                 `json:"encrypted_dek"`
	Attributes         map[string]interface{} `json:"attributes"`
	PolicyBindings     []string               `json:"policy_bindings"`
	EncryptionMetadata EncryptionMetadata     `json:"encryption_metadata"`
}

type EncryptionMetadata struct {
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"key_id"`
	IV           []byte `json:"iv"`
	EncryptedBy  string `json:"encrypted_by"`
	EncryptedAt  string `json:"encrypted_at"`
}

type EncryptionOptions struct {
	Attributes     map[string]interface{}
	PolicyBindings []string
	KeyID          string
	EncryptedBy    string
}

// EncryptFile encrypts a file using ZTDF format
func EncryptFile(ctx context.Context, inputPath string, outputPath string, publicKey *rsa.PublicKey, options EncryptionOptions) error {
	// Read the plaintext file
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Generate a random Data Encryption Key (DEK)
	dek := make([]byte, 32) // 256-bit AES key
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt the plaintext with AES-GCM using the DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	encryptedPayload := gcm.Seal(nil, nonce, plaintext, nil)

	// Encrypt the DEK with the public key (RSA-OAEP)
	encryptedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, dek, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Create ZTDF manifest
	manifest := ZTDFManifest{
		Version:          "1.0",
		EncryptedPayload: encryptedPayload,
		EncryptedDEK:     encryptedDEK,
		Attributes:       options.Attributes,
		PolicyBindings:   options.PolicyBindings,
		EncryptionMetadata: EncryptionMetadata{
			Algorithm:   "AES-256-GCM",
			KeyID:       options.KeyID,
			IV:          nonce,
			EncryptedBy: options.EncryptedBy,
			EncryptedAt: fmt.Sprintf("%d", time.Now().Unix()),
		},
	}

	// Marshal manifest to JSON
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// Write encrypted file
	if err := os.WriteFile(outputPath, manifestJSON, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("✓ File encrypted successfully: %s\n", outputPath)
	fmt.Printf("  Algorithm: %s\n", manifest.EncryptionMetadata.Algorithm)
	fmt.Printf("  Key ID: %s\n", options.KeyID)
	fmt.Printf("  Attributes: %v\n", options.Attributes)

	return nil
}
```

### ZTDF Decryption

Create `internal/ztdf/decrypt.go`:

```go
package ztdf

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

type PolicyEvaluator interface {
	Evaluate(ctx context.Context, subject, resource map[string]interface{}, action string) (bool, error)
}

// DecryptFile decrypts a ZTDF file with policy enforcement
func DecryptFile(ctx context.Context, inputPath string, outputPath string, privateKey *rsa.PrivateKey, userClaims map[string]interface{}, evaluator PolicyEvaluator) error {
	// Read the encrypted file
	manifestJSON, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Parse ZTDF manifest
	var manifest ZTDFManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Evaluate policies before decryption
	allowed, err := evaluator.Evaluate(ctx, userClaims, manifest.Attributes, "read")
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}

	if !allowed {
		return fmt.Errorf("access denied: policy evaluation returned DENY")
	}

	// Decrypt the DEK with the private key
	dek, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, manifest.EncryptedDEK, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Decrypt the payload with AES-GCM using the DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, manifest.EncryptionMetadata.IV, manifest.EncryptedPayload, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt payload: %w", err)
	}

	// Write decrypted file
	if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("✓ File decrypted successfully: %s\n", outputPath)
	fmt.Printf("  Encrypted by: %s\n", manifest.EncryptionMetadata.EncryptedBy)
	fmt.Printf("  Attributes: %v\n", manifest.Attributes)

	return nil
}
```

### Policy Evaluator Implementation

Create `internal/ztdf/policy.go`:

```go
package ztdf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type PDPClient struct {
	baseURL string
	client  *http.Client
}

func NewPDPClient(baseURL string) *PDPClient {
	return &PDPClient{
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

type EvaluationRequest struct {
	Subject  map[string]interface{} `json:"subject"`
	Resource map[string]interface{} `json:"resource"`
	Action   map[string]interface{} `json:"action"`
}

type EvaluationResponse struct {
	Decision string `json:"decision"`
}

func (p *PDPClient) Evaluate(ctx context.Context, subject, resource map[string]interface{}, action string) (bool, error) {
	req := EvaluationRequest{
		Subject:  subject,
		Resource: resource,
		Action: map[string]interface{}{
			"action_name": action,
		},
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/v1/evaluate", bytes.NewReader(reqBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("policy evaluation failed with status: %d", resp.StatusCode)
	}

	var evalResp EvaluationResponse
	if err := json.NewDecoder(resp.Body).Decode(&evalResp); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	return evalResp.Decision == "ALLOW", nil
}
```

## Complete Working Example

Create `cmd/main.go`:

```go
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yourusername/stratium-client-sample/internal/auth"
	"github.com/yourusername/stratium-client-sample/internal/keymanager"
	"github.com/yourusername/stratium-client-sample/internal/ztdf"
)

var (
	// Global flags
	keycloakURL  string
	clientID     string
	clientSecret string
	kmAddress    string
	pdpURL       string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "stratium-cli",
		Short: "Stratium ZTDF CLI Client",
		Long:  "A command-line client for encrypting and decrypting files using Stratium's zero-trust framework",
	}

	rootCmd.PersistentFlags().StringVar(&keycloakURL, "keycloak-url", "http://localhost:8080/realms/stratium", "Keycloak realm URL")
	rootCmd.PersistentFlags().StringVar(&clientID, "client-id", "stratium-cli-client", "OIDC client ID")
	rootCmd.PersistentFlags().StringVar(&clientSecret, "client-secret", "", "OIDC client secret")
	rootCmd.PersistentFlags().StringVar(&kmAddress, "km-address", "localhost:50052", "Key Manager gRPC address")
	rootCmd.PersistentFlags().StringVar(&pdpURL, "pdp-url", "http://localhost:50051", "Policy Decision Point URL")

	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(encryptCmd())
	rootCmd.AddCommand(decryptCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	var username, password string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize client and register public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// 1. Authenticate with Keycloak
			fmt.Println("🔐 Authenticating with Keycloak...")
			oidcClient, err := auth.NewOIDCClient(ctx, auth.OIDCConfig{
				ProviderURL:  keycloakURL,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{"department", "clearance", "role"},
			})
			if err != nil {
				return fmt.Errorf("failed to create OIDC client: %w", err)
			}

			token, err := oidcClient.AuthenticatePasswordGrant(ctx, username, password)
			if err != nil {
				return fmt.Errorf("authentication failed: %w", err)
			}

			userInfo, err := oidcClient.GetUserInfo(ctx, token)
			if err != nil {
				return fmt.Errorf("failed to get user info: %w", err)
			}

			fmt.Printf("✓ Authenticated as: %s\n", userInfo["preferred_username"])
			fmt.Printf("  Department: %s\n", userInfo["department"])
			fmt.Printf("  Clearance: %s\n", userInfo["clearance"])

			// 2. Generate key pair
			fmt.Println("\n🔑 Generating RSA key pair...")
			privateKey, err := keymanager.GenerateKeyPair(2048)
			if err != nil {
				return fmt.Errorf("key generation failed: %w", err)
			}

			// Save private key
			if err := os.MkdirAll("keys", 0700); err != nil {
				return fmt.Errorf("failed to create keys directory: %w", err)
			}

			if err := keymanager.SavePrivateKey(privateKey, "keys/client_private.pem"); err != nil {
				return fmt.Errorf("failed to save private key: %w", err)
			}

			publicKeyPEM, err := keymanager.PublicKeyToPEM(&privateKey.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to convert public key: %w", err)
			}

			fmt.Println("✓ Key pair generated and saved to keys/")

			// 3. Register public key with Key Manager
			fmt.Println("\n📝 Registering public key with Key Manager...")
			kmClient, err := keymanager.NewKeyManagerClient(kmAddress)
			if err != nil {
				return fmt.Errorf("failed to connect to Key Manager: %w", err)
			}
			defer kmClient.Close()

			resp, err := kmClient.RegisterClientKey(ctx, username, publicKeyPEM, token.AccessToken)
			if err != nil {
				return fmt.Errorf("failed to register key: %w", err)
			}

			fmt.Printf("✓ Public key registered successfully\n")
			fmt.Printf("  Key ID: %s\n", resp.KeyId)
			fmt.Printf("  Status: %s\n", resp.Status)

			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username for authentication")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password for authentication")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")

	return cmd
}

func encryptCmd() *cobra.Command {
	var (
		username     string
		password     string
		inputFile    string
		outputFile   string
		owner        string
		classification string
		project      string
	)

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a file with ZTDF",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// 1. Authenticate
			fmt.Println("🔐 Authenticating...")
			oidcClient, err := auth.NewOIDCClient(ctx, auth.OIDCConfig{
				ProviderURL:  keycloakURL,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{"department", "clearance", "role"},
			})
			if err != nil {
				return err
			}

			token, err := oidcClient.AuthenticatePasswordGrant(ctx, username, password)
			if err != nil {
				return err
			}

			userInfo, err := oidcClient.GetUserInfo(ctx, token)
			if err != nil {
				return err
			}

			// 2. Get client key from Key Manager
			fmt.Println("🔑 Retrieving encryption key...")
			kmClient, err := keymanager.NewKeyManagerClient(kmAddress)
			if err != nil {
				return err
			}
			defer kmClient.Close()

			keyResp, err := kmClient.GetClientKey(ctx, username, token.AccessToken)
			if err != nil {
				return err
			}

			// Parse public key
			block, _ := pem.Decode([]byte(keyResp.PublicKeyPem))
			if block == nil {
				return fmt.Errorf("failed to parse PEM block")
			}

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			}

			publicKey, ok := pub.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("not an RSA public key")
			}

			// 3. Encrypt file
			fmt.Printf("\n🔒 Encrypting file: %s\n", inputFile)
			err = ztdf.EncryptFile(ctx, inputFile, outputFile, publicKey, ztdf.EncryptionOptions{
				Attributes: map[string]interface{}{
					"owner":          owner,
					"classification": classification,
					"project":        project,
					"resource_type":  "file",
				},
				PolicyBindings: []string{"department-access", "clearance-check"},
				KeyID:          keyResp.KeyId,
				EncryptedBy:    userInfo["preferred_username"].(string),
			})
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password")
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to encrypt")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output encrypted file")
	cmd.Flags().StringVar(&owner, "owner", "", "Resource owner (e.g., engineering)")
	cmd.Flags().StringVar(&classification, "classification", "CONFIDENTIAL", "Data classification")
	cmd.Flags().StringVar(&project, "project", "", "Project name")

	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	cmd.MarkFlagRequired("input")
	cmd.MarkFlagRequired("output")
	cmd.MarkFlagRequired("owner")

	return cmd
}

func decryptCmd() *cobra.Command {
	var (
		username   string
		password   string
		inputFile  string
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a ZTDF file",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// 1. Authenticate
			fmt.Println("🔐 Authenticating...")
			oidcClient, err := auth.NewOIDCClient(ctx, auth.OIDCConfig{
				ProviderURL:  keycloakURL,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{"department", "clearance", "role"},
			})
			if err != nil {
				return err
			}

			token, err := oidcClient.AuthenticatePasswordGrant(ctx, username, password)
			if err != nil {
				return err
			}

			userInfo, err := oidcClient.GetUserInfo(ctx, token)
			if err != nil {
				return err
			}

			fmt.Printf("✓ Authenticated as: %s\n", userInfo["preferred_username"])

			// 2. Load private key
			fmt.Println("🔑 Loading private key...")
			privateKeyPEM, err := os.ReadFile("keys/client_private.pem")
			if err != nil {
				return fmt.Errorf("failed to read private key: %w", err)
			}

			block, _ := pem.Decode(privateKeyPEM)
			if block == nil {
				return fmt.Errorf("failed to parse PEM block")
			}

			privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return err
			}

			// 3. Create policy evaluator
			pdpClient := ztdf.NewPDPClient(pdpURL)

			// 4. Decrypt file
			fmt.Printf("\n🔓 Decrypting file: %s\n", inputFile)
			err = ztdf.DecryptFile(ctx, inputFile, outputFile, privateKey, userInfo, pdpClient)
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password")
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input encrypted file")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output decrypted file")

	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	cmd.MarkFlagRequired("input")
	cmd.MarkFlagRequired("output")

	return cmd
}
```

## Running the Sample

### Step 1: Initialize the Client

```bash
./stratium-cli init \
  --username engineer1 \
  --password password123 \
  --client-secret YOUR_CLIENT_SECRET
```

Expected output:
```
🔐 Authenticating with Keycloak...
✓ Authenticated as: engineer1
  Department: engineering
  Clearance: SECRET

🔑 Generating RSA key pair...
✓ Key pair generated and saved to keys/

📝 Registering public key with Key Manager...
✓ Public key registered successfully
  Key ID: client-key-abc123
  Status: ACTIVE
```

### Step 2: Encrypt a File

```bash
echo "Confidential engineering data" > test.txt

./stratium-cli encrypt \
  --username engineer1 \
  --password password123 \
  --input test.txt \
  --output test.txt.ztdf \
  --owner engineering \
  --classification SECRET \
  --project alpha \
  --client-secret YOUR_CLIENT_SECRET
```

Expected output:
```
🔐 Authenticating...
🔑 Retrieving encryption key...
🔒 Encrypting file: test.txt
✓ File encrypted successfully: test.txt.ztdf
  Algorithm: AES-256-GCM
  Key ID: client-key-abc123
  Attributes: map[classification:SECRET owner:engineering project:alpha]
```

### Step 3: Decrypt a File

```bash
./stratium-cli decrypt \
  --username engineer1 \
  --password password123 \
  --input test.txt.ztdf \
  --output test_decrypted.txt \
  --client-secret YOUR_CLIENT_SECRET
```

Expected output:
```
🔐 Authenticating...
✓ Authenticated as: engineer1
🔑 Loading private key...
🔓 Decrypting file: test.txt.ztdf
✓ File decrypted successfully: test_decrypted.txt
  Encrypted by: engineer1
  Attributes: map[classification:SECRET owner:engineering project:alpha]
```

### Step 4: Test Access Control

Try decrypting as a finance user (should fail):

```bash
./stratium-cli decrypt \
  --username finance1 \
  --password password123 \
  --input test.txt.ztdf \
  --output test_decrypted.txt \
  --client-secret YOUR_CLIENT_SECRET
```

Expected output:
```
🔐 Authenticating...
✓ Authenticated as: finance1
🔑 Loading private key...
🔓 Decrypting file: test.txt.ztdf
Error: access denied: policy evaluation returned DENY
```

## Troubleshooting

### Issue: "failed to connect to Key Manager"

**Solution**: Ensure Key Manager is running:
```bash
# Check if service is running
grpcurl -plaintext localhost:50052 list

# Start Key Manager if needed
cd /path/to/stratium
go run cmd/key-manager/main.go
```

### Issue: "authentication failed"

**Solutions**:
1. Verify Keycloak is running: `curl http://localhost:8080`
2. Check client secret is correct
3. Verify user credentials
4. Check realm name matches configuration

### Issue: "policy evaluation failed"

**Solutions**:
1. Verify PDP is running
2. Check policies are enabled
3. Review policy conditions match user attributes
4. Check entitlements grant access

### Issue: "failed to register key"

**Solutions**:
1. Ensure access token is valid
2. Check Key Manager authentication settings
3. Verify client has permission to register keys

## Next Steps

- [Key Manager Integration Guide](../integration/KEY_MANAGER.md)
- [OIDC Integration Guide](../integration/OIDC_INTEGRATION.md)
- [Policy Best Practices](../policies/BEST_PRACTICES.md)
- [Creating Entitlements](../entitlements/CREATING_ENTITLEMENTS.md)

## License

Copyright © 2025 Stratium Data