# Key Manager and Admin Key Guide

Learn how to manage encryption keys, admin keys, and client keys in Stratium for Zero Trust Data Format (ZTDF) operations and administrative functions.

## Table of Contents
- [Overview](#overview)
- [Key Types](#key-types)
- [Admin Key Management](#admin-key-management)
- [Client Key Management](#client-key-management)
- [Key Generation](#key-generation)
- [Key Storage](#key-storage)
- [Key Rotation](#key-rotation)
- [ZTDF Operations](#ztdf-operations)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

Stratium's Key Manager handles cryptographic keys for:

- **ZTDF File Encryption**: Encrypting and decrypting Zero Trust Data Format files
- **Client Authentication**: Client public/private key pairs for API access
- **Administrative Operations**: Admin keys for privileged operations
- **Symmetric Encryption**: Symmetric keys for file content encryption
- **Asymmetric Encryption**: Public/private key pairs for key wrapping

**Key Security Features:**
- Hardware Security Module (HSM) support
- Key versioning and rotation
- Automatic key expiration
- Audit logging of key operations
- Encryption at rest for private keys

## Key Types

### 1. Admin Keys

**Purpose**: Administrative operations requiring elevated privileges

**Use Cases:**
- Emergency access to encrypted files
- Key recovery operations
- System maintenance
- Bulk re-encryption

**Key Characteristics:**
- RSA 4096-bit or Ed25519
- Long-lived (years)
- Highly protected
- Requires multi-factor authentication

### 2. Client Keys

**Purpose**: Client-specific encryption for ZTDF files

**Use Cases:**
- User file encryption
- Application-specific encryption
- Service-to-service encryption

**Key Characteristics:**
- RSA 2048/4096-bit or X25519
- Client-specific
- Can be rotated
- Stored per-client in database

### 3. Symmetric Keys

**Purpose**: File content encryption

**Use Cases:**
- ZTDF file data encryption
- Fast bulk encryption

**Key Characteristics:**
- AES-256-GCM
- Ephemeral or short-lived
- Wrapped with asymmetric keys
- Never stored in plaintext

### 4. Key Encryption Keys (KEK)

**Purpose**: Wrapping other keys for storage

**Use Cases:**
- Encrypting symmetric keys
- Protecting private keys at rest

**Key Characteristics:**
- RSA or AES
- Long-lived
- Stored in HSM or secrets manager

## Admin Key Management

### Generating Admin Keys

Admin keys are typically generated during initial system setup:

```bash
# Generate admin key pair
stratium admin generate-key \
    --algorithm rsa \
    --key-size 4096 \
    --output-private ./admin_private_key.pem \
    --output-public ./admin_public_key.pem

# Or with Ed25519 (recommended for modern systems)
stratium admin generate-key \
    --algorithm ed25519 \
    --output-private ./admin_private_key.pem \
    --output-public ./admin_public_key.pem
```

**Output:**

```
Admin key pair generated successfully:
  Algorithm: RSA-4096
  Private Key: ./admin_private_key.pem
  Public Key: ./admin_public_key.pem
  Fingerprint: SHA256:k8j3h2g1f0d9c8b7a6z5y4x3w2v1u0t9s8r7q6p5o4n3m2l1
```

### Storing Admin Keys Securely

Admin private keys should NEVER be stored in plaintext on disk or in configuration files.

#### Option 1: Hardware Security Module (HSM)

```yaml
# config.yaml
admin_key:
  storage: "hsm"
  hsm:
    type: "pkcs11"  # or "aws_cloudhsm", "azure_key_vault_hsm"
    library_path: "/usr/lib/softhsm/libsofthsm2.so"
    slot: 0
    pin: "${HSM_PIN}"
    key_label: "stratium-admin-key"
```

#### Option 2: Secrets Manager

```yaml
# config.yaml
admin_key:
  storage: "vault"
  vault:
    path: "secret/data/stratium/admin/key"
    public_key_field: "public_key"
    private_key_field: "private_key"
```

#### Option 3: Encrypted File (Development Only)

```yaml
# config.yaml
admin_key:
  storage: "encrypted_file"
  file:
    private_key_path: "/etc/stratium/keys/admin_private_key.pem.enc"
    public_key_path: "/etc/stratium/keys/admin_public_key.pem"
    encryption_passphrase: "${ADMIN_KEY_PASSPHRASE}"
```

## Client Key Management

### Client Key Lifecycle

```

┌─────────────┐
│  Generated  │
└─────┬───────┘
      │
      ▼
┌─────────────┐
│  Registered │ ← Client public key stored in database
└─────┬───────┘
      │
      ▼
┌─────────────┐
│   Active    │ ← Used for encryption/decryption
└─────┬───────┘
      │
      ▼
┌─────────────┐
│  Expiring   │ ← Approaching expiration date
└─────┬───────┘
      │
      ▼
┌─────────────┐
│   Expired   │ ← No longer used for new operations
└─────┬───────┘
      │
      ▼
┌─────────────┐
│   Revoked   │ ← Explicitly revoked (compromise suspected)
└─────────────┘
```

### Registering Client Keys

#### Creating Keys with Key Manager

The Key Manager creates and manages encryption keys for clients:

```bash
# Create a new key for a client using grpcurl
grpcurl -plaintext \
    -d '{
        "name": "user-123-client-key",
        "key_type": "KEY_TYPE_RSA_2048",
        "provider_type": "KEY_PROVIDER_TYPE_SOFTWARE",
        "rotation_policy": "ROTATION_POLICY_TIME_BASED",
        "rotation_interval_days": 90,
        "authorized_subjects": ["user-123"],
        "authorized_resources": ["resource-abc", "resource-xyz"],
        "metadata": {
            "client_id": "user-123",
            "environment": "production",
            "department": "engineering"
        }
    }' \
    localhost:50052 keymanager.KeyManagerService/CreateKey
```

**Response:**

```json
{
  "key": {
    "keyId": "key-abc123def456",
    "name": "user-123-client-key",
    "keyType": "KEY_TYPE_RSA_2048",
    "providerType": "KEY_PROVIDER_TYPE_SOFTWARE",
    "status": "KEY_STATUS_ACTIVE",
    "createdAt": "2025-01-15T10:00:00Z",
    "rotationPolicy": "ROTATION_POLICY_TIME_BASED",
    "rotationIntervalDays": 90,
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
    "authorizedSubjects": ["user-123"],
    "authorizedResources": ["resource-abc", "resource-xyz"],
    "usageCount": 0,
    "metadata": {
      "client_id": "user-123",
      "environment": "production",
      "department": "engineering"
    }
  }
}
```

**Key Types:**
- `KEY_TYPE_RSA_2048` - RSA 2048-bit (recommended for most uses)
- `KEY_TYPE_RSA_4096` - RSA 4096-bit (high security)
- `KEY_TYPE_ED25519` - Ed25519 (modern, fast)

**Provider Types:**
- `KEY_PROVIDER_TYPE_SOFTWARE` - Software-based keys
- `KEY_PROVIDER_TYPE_HSM` - Hardware Security Module
- `KEY_PROVIDER_TYPE_CLOUD_KMS` - Cloud KMS (AWS, Azure, GCP)

### Listing Client Keys

```bash
# List all keys using grpcurl
grpcurl -plaintext \
    -d '{
        "page_size": 10,
        "page_token": ""
    }' \
    localhost:50052 keymanager.KeyManagerService/ListKeys

# List keys for a specific subject
grpcurl -plaintext \
    -d '{
        "subject_filter": "user-123",
        "page_size": 10
    }' \
    localhost:50052 keymanager.KeyManagerService/ListKeys
```

**Response:**

```json
{
  "keys": [
    {
      "keyId": "key-abc123def456",
      "name": "user-123-client-key",
      "keyType": "KEY_TYPE_RSA_2048",
      "providerType": "KEY_PROVIDER_TYPE_SOFTWARE",
      "status": "KEY_STATUS_ACTIVE",
      "createdAt": "2025-01-15T10:00:00Z",
      "lastRotated": "2025-01-15T10:00:00Z",
      "rotationPolicy": "ROTATION_POLICY_TIME_BASED",
      "rotationIntervalDays": 90,
      "authorizedSubjects": ["user-123"],
      "usageCount": 42,
      "metadata": {
        "client_id": "user-123",
        "environment": "production"
      }
    }
  ],
  "totalCount": 1,
  "nextPageToken": ""
}
```

### Getting a Specific Key

```bash
# Get key details including public key
grpcurl -plaintext \
    -d '{
        "key_id": "key-abc123def456",
        "include_public_key": true
    }' \
    localhost:50052 keymanager.KeyManagerService/GetKey
```

**Response:**

```json
{
  "key": {
    "keyId": "key-abc123def456",
    "name": "user-123-client-key",
    "keyType": "KEY_TYPE_RSA_2048",
    "status": "KEY_STATUS_ACTIVE",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
    "authorizedSubjects": ["user-123"],
    "usageCount": 42
  }
}
```

### Deleting Client Keys

Delete a key when it's no longer needed:

```bash
# Delete key using grpcurl
grpcurl -plaintext \
    -d '{
        "key_id": "key-abc123def456",
        "force": true
    }' \
    localhost:50052 keymanager.KeyManagerService/DeleteKey
```

**Response:**

```json
{
  "success": true,
  "message": "Key key-abc123def456 successfully deleted"
}
```

### Client Public Key Management

The Key Manager also supports registering client-provided public keys (bring-your-own-key model).

#### Registering a Client Public Key

Clients can generate their own key pairs and register just the public key:

```bash
# First, generate a key pair locally
openssl genpkey -algorithm RSA -out client_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in client_private.pem -out client_public.pem

# Register the public key with Key Manager
grpcurl -plaintext \
    -d '{
        "client_id": "user-123",
        "public_key_pem": "'"$(cat client_public.pem | sed 's/$/\\n/' | tr -d '\n')"'",
        "key_type": "KEY_TYPE_RSA_2048",
        "metadata": {
            "purpose": "file-encryption",
            "generated_by": "client"
        }
    }' \
    localhost:50052 keymanager.KeyManagerService/RegisterClientKey
```

**Response:**

```json
{
  "key": {
    "keyId": "client-key-xyz789",
    "clientId": "user-123",
    "name": "",
    "keyType": "KEY_TYPE_RSA_2048",
    "providerType": "KEY_PROVIDER_TYPE_SOFTWARE",
    "status": "KEY_STATUS_ACTIVE",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----",
    "createdAt": "2025-01-15T10:00:00Z",
    "metadata": {
      "purpose": "file-encryption",
      "generated_by": "client"
    }
  },
  "success": true,
  "timestamp": "2025-01-15T10:00:00Z"
}
```

#### Getting a Client's Public Key

Retrieve a specific client's public key:

```bash
# Get active key for a client
grpcurl -plaintext \
    -d '{
        "client_id": "user-123"
    }' \
    localhost:50052 keymanager.KeyManagerService/GetClientKey

# Get specific key by ID
grpcurl -plaintext \
    -d '{
        "client_id": "user-123",
        "key_id": "client-key-xyz789"
    }' \
    localhost:50052 keymanager.KeyManagerService/GetClientKey
```

**Response:**

```json
{
  "key": {
    "keyId": "client-key-xyz789",
    "clientId": "user-123",
    "keyType": "KEY_TYPE_RSA_2048",
    "status": "KEY_STATUS_ACTIVE",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----",
    "createdAt": "2025-01-15T10:00:00Z"
  },
  "found": true,
  "timestamp": "2025-01-15T10:00:00Z"
}
```

#### Listing All Keys for a Client

List all keys registered for a specific client:

```bash
# List all keys for a client
grpcurl -plaintext \
    -d '{
        "client_id": "user-123",
        "page_size": 10,
        "include_revoked": false
    }' \
    localhost:50052 keymanager.KeyManagerService/ListClientKeys
```

**Response:**

```json
{
  "keys": [
    {
      "keyId": "client-key-xyz789",
      "clientId": "user-123",
      "keyType": "KEY_TYPE_RSA_2048",
      "status": "KEY_STATUS_ACTIVE",
      "createdAt": "2025-01-15T10:00:00Z",
      "usageCount": 150
    },
    {
      "keyId": "client-key-old123",
      "clientId": "user-123",
      "keyType": "KEY_TYPE_RSA_2048",
      "status": "KEY_STATUS_DEPRECATED",
      "createdAt": "2024-10-15T10:00:00Z",
      "usageCount": 5432
    }
  ],
  "totalCount": 2,
  "timestamp": "2025-01-15T10:00:00Z"
}
```

#### Revoking a Client Key

Revoke a compromised or outdated client key:

```bash
# Revoke a client key
grpcurl -plaintext \
    -d '{
        "client_id": "user-123",
        "key_id": "client-key-xyz789",
        "reason": "Key rotation - regular maintenance"
    }' \
    localhost:50052 keymanager.KeyManagerService/RevokeClientKey
```

**Response:**

```json
{
  "success": true,
  "timestamp": "2025-01-15T10:00:00Z"
}
```

#### Listing All Clients (Admin)

List all clients that have registered keys:

```bash
# List all clients with keys
grpcurl -plaintext \
    -d '{
        "page_size": 50
    }' \
    localhost:50052 keymanager.KeyManagerService/ListClients
```

**Response:**

```json
{
  "clients": [
    "user-123",
    "user-456",
    "service-account-abc",
    "application-xyz"
  ],
  "totalCount": 4,
  "timestamp": "2025-01-15T10:00:00Z"
}
```

## Key Generation

### Supported Algorithms

| Algorithm | Key Size | Use Case | Performance | Security |
|-----------|----------|----------|-------------|----------|
| **RSA** | 2048-bit | Client keys, compatibility | Medium | Good |
| **RSA** | 4096-bit | Admin keys, high security | Slow | Excellent |
| **Ed25519** | 256-bit | Modern systems, performance | Fast | Excellent |
| **X25519** | 256-bit | Key exchange, ECDH | Fast | Excellent |
| **AES-256-GCM** | 256-bit | Symmetric encryption | Very Fast | Excellent |

### Generating Keys

#### RSA Keys

```bash
# Generate 2048-bit RSA key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in private_key.pem -out public_key.pem

# Generate 4096-bit RSA key (admin)
openssl genpkey -algorithm RSA -out admin_private_key.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in admin_private_key.pem -out admin_public_key.pem
```

#### Ed25519 Keys

```bash
# Generate Ed25519 key
openssl genpkey -algorithm Ed25519 -out private_key.pem

# Extract public key
openssl pkey -in private_key.pem -pubout -out public_key.pem
```

#### AES Symmetric Keys

```bash
# Generate 256-bit AES key (32 bytes)
openssl rand -base64 32 > symmetric_key.txt
```

### Key Fingerprints

Calculate key fingerprints for verification:

```bash
# SHA256 fingerprint of public key
ssh-keygen -lf public_key.pem

# Or with openssl
openssl pkey -pubin -in public_key.pem -outform DER | \
    openssl dgst -sha256 -binary | \
    base64
```

## Key Storage

### Storage Options

#### 1. Database Storage

Client public keys are stored in the database:

```sql
CREATE TABLE client_keys (
    id UUID PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    key_type VARCHAR(50) NOT NULL,
    public_key BYTEA NOT NULL,
    encrypted_private_key BYTEA,  -- Only if server-generated
    key_metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by VARCHAR(255),
    revocation_reason TEXT
);
```

#### 2. HSM Storage

For maximum security, store admin private keys in HSM:

```yaml
admin_key:
  storage: "hsm"
  hsm:
    type: "pkcs11"
    library_path: "/usr/lib/libpkcs11.so"
    slot: 0
    pin: "${HSM_PIN}"
    key_label: "stratium-admin"
```

#### 3. Secrets Manager

Store admin keys in a secrets manager:

```yaml
admin_key:
  storage: "vault"
  vault:
    address: "https://vault.example.com"
    path: "secret/data/stratium/admin/key"
```

### Client-Side Storage

Clients must store their private keys securely:

**Best Practices:**
- **Never** store in source code
- **Never** commit to version control
- Use encrypted storage (OS keychain, password manager)
- Set appropriate file permissions (600 for private keys)

```bash
# Set restrictive permissions
chmod 600 private_key.pem
chmod 644 public_key.pem

# Verify permissions
ls -l *.pem
# -rw------- 1 user user 1234 Jan 15 10:00 private_key.pem
# -rw-r--r-- 1 user user  456 Jan 15 10:00 public_key.pem
```

## Key Rotation

### Automated Key Rotation

Configure automatic key rotation:

```yaml
key_management:
  rotation:
    enabled: true

    # Client keys
    client_keys:
      rotation_period: 90d  # Rotate every 90 days
      advance_notice: 14d   # Notify 14 days before expiration
      grace_period: 7d      # Allow old key for 7 days after rotation

    # Admin keys
    admin_keys:
      rotation_period: 365d  # Rotate annually
      advance_notice: 30d
      require_manual_approval: true
```

### Manual Key Rotation

#### Client Key Rotation

```bash
# 1. Generate new key pair
openssl genpkey -algorithm RSA -out new_private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in new_private_key.pem -out new_public_key.pem

# 2. Register new public key
curl -X POST https://stratium.example.com/api/v1/keys/register \
    -H "Authorization: Bearer $TOKEN" \
    -d @- <<EOF
{
    "client_id": "user-123",
    "public_key": "$(cat new_public_key.pem)",
    "key_type": "rsa"
}
EOF

# 3. Update applications to use new private key

# 4. Revoke old key after transition period
curl -X POST https://stratium.example.com/api/v1/keys/old-key-id/revoke \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"reason": "Routine key rotation"}'
```

#### Admin Key Rotation

```bash
# 1. Generate new admin key pair
stratium admin generate-key \
    --algorithm rsa \
    --key-size 4096 \
    --output-private ./new_admin_private_key.pem \
    --output-public ./new_admin_public_key.pem

# 2. Update configuration to use new key
# (Keep old key available for decrypting existing files)

# 3. Re-encrypt critical files with new admin key (optional)
stratium admin bulk-reencrypt \
    --old-admin-key ./admin_private_key.pem \
    --new-admin-key ./new_admin_private_key.pem \
    --file-pattern "*.ztdf"

# 4. Securely destroy old admin key after transition
shred -u admin_private_key.pem
```

### Key Rotation Notifications

Users should be notified before key expiration:

```bash
# Get keys expiring soon
curl https://stratium.example.com/api/v1/keys/expiring?days=30 \
    -H "Authorization: Bearer $TOKEN"
```

**Response:**

```json
{
  "expiring_keys": [
    {
      "id": "key-abc123",
      "client_id": "user-123",
      "expires_at": "2025-02-14T00:00:00Z",
      "days_until_expiration": 25
    }
  ]
}
```

## ZTDF Operations

### Encrypting Files

#### Encrypt with Client Key

```bash
# Encrypt file using client's public key
stratium ztdf encrypt \
    --input sensitive_data.txt \
    --output sensitive_data.ztdf \
    --client-id user-123 \
    --policy-attributes '{"classification": "SECRET", "project": "alpha"}'
```

**What happens:**
1. Generate random AES-256 symmetric key
2. Encrypt file content with symmetric key
3. Wrap symmetric key with client's public key
4. Also wrap symmetric key with admin public key (for recovery)
5. Embed policy attributes in ZTDF header
6. Write encrypted ZTDF file

#### Encrypt with Admin Key Only

```bash
# Encrypt for admin-only access
stratium ztdf encrypt \
    --input admin_document.txt \
    --output admin_document.ztdf \
    --admin-key-only \
    --policy-attributes '{"classification": "TOP-SECRET", "department": "executive"}'
```

### Decrypting Files

#### Decrypt with Client Key

```bash
# Decrypt file using client's private key
stratium ztdf decrypt \
    --input sensitive_data.ztdf \
    --output sensitive_data.txt \
    --private-key ./client_private_key.pem
```

**Process:**
1. Read ZTDF header
2. Extract policy attributes
3. **Evaluate policies** (authorization check)
4. If authorized, unwrap symmetric key using client private key
5. Decrypt file content with symmetric key
6. Write plaintext output

#### Decrypt with Admin Key

```bash
# Emergency access using admin key
stratium ztdf decrypt \
    --input sensitive_data.ztdf \
    --output sensitive_data.txt \
    --admin-key ./admin_private_key.pem \
    --bypass-policy \
    --reason "Emergency access - incident #789"
```

⚠️ **Warning**: Admin key decryption bypasses policy evaluation. This is logged for audit.

### Inspecting ZTDF Files

View ZTDF metadata without decrypting:

```bash
# Show ZTDF file information
stratium ztdf info encrypted_file.ztdf
```

**Output:**

```
ZTDF File Information:
  Version: 1.0
  Encrypted: Yes
  Created: 2025-01-15T10:00:00Z
  File Size: 1,234,567 bytes
  Encrypted Size: 1,234,890 bytes

Policy Attributes:
  classification: SECRET
  project: alpha
  department: engineering

Encryption:
  Algorithm: AES-256-GCM
  Key Recipients:
    - Client: user-123 (RSA-2048)
    - Admin: admin-key (RSA-4096)

Signature:
  Signed: Yes
  Signer: user-123
  Signature Algorithm: RSA-SHA256
```

## Security Best Practices

### 1. Protect Private Keys

**NEVER:**
- Store private keys in source code
- Commit private keys to version control
- Send private keys over email or chat
- Store private keys in plaintext

**ALWAYS:**
- Use restrictive file permissions (600)
- Encrypt private keys at rest
- Use HSM for admin keys in production
- Implement key access logging

### 2. Use Strong Key Sizes

Minimum recommended key sizes:

- **RSA**: 2048-bit (client keys), 4096-bit (admin keys)
- **Ed25519**: 256-bit (default)
- **AES**: 256-bit (symmetric encryption)

### 3. Implement Key Expiration

Set expiration dates on all keys:

```yaml
key_management:
  default_expiration:
    client_keys: 90d  # 90 days
    admin_keys: 365d  # 1 year
```

### 4. Rotate Keys Regularly

- **Client keys**: Every 90 days
- **Admin keys**: Annually
- **Immediately**: If compromise suspected

### 5. Audit Key Operations

Enable comprehensive audit logging:

```yaml
audit:
  log_key_operations: true
  events:
    - key_generation
    - key_registration
    - key_usage
    - key_rotation
    - key_revocation
    - admin_key_usage
```

### 6. Multi-Factor Authentication for Admin Keys

Require MFA for admin key operations:

```yaml
admin_key:
  require_mfa: true
  mfa_methods:
    - totp
    - hardware_token
```

### 7. Implement Key Backup and Recovery

**Backup Strategy:**
- Store admin key backup in secure offline location
- Use Shamir's Secret Sharing for key splitting
- Require multiple parties for key recovery

```bash
# Split admin key using Shamir's Secret Sharing
stratium admin split-key \
    --input admin_private_key.pem \
    --shares 5 \
    --threshold 3 \
    --output-dir ./key_shares/

# Recover key (requires 3 of 5 shares)
stratium admin recover-key \
    --shares ./key_shares/share1.json \
    --shares ./key_shares/share3.json \
    --shares ./key_shares/share4.json \
    --output admin_private_key_recovered.pem
```

### 8. Limit Admin Key Usage

Restrict admin key operations:

- Require explicit reason/justification
- Implement approval workflow
- Alert security team on usage
- Time-bound admin access

### 9. Hardware Security Modules (HSM)

For production environments, use HSM:

```yaml
admin_key:
  storage: "hsm"
  hsm:
    type: "aws_cloudhsm"
    cluster_id: "cluster-abc123"
    # Keys never leave HSM
```

### 10. Key Destruction

Securely destroy revoked/expired keys:

```bash
# Secure file deletion
shred -u -n 3 old_private_key.pem

# Or use secure delete
srm old_private_key.pem

# For HSM keys
stratium admin destroy-key --key-id key-abc123 --confirm
```

## Troubleshooting

### Key Not Found

**Error**: `client key not found` or `key does not exist`

**Solutions:**

1. **Verify key is registered**:
   ```bash
   curl https://stratium.example.com/api/v1/keys?client_id=user-123 \
       -H "Authorization: Bearer $TOKEN"
   ```

2. **Check key expiration**:
   ```bash
   curl https://stratium.example.com/api/v1/keys/key-id \
       -H "Authorization: Bearer $TOKEN"
   ```

3. **Verify client ID matches**

### Decryption Failed

**Error**: `failed to decrypt` or `invalid key`

**Solutions:**

1. **Verify you have the correct private key**:
   ```bash
   # Calculate fingerprint
   openssl pkey -in private_key.pem -pubout -outform DER | \
       openssl dgst -sha256
   ```

2. **Check key hasn't been revoked**

3. **Verify file is encrypted for your key**:
   ```bash
   stratium ztdf info file.ztdf
   ```

### Key Expired

**Error**: `key has expired`

**Solutions:**

1. **Generate and register new key**:
   ```bash
   # Generate new key
   openssl genpkey -algorithm RSA -out new_key.pem -pkeyopt rsa_keygen_bits:2048
   openssl rsa -pubout -in new_key.pem -out new_public_key.pem

   # Register
   curl -X POST https://stratium.example.com/api/v1/keys/register \
       -H "Authorization: Bearer $TOKEN" \
       -d @- <<EOF
   {
       "client_id": "user-123",
       "public_key": "$(cat new_public_key.pem)"
   }
   EOF
   ```

2. **For existing encrypted files, use admin key to re-encrypt**

### Admin Key Access Denied

**Error**: `admin key operation requires authorization`

**Solutions:**

1. **Provide justification**:
   ```bash
   stratium admin decrypt-file \
       --input file.ztdf \
       --admin-key ./admin_key.pem \
       --reason "Emergency access - incident #12345" \
       --ticket-id "INC-12345"
   ```

2. **Complete MFA if required**

3. **Verify admin key permissions**

## API Reference

### Key Management Endpoints

```bash
# Register public key
POST /api/v1/keys/register
Content-Type: application/json
{
  "client_id": "user-123",
  "public_key": "...",
  "key_type": "rsa",
  "expires_at": "2026-01-15T00:00:00Z"
}

# Generate key pair (server-side)
POST /api/v1/keys/generate
Content-Type: application/json
{
  "client_id": "user-123",
  "key_type": "rsa",
  "key_size": 2048
}

# List keys
GET /api/v1/keys?client_id=user-123

# Get specific key
GET /api/v1/keys/{key_id}

# Revoke key
POST /api/v1/keys/{key_id}/revoke
Content-Type: application/json
{
  "reason": "Key compromise suspected"
}

# Delete key
DELETE /api/v1/keys/{key_id}

# Get expiring keys
GET /api/v1/keys/expiring?days=30
```

## Next Steps

- [ZTDF File Format Specification](../ztdf/FILE_FORMAT.md)
- [Secrets Manager Integration](./SECRETS_MANAGER.md)
- [Security Best Practices](../security/BEST_PRACTICES.md)
- [Audit Logging](../audit/AUDIT_LOGGING.md)

## Support

Need help with key management?
- Technical Support: support@stratium.example
- Documentation Issues: Create an issue in the repository
- Security Issues: security@stratium.example

## License

Copyright © 2025 Stratium Data