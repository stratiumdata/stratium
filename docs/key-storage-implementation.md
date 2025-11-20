# Encrypted Key Storage Implementation

## Overview

This document describes the implementation of persistent, encrypted key storage for the Stratium Key Manager service. Software keys (asymmetric keys) are now stored in a **separate PostgreSQL database** (`stratium_keymanager`) with encryption using a master "admin" key.

**Database Isolation:** The Key Manager uses its own dedicated database (`stratium_keymanager`), completely separate from the PAP database (`stratium_pap`). This provides better security isolation and allows for independent backup, scaling, and security policies for cryptographic key material.

## Architecture

### Components

1. **Admin Key Manager** (`admin_key.go`)
   - Manages the master encryption key (KEK - Key Encryption Key)
   - Supports multiple providers for admin key storage
   - Generates new admin keys with proper entropy

2. **Key Encryption** (`key_encryption.go`)
   - Encrypts/decrypts private key material using AES-256-GCM
   - Handles serialization of different key types (RSA, ECC, Kyber)
   - Provides PEM conversion utilities

3. **PostgreSQL Key Store** (`postgres_key_store.go`)
   - Implements persistent key storage with encryption
   - Stores encrypted private keys in PostgreSQL
   - Provides full CRUD operations for key pairs

4. **Database Schema** (`deployment/postgres/init.sql`)
   - `admin_keys` - Stores admin key metadata
   - `key_pairs` - Stores encrypted asymmetric key pairs
   - `client_keys` - Stores client public keys
   - `key_audit_logs` - Audit trail for all key operations

## Security Design

### Encryption Flow

```
┌─────────────────┐
│  Admin Key      │ (32-byte AES-256 key)
│  (KEK)          │ Stored in secrets manager or file
└────────┬────────┘
         │
         ├─────> Encrypts private key material (AES-256-GCM)
         │
         v
┌─────────────────┐
│  Encrypted      │
│  Private Keys   │ Stored in PostgreSQL
└─────────────────┘
```

### Key Hierarchy

1. **Admin Key (KEK)** - 256-bit symmetric key
   - Encrypts all private key material
   - Stored externally (secrets manager or encrypted file)
   - Can be rotated (requires re-encryption of all keys)

2. **Private Keys (DEK)** - Asymmetric keys
   - RSA (2048, 3072, 4096-bit)
   - ECC (P-256, P-384, P-521)
   - Post-Quantum Kyber (512, 768, 1024-bit)
   - Encrypted at rest using admin key

3. **Public Keys**
   - Stored in plaintext (not sensitive)
   - Used for encryption and verification

## Admin Key Providers

### Environment Variable Provider

```bash
export STRATIUM_ADMIN_KEY="<base64-encoded-32-byte-key>"
```

**Use Case:** Development/testing only
**Security:** Not recommended for production

### File Provider

```bash
# Store admin key in a file
echo "<base64-encoded-32-byte-key>" > /var/run/secrets/stratium/admin-key
chmod 600 /var/run/secrets/stratium/admin-key
```

**Use Case:** Docker volumes, persistent storage
**Security:** Good for Docker deployments with volume encryption

### Composite Provider (Recommended)

Tries multiple providers in order:
1. File provider (`/var/run/secrets/stratium/admin-key`)
2. Environment variable (`STRATIUM_ADMIN_KEY`)

**Use Case:** Production with fallback
**Security:** Flexible, allows migration

### Future: Secrets Manager Providers

Planned support for:
- **AWS Secrets Manager**
- **HashiCorp Vault**
- **Google Cloud Secret Manager**
- **Azure Key Vault**

## Configuration

### Environment Variables

```bash
# Database connection for Key Manager (separate from PAP database)
DATABASE_URL=postgres://stratium:stratium@postgres:5432/stratium_keymanager?sslmode=disable

# Admin key provider type: "env", "file", or "composite"
ADMIN_KEY_PROVIDER=composite

# Configuration for the provider (path or env var name)
ADMIN_KEY_CONFIG=/var/run/secrets/stratium/admin-key

# Optional: Direct admin key (development only)
# STRATIUM_ADMIN_KEY=<base64-encoded-key>
```

### Docker Deployment

#### Using Docker Volumes

```yaml
services:
  key-manager:
    image: stratium/key-manager:latest
    volumes:
      - key-storage:/var/run/secrets/stratium
    environment:
      - DATABASE_URL=postgres://stratium:stratium@postgres:5432/stratium_pap
      - ADMIN_KEY_PROVIDER=file
      - ADMIN_KEY_CONFIG=/var/run/secrets/stratium/admin-key

volumes:
  key-storage:
    driver: local
```

**Benefits:**
- Admin key persists across container restarts
- Volume can be backed up independently
- Can be encrypted at the volume level

#### Using Docker Secrets

```yaml
services:
  key-manager:
    image: stratium/key-manager:latest
    secrets:
      - admin_key
    environment:
      - DATABASE_URL=postgres://stratium:stratium@postgres:5432/stratium_pap
      - ADMIN_KEY_PROVIDER=file
      - ADMIN_KEY_CONFIG=/run/secrets/admin_key

secrets:
  admin_key:
    external: true
```

**Benefits:**
- Secure secret distribution
- Encrypted in transit and at rest
- Integrated with Docker Swarm

## Database Schema

### Admin Keys Table

```sql
CREATE TABLE admin_keys (
    id UUID PRIMARY KEY,
    key_id VARCHAR(255) NOT NULL UNIQUE,
    encrypted_key_material BYTEA NOT NULL,
    encryption_algorithm VARCHAR(50) DEFAULT 'AES-256-GCM',
    key_version INTEGER DEFAULT 1,
    status VARCHAR(20) CHECK (status IN ('active', 'rotated', 'revoked')),
    created_at TIMESTAMP WITH TIME ZONE,
    rotated_at TIMESTAMP WITH TIME ZONE
);
```

### Key Pairs Table

```sql
CREATE TABLE key_pairs (
    id UUID PRIMARY KEY,
    key_id VARCHAR(255) NOT NULL UNIQUE,
    key_type VARCHAR(50) CHECK (key_type IN ('RSA', 'ECC', 'Kyber')),
    provider_type VARCHAR(50) CHECK (provider_type IN ('software', 'hsm', 'smartcard')),

    -- Public key (plaintext)
    public_key_pem TEXT NOT NULL,

    -- Private key (encrypted with admin key)
    encrypted_private_key BYTEA NOT NULL,
    encryption_algorithm VARCHAR(50) DEFAULT 'AES-256-GCM',
    encryption_key_id VARCHAR(255) REFERENCES admin_keys(key_id),
    nonce BYTEA,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Usage tracking
    usage_count BIGINT DEFAULT 0,
    max_usage_count BIGINT,

    metadata JSONB
);
```

## Operations

### Initialization

On first startup, the Key Manager:

1. Connects to PostgreSQL
2. Creates or loads the admin key
3. Initializes the PostgreSQL key store with encryption
4. Falls back to in-memory storage if PostgreSQL fails

```
✓ Database connection established
✓ Admin key provider created: composite(file,env)
✓ Admin key loaded successfully
✓ PostgreSQL key store initialized with encryption
==================================================================
IMPORTANT: All private keys are encrypted with the admin key
Ensure the admin key is backed up to your secrets manager!
==================================================================
```

### Key Creation

When creating a new key:

1. Generate asymmetric key pair (RSA/ECC/Kyber)
2. Serialize private key to bytes
3. Encrypt private key with admin key using AES-256-GCM
4. Store encrypted private key + public key in PostgreSQL
5. Record audit log entry

### Key Retrieval

When retrieving a key for cryptographic operations:

1. Load encrypted private key from PostgreSQL
2. Decrypt using admin key
3. Deserialize to appropriate key type
4. Return key pair for use

### Admin Key Rotation

To rotate the admin key:

```go
oldKey, newKey, err := adminKeyMgr.RotateAdminKey(ctx)
if err != nil {
    return err
}

// Re-encrypt all keys with new admin key
keys, err := keyStore.ListKeys(ctx, nil)
for _, key := range keys {
    keyPair, err := keyStore.GetKeyPair(ctx, key.KeyId)

    // Decrypt with old key
    oldEncryption, _ := NewKeyEncryption(oldKey)
    privateKey, _ := oldEncryption.DecryptPrivateKey(...)

    // Encrypt with new key
    newEncryption, _ := NewKeyEncryption(newKey)
    encryptedData, _ := newEncryption.EncryptPrivateKey(privateKey, keyType)

    // Update in database
    keyStore.StoreKeyPair(ctx, ...)
}
```

## Migration from In-Memory Storage

The implementation includes automatic fallback:

```go
keyStore, err := initializePostgresKeyStore(...)
if err != nil {
    log.Println("Falling back to in-memory key store (keys will not persist!)")
    keyStore = NewInMemoryKeyStore()
}
```

For manual migration:

1. Export keys from in-memory store (if needed)
2. Configure PostgreSQL connection
3. Set up admin key provider
4. Restart Key Manager service
5. Keys will now be persisted automatically

## Best Practices

### For Development

- Use file provider with local file storage
- Store admin key in project-ignored directory
- Use development database

```bash
# Generate admin key
openssl rand -base64 32 > .secrets/admin-key
chmod 600 .secrets/admin-key

export ADMIN_KEY_PROVIDER=file
export ADMIN_KEY_CONFIG=.secrets/admin-key
```

### For Production

1. **Use Secrets Manager**
   - AWS Secrets Manager, HashiCorp Vault, etc.
   - Automatic rotation support
   - Audit logging

2. **Encrypt Database**
   - Enable PostgreSQL encryption at rest
   - Use encrypted storage volumes
   - Configure SSL/TLS for connections

3. **Backup Admin Key**
   - Store encrypted backups in multiple locations
   - Use key splitting/shamir secret sharing
   - Document recovery procedures

4. **Monitor Key Usage**
   - Review `key_audit_logs` regularly
   - Alert on suspicious activity
   - Track key age and rotation

5. **Network Security**
   - Restrict database access to Key Manager only
   - Use private networks/VPC
   - Enable database authentication

## Security Considerations

### Threat Model

**Protected Against:**
- Database compromise (keys encrypted at rest)
- Unauthorized key access (encryption + audit logs)
- Key exposure in backups (encrypted)
- Memory dumps (keys encrypted in database)

**Not Protected Against:**
- Admin key compromise (full system compromise)
- Memory dumps while keys in use (decrypted in RAM)
- Compromised Key Manager process
- Side-channel attacks on cryptographic operations

### Recommendations

1. **Protect the Admin Key**
   - Use secrets manager with access controls
   - Rotate regularly (e.g., every 90 days)
   - Monitor access and usage

2. **Secure the Runtime**
   - Run Key Manager in isolated environment
   - Use minimal container images
   - Enable security scanning

3. **Audit Everything**
   - Log all key operations
   - Monitor audit logs for anomalies
   - Set up alerts for suspicious activity

4. **Plan for Incidents**
   - Document key recovery procedures
   - Test backup and restore regularly
   - Have revocation procedures ready

## Performance

### Encryption Overhead

- **AES-256-GCM**: ~100 MB/s per core
- **RSA key encryption**: <1ms per key
- **Kyber key encryption**: <1ms per key

### Database Impact

- **Key creation**: 1 INSERT (encrypted private key)
- **Key retrieval**: 1 SELECT + decryption
- **Key listing**: N SELECTs (public keys only)

### Caching

Consider implementing caching for frequently accessed keys:

```go
// Pseudocode
cachedKey, ok := cache.Get(keyID)
if !ok {
    cachedKey = keyStore.GetKeyPair(ctx, keyID)
    cache.Set(keyID, cachedKey, 5*time.Minute)
}
```

## Troubleshooting

### Admin Key Not Found

```
Error: admin key not found in environment variable STRATIUM_ADMIN_KEY
```

**Solution:** Set the admin key via environment variable or file

### Database Connection Failed

```
Error: failed to connect to database: connection refused
```

**Solution:** Check DATABASE_URL and ensure PostgreSQL is running

### Key Decryption Failed

```
Error: failed to decrypt key material: cipher: message authentication failed
```

**Possible Causes:**
- Wrong admin key (key rotation?)
- Corrupted encrypted data
- Database integrity issue

**Solution:** Verify admin key matches the one used for encryption

### Fallback to In-Memory

```
Warning: Failed to initialize PostgreSQL key store: ...
Falling back to in-memory key store (keys will not persist!)
```

**Impact:** Keys will not survive restart
**Solution:** Fix PostgreSQL connection and admin key configuration

## Future Enhancements

1. **Hardware Security Module (HSM) Integration**
   - Store admin key in HSM
   - Use HSM for all encryption operations
   - FIPS 140-2 compliance

2. **Multi-Tenant Key Isolation**
   - Separate admin keys per tenant
   - Row-level security in PostgreSQL
   - Tenant-specific encryption

3. **Key Versioning**
   - Track key version history
   - Support key rollback
   - Automated key rotation

4. **Distributed Key Management**
   - Multi-region key replication
   - Consensus-based key operations
   - Geographic key distribution

## References

- [NIST SP 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [PostgreSQL Encryption](https://www.postgresql.org/docs/current/encryption-options.html)
- [AES-GCM Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)