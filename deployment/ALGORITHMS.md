# Encryption Algorithm Configuration Guide

This guide explains how to configure and test different encryption algorithms in the Stratium deployment.

## Available Algorithms

The `ENCRYPTION_ALGORITHM` environment variable accepts the following values from `stratium/security/encryption.Algorithm`:

### RSA Family
- **RSA2048** - 2048-bit RSA keys (fast, minimum recommended security)
- **RSA3072** - 3072-bit RSA keys (balanced performance and security)
- **RSA4096** - 4096-bit RSA keys (slower, highest classical security)

### Elliptic Curve Cryptography (ECC)
- **P256** - NIST P-256 curve (fast, ~128-bit security level)
- **P384** - NIST P-384 curve (balanced, ~192-bit security level)
- **P521** - NIST P-521 curve (slower, ~256-bit security level)

### Post-Quantum KEM (Kyber)
- **KYBER512** - Kyber-512 (fast, ~128-bit quantum security)
- **KYBER768** - Kyber-768 (balanced, ~192-bit quantum security, **recommended**)
- **KYBER1024** - Kyber-1024 (slower, ~256-bit quantum security)

## Configuration Methods

### Method 1: Environment Variables (Per Service)

Set individual algorithms for each service:

```bash
export PLATFORM_ENCRYPTION_ALGORITHM=RSA2048
export KEY_MANAGER_ENCRYPTION_ALGORITHM=P256
export KEY_ACCESS_ENCRYPTION_ALGORITHM=KYBER768
```

### Method 2: .env File

Edit `deployment/.env`:

```bash
PLATFORM_ENCRYPTION_ALGORITHM=RSA2048
KEY_MANAGER_ENCRYPTION_ALGORITHM=RSA2048
KEY_ACCESS_ENCRYPTION_ALGORITHM=RSA2048
```

### Method 3: Docker Compose Override Files

Use the provided override files for algorithm families:

#### Test RSA2048 (Default)
```bash
cd deployment
docker-compose up --build
```

#### Test RSA4096
```bash
cd deployment
export RSA_ALGORITHM=RSA4096
docker-compose -f docker-compose.yml -f docker-compose.rsa.yml up --build
```

#### Test P256 (ECC)
```bash
cd deployment
export ECC_ALGORITHM=P256
docker-compose -f docker-compose.yml -f docker-compose.ecc.yml up --build
```

#### Test P521 (ECC - Higher Security)
```bash
cd deployment
export ECC_ALGORITHM=P521
docker-compose -f docker-compose.yml -f docker-compose.ecc.yml up --build
```

#### Test KYBER768 (Post-Quantum)
```bash
cd deployment
export KYBER_ALGORITHM=KYBER768
docker-compose -f docker-compose.yml -f docker-compose.kem.yml up --build
```

## Testing Different Algorithms

### Quick Test Script

Create `deployment/test-algorithms.sh`:

```bash
#!/bin/bash

algorithms=("RSA2048" "RSA3072" "RSA4096" "P256" "P384" "P521" "KYBER512" "KYBER768" "KYBER1024")

for algo in "${algorithms[@]}"; do
  echo "====================================="
  echo "Testing algorithm: $algo"
  echo "====================================="

  # Set algorithm for all services
  export PLATFORM_ENCRYPTION_ALGORITHM=$algo
  export KEY_MANAGER_ENCRYPTION_ALGORITHM=$algo
  export KEY_ACCESS_ENCRYPTION_ALGORITHM=$algo

  # Start services
  docker-compose up -d

  # Wait for health checks
  sleep 15

  # Run your tests here
  # Example: grpcurl -plaintext localhost:50052 keymanager.KeyManagerService/ListProviders

  # Stop services
  docker-compose down

  echo ""
done
```

### Verify Algorithm in Use

Check the logs to verify which algorithm is active:

```bash
# Check Key Manager logs
docker-compose logs key-manager | grep -i algorithm

# Check Key Access logs
docker-compose logs key-access | grep -i algorithm
```

## Performance Comparison

Run benchmarks for different algorithms:

```bash
# RSA Family
cd deployment
for size in RSA2048 RSA3072 RSA4096; do
  export RSA_ALGORITHM=$size
  echo "Benchmarking $size..."
  docker-compose -f docker-compose.yml -f docker-compose.rsa.yml up -d
  # Run your benchmark suite
  docker-compose down
done

# ECC Family
for curve in P256 P384 P521; do
  export ECC_ALGORITHM=$curve
  echo "Benchmarking $curve..."
  docker-compose -f docker-compose.yml -f docker-compose.ecc.yml up -d
  # Run your benchmark suite
  docker-compose down
done

# Kyber Family
for level in KYBER512 KYBER768 KYBER1024; do
  export KYBER_ALGORITHM=$level
  echo "Benchmarking $level..."
  docker-compose -f docker-compose.yml -f docker-compose.kem.yml up -d
  # Run your benchmark suite
  docker-compose down
done
```

## Security Recommendations

### Development/Testing
- **RSA2048** - Fast, suitable for local development
- **P256** - Modern, good performance for testing ECC

### Production (Classical Threats)
- **RSA3072** or **RSA4096** - Future-proof classical security
- **P384** or **P521** - High-security ECC deployments

### Production (Quantum-Resistant)
- **KYBER768** - Balanced post-quantum security (NIST recommended)
- **KYBER1024** - Maximum post-quantum security

### Hybrid Approach
For maximum security, consider using different algorithms per service:

```bash
PLATFORM_ENCRYPTION_ALGORITHM=P384      # Fast ECC for frequent operations
KEY_MANAGER_ENCRYPTION_ALGORITHM=KYBER768   # Quantum-resistant for key management
KEY_ACCESS_ENCRYPTION_ALGORITHM=RSA4096     # Strong classical for data encryption
```

## Troubleshooting

### Invalid Algorithm Error
```
Error: invalid ENCRYPTION_ALGORITHM: unsupported algorithm: RSA
```

**Solution:** Use exact algorithm names from the list above (e.g., `RSA2048` not `RSA`).

### Algorithm Not Supported by Service
Some services may not support all algorithms. Check service logs:

```bash
docker-compose logs [service-name] | grep -i "unsupported"
```

### Performance Issues
If you experience slow performance:
- Switch to smaller key sizes (RSA2048, P256, KYBER512)
- Check if quantum resistance is required for your use case
- Consider using ECC for better performance/security ratio

## Example: Complete Test Workflow

```bash
cd deployment

# 1. Test with RSA2048 (baseline)
echo "Testing RSA2048..."
export RSA_ALGORITHM=RSA2048
docker-compose -f docker-compose.yml -f docker-compose.rsa.yml up -d
# Run tests
docker-compose down

# 2. Test with P256 (ECC)
echo "Testing P256..."
export ECC_ALGORITHM=P256
docker-compose -f docker-compose.yml -f docker-compose.ecc.yml up -d
# Run tests
docker-compose down

# 3. Test with KYBER768 (Post-Quantum)
echo "Testing KYBER768..."
export KYBER_ALGORITHM=KYBER768
docker-compose -f docker-compose.yml -f docker-compose.kem.yml up -d
# Run tests
docker-compose down

echo "Algorithm testing complete!"
```

## Integration with Code

The services read the `ENCRYPTION_ALGORITHM` environment variable using the `config` package:

```go
import "stratium/config"
import "stratium/security/encryption"

// Load configuration
cfg, err := config.LoadFromEnv()
if err != nil {
    log.Fatalf("Failed to load config: %v", err)
}

// Use the algorithm
algorithm := cfg.EncryptionAlgorithm
log.Printf("Using encryption algorithm: %s", algorithm)
```

The algorithm value is then used when creating keys or performing cryptographic operations.
