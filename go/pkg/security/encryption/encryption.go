package encryption

import (
	"fmt"
)

type Algorithm string

const (
	// Post-Quantum Cryptography (KEM-based algorithms)
	KYBER512  Algorithm = "KYBER512"
	KYBER768  Algorithm = "KYBER768"
	KYBER1024 Algorithm = "KYBER1024"

	// Classical asymmetric encryption algorithms
	RSA2048 Algorithm = "RSA2048"
	RSA3072 Algorithm = "RSA3072"
	RSA4096 Algorithm = "RSA4096"

	// Elliptic Curve Cryptography algorithms
	ECC_P256 Algorithm = "P256"
	ECC_P384 Algorithm = "P384"
	ECC_P521 Algorithm = "P521"
)

// ParseAlgorithm converts a string (usually from an environment variable)
// into the corresponding Algorithm type.
func ParseAlgorithm(alg string) (Algorithm, error) {
	switch Algorithm(alg) {
	case KYBER512:
		return KYBER512, nil
	case KYBER768:
		return KYBER768, nil
	case KYBER1024:
		return KYBER1024, nil
	case RSA2048:
		return RSA2048, nil
	case RSA3072:
		return RSA3072, nil
	case RSA4096:
		return RSA4096, nil
	case ECC_P256:
		return ECC_P256, nil
	case ECC_P384:
		return ECC_P384, nil
	case ECC_P521:
		return ECC_P521, nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

type Provider interface {
	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
}
