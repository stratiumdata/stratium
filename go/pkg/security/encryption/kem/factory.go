package kem

import (
	"fmt"
	"stratium/pkg/security/encryption"
)

type KyberAlgorithm struct {
	ciphertextSize int
	sharedKeySize  int
}

type KyberProvider interface {
	encryption.Provider

	EncapsulateTo(seed []byte) ([]byte, []byte)
	DecapsulateTo(ct []byte) []byte
}

// NewKEMProvider creates and returns the KEM provider based on the algorithm name.
func NewKEMProvider(alg encryption.Algorithm) (KyberProvider, error) {
	var provider KyberProvider
	var err error

	switch alg {
	case encryption.KYBER512:
		provider, err = NewKyber512Provider()
	case encryption.KYBER768:
		provider, err = NewKyber768Provider()
	case encryption.KYBER1024:
		provider, err = NewKyber1024Provider()
	default:
		return nil, fmt.Errorf("unsupported KEM algorithm: %s. Set KEM_ALGORITHM to KYBER1024", alg)
	}

	if err != nil {
		return nil, err
	}
	return provider, nil
}
