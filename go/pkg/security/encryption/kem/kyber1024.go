package kem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

// =============================================================================
// Kyber1024
// =============================================================================

// Kyber1024Provider implements the KEMKeyGenerator interface.
type Kyber1024Provider struct {
	KyberAlgorithm

	pk *kyber1024.PublicKey
	sk *kyber1024.PrivateKey
}

// NewKyber1024Provider uses the underlying kyber1024 package to create keys for the new provider.
func NewKyber1024Provider() (*Kyber1024Provider, error) {
	// kyber1024.GenerateKeyPair returns the concrete Kyber types.
	publicKey, privateKey, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return &Kyber1024Provider{}, err
	}

	// We return the concrete types as the required interfaces,
	// and the size constants for buffer allocation.
	return &Kyber1024Provider{
		pk: publicKey,
		sk: privateKey,
		KyberAlgorithm: KyberAlgorithm{
			ciphertextSize: kyber1024.CiphertextSize,
			sharedKeySize:  kyber1024.SharedKeySize,
		},
	}, nil
}

// EncapsulateTo Helper to bridge the gap: *kyber1024.PublicKey implements PublicKeyKEM.
// This function wraps the original EncapsulateTo to simplify the caller interface.
func (provider *Kyber1024Provider) EncapsulateTo(seed []byte) ([]byte, []byte) {
	// The original method requires a seed argument, which we set to nil to use
	// an internal cryptographically secure random number generator.
	ct := make([]byte, provider.ciphertextSize)
	ss := make([]byte, provider.sharedKeySize)

	provider.pk.EncapsulateTo(ct, ss, seed)

	return ct, ss
}

// DecapsulateTo Helper to bridge the gap: *kyber1024.PrivateKey implements PrivateKeyKEM.
func (provider *Kyber1024Provider) DecapsulateTo(ct []byte) []byte {
	rs := make([]byte, provider.sharedKeySize)

	provider.sk.DecapsulateTo(rs, ct)

	return rs
}

func (provider *Kyber1024Provider) Encrypt(key, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Seal will append the nonce to the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, pt, nil)
	return ciphertext, nil
}

func (provider *Kyber1024Provider) Decrypt(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ct) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Split the nonce from the ciphertext.
	nonce, ciphertext := ct[:nonceSize], ct[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
