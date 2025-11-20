package kem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
)

// =============================================================================
// Kyber512
// =============================================================================

// Kyber512Provider implements the KEMKeyGenerator interface.
type Kyber512Provider struct {
	KyberAlgorithm

	pk *kyber512.PublicKey
	sk *kyber512.PrivateKey
}

// NewKyber512Provider uses the underlying kyber512 package to create keys for the new provider.
func NewKyber512Provider() (*Kyber512Provider, error) {
	// kyber512.GenerateKeyPair returns the concrete Kyber types.
	publicKey, privateKey, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		return &Kyber512Provider{}, err
	}

	// We return the concrete types as the required interfaces,
	// and the size constants for buffer allocation.
	return &Kyber512Provider{
		pk: publicKey,
		sk: privateKey,
		KyberAlgorithm: KyberAlgorithm{
			ciphertextSize: kyber512.CiphertextSize,
			sharedKeySize:  kyber512.SharedKeySize,
		},
	}, nil
}

// EncapsulateTo Helper to bridge the gap: *kyber512.PublicKey implements PublicKeyKEM.
// This function wraps the original EncapsulateTo to simplify the caller interface.
func (provider *Kyber512Provider) EncapsulateTo(seed []byte) ([]byte, []byte) {
	// The original method requires a seed argument, which we set to nil to use
	// an internal cryptographically secure random number generator.
	ct := make([]byte, provider.ciphertextSize)
	ss := make([]byte, provider.sharedKeySize)

	provider.pk.EncapsulateTo(ct, ss, seed)

	return ct, ss
}

// DecapsulateTo Helper to bridge the gap: *kyber512.PrivateKey implements PrivateKeyKEM.
func (provider *Kyber512Provider) DecapsulateTo(ct []byte) []byte {
	rs := make([]byte, provider.sharedKeySize)

	provider.sk.DecapsulateTo(rs, ct)

	return rs
}

func (provider *Kyber512Provider) Encrypt(key, pt []byte) ([]byte, error) {
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

func (provider *Kyber512Provider) Decrypt(key, ct []byte) ([]byte, error) {
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
