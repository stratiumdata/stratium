package ztdf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"stratium/pkg/models"
)

// GenerateDEK generates a random 256-bit AES key for data encryption
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32) // AES-256
	if _, err := rand.Read(dek); err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to generate DEK",
			Err:     err,
		}
	}
	return dek, nil
}

// EncryptPayload encrypts plaintext with AES-256-GCM using the provided key
// Returns the ciphertext and initialization vector (IV)
func EncryptPayload(plaintext, key []byte) (ciphertext, iv []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to create AES cipher",
			Err:     err,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to create GCM mode",
			Err:     err,
		}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to generate nonce",
			Err:     err,
		}
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptPayload decrypts ciphertext with AES-256-GCM using the provided key and IV
func DecryptPayload(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "failed to create AES cipher",
			Err:     err,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "failed to create GCM mode",
			Err:     err,
		}
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "decryption failed",
			Err:     err,
		}
	}

	return plaintext, nil
}

// EncryptDEKWithPublicKey encrypts a DEK using RSA-OAEP with SHA-256
func EncryptDEKWithPublicKey(publicKey *rsa.PublicKey, dek []byte) ([]byte, error) {
	encryptedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, dek, nil)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to encrypt DEK with public key",
			Err:     err,
		}
	}
	return encryptedDEK, nil
}

// DecryptDEKWithPrivateKey decrypts a DEK using RSA-OAEP with SHA-256
func DecryptDEKWithPrivateKey(privateKey *rsa.PrivateKey, encryptedDEK []byte) ([]byte, error) {
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedDEK, nil)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "failed to decrypt DEK with private key",
			Err:     err,
		}
	}
	return dek, nil
}

// WrapDEKWithPrivateKey wraps a DEK using the client's private RSA key (PKCS#1 v1.5 signing format)
func WrapDEKWithPrivateKey(privateKey *rsa.PrivateKey, dek []byte) ([]byte, error) {
	k := (privateKey.N.BitLen() + 7) / 8
	if len(dek) > k-11 {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "DEK too large for client key",
		}
	}

	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x01
	psLen := k - len(dek) - 3
	for i := 0; i < psLen; i++ {
		em[2+i] = 0xff
	}
	em[2+psLen] = 0x00
	copy(em[3+psLen:], dek)

	m := new(big.Int).SetBytes(em)
	if m.Cmp(privateKey.N) >= 0 {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "message representative out of range",
		}
	}

	var c *big.Int
	if privateKey.Precomputed.Dp == nil {
		c = new(big.Int).Exp(m, privateKey.D, privateKey.N)
	} else {
		c = new(big.Int).Exp(m, privateKey.D, privateKey.N)
	}

	out := c.Bytes()
	if len(out) < k {
		padded := make([]byte, k)
		copy(padded[k-len(out):], out)
		out = padded
	}
	return out, nil
}

// CalculatePolicyBinding computes HMAC-SHA256 of the policy using the DEK as the key
// This creates a binding between the DEK and the policy to prevent tampering
func CalculatePolicyBinding(dek []byte, policyBase64 string) string {
	h := hmac.New(sha256.New, dek)
	h.Write([]byte(policyBase64))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// VerifyPolicyBinding verifies the HMAC of the policy matches the expected hash
func VerifyPolicyBinding(dek []byte, policyBase64 string, expectedHash string) error {
	calculatedHash := CalculatePolicyBinding(dek, policyBase64)
	if calculatedHash != expectedHash {
		return &models.Error{
			Code:    models.ErrCodeIntegrityFailed,
			Message: "policy binding verification failed: HMAC mismatch",
		}
	}
	return nil
}

// CalculatePayloadHash computes SHA-256 hash of the payload for integrity verification
func CalculatePayloadHash(payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return hash[:]
}

// VerifyPayloadHash verifies the payload hash matches the expected hash
func VerifyPayloadHash(payload []byte, expectedHash []byte) error {
	actualHash := CalculatePayloadHash(payload)
	if !hmac.Equal(actualHash, expectedHash) {
		return &models.Error{
			Code:    models.ErrCodeIntegrityFailed,
			Message: "payload integrity verification failed: hash mismatch",
		}
	}
	return nil
}
