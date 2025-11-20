package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// EncryptWithPublicKey encrypts data using RSA-OAEP with the given public key
func EncryptWithPublicKey(publicKey crypto.PublicKey, plaintext []byte) ([]byte, error) {
	rsaPubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA type")
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data using RSA-OAEP with the given private key
func DecryptWithPrivateKey(privateKey crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	rsaPrivKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA type")
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decryption failed: %w", err)
	}

	return plaintext, nil
}

// SignWithPrivateKey signs data using RSA-PSS with the given private key
func SignWithPrivateKey(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	rsaPrivKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA type")
	}

	hash := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("RSA signing failed: %w", err)
	}

	return signature, nil
}

// VerifySignature verifies an RSA signature
func VerifySignature(publicKey crypto.PublicKey, data []byte, signature []byte) error {
	rsaPubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA type")
	}

	hash := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// GenerateRSAKeyPair generates a new RSA key pair with the specified bit size
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	return privateKey, nil
}