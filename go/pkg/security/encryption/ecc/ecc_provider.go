package ecc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"stratium/pkg/security/encryption"
)

type Provider struct {
	curve      elliptic.Curve
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
	curveName  string
}

// NewECCProvider creates a new ECC provider with the specified curve
func NewECCProvider(algorithm encryption.Algorithm) (*Provider, error) {
	var curve elliptic.Curve
	var ecdhCurve ecdh.Curve

	switch algorithm {
	case encryption.ECC_P256:
		curve = elliptic.P256()
		ecdhCurve = ecdh.P256()
	case encryption.ECC_P384:
		curve = elliptic.P384()
		ecdhCurve = ecdh.P384()
	case encryption.ECC_P521:
		curve = elliptic.P521()
		ecdhCurve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported ECC curve: %s", string(algorithm))
	}

	privateKey, err := ecdhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECC key: %w", err)
	}

	return &Provider{
		curve:      curve,
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
		curveName:  string(algorithm),
	}, nil
}

// deriveKey derives an AES key from the ECDH shared secret
func (e *Provider) deriveKey(sharedSecret []byte) []byte {
	hash := sha256.Sum256(sharedSecret)
	return hash[:] // Return 32 bytes for AES-256
}

// Encrypt encrypts data using ECDH + AES-GCM
func (e *Provider) Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	// Generate ephemeral key pair for this encryption
	ephemeralPrivateKey, err := e.privateKey.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := ephemeralPrivateKey.ECDH(e.publicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive AES key from shared secret
	aesKey := e.deriveKey(sharedSecret)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Prepend ephemeral public key to ciphertext
	ephemeralPublicKeyBytes := ephemeralPrivateKey.PublicKey().Bytes()
	result := make([]byte, len(ephemeralPublicKeyBytes)+len(ciphertext))
	copy(result, ephemeralPublicKeyBytes)
	copy(result[len(ephemeralPublicKeyBytes):], ciphertext)

	return result, nil
}

// Decrypt decrypts data using ECDH + AES-GCM
func (e *Provider) Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	// Extract ephemeral public key
	curve := e.privateKey.Curve()
	var ephemeralPublicKeySize int

	switch e.curveName {
	case "P256":
		ephemeralPublicKeySize = 65 // 1 + 2*32 bytes for uncompressed point
	case "P384":
		ephemeralPublicKeySize = 97 // 1 + 2*48 bytes for uncompressed point
	case "P521":
		ephemeralPublicKeySize = 133 // 1 + 2*66 bytes for uncompressed point
	default:
		return nil, fmt.Errorf("unknown curve size for %s", e.curveName)
	}

	if len(ciphertext) < ephemeralPublicKeySize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	ephemeralPublicKeyBytes := ciphertext[:ephemeralPublicKeySize]
	encryptedData := ciphertext[ephemeralPublicKeySize:]

	// Reconstruct ephemeral public key
	ephemeralPublicKey, err := curve.NewPublicKey(ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct ephemeral public key: %w", err)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := e.privateKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive AES key from shared secret
	aesKey := e.deriveKey(sharedSecret)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short for nonce")
	}

	nonce := encryptedData[:nonceSize]
	actualCiphertext := encryptedData[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// GetPublicKeyBytes returns the public key in DER format
func (e *Provider) GetPublicKeyBytes() ([]byte, error) {
	// Convert ECDH public key to ECDSA for standard encoding
	ecdsaKey := &ecdsa.PublicKey{
		Curve: e.curve,
	}

	// Extract coordinates from ECDH public key
	pubKeyBytes := e.publicKey.Bytes()
	if len(pubKeyBytes) == 0 || pubKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid public key format")
	}

	coordSize := (len(pubKeyBytes) - 1) / 2
	ecdsaKey.X.SetBytes(pubKeyBytes[1 : 1+coordSize])
	ecdsaKey.Y.SetBytes(pubKeyBytes[1+coordSize:])

	return x509.MarshalPKIXPublicKey(ecdsaKey)
}

// GetCurveName returns the name of the elliptic curve
func (e *Provider) GetCurveName() string {
	return e.curveName
}

// GetPublicKey returns the public key
func (e *Provider) GetPublicKey() *ecdh.PublicKey {
	return e.publicKey
}

// GetPrivateKey returns the private key
func (e *Provider) GetPrivateKey() *ecdh.PrivateKey {
	return e.privateKey
}
