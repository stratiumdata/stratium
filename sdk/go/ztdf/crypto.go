package ztdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/stratiumdata/go-sdk/gen/models"
	"golang.org/x/crypto/hkdf"
)

const (
	payloadChunkSize      = 64 * 1024 * 1024
	nonceCounterBytes     = 4
	defaultSegmentHashAlg = "SHA256"
)

type payloadEncryptionResult struct {
	Ciphertext     []byte
	BaseNonce      []byte
	Segments       []*models.EncryptionInformation_IntegrityInformation_Segment
	PayloadHash    []byte
	PlaintextSize  int64
	CiphertextSize int64
}

// GenerateRSAKeyPair generates an RSA key pair for the client
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return privateKey, nil
}

// SaveRSAPrivateKey saves RSA private key to file
func SaveRSAPrivateKey(privateKey *rsa.PrivateKey, dir string, filename string) error {
	privateKeyPath := filepath.Join(dir, filename)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return os.WriteFile(privateKeyPath, privateKeyPEM, 0600)
}

// GetRSAPrivateKeyFromFile gets private key from file
func GetRSAPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	privateKeyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privateKey, nil
}

// RSAPublicKeyToPEM converts public key to PEM format
func RSAPublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM), nil
}

// GenerateECCKeyPair generates an ECC key pair for the client.
// Supported curves: "P-256" (NIST P-256) and "P-384" (NIST P-384).
//
// Example:
//
//	privateKey, err := ztdf.GenerateECCKeyPair("P-256")
//	if err != nil {
//	    log.Fatal(err)
//	}
func GenerateECCKeyPair(curve string) (*ecdh.PrivateKey, error) {
	var c ecdh.Curve

	switch curve {
	case "P-256":
		c = ecdh.P256()
	case "P-384":
		c = ecdh.P384()
	default:
		return nil, fmt.Errorf("unsupported curve: %s (supported: P-256, P-384)", curve)
	}

	privateKey, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECC key pair: %w", err)
	}

	return privateKey, nil
}

// SaveECCPrivateKey saves ECC private key to file in PKCS#8 PEM format.
//
// Example:
//
//	err := ztdf.SaveECCPrivateKey(privateKey, "./keys", "client.key")
//	if err != nil {
//	    log.Fatal(err)
//	}
func SaveECCPrivateKey(privateKey *ecdh.PrivateKey, dir string, filename string) error {
	privateKeyPath := filepath.Join(dir, filename)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Marshal to PKCS#8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ECC private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return os.WriteFile(privateKeyPath, privateKeyPEM, 0600)
}

// GetECCPrivateKeyFromFile loads an ECC private key from a PEM file.
//
// Example:
//
//	privateKey, err := ztdf.GetECCPrivateKeyFromFile("./keys/client.key")
//	if err != nil {
//	    log.Fatal(err)
//	}
func GetECCPrivateKeyFromFile(filename string) (*ecdh.PrivateKey, error) {
	privateKeyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Parse as PKCS#8 (which supports ECC)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Check if it's already an *ecdh.PrivateKey
	if ecdhKey, ok := key.(*ecdh.PrivateKey); ok {
		return ecdhKey, nil
	}

	// x509.ParsePKCS8PrivateKey may return *ecdsa.PrivateKey for ECC keys
	// Convert it to *ecdh.PrivateKey using the raw key bytes
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECC private key, got type %T", key)
	}

	// Determine the curve and create ecdh.PrivateKey from raw bytes
	var curve ecdh.Curve
	switch ecdsaKey.Curve.Params().Name {
	case "P-256":
		curve = ecdh.P256()
	case "P-384":
		curve = ecdh.P384()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", ecdsaKey.Curve.Params().Name)
	}

	// Convert ecdsa key to ecdh key using raw bytes
	ecdhKey, err := curve.NewPrivateKey(ecdsaKey.D.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to convert ecdsa key to ecdh: %w", err)
	}

	return ecdhKey, nil
}

// ECCPublicKeyToPEM converts an ECC public key to PEM format.
//
// Example:
//
//	publicKeyPEM, err := ztdf.ECCPublicKeyToPEM(privateKey.PublicKey())
//	if err != nil {
//	    log.Fatal(err)
//	}
func ECCPublicKeyToPEM(publicKey *ecdh.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ECC public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

// GenerateDEK generates a random 256-bit AES key for data encryption.
//
// Example:
//
//	dek, err := ztdf.GenerateDEK()
//	if err != nil {
//	    log.Fatal(err)
//	}
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, AESKeySize) // AES-256 (32 bytes)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

// EncryptPayload encrypts plaintext with AES-256-GCM using the provided DEK.
// Returns the ciphertext and initialization vector (IV).
//
// Example:
//
//	dek, _ := ztdf.GenerateDEK()
//	ciphertext, iv, err := ztdf.EncryptPayload(plaintext, dek)
//	if err != nil {
//	    log.Fatal(err)
//	}
func EncryptPayload(plaintext, dek []byte) (ciphertext, iv []byte, err error) {
	result, err := encryptPayloadStream(bytes.NewReader(plaintext), dek)
	if err != nil {
		return nil, nil, err
	}
	return result.Ciphertext, result.BaseNonce, nil
}

func encryptPayloadStream(reader io.Reader, dek []byte) (*payloadEncryptionResult, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	baseNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(baseNonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	result := &payloadEncryptionResult{
		BaseNonce: baseNonce,
	}

	rootHasher := sha256.New()
	buffer := bytes.NewBuffer(nil)
	buf := make([]byte, payloadChunkSize)

	var chunkIndex uint32
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			nonceForChunk := deriveChunkNonce(baseNonce, chunkIndex)
			chunkCipher := gcm.Seal(nil, nonceForChunk, buf[:n], nil)
			buffer.Write(chunkCipher)
			rootHasher.Write(chunkCipher)

			chunkHash := sha256.Sum256(chunkCipher)
			result.Segments = append(result.Segments, &models.EncryptionInformation_IntegrityInformation_Segment{
				Hash:                 base64.StdEncoding.EncodeToString(chunkHash[:]),
				SegmentSize:          int32(n),
				EncryptedSegmentSize: int32(len(chunkCipher)),
			})
			result.PlaintextSize += int64(n)
			result.CiphertextSize += int64(len(chunkCipher))
			chunkIndex++
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("failed to read plaintext: %w", readErr)
		}
	}

	if len(result.Segments) == 0 {
		nonceForChunk := deriveChunkNonce(baseNonce, 0)
		chunkCipher := gcm.Seal(nil, nonceForChunk, []byte{}, nil)
		buffer.Write(chunkCipher)
		rootHasher.Write(chunkCipher)
		chunkHash := sha256.Sum256(chunkCipher)
		result.Segments = append(result.Segments, &models.EncryptionInformation_IntegrityInformation_Segment{
			Hash:                 base64.StdEncoding.EncodeToString(chunkHash[:]),
			SegmentSize:          0,
			EncryptedSegmentSize: int32(len(chunkCipher)),
		})
		result.CiphertextSize += int64(len(chunkCipher))
		chunkIndex++
	}

	result.Ciphertext = buffer.Bytes()
	result.PayloadHash = rootHasher.Sum(nil)
	return result, nil
}

// DecryptPayload decrypts ciphertext with AES-256-GCM using the provided DEK and IV.
//
// Example:
//
//	plaintext, err := ztdf.DecryptPayload(ciphertext, dek, iv)
//	if err != nil {
//	    log.Fatal(err)
//	}
func DecryptPayload(ciphertext, dek, iv []byte) ([]byte, error) {
	chunkHash := sha256.Sum256(ciphertext)
	segment := &models.EncryptionInformation_IntegrityInformation_Segment{
		Hash:                 base64.StdEncoding.EncodeToString(chunkHash[:]),
		SegmentSize:          int32(len(ciphertext)),
		EncryptedSegmentSize: int32(len(ciphertext)),
	}
	return decryptPayloadWithSegments(ciphertext, dek, iv, []*models.EncryptionInformation_IntegrityInformation_Segment{segment}, nil)
}

func decryptPayloadWithSegments(ciphertext, dek, iv []byte, segments []*models.EncryptionInformation_IntegrityInformation_Segment, expectedRootHash []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	if len(segments) == 0 {
		return nil, errors.New("missing integrity segments for payload decryption")
	}

	reader := bytes.NewReader(ciphertext)
	var plaintext bytes.Buffer
	cipherRootHasher := sha256.New()
	plainRootHasher := sha256.New()

	for idx, segment := range segments {
		chunkSize := int(segment.GetEncryptedSegmentSize())
		if chunkSize <= 0 {
			return nil, fmt.Errorf("invalid encrypted segment size (%d)", chunkSize)
		}

		chunkCipher := make([]byte, chunkSize)
		if _, err := io.ReadFull(reader, chunkCipher); err != nil {
			return nil, fmt.Errorf("failed to read encrypted payload segment: %w", err)
		}

		nonceForChunk := deriveChunkNonce(iv, uint32(idx))
		chunkPlaintext, err := gcm.Open(nil, nonceForChunk, chunkCipher, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt payload segment: %w", err)
		}

		cipherRootHasher.Write(chunkCipher)
		plainRootHasher.Write(chunkPlaintext)

		if segment.GetHash() != "" {
			expectedChunkHash, err := base64.StdEncoding.DecodeString(segment.GetHash())
			if err != nil {
				return nil, fmt.Errorf("failed to decode segment hash: %w", err)
			}
			cipherChunkHash := sha256.Sum256(chunkCipher)
			if !hmac.Equal(cipherChunkHash[:], expectedChunkHash) {
				plainChunkHash := sha256.Sum256(chunkPlaintext)
				if !hmac.Equal(plainChunkHash[:], expectedChunkHash) {
					return nil, errors.New("segment hash mismatch")
				}
			}
		}
		plaintext.Write(chunkPlaintext)
	}

	if reader.Len() != 0 {
		return nil, errors.New("encrypted payload has extra bytes beyond declared segments")
	}

	if len(expectedRootHash) > 0 {
		cipherRoot := cipherRootHasher.Sum(nil)
		plainRoot := plainRootHasher.Sum(nil)
		if !hmac.Equal(cipherRoot, expectedRootHash) && !hmac.Equal(plainRoot, expectedRootHash) {
			return nil, errors.New("payload hash mismatch")
		}
	}

	return plaintext.Bytes(), nil
}

func decryptSinglePayload(ciphertext, dek, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	return plaintext, nil
}

// EncryptDEKWithRSAPublicKey encrypts a DEK using RSA-OAEP with SHA-256.
// Used to encrypt the DEK with the client's public key.
//
// Example:
//
//	encryptedDEK, err := ztdf.EncryptDEKWithPublicKey(publicKey, dek)
//	if err != nil {
//	    log.Fatal(err)
//	}
func EncryptDEKWithRSAPublicKey(publicKey *rsa.PublicKey, dek []byte) ([]byte, error) {
	encryptedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK with public key: %w", err)
	}
	return encryptedDEK, nil
}

// WrapDEKWithRSAPrivateKey wraps a DEK using the client's private RSA key (PKCS#1 v1.5 padding).
// This keeps the DEK opaque while it is in transit to the Key Access service.
func WrapDEKWithRSAPrivateKey(privateKey *rsa.PrivateKey, dek []byte) ([]byte, error) {
	k := (privateKey.N.BitLen() + 7) / 8
	if len(dek) > k-11 {
		return nil, fmt.Errorf("DEK too large for client key")
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
		return nil, fmt.Errorf("message representative out of range")
	}

	c := new(big.Int).Exp(m, privateKey.D, privateKey.N)
	out := c.Bytes()
	if len(out) < k {
		padded := make([]byte, k)
		copy(padded[k-len(out):], out)
		out = padded
	}
	return out, nil
}

// DecryptDEKWithRSAPrivateKey decrypts a DEK using RSA-OAEP with SHA-256.
// Used to decrypt the DEK with the client's private key.
//
// Example:
//
//	dek, err := ztdf.DecryptDEKWithPrivateKey(privateKey, encryptedDEK)
//	if err != nil {
//	    log.Fatal(err)
//	}
func DecryptDEKWithRSAPrivateKey(privateKey *rsa.PrivateKey, encryptedDEK []byte) ([]byte, error) {
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with private key: %w", err)
	}
	return dek, nil
}

// EncryptDEKWithECCPublicKey encrypts a DEK using ECIES (Elliptic Curve Integrated Encryption Scheme).
// Uses ECDH for key agreement, HKDF-SHA256 for key derivation, and AES-256-GCM for encryption.
//
// The returned ciphertext format is:
// [ephemeral public key length (1 byte)][ephemeral public key][nonce (12 bytes)][ciphertext]
//
// Example:
//
//	encryptedDEK, err := ztdf.EncryptDEKWithECCPublicKey(publicKey, dek)
//	if err != nil {
//	    log.Fatal(err)
//	}
func EncryptDEKWithECCPublicKey(publicKey *ecdh.PublicKey, dek []byte) ([]byte, error) {
	// Generate ephemeral key pair using the same curve as the recipient's public key
	curve := publicKey.Curve()
	ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := ephemeralPrivateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform ECDH: %w", err)
	}

	// Derive encryption key using HKDF-SHA256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ztdf-ecies-v1"))
	derivedKey := make([]byte, 32) // AES-256 key
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encrypt DEK with AES-256-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, dek, nil)

	// Package result: [ephemeral public key length][ephemeral public key][nonce][ciphertext]
	ephemeralPublicKeyBytes := ephemeralPrivateKey.PublicKey().Bytes()
	result := make([]byte, 0, 1+len(ephemeralPublicKeyBytes)+len(nonce)+len(ciphertext))
	result = append(result, byte(len(ephemeralPublicKeyBytes)))
	result = append(result, ephemeralPublicKeyBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptDEKWithECCPrivateKey decrypts a DEK using ECIES (Elliptic Curve Integrated Encryption Scheme).
// Uses ECDH for key agreement, HKDF-SHA256 for key derivation, and AES-256-GCM for decryption.
//
// The input ciphertext format must be:
// [ephemeral public key length (1 byte)][ephemeral public key][nonce (12 bytes)][ciphertext]
//
// Example:
//
//	dek, err := ztdf.DecryptDEKWithECCPrivateKey(privateKey, encryptedDEK)
//	if err != nil {
//	    log.Fatal(err)
//	}
func DecryptDEKWithECCPrivateKey(privateKey *ecdh.PrivateKey, encryptedDEK []byte) ([]byte, error) {
	// Parse encrypted blob
	if len(encryptedDEK) < 1 {
		return nil, errors.New("encrypted DEK too short")
	}

	// Extract ephemeral public key
	ephemeralPublicKeyLen := int(encryptedDEK[0])
	if len(encryptedDEK) < 1+ephemeralPublicKeyLen+12 {
		return nil, errors.New("encrypted DEK format invalid")
	}

	ephemeralPublicKeyBytes := encryptedDEK[1 : 1+ephemeralPublicKeyLen]
	curve := privateKey.Curve()
	ephemeralPublicKey, err := curve.NewPublicKey(ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Extract nonce and ciphertext
	nonceStart := 1 + ephemeralPublicKeyLen
	nonce := encryptedDEK[nonceStart : nonceStart+12]
	ciphertext := encryptedDEK[nonceStart+12:]

	// Perform ECDH to get shared secret
	sharedSecret, err := privateKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform ECDH: %w", err)
	}

	// Derive encryption key using HKDF-SHA256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ztdf-ecies-v1"))
	derivedKey := make([]byte, 32) // AES-256 key
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Decrypt DEK with AES-256-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return dek, nil
}

// CalculatePolicyBinding computes HMAC-SHA256 of the policy using the DEK as the key.
// This creates a cryptographic binding between the DEK and the policy to prevent tampering.
//
// Example:
//
//	binding := ztdf.CalculatePolicyBinding(dek, policyBase64)
func CalculatePolicyBinding(dek []byte, policyBase64 string) string {
	h := hmac.New(sha256.New, dek)
	h.Write([]byte(policyBase64))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// VerifyPolicyBinding verifies that the HMAC of the policy matches the expected hash.
// Returns an error if the binding verification fails.
//
// Example:
//
//	if err := ztdf.VerifyPolicyBinding(dek, policyBase64, expectedHash); err != nil {
//	    log.Fatal("Policy has been tampered with!")
//	}
func VerifyPolicyBinding(dek []byte, policyBase64 string, expectedHash string) error {
	calculatedHash := CalculatePolicyBinding(dek, policyBase64)
	if calculatedHash != expectedHash {
		return fmt.Errorf("policy binding verification failed: HMAC mismatch")
	}
	return nil
}

// CalculatePayloadHash computes SHA-256 hash of the payload for integrity verification.
//
// Example:
//
//	hash := ztdf.CalculatePayloadHash(payload)
func CalculatePayloadHash(payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return hash[:]
}

// VerifyPayloadHash verifies that the payload hash matches the expected hash.
// Returns an error if the integrity check fails.
//
// Example:
//
//	if err := ztdf.VerifyPayloadHash(payload, expectedHash); err != nil {
//	    log.Fatal("Payload has been tampered with!")
//	}
func VerifyPayloadHash(payload []byte, expectedHash []byte) error {
	actualHash := CalculatePayloadHash(payload)
	if !hmac.Equal(actualHash, expectedHash) {
		return fmt.Errorf("payload integrity verification failed: hash mismatch")
	}
	return nil
}

func deriveChunkNonce(base []byte, counter uint32) []byte {
	nonce := make([]byte, len(base))
	copy(nonce, base)
	if len(nonce) < nonceCounterBytes {
		return nonce
	}
	offset := len(nonce) - nonceCounterBytes
	binary.BigEndian.PutUint32(nonce[offset:], counter)
	return nonce
}
