package ztdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"stratium/pkg/models"
)

const (
	payloadChunkSize      = 64 * 1024 * 1024 // 64MB chunks for streaming encryption
	nonceCounterBytes     = 4                // use last 4 bytes of nonce for chunk counter
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
	result, err := encryptPayloadBuffered(bytes.NewReader(plaintext), key)
	if err != nil {
		return nil, nil, err
	}
	return result.Ciphertext, result.BaseNonce, nil
}

func encryptPayloadBuffered(reader io.Reader, key []byte) (*payloadEncryptionResult, error) {
	buffer := bytes.NewBuffer(nil)
	result, err := encryptPayloadToWriter(reader, key, buffer)
	if err != nil {
		return nil, err
	}
	result.Ciphertext = buffer.Bytes()
	return result, nil
}

func encryptPayloadToWriter(reader io.Reader, key []byte, writer io.Writer) (*payloadEncryptionResult, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to create AES cipher",
			Err:     err,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to create GCM mode",
			Err:     err,
		}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to generate nonce",
			Err:     err,
		}
	}

	result := &payloadEncryptionResult{
		BaseNonce: nonce,
	}

	rootHasher := sha256.New()
	buf := make([]byte, payloadChunkSize)
	var chunkIndex uint32

	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			nonceForChunk := deriveChunkNonce(nonce, chunkIndex)
			chunkCipher := gcm.Seal(nil, nonceForChunk, buf[:n], nil)
			if _, err := writer.Write(chunkCipher); err != nil {
				return nil, &models.Error{
					Code:    models.ErrCodeEncryptionFailed,
					Message: "failed to write encrypted payload",
					Err:     err,
				}
			}
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
			return nil, &models.Error{
				Code:    models.ErrCodeEncryptionFailed,
				Message: "failed to read plaintext for encryption",
				Err:     readErr,
			}
		}
	}

	if len(result.Segments) == 0 {
		nonceForChunk := deriveChunkNonce(nonce, 0)
		chunkCipher := gcm.Seal(nil, nonceForChunk, []byte{}, nil)
		if _, err := writer.Write(chunkCipher); err != nil {
			return nil, &models.Error{
				Code:    models.ErrCodeEncryptionFailed,
				Message: "failed to write encrypted payload",
				Err:     err,
			}
		}
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

	result.PayloadHash = rootHasher.Sum(nil)
	return result, nil
}

// DecryptPayload decrypts ciphertext with AES-256-GCM using the provided key and IV
func DecryptPayload(ciphertext, key, iv []byte) ([]byte, error) {
	chunkHash := sha256.Sum256(ciphertext)
	segment := &models.EncryptionInformation_IntegrityInformation_Segment{
		Hash:                 base64.StdEncoding.EncodeToString(chunkHash[:]),
		SegmentSize:          int32(len(ciphertext)),
		EncryptedSegmentSize: int32(len(ciphertext)),
	}
	return decryptPayloadWithSegments(ciphertext, key, iv, []*models.EncryptionInformation_IntegrityInformation_Segment{segment}, nil)
}

func decryptPayloadWithSegments(ciphertext, key, iv []byte, segments []*models.EncryptionInformation_IntegrityInformation_Segment, expectedRootHash []byte) ([]byte, error) {
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

	if len(segments) == 0 {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "missing integrity segments for payload",
		}
	}

	reader := bytes.NewReader(ciphertext)
	var plaintext bytes.Buffer
	rootHasher := sha256.New()

	for idx, segment := range segments {
		chunkSize := int(segment.GetEncryptedSegmentSize())
		if chunkSize <= 0 {
			return nil, &models.Error{
				Code:    models.ErrCodeDecryptionFailed,
				Message: "invalid encrypted segment size",
			}
		}

		chunkCipher := make([]byte, chunkSize)
		if _, err := io.ReadFull(reader, chunkCipher); err != nil {
			return nil, &models.Error{
				Code:    models.ErrCodeDecryptionFailed,
				Message: "failed to read encrypted payload segment",
				Err:     err,
			}
		}

		expectedChunkHash, err := base64.StdEncoding.DecodeString(segment.GetHash())
		if err != nil {
			return nil, &models.Error{
				Code:    models.ErrCodeDecryptionFailed,
				Message: "failed to decode segment hash",
				Err:     err,
			}
		}
		actualChunkHash := sha256.Sum256(chunkCipher)
		if !hmac.Equal(actualChunkHash[:], expectedChunkHash) {
			return nil, &models.Error{
				Code:    models.ErrCodeIntegrityFailed,
				Message: "segment hash mismatch",
			}
		}

		nonceForChunk := deriveChunkNonce(iv, uint32(idx))
		chunkPlaintext, err := gcm.Open(nil, nonceForChunk, chunkCipher, nil)
		if err != nil {
			return nil, &models.Error{
				Code:    models.ErrCodeDecryptionFailed,
				Message: "failed to decrypt payload segment",
				Err:     err,
			}
		}

		rootHasher.Write(chunkCipher)
		plaintext.Write(chunkPlaintext)
	}

	if reader.Len() != 0 {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "encrypted payload has extra data beyond segments",
		}
	}

	if len(expectedRootHash) > 0 {
		actual := rootHasher.Sum(nil)
		if !hmac.Equal(actual, expectedRootHash) {
			return nil, &models.Error{
				Code:    models.ErrCodeIntegrityFailed,
				Message: "payload hash mismatch",
			}
		}
	}

	return plaintext.Bytes(), nil
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
