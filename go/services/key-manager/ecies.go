package key_manager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// encryptDEKWithECCPublicKey encrypts plaintext using ECIES with the provided ECDSA public key.
// The output format is: ephemeralPublicX || ephemeralPublicY || nonce || ciphertext
func encryptDEKWithECCPublicKey(publicKey *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	if publicKey == nil || publicKey.Curve == nil {
		return nil, fmt.Errorf("invalid ECC public key")
	}

	ephemeralKey, err := ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	sharedX, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeralKey.D.Bytes())
	if sharedX == nil {
		return nil, fmt.Errorf("failed to derive shared secret")
	}

	kdf := hkdf.New(sha256.New, sharedX.Bytes(), nil, []byte("key-manager-ecc-dek"))
	encKey := make([]byte, 32)
	if _, err := kdf.Read(encKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	block, err := aes.NewCipher(encKey)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	coordSize := (publicKey.Curve.Params().BitSize + 7) / 8
	ephemeralX := ephemeralKey.PublicKey.X.FillBytes(make([]byte, coordSize))
	ephemeralY := ephemeralKey.PublicKey.Y.FillBytes(make([]byte, coordSize))

	out := make([]byte, 0, len(ephemeralX)+len(ephemeralY)+len(ciphertext))
	out = append(out, ephemeralX...)
	out = append(out, ephemeralY...)
	out = append(out, ciphertext...)
	return out, nil
}

// decryptDEKWithECCPrivateKey decrypts ECIES ciphertext produced by encryptDEKWithECCPublicKey.
func decryptDEKWithECCPrivateKey(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	if privateKey == nil || privateKey.Curve == nil {
		return nil, fmt.Errorf("invalid ECC private key")
	}

	coordSize := (privateKey.Curve.Params().BitSize + 7) / 8
	headerSize := coordSize * 2
	if len(data) <= headerSize {
		return nil, fmt.Errorf("ciphertext too short for ECC payload")
	}

	xBytes := data[:coordSize]
	yBytes := data[coordSize:headerSize]
	ciphertext := data[headerSize:]

	ephemeralX := new(big.Int).SetBytes(xBytes)
	ephemeralY := new(big.Int).SetBytes(yBytes)
	if !privateKey.Curve.IsOnCurve(ephemeralX, ephemeralY) {
		return nil, fmt.Errorf("ephemeral public key not on curve")
	}

	sharedX, _ := privateKey.Curve.ScalarMult(ephemeralX, ephemeralY, privateKey.D.Bytes())
	if sharedX == nil {
		return nil, fmt.Errorf("failed to derive shared secret")
	}

	kdf := hkdf.New(sha256.New, sharedX.Bytes(), nil, []byte("key-manager-ecc-dek"))
	encKey := make([]byte, 32)
	if _, err := kdf.Read(encKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext missing nonce")
	}

	nonce := ciphertext[:nonceSize]
	payload := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}
	return plaintext, nil
}
