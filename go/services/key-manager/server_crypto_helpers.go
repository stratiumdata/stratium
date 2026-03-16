package key_manager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func isYubiKeyClientKey(key *Key) bool {
	if key == nil || key.Metadata == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(key.Metadata[clientKeyProviderMetadataKey]), clientKeyProviderYubiKey)
}

func shouldAllowYubiKeyPlainClientEnvelope(key *Key) bool {
	if key == nil || key.Metadata == nil {
		return false
	}
	if !isYubiKeyClientKey(key) {
		return false
	}
	return parseMetadataBool(key.Metadata[yubiKeyTouchRequiredMetadataKey])
}

func recoverYubiKeySignedDEK(key *Key, wrapped []byte) ([]byte, error) {
	var envelope yubiKeySignedDEKEnvelope
	if err := json.Unmarshal(wrapped, &envelope); err != nil {
		return nil, fmt.Errorf("failed to decode YubiKey envelope: %w", err)
	}

	if envelope.Version != yubiKeyEnvelopeVersionSignedV1 {
		return nil, fmt.Errorf("unsupported YubiKey envelope version %q", envelope.Version)
	}

	dek, err := base64.StdEncoding.DecodeString(envelope.DEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DEK from envelope: %w", err)
	}
	if len(dek) == 0 {
		return nil, errors.New("DEK in envelope is empty")
	}

	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature from envelope: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("signature in envelope is empty")
	}

	pub, err := parseClientPublicKey(key)
	if err != nil {
		return nil, err
	}

	switch rsaKey := pub.(type) {
	case *rsa.PublicKey:
		if err := verifyYubiKeyRSASignature(rsaKey, dek, signature); err != nil {
			return nil, err
		}
		return dek, nil
	default:
		return nil, fmt.Errorf("client key type %s is not supported for YubiKey signed wrapping", key.KeyType.String())
	}
}

func verifyYubiKeyRSASignature(pub *rsa.PublicKey, dek []byte, signature []byte) error {
	digest := sha256.Sum256(dek)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err == nil {
		return nil
	}
	return errors.New("invalid YubiKey DEK signature")
}

func (s *Server) decryptClientWrappedDEK(ctx context.Context, clientKeyID string, encrypted []byte) ([]byte, error) {
	key, err := s.clientKeyStore.GetKey(ctx, clientKeyID)
	if err != nil {
		return nil, err
	}
	return decryptClientWrappedDEKWithKey(key, encrypted)
}

func decryptClientWrappedDEKWithKey(key *Key, encrypted []byte) ([]byte, error) {
	pub, err := parseClientPublicKey(key)
	if err != nil {
		return nil, err
	}

	switch rsaKey := pub.(type) {
	case *rsa.PublicKey:
		return rsaPublicUnwrap(rsaKey, encrypted)
	default:
		return nil, fmt.Errorf("client key type %s is not supported for secure wrapping", key.KeyType.String())
	}
}

func parseClientPublicKey(key *Key) (any, error) {
	if key == nil {
		return nil, errors.New("client key record is required")
	}
	if key.PublicKeyPem == "" {
		return nil, fmt.Errorf("client key %s missing public key PEM", key.KeyId)
	}

	block, _ := pem.Decode([]byte(key.PublicKeyPem))
	if block == nil {
		return nil, errors.New("failed to decode client public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client public key: %w", err)
	}
	return pub, nil
}

func (s *Server) wrapWithServiceKey(ctx context.Context, serviceKeyID string, plaintext []byte) ([]byte, error) {
	keyPair, err := s.keyStore.GetKeyPair(ctx, serviceKeyID)
	if err != nil {
		return nil, err
	}
	if s.fipsEnabled && !isFIPSKeyTypeAllowed(keyPair.KeyType) {
		return nil, fmt.Errorf("service key type %s is not allowed in FIPS mode", keyPair.KeyType)
	}

	provider, err := s.providerFactory.GetProvider(keyPair.ProviderType)
	if err != nil {
		return nil, err
	}

	return provider.Encrypt(ctx, serviceKeyID, plaintext)
}

func rsaPublicUnwrap(pub *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if len(ciphertext) != k {
		return nil, fmt.Errorf("invalid ciphertext length: expected %d, got %d", k, len(ciphertext))
	}

	c := new(big.Int).SetBytes(ciphertext)
	if c.Sign() <= 0 || c.Cmp(pub.N) >= 0 {
		return nil, errors.New("ciphertext representative out of range")
	}

	m := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N)
	em := m.Bytes()
	if len(em) < k {
		padded := make([]byte, k)
		copy(padded[k-len(em):], em)
		em = padded
	}

	if len(em) < 11 || em[0] != 0x00 || em[1] != 0x01 {
		return nil, errors.New("invalid PKCS#1 padding")
	}

	index := 2
	for index < len(em) && em[index] == 0xff {
		index++
	}
	if index >= len(em) || em[index] != 0x00 {
		return nil, errors.New("invalid PKCS#1 padding delimiter")
	}

	plain := em[index+1:]
	if len(plain) == 0 {
		return nil, errors.New("empty decrypted payload")
	}

	return plain, nil
}

func inferKeyTypeFromPEM(pemData string) (KeyType, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return KeyType_KEY_TYPE_UNSPECIFIED, errors.New("failed to decode public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch key := pub.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		switch bits {
		case 2048:
			return KeyType_KEY_TYPE_RSA_2048, nil
		case 3072:
			return KeyType_KEY_TYPE_RSA_3072, nil
		case 4096:
			return KeyType_KEY_TYPE_RSA_4096, nil
		default:
			return KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported RSA key size: %d", bits)
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().Name {
		case "P-256":
			return KeyType_KEY_TYPE_ECC_P256, nil
		case "P-384":
			return KeyType_KEY_TYPE_ECC_P384, nil
		case "P-521":
			return KeyType_KEY_TYPE_ECC_P521, nil
		default:
			return KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported ECC curve: %s", key.Curve.Params().Name)
		}
	default:
		return KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported key type %T", pub)
	}
}

// validateCreateKeyRequest validates the create key request
func (s *Server) validateCreateKeyRequest(req *CreateKeyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("key name is required")
	}

	if req.KeyType == KeyType_KEY_TYPE_UNSPECIFIED {
		return fmt.Errorf("key type is required")
	}

	if req.ProviderType == KeyProviderType_KEY_PROVIDER_TYPE_UNSPECIFIED {
		return fmt.Errorf("provider type is required")
	}

	if s.fipsEnabled && !isFIPSKeyTypeAllowed(req.KeyType) {
		return fmt.Errorf("key type %s is not allowed in FIPS mode", req.KeyType)
	}

	return nil
}

func isFIPSKeyTypeAllowed(keyType KeyType) bool {
	switch keyType {
	case KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_RSA_3072,
		KeyType_KEY_TYPE_RSA_4096:
		return true
	default:
		return false
	}
}

func filterFIPSKeyTypes(keyTypes []KeyType) []KeyType {
	filtered := make([]KeyType, 0, len(keyTypes))
	for _, keyType := range keyTypes {
		if isFIPSKeyTypeAllowed(keyType) {
			filtered = append(filtered, keyType)
		}
	}
	return filtered
}

// keyPairToKey converts a KeyPair to a Key protobuf message
func (s *Server) keyPairToKey(keyPair *KeyPair) *Key {
	key := &Key{
		KeyId:         keyPair.KeyID,
		KeyType:       keyPair.KeyType,
		ProviderType:  keyPair.ProviderType,
		Status:        KeyStatus_KEY_STATUS_ACTIVE,
		PublicKeyPem:  keyPair.PublicKeyPEM,
		CreatedAt:     timestamppb.New(keyPair.CreatedAt),
		UsageCount:    keyPair.UsageCount,
		MaxUsageCount: keyPair.MaxUsageCount,
		Metadata:      make(map[string]string),
	}

	if keyPair.ExpiresAt != nil {
		key.ExpiresAt = timestamppb.New(*keyPair.ExpiresAt)
	}

	if keyPair.LastRotated != nil {
		key.LastRotated = timestamppb.New(*keyPair.LastRotated)
	}

	for k, v := range keyPair.Metadata {
		key.Metadata[k] = v
	}

	if keyPair.ExternallyManaged {
		key.ExternallyManaged = true
		key.ExternalSource = keyPair.ExternalSource
		key.ExternalManifestPath = keyPair.ExternalManifestPath
		key.PrivateKeySource = keyPair.PrivateKeySource
		if keyPair.ExternalLoadedAt != nil {
			key.ExternalLoadedAt = timestamppb.New(*keyPair.ExternalLoadedAt)
		}
	}

	return key
}
