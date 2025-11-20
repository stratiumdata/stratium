package key_manager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"stratium/pkg/security/encryption"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// dekTestEnv holds the scaffolding for future end-to-end DEK workflow tests.
type dekTestEnv struct {
	algorithm       encryption.Algorithm
	server          *Server
	providerFactory *DefaultProviderFactory
}

type testTrustedDataObject struct {
	Manifest *testManifest
	Payload  []byte
}

type testManifest struct {
	Method    *testEncryptionMethod
	KeyAccess []*testKeyAccess
}

type testEncryptionMethod struct {
	Algorithm string
	IVBase64  string
}

type testKeyAccess struct {
	WrappedKeyBase64 string
	KeyID            string
}

// newDEKTestEnv builds a key manager server backed by in-memory stores.
func newDEKTestEnv(t *testing.T, alg encryption.Algorithm) *dekTestEnv {
	t.Helper()
	server := newTestKeyManagerServer(t, alg)

	factory := NewDefaultProviderFactory(alg)
	for _, providerType := range factory.GetAvailableProviders() {
		provider, err := factory.GetProvider(providerType)
		if err != nil {
			continue
		}
		if softwareProvider, ok := provider.(*SoftwareKeyProvider); ok {
			softwareProvider.SetKeyStore(server.keyStore)
		}
	}

	// Align server fields for upcoming tests.
	server.providerFactory = factory
	server.dekService = NewDEKUnwrappingService(server.keyStore, factory, server.clientKeyStore)

	return &dekTestEnv{
		algorithm:       alg,
		server:          server,
		providerFactory: factory,
	}
}

// createServiceKey provisions a key compatible with the algorithm under test.
func (env *dekTestEnv) createServiceKey(t *testing.T) *Key {
	t.Helper()
	keyType, err := AlgorithmToKeyType(env.providerFactory.GetEncryptionAlgorithm())
	if err != nil {
		t.Fatalf("Failed to convert algorithm %s to key type: %v", env.algorithm, err)
	}

	req := &CreateKeyRequest{
		Name:         "dek-test-key-" + string(env.algorithm),
		KeyType:      keyType,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Metadata: map[string]string{
			"algorithm": string(env.algorithm),
		},
	}

	resp, err := env.server.CreateKey(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateKey failed for %s: %v", env.algorithm, err)
	}

	return resp.Key
}

func (env *dekTestEnv) createZTDF(t *testing.T, key *Key, plaintext []byte) (*testTrustedDataObject, []byte) {
	t.Helper()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("failed to generate DEK: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to create GCM: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	wrappedDEK := env.wrapDEK(t, key, dek)

	manifest := &testManifest{
		Method: &testEncryptionMethod{
			Algorithm: "AES-256-GCM",
			IVBase64:  base64.StdEncoding.EncodeToString(nonce),
		},
		KeyAccess: []*testKeyAccess{
			{
				WrappedKeyBase64: base64.StdEncoding.EncodeToString(wrappedDEK),
				KeyID:            key.KeyId,
			},
		},
	}

	tdo := &testTrustedDataObject{
		Manifest: manifest,
		Payload:  ciphertext,
	}

	return tdo, dek
}

func (env *dekTestEnv) unwrapZTDF(t *testing.T, key *Key, tdo *testTrustedDataObject) []byte {
	t.Helper()
	manifest := tdo.Manifest
	if manifest == nil || len(manifest.KeyAccess) == 0 {
		t.Fatalf("manifest missing encryption information")
	}
	ka := manifest.KeyAccess[0]
	wrapped, err := base64.StdEncoding.DecodeString(ka.WrappedKeyBase64)
	if err != nil {
		t.Fatalf("failed to decode wrapped key: %v", err)
	}
	provider, err := env.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("failed to get provider: %v", err)
	}
	dek, err := provider.Decrypt(context.Background(), key.KeyId, wrapped)
	if err != nil {
		t.Fatalf("failed to unwrap DEK: %v", err)
	}
	ivBytes, err := base64.StdEncoding.DecodeString(manifest.Method.IVBase64)
	if err != nil {
		t.Fatalf("failed to decode IV: %v", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to create GCM: %v", err)
	}
	plaintext, err := gcm.Open(nil, ivBytes, tdo.Payload, nil)
	if err != nil {
		t.Fatalf("failed to decrypt payload: %v", err)
	}
	return plaintext
}

func (env *dekTestEnv) wrapDEK(t *testing.T, key *Key, dek []byte) []byte {
	t.Helper()
	ctx := context.Background()
	switch key.KeyType {
	case KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_RSA_3072,
		KeyType_KEY_TYPE_RSA_4096,
		KeyType_KEY_TYPE_ECC_P256,
		KeyType_KEY_TYPE_ECC_P384,
		KeyType_KEY_TYPE_ECC_P521:
		provider, err := env.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
		if err != nil {
			t.Fatalf("failed to get provider: %v", err)
		}
		wrapped, err := provider.Encrypt(ctx, key.KeyId, dek)
		if err != nil {
			t.Fatalf("failed to wrap DEK: %v", err)
		}
		return wrapped
	case KeyType_KEY_TYPE_KYBER_512:
		return env.wrapDEKWithKyber512(t, key.KeyId, dek)
	case KeyType_KEY_TYPE_KYBER_768:
		return env.wrapDEKWithKyber768(t, key.KeyId, dek)
	case KeyType_KEY_TYPE_KYBER_1024:
		return env.wrapDEKWithKyber1024(t, key.KeyId, dek)
	default:
		t.Skipf("key type %v is not currently supported for DEK encryption", key.KeyType)
		return nil
	}
}

func (env *dekTestEnv) wrapDEKWithKyber512(t *testing.T, keyID string, dek []byte) []byte {
	return env.wrapDEKWithKyber(t, keyID, dek, kyber512.Scheme().CiphertextSize(), func(pub interface{}) ([]byte, []byte, error) {
		key, ok := pub.(*kyber512.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("expected kyber512 public key, got %T", pub)
		}
		return kyber512.Scheme().Encapsulate(key)
	})
}

func (env *dekTestEnv) wrapDEKWithKyber768(t *testing.T, keyID string, dek []byte) []byte {
	return env.wrapDEKWithKyber(t, keyID, dek, kyber768.Scheme().CiphertextSize(), func(pub interface{}) ([]byte, []byte, error) {
		key, ok := pub.(*kyber768.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("expected kyber768 public key, got %T", pub)
		}
		return kyber768.Scheme().Encapsulate(key)
	})
}

func (env *dekTestEnv) wrapDEKWithKyber1024(t *testing.T, keyID string, dek []byte) []byte {
	return env.wrapDEKWithKyber(t, keyID, dek, kyber1024.Scheme().CiphertextSize(), func(pub interface{}) ([]byte, []byte, error) {
		key, ok := pub.(*kyber1024.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("expected kyber1024 public key, got %T", pub)
		}
		return kyber1024.Scheme().Encapsulate(key)
	})
}

func (env *dekTestEnv) wrapDEKWithKyber(t *testing.T, keyID string, dek []byte, ciphertextSize int, encap func(interface{}) ([]byte, []byte, error)) []byte {
	t.Helper()
	ctx := context.Background()
	keyPair, err := env.server.keyStore.GetKeyPair(ctx, keyID)
	if err != nil {
		t.Fatalf("failed to retrieve key pair: %v", err)
	}
	ciphertext, sharedSecret, err := encap(keyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encapsulate: %v", err)
	}
	encryptedDEK := encryptDEKWithSharedSecret(t, sharedSecret, dek)
	wrapped := make([]byte, 0, ciphertextSize+len(encryptedDEK))
	wrapped = append(wrapped, ciphertext...)
	wrapped = append(wrapped, encryptedDEK...)
	return wrapped
}

func encryptDEKWithSharedSecret(t *testing.T, sharedSecret, dek []byte) []byte {
	t.Helper()
	if len(sharedSecret) < 32 {
		t.Fatalf("shared secret too short: %d", len(sharedSecret))
	}
	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to create GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, dek, nil)
	return append(nonce, ciphertext...)
}

func TestDEKWorkflowScaffolding(t *testing.T) {
	algorithms := []encryption.Algorithm{
		encryption.RSA2048,
		encryption.RSA3072,
		encryption.RSA4096,
		encryption.ECC_P256,
		encryption.ECC_P384,
		encryption.ECC_P521,
		encryption.KYBER512,
		encryption.KYBER768,
		encryption.KYBER1024,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			env := newDEKTestEnv(t, alg)
			key := env.createServiceKey(t)
			plaintext := []byte("Secret data for " + string(alg))
			tdo, originalDEK := env.createZTDF(t, key, plaintext)
			if len(tdo.Payload) == 0 {
				t.Fatalf("expected payload data for %s", alg)
			}
			got := env.unwrapZTDF(t, key, tdo)
			if string(got) != string(plaintext) {
				t.Fatalf("plaintext mismatch for %s", alg)
			}
			if len(originalDEK) != 32 {
				t.Fatalf("expected 32 byte DEK for %s", alg)
			}
		})
	}
}
