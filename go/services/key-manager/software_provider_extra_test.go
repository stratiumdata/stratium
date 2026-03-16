//go:build !fips

package key_manager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSoftwareKeyProvider_ListKeyPairs_NoKeyStore(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	// No keyStore set - should return error
	_, err := provider.ListKeyPairs(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyStore not initialized")
}

func TestSoftwareKeyProvider_ListKeyPairs_WithKeyStore(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	// Generate a few key pairs; also store Key metadata so ListKeys can filter by provider_type
	keyPair1, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "list-key-1", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair1)
	require.NoError(t, err)
	err = keyStore.StoreKey(ctx, &Key{
		KeyId:        "list-key-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
	})
	require.NoError(t, err)

	keyPair2, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "list-key-2", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair2)
	require.NoError(t, err)
	err = keyStore.StoreKey(ctx, &Key{
		KeyId:        "list-key-2",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
	})
	require.NoError(t, err)

	ids, err := provider.ListKeyPairs(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(ids), 2)
	assert.Contains(t, ids, "list-key-1")
	assert.Contains(t, ids, "list-key-2")
}

func TestSoftwareKeyProvider_DeleteKeyPair_NoKeyStore(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	// No keyStore set - should return error
	err := provider.DeleteKeyPair(context.Background(), "some-key-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyStore not initialized")
}

func TestSoftwareKeyProvider_DeleteKeyPair_WithKeyStore(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	// Delete should be a no-op for software provider
	err := provider.DeleteKeyPair(ctx, "non-existent-key")
	require.NoError(t, err)
}

func TestSoftwareKeyProvider_GetKeyPair_NoKeyStore(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, err := provider.GetKeyPair(context.Background(), "some-key-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyStore not initialized")
}

func TestSoftwareKeyProvider_GetKeyPair_NotFound(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	_, err := provider.GetKeyPair(ctx, "non-existent-key")
	require.Error(t, err)
}

func TestSoftwareKeyProvider_Sign_RSA(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "sign-key", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	data := []byte("hello, world")
	signature, err := provider.Sign(ctx, "sign-key", data)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSoftwareKeyProvider_Sign_ECC(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "sign-ecc-key", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	data := []byte("data to sign")
	signature, err := provider.Sign(ctx, "sign-ecc-key", data)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSoftwareKeyProvider_Sign_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	_, err := provider.Sign(ctx, "missing-key", []byte("data"))
	require.Error(t, err)
}

func TestSoftwareKeyProvider_Encrypt_RSA(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "enc-key", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	plaintext := []byte("secret data")
	ciphertext, err := provider.Encrypt(ctx, "enc-key", plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
}

func TestSoftwareKeyProvider_Decrypt_RSA(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "dec-key", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	plaintext := []byte("secret data to encrypt and decrypt")
	ciphertext, err := provider.Encrypt(ctx, "dec-key", plaintext)
	require.NoError(t, err)

	decrypted, err := provider.Decrypt(ctx, "dec-key", ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSoftwareKeyProvider_Encrypt_ECC(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "enc-ecc-key", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	plaintext := []byte("ecc secret")
	ciphertext, err := provider.Encrypt(ctx, "enc-ecc-key", plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
}

func TestSoftwareKeyProvider_Decrypt_ECC(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "dec-ecc-key", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	plaintext := []byte("ecc secret to roundtrip")
	ciphertext, err := provider.Encrypt(ctx, "dec-ecc-key", plaintext)
	require.NoError(t, err)

	decrypted, err := provider.Decrypt(ctx, "dec-ecc-key", ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSoftwareKeyProvider_RotateKey(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "rotate-key", nil)
	require.NoError(t, err)
	err = keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	newKeyPair, err := provider.RotateKey(ctx, "rotate-key")
	require.NoError(t, err)
	assert.NotNil(t, newKeyPair)
	assert.NotNil(t, newKeyPair.LastRotated)
}

func TestSoftwareKeyProvider_RotateKey_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	_, err := provider.RotateKey(ctx, "non-existent-key")
	require.Error(t, err)
}

func TestSoftwareKeyProvider_SetKeyStore(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)

	keyStore1 := NewInMemoryKeyStore()
	provider.SetKeyStore(keyStore1)

	// Replace with a new key store
	keyStore2 := NewInMemoryKeyStore()
	provider.SetKeyStore(keyStore2)

	// Should work with the new key store
	ctx := context.Background()
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "test-key", nil)
	require.NoError(t, err)
	err = keyStore2.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	retrieved, err := provider.GetKeyPair(ctx, "test-key")
	require.NoError(t, err)
	assert.Equal(t, "test-key", retrieved.KeyID)
}
