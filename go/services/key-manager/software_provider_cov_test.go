//go:build !fips

package key_manager

import (
	"context"
	"crypto/rand"
	"testing"
)

func TestCoverageFinal80_SoftwareProvider_ListKeyPairsNoStore(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	ctx := context.Background()

	_, err := provider.ListKeyPairs(ctx)
	if err == nil {
		t.Fatal("expected error for nil keyStore")
	}
}

func TestCoverageFinal80_SoftwareProvider_RotateKey(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)
	ctx := context.Background()

	kp, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "rotate-sw-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Add metadata to cover the loop at line 352
	kp.Metadata = map[string]string{"env": "test"}

	// Store the key pair in the key store so RotateKey can find it
	if err := keyStore.StoreKeyPair(ctx, kp); err != nil {
		t.Fatal(err)
	}

	newKP, err := provider.RotateKey(ctx, "rotate-sw-key")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if newKP.LastRotated == nil {
		t.Fatal("expected LastRotated set")
	}
}

func TestCoverageFinal80_SoftwareProvider_GenerateKeyPair_Unsupported(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_UNSPECIFIED, "k", nil)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestCoverageFinal80_SoftwareProvider_SharedSecretEncryptDecrypt(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatal(err)
	}
	kemCiphertext := []byte("kem-ct-placeholder")

	encrypted, err := provider.encryptDEKWithSharedSecret(dek, sharedSecret, kemCiphertext)
	if err != nil {
		t.Fatalf("encryptDEKWithSharedSecret: %v", err)
	}

	// Decrypt: strip the KEM ciphertext prefix
	encryptedDEK := encrypted[len(kemCiphertext):]
	decrypted, err := provider.decryptDEKWithSharedSecret(encryptedDEK, sharedSecret)
	if err != nil {
		t.Fatalf("decryptDEKWithSharedSecret: %v", err)
	}

	if string(decrypted) != string(dek) {
		t.Fatal("round-trip mismatch")
	}
}

func TestCoverageFinal80_SoftwareProvider_PublicKeyToPEM_Unsupported(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, err := provider.publicKeyToPEM("not-a-key")
	if err == nil {
		t.Fatal("expected error for unsupported public key type")
	}
}

func TestCoverageFinal80_SoftwareProvider_DecryptDEKWithSharedSecret_TooShort(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatal(err)
	}
	// Encrypted DEK too short for nonce
	_, err := provider.decryptDEKWithSharedSecret([]byte{1}, sharedSecret)
	if err == nil {
		t.Fatal("expected error for encrypted DEK too short")
	}
}

func TestCoverageFinal80_SoftwareProvider_SharedSecretTooShort(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, err := provider.encryptDEKWithSharedSecret([]byte("dek"), []byte("short"), nil)
	if err == nil {
		t.Fatal("expected error for short shared secret")
	}
	_, err = provider.decryptDEKWithSharedSecret([]byte("enc"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for short shared secret in decrypt")
	}
}
