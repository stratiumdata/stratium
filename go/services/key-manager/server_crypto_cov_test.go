//go:build !fips

package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCoverageFinal80_ParseClientPublicKey(t *testing.T) {
	// nil key
	_, err := parseClientPublicKey(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}

	// empty PEM
	_, err = parseClientPublicKey(&Key{KeyId: "k"})
	if err == nil {
		t.Fatal("expected error for empty PEM")
	}

	// invalid PEM
	_, err = parseClientPublicKey(&Key{KeyId: "k", PublicKeyPem: "not-pem"})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}

	// valid PEM
	pubPEM := generateRSAPEM(t)
	pub, err := parseClientPublicKey(&Key{KeyId: "k", PublicKeyPem: pubPEM, KeyType: KeyType_KEY_TYPE_RSA_2048})
	if err != nil {
		t.Fatal(err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestCoverageFinal80_DecryptClientWrappedDEKWithKey_UnsupportedType(t *testing.T) {
	// ECC key - not supported for secure wrapping
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	key := &Key{KeyId: "ecc", PublicKeyPem: ecPEM, KeyType: KeyType_KEY_TYPE_ECC_P256}
	_, err := decryptClientWrappedDEKWithKey(key, []byte("ciphertext"))
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestCoverageFinal80_RsaPublicUnwrap_InvalidLength(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := rsaPublicUnwrap(&rsaKey.PublicKey, []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid ciphertext length")
	}
}

func TestCoverageFinal80_RsaPublicUnwrap_BadPadding(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	k := (rsaKey.PublicKey.N.BitLen() + 7) / 8
	// Create ciphertext of correct length but invalid content
	badCiphertext := make([]byte, k)
	badCiphertext[0] = 0x01 // valid range but bad padding
	_, err := rsaPublicUnwrap(&rsaKey.PublicKey, badCiphertext)
	if err == nil {
		t.Fatal("expected error for bad padding")
	}
}

func TestCoverageFinal80_VerifyYubiKeyRSASignature_Invalid(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	err := verifyYubiKeyRSASignature(&rsaKey.PublicKey, []byte("data"), []byte("bad-sig"))
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestCoverageFinal80_InferKeyTypeFromPEM_ECC(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	kt, err := inferKeyTypeFromPEM(ecPEM)
	if err != nil {
		t.Fatal(err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P384 {
		t.Fatalf("expected ECC_P384, got %v", kt)
	}
}
