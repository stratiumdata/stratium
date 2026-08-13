package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// generateRSAKeyPEM writes an RSA private key, PEM-encoded as PKCS8, to a
// fresh file and returns its path. PKCS8 specifically (not PKCS1's "RSA
// PRIVATE KEY" block): ParseECPrivateKeyFromPEM tries x509.ParseECPrivateKey
// first, which rejects any RSA encoding outright, then falls back to
// x509.ParsePKCS8PrivateKey. A PKCS1 block fails that fallback too (wrong
// container entirely) and would surface a generic ASN.1 error that never
// actually proves "an RSA key was rejected for being RSA." PKCS8 is a
// generic container the fallback parses successfully — yielding an
// *rsa.PrivateKey — so the failure this test observes is specifically
// readECPrivateKey's own type check (jwt.ErrNotECPrivateKey), which is the
// property under test.
func generateRSAKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal RSA key: %v", err)
	}
	return writePEMFile(t, "PRIVATE KEY", der)
}

func TestLoad_ValidCurrentKey_Succeeds(t *testing.T) {
	signer, err := Load(writeECKeyPEM(t, generateECKey(t)), "")
	if err != nil {
		t.Fatalf("Load() = %v, want success", err)
	}
	if signer == nil {
		t.Fatal("Load() returned a nil Signer alongside a nil error")
	}
}

// TestLoad_EmptyCurrentPath: an empty path must fail Load itself, not defer
// the problem to the first Sign/Verify call — internal/config.Load already
// guarantees this never happens via a real deployment (no default for
// STRATIUM_TOKEN_SIGNING_KEY_PATH), but Load must not rely on that guarantee
// to fail safely when called directly.
func TestLoad_EmptyCurrentPath(t *testing.T) {
	_, err := Load("", "")
	if err == nil {
		t.Fatal("Load(\"\", \"\") : want error, got nil")
	}
}

func TestLoad_MissingCurrentKeyFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.pem")

	_, err := Load(missing, "")
	if err == nil {
		t.Fatal("Load() with a nonexistent current key file: want error, got nil")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not name the missing path %q", err.Error(), missing)
	}
}

// TestLoad_UnreadableCurrentKeyFile: a file that exists but this process
// cannot open must fail Load the same way a missing one does — an operator
// fixing a permissions mistake needs the same clear signal a typo in the
// path would give. Skipped when running as root: root bypasses Unix
// permission bits entirely, which would make this test assert something
// that is not true for the account actually running it.
func TestLoad_UnreadableCurrentKeyFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not restrict root's own reads")
	}
	path := writeECKeyPEM(t, generateECKey(t))
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}

	_, err := Load(path, "")
	if err == nil {
		t.Fatal("Load() with an unreadable current key file: want error, got nil")
	}
}

func TestLoad_NonPEMCurrentKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-pem.txt")
	if err := os.WriteFile(path, []byte("this is not a PEM file, just plain text\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	_, err := Load(path, "")
	if err == nil {
		t.Fatal("Load() with a non-PEM current key file: want error, got nil")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("error %q does not name the problem (not PEM-encoded)", err.Error())
	}
}

// TestLoad_RSACurrentKeyRejected: spec K1 requires EC (ES256); an RSA key
// must be refused at Load, naming the mismatch, not accepted and left to
// fail confusingly the first time something tries to use it as an ES256
// key.
func TestLoad_RSACurrentKeyRejected(t *testing.T) {
	path := generateRSAKeyPEM(t)

	_, err := Load(path, "")
	if err == nil {
		t.Fatal("Load() with an RSA current key: want error, got nil")
	}
	if !strings.Contains(err.Error(), "ECDSA") {
		t.Errorf("error %q does not name the problem (not an ECDSA key)", err.Error())
	}
}

// TestLoad_PreviousKeyOptional_Absent: previousPath == "" is the ordinary,
// steady-state configuration (see internal/config.Config.TokenPreviousKeyPath's
// own doc comment) and must succeed with no previous key registered — checked
// structurally here (the field itself is nil), not just "Load returned no
// error," since a Signer that silently treated some OTHER key as previous
// would also return no error.
func TestLoad_PreviousKeyOptional_Absent(t *testing.T) {
	signer, err := Load(writeECKeyPEM(t, generateECKey(t)), "")
	if err != nil {
		t.Fatalf("Load() = %v, want success", err)
	}
	if signer.previous != nil {
		t.Errorf("signer.previous = %v, want nil when STRATIUM_TOKEN_PREVIOUS_KEY_PATH is unset", signer.previous)
	}
}

// TestLoad_PreviousKeyBadFile_Fails: a CONFIGURED previous key that is
// missing, unreadable, non-PEM, or the wrong type must fail Load exactly
// like a bad current key does — an operator who set
// STRATIUM_TOKEN_PREVIOUS_KEY_PATH to a broken path must learn that at
// startup, not have Load quietly proceed with no previous key at all
// (silently narrowing "rotation in progress" to "rotation in progress,
// except every token issued before the restart now fails to verify").
func TestLoad_PreviousKeyBadFile_Fails(t *testing.T) {
	currentPath := writeECKeyPEM(t, generateECKey(t))
	badPreviousPath := filepath.Join(t.TempDir(), "does-not-exist.pem")

	_, err := Load(currentPath, badPreviousPath)
	if err == nil {
		t.Fatal("Load() with a nonexistent previous key file: want error, got nil")
	}
	if !strings.Contains(err.Error(), badPreviousPath) {
		t.Errorf("error %q does not name the missing previous key path %q", err.Error(), badPreviousPath)
	}
}

// TestLoad_PreviousKeyRSARejected mirrors TestLoad_RSACurrentKeyRejected for
// the previous key slot: the type requirement applies to both keys, not
// only the one that also signs.
func TestLoad_PreviousKeyRSARejected(t *testing.T) {
	currentPath := writeECKeyPEM(t, generateECKey(t))
	rsaPreviousPath := generateRSAKeyPEM(t)

	_, err := Load(currentPath, rsaPreviousPath)
	if err == nil {
		t.Fatal("Load() with an RSA previous key: want error, got nil")
	}
	if !strings.Contains(err.Error(), "ECDSA") {
		t.Errorf("error %q does not name the problem (not an ECDSA key)", err.Error())
	}
}
