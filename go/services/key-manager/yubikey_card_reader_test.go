package key_manager

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeYubiPIVRunner struct {
	t                *testing.T
	privateKey       *rsa.PrivateKey
	expectedPIN      string
	touchPolicy      string
	ykmanInfoOutput  string
	yubicoStatusText string
}

func (f *fakeYubiPIVRunner) run(name string, stdin string, args ...string) ([]byte, error) {
	if strings.Contains(name, "ykman") && len(args) >= 4 &&
		args[0] == "piv" && args[1] == "keys" && args[2] == "info" {
		if strings.TrimSpace(f.ykmanInfoOutput) != "" {
			return []byte(f.ykmanInfoOutput), nil
		}
		policy := f.touchPolicy
		if policy == "" {
			policy = "ALWAYS"
		}
		return []byte("Algorithm: RSA2048\nTouch policy: " + policy + "\n"), nil
	}

	if containsArg(args, "--sign") {
		if strings.TrimSpace(stdin) != f.expectedPIN {
			return nil, fmt.Errorf("invalid PIN")
		}
		if containsArg(args, "-P") {
			return nil, fmt.Errorf("pin must not be passed as CLI argument")
		}
		inputPath := argValue(args, "-i")
		outputPath := argValue(args, "-o")
		payload, err := os.ReadFile(inputPath)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(payload)
		signature, err := rsa.SignPKCS1v15(rand.Reader, f.privateKey, crypto.SHA256, digest[:])
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(outputPath, signature, 0600); err != nil {
			return nil, err
		}
		return []byte("ok"), nil
	}
	if hasAction(args, "test-decipher") {
		if strings.TrimSpace(stdin) != f.expectedPIN {
			return nil, fmt.Errorf("invalid PIN")
		}
		if containsArg(args, "-P") {
			return nil, fmt.Errorf("pin must not be passed as CLI argument")
		}
		inputPath := argValue(args, "-i")
		outputPath := argValue(args, "-o")
		ciphertext, err := os.ReadFile(inputPath)
		if err != nil {
			return nil, err
		}
		plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.privateKey, ciphertext, nil)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
			return nil, err
		}
		return []byte("ok"), nil
	}

	action := argValue(args, "-a")
	switch action {
	case "verify-pin":
		if strings.TrimSpace(stdin) != f.expectedPIN {
			return nil, fmt.Errorf("invalid PIN")
		}
		if containsArg(args, "-P") {
			return nil, fmt.Errorf("pin must not be passed as CLI argument")
		}
		return []byte("PIN verified"), nil
	case "status":
		if strings.TrimSpace(f.yubicoStatusText) != "" {
			return []byte(f.yubicoStatusText), nil
		}
		return []byte(""), nil
	case "read-certificate":
		outputPath := argValue(args, "-o")
		if outputPath == "" {
			return nil, fmt.Errorf("missing output path")
		}
		certPEM, err := createCertificatePEM(f.privateKey)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(outputPath, certPEM, 0600); err != nil {
			return nil, err
		}
		return []byte("ok"), nil
	case "test-decipher":
		inputPath := argValue(args, "-i")
		outputPath := argValue(args, "-o")
		ciphertext, err := os.ReadFile(inputPath)
		if err != nil {
			return nil, err
		}
		plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.privateKey, ciphertext, nil)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
			return nil, err
		}
		return []byte("ok"), nil
	case "generate":
		outputPath := argValue(args, "-o")
		if outputPath == "" {
			return nil, fmt.Errorf("missing output path")
		}
		publicDER, err := x509.MarshalPKIXPublicKey(&f.privateKey.PublicKey)
		if err != nil {
			return nil, err
		}
		publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
		if err := os.WriteFile(outputPath, publicPEM, 0600); err != nil {
			return nil, err
		}
		return []byte("ok"), nil
	default:
		return []byte("ok"), nil
	}
}

func containsArg(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func hasAction(args []string, action string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-a" && args[i+1] == action {
			return true
		}
	}
	return false
}

func argValue(args []string, flag string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func createCertificatePEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stratium-test-yubikey"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func TestYubiKeyPIVCardReader_ConfigureAuthenticateGenerateAndRoundTrip(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tmpDir := t.TempDir()
	pkcs11Path := filepath.Join(tmpDir, "opensc-pkcs11.so")
	if err := os.WriteFile(pkcs11Path, []byte("stub"), 0600); err != nil {
		t.Fatalf("failed to write pkcs11 stub path: %v", err)
	}

	fake := &fakeYubiPIVRunner{
		t:           t,
		privateKey:  privateKey,
		expectedPIN: "123456",
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fake.run
	reader.lookPath = func(file string) (string, error) {
		return "/usr/bin/" + strings.TrimSpace(file), nil
	}

	if err := reader.Connect(map[string]string{
		"pkcs11_library": pkcs11Path,
		"slot":           "9d",
	}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	if err := reader.Authenticate("123456"); err != nil {
		t.Fatalf("Authenticate() failed: %v", err)
	}

	if err := reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "service-key-1", map[string]interface{}{}); err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	if _, err := reader.GetPublicKey("service-key-1"); err != nil {
		t.Fatalf("GetPublicKey() failed: %v", err)
	}

	plaintext := []byte("yubikey-backed roundtrip")
	ciphertext, err := reader.Encrypt("service-key-1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	decrypted, err := reader.Decrypt("service-key-1", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted text mismatch: got %q want %q", string(decrypted), string(plaintext))
	}

	keys, err := reader.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() failed: %v", err)
	}
	if len(keys) != 1 || keys[0] != "service-key-1" {
		t.Fatalf("unexpected key list: %#v", keys)
	}
}

func TestYubiKeyPIVCardReader_Authenticate_RequireTouchPolicy(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	fake := &fakeYubiPIVRunner{
		t:           t,
		privateKey:  privateKey,
		expectedPIN: "123456",
		touchPolicy: "ALWAYS",
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fake.run
	reader.lookPath = func(file string) (string, error) {
		return "/usr/bin/" + strings.TrimSpace(file), nil
	}

	if err := reader.Connect(map[string]string{
		"slot":          "9d",
		"require_touch": "true",
	}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	if err := reader.Authenticate("123456"); err != nil {
		t.Fatalf("Authenticate() failed: %v", err)
	}
}

func TestYubiKeyPIVCardReader_Authenticate_RequireTouchPolicyRejectedWhenNotAlways(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	fake := &fakeYubiPIVRunner{
		t:           t,
		privateKey:  privateKey,
		expectedPIN: "123456",
		touchPolicy: "NEVER",
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fake.run
	reader.lookPath = func(file string) (string, error) {
		return "/usr/bin/" + strings.TrimSpace(file), nil
	}

	if err := reader.Connect(map[string]string{
		"slot":          "9d",
		"require_touch": "true",
	}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	err = reader.Authenticate("123456")
	if err == nil {
		t.Fatal("expected Authenticate() to fail when touch policy is not ALWAYS")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "touch policy") {
		t.Fatalf("expected touch policy error, got: %v", err)
	}
}

func TestYubiKeyPIVCardReader_Authenticate_RequireTouchPolicy_FallbackToPIVStatus(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	fake := &fakeYubiPIVRunner{
		t:           t,
		privateKey:  privateKey,
		expectedPIN: "123456",
		ykmanInfoOutput: `Algorithm: RSA2048
Metadata: unavailable on this firmware`,
		yubicoStatusText: `Version: 5.7.0
Slot 9d:
  Algorithm: RSA2048
  Touch required for use: ALWAYS`,
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fake.run
	reader.lookPath = func(file string) (string, error) {
		return "/usr/bin/" + strings.TrimSpace(file), nil
	}

	if err := reader.Connect(map[string]string{
		"slot":          "9d",
		"require_touch": "true",
	}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	if err := reader.Authenticate("123456"); err != nil {
		t.Fatalf("Authenticate() failed with fallback status parser: %v", err)
	}
}

func TestParseTouchPolicyFromYKManInfo_VariantFormats(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name: "colon uppercase",
			input: `Algorithm: RSA2048
Touch policy: ALWAYS`,
			expect: "always",
		},
		{
			name: "aligned spacing",
			input: `Algorithm         RSA2048
Touch    policy    ALWAYS`,
			expect: "always",
		},
		{
			name:   "equals syntax",
			input:  `touch policy = cached`,
			expect: "cached",
		},
		{
			name:   "required for use syntax",
			input:  `Touch required for use: ALWAYS`,
			expect: "always",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTouchPolicyFromYKManInfo([]byte(tc.input))
			if err != nil {
				t.Fatalf("parseTouchPolicyFromYKManInfo() failed: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("unexpected touch policy: got %q want %q", got, tc.expect)
			}
		})
	}
}

func TestYubiKeyPIVCardReader_Authenticate_RequireTouchPolicyFailsWhenPolicyUnavailable(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	fake := &fakeYubiPIVRunner{
		t:               t,
		privateKey:      privateKey,
		expectedPIN:     "123456",
		ykmanInfoOutput: "Metadata unavailable",
		// No touch policy data in status output either.
		yubicoStatusText: "Version: 5.7.0\nSlot 9d:\n  Algorithm: RSA2048",
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fake.run
	reader.lookPath = func(file string) (string, error) {
		return "/usr/bin/" + strings.TrimSpace(file), nil
	}

	if err := reader.Connect(map[string]string{
		"slot":          "9d",
		"require_touch": "true",
	}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	err = reader.Authenticate("123456")
	if err == nil {
		t.Fatal("expected Authenticate() to fail when touch policy cannot be determined")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "failed to verify touch policy") {
		t.Fatalf("expected strict touch-policy verification error, got: %v", err)
	}
}
