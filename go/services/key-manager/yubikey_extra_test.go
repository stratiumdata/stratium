package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newSHA256() hash.Hash { return sha256.New() }

// ---------------------------------------------------------------------------
// defaultCommandRunner
// ---------------------------------------------------------------------------

func TestDefaultCommandRunner_Echo(t *testing.T) {
	output, err := defaultCommandRunner("echo", "", "hello")
	if err != nil {
		t.Fatalf("defaultCommandRunner(echo) error = %v", err)
	}
	if !strings.Contains(string(output), "hello") {
		t.Fatalf("expected output to contain 'hello', got %q", string(output))
	}
}

func TestDefaultCommandRunner_NonexistentCommand(t *testing.T) {
	_, err := defaultCommandRunner("__nonexistent_command_xyz987__", "", "arg1")
	if err == nil {
		t.Fatal("expected error for nonexistent command, got nil")
	}
}

func TestDefaultCommandRunner_WithStdin(t *testing.T) {
	output, err := defaultCommandRunner("cat", "hello-stdin")
	if err != nil {
		t.Fatalf("defaultCommandRunner(cat with stdin) error = %v", err)
	}
	if !strings.Contains(string(output), "hello-stdin") {
		t.Fatalf("expected output to contain 'hello-stdin', got %q", string(output))
	}
}

func TestDefaultCommandRunner_CommandFails(t *testing.T) {
	_, err := defaultCommandRunner("false", "")
	if err == nil {
		t.Fatal("expected error for command that exits with non-zero status")
	}
}

func TestDefaultCommandRunner_CommandFailsWithOutput(t *testing.T) {
	_, err := defaultCommandRunner("ls", "", "/this/path/does/not/exist/abc123xyz")
	if err == nil {
		t.Fatal("expected error for ls of nonexistent path")
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Fatal("expected non-empty error message")
	}
}

// ---------------------------------------------------------------------------
// generateKeyAndReadPublicKey
// ---------------------------------------------------------------------------

func makeGenerateRunner(outputDER []byte) commandRunner {
	return func(name string, stdin string, args ...string) ([]byte, error) {
		action := argValue(args, "-a")
		if action == "generate" {
			outputPath := argValue(args, "-o")
			if outputPath == "" {
				return nil, fmt.Errorf("missing -o argument")
			}
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: outputDER})
			return []byte("ok"), os.WriteFile(outputPath, pubPEM, 0600)
		}
		return []byte("ok"), nil
	}
}

func TestGenerateKeyAndReadPublicKey_RSA2048(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = makeGenerateRunner(pubDER)
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.sessionPIN = "123456"

	pub, err := reader.generateKeyAndReadPublicKey("9d", KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("generateKeyAndReadPublicKey RSA2048 failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestGenerateKeyAndReadPublicKey_ECCP256(t *testing.T) {
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privEC.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = makeGenerateRunner(pubDER)
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.sessionPIN = "123456"

	pub, err := reader.generateKeyAndReadPublicKey("9d", KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("generateKeyAndReadPublicKey ECCP256 failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestGenerateKeyAndReadPublicKey_ECCP384(t *testing.T) {
	privEC, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privEC.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = makeGenerateRunner(pubDER)
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.sessionPIN = "123456"

	pub, err := reader.generateKeyAndReadPublicKey("9d", KeyType_KEY_TYPE_ECC_P384)
	if err != nil {
		t.Fatalf("generateKeyAndReadPublicKey ECCP384 failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestGenerateKeyAndReadPublicKey_UnsupportedKeyType(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	_, err := reader.generateKeyAndReadPublicKey("9d", KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestGenerateKeyAndReadPublicKey_RunnerError(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		if argValue(args, "-a") == "generate" {
			return nil, fmt.Errorf("simulated runner error")
		}
		return []byte("ok"), nil
	}
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	_, err := reader.generateKeyAndReadPublicKey("9d", KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error when runner fails")
	}
}

func TestGenerateKeyAndReadPublicKey_BadPEM(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		if argValue(args, "-a") == "generate" {
			outputPath := argValue(args, "-o")
			return []byte("ok"), os.WriteFile(outputPath, []byte("not-a-pem"), 0600)
		}
		return []byte("ok"), nil
	}
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	_, err := reader.generateKeyAndReadPublicKey("9d", KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error when PEM is invalid")
	}
}

// ---------------------------------------------------------------------------
// resolveSlotFromConfig - covering all branches
// ---------------------------------------------------------------------------

func TestResolveSlotFromConfig_SlotInParam(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	slot := reader.resolveSlotFromConfig(map[string]string{"slot": "9A"})
	if slot != "9a" {
		t.Fatalf("expected 9a, got %s", slot)
	}
}

func TestResolveSlotFromConfig_KeyIDInParam(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	slot := reader.resolveSlotFromConfig(map[string]string{"key_id": "9c"})
	if slot != "9c" {
		t.Fatalf("expected 9c, got %s", slot)
	}
}

func TestResolveSlotFromConfig_SlotInReaderConfig(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.config["slot"] = "9B"
	slot := reader.resolveSlotFromConfig(map[string]string{})
	if slot != "9b" {
		t.Fatalf("expected 9b, got %s", slot)
	}
}

func TestResolveSlotFromConfig_KeyIDInReaderConfig(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.config["key_id"] = "9e"
	slot := reader.resolveSlotFromConfig(map[string]string{})
	if slot != "9e" {
		t.Fatalf("expected 9e, got %s", slot)
	}
}

func TestResolveSlotFromConfig_SelectedSlot(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.selectedSlot = "9F"
	slot := reader.resolveSlotFromConfig(map[string]string{})
	if slot != "9f" {
		t.Fatalf("expected 9f, got %s", slot)
	}
}

func TestResolveSlotFromConfig_DefaultSlot(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	slot := reader.resolveSlotFromConfig(map[string]string{})
	if slot != "9d" {
		t.Fatalf("expected default 9d, got %s", slot)
	}
}

func TestResolveSlotFromConfig_NilConfig(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	slot := reader.resolveSlotFromConfig(nil)
	if slot != "9d" {
		t.Fatalf("expected default 9d for nil config, got %s", slot)
	}
}

// ---------------------------------------------------------------------------
// parsePublicKeyFromPEMBlob - additional branches
// ---------------------------------------------------------------------------

func TestParsePublicKeyFromPEMBlob_PublicKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	pub, err := parsePublicKeyFromPEMBlob(pubPEM)
	if err != nil {
		t.Fatalf("parsePublicKeyFromPEMBlob PUBLIC KEY failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestParsePublicKeyFromPEMBlob_ECPublicKeyPEM(t *testing.T) {
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privEC.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	// "EC PUBLIC KEY" exercises the alternate parse branch
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PUBLIC KEY", Bytes: pubDER})

	pub, err := parsePublicKeyFromPEMBlob(pubPEM)
	if err != nil {
		t.Fatalf("parsePublicKeyFromPEMBlob EC PUBLIC KEY failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestParsePublicKeyFromPEMBlob_MultipleBlocksFirstUnknown(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)

	garbage := pem.EncodeToMemory(&pem.Block{Type: "GARBAGE BLOCK", Bytes: []byte("junk")})
	validPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	combined := append(garbage, validPub...)

	pub, err := parsePublicKeyFromPEMBlob(combined)
	if err != nil {
		t.Fatalf("parsePublicKeyFromPEMBlob with leading garbage block failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key from second block")
	}
}

func TestParsePublicKeyFromPEMBlob_NoParseableKey(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "GARBAGE", Bytes: []byte("junk")})
	_, err := parsePublicKeyFromPEMBlob(badPEM)
	if err == nil {
		t.Fatal("expected error for PEM with no parseable public key")
	}
}

func TestParsePublicKeyFromPEMBlob_InvalidCertificate(t *testing.T) {
	badCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid-der-data")})
	_, err := parsePublicKeyFromPEMBlob(badCertPEM)
	if err == nil {
		t.Fatal("expected error for invalid CERTIFICATE DER content")
	}
}

// ---------------------------------------------------------------------------
// Encrypt - additional branches (ECC and unsupported key type)
// ---------------------------------------------------------------------------

func TestYubiKey_Encrypt_WithECCKey(t *testing.T) {
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	reader := NewYubiKeyPIVCardReader()
	reader.keys["ecc-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_ECC_P256,
		publicKey: &privEC.PublicKey,
	}

	ct, err := reader.Encrypt("ecc-key", []byte("test-plaintext"))
	if err != nil {
		t.Fatalf("Encrypt with ECC key failed: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}
}

func TestYubiKey_Encrypt_UnsupportedKeyType(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.keys["bad-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_UNSPECIFIED,
		publicKey: "not-a-crypto-key",
	}

	_, err := reader.Encrypt("bad-key", []byte("plaintext"))
	if err == nil {
		t.Fatal("expected error for unsupported public key type")
	}
}

// ---------------------------------------------------------------------------
// Sign - fallback paths
// ---------------------------------------------------------------------------

func TestYubiKey_Sign_FallbackToTestSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	fakeRunner := func(name string, stdin string, args ...string) ([]byte, error) {
		if containsArg(args, "--sign") {
			return nil, fmt.Errorf("primary sign not supported")
		}
		if hasAction(args, "test-signature") {
			outputPath := argValue(args, "-o")
			return []byte("ok"), os.WriteFile(outputPath, []byte("fake-sig"), 0600)
		}
		return []byte("ok"), nil
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fakeRunner
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.connected = true
	reader.authenticated = true
	reader.sessionPIN = "123456"
	reader.keys["sign-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_RSA_2048,
		publicKey: &priv.PublicKey,
	}

	sig, err := reader.Sign("sign-key", []byte("data"))
	if err != nil {
		t.Fatalf("Sign with test-signature fallback failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature from fallback")
	}
}

func TestYubiKey_Sign_FallbackToLegacySign(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	fakeRunner := func(name string, stdin string, args ...string) ([]byte, error) {
		if containsArg(args, "--sign") {
			return nil, fmt.Errorf("primary sign not supported")
		}
		if hasAction(args, "test-signature") {
			return nil, fmt.Errorf("test-signature not supported")
		}
		if argValue(args, "-a") == "sign" {
			outputPath := argValue(args, "-o")
			return []byte("ok"), os.WriteFile(outputPath, []byte("legacy-sig"), 0600)
		}
		return []byte("ok"), nil
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fakeRunner
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.connected = true
	reader.authenticated = true
	reader.sessionPIN = "123456"
	reader.keys["sign-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_RSA_2048,
		publicKey: &priv.PublicKey,
	}

	sig, err := reader.Sign("sign-key", []byte("data"))
	if err != nil {
		t.Fatalf("Sign with legacy fallback failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature from legacy fallback")
	}
}

func TestYubiKey_Sign_AllMethodsFail(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	fakeRunner := func(name string, stdin string, args ...string) ([]byte, error) {
		if containsArg(args, "--sign") {
			return nil, fmt.Errorf("primary sign not supported")
		}
		if hasAction(args, "test-signature") {
			return nil, fmt.Errorf("test-signature not supported")
		}
		if argValue(args, "-a") == "sign" {
			return nil, fmt.Errorf("legacy sign not supported")
		}
		return []byte("ok"), nil
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fakeRunner
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.connected = true
	reader.authenticated = true
	reader.sessionPIN = "123456"
	reader.keys["sign-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_RSA_2048,
		publicKey: &priv.PublicKey,
	}

	_, err = reader.Sign("sign-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error when all sign methods fail")
	}
	if !strings.Contains(err.Error(), "YubiKey sign failed") {
		t.Fatalf("expected 'YubiKey sign failed' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Decrypt - fallback path
// ---------------------------------------------------------------------------

func TestYubiKey_Decrypt_FallbackToLegacy(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	fakeRunner := func(name string, stdin string, args ...string) ([]byte, error) {
		// Primary path: verify-pin combined with test-decipher – fail it
		if hasAction(args, "verify-pin") && hasAction(args, "test-decipher") {
			return nil, fmt.Errorf("primary decipher not supported")
		}
		// Legacy path: test-decipher alone – succeed
		if hasAction(args, "test-decipher") {
			inputPath := argValue(args, "-i")
			outputPath := argValue(args, "-o")
			ciphertext, readErr := os.ReadFile(inputPath)
			if readErr != nil {
				return nil, readErr
			}
			plaintext, decErr := rsa.DecryptOAEP(newSHA256(), rand.Reader, priv, ciphertext, nil)
			if decErr != nil {
				return nil, decErr
			}
			return []byte("ok"), os.WriteFile(outputPath, plaintext, 0600)
		}
		return []byte("ok"), nil
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fakeRunner
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.connected = true
	reader.authenticated = true
	reader.sessionPIN = "123456"
	reader.keys["dec-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_RSA_2048,
		publicKey: &priv.PublicKey,
	}

	ciphertext, err := rsa.EncryptOAEP(newSHA256(), rand.Reader, &priv.PublicKey, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("test encrypt failed: %v", err)
	}

	plaintext, err := reader.Decrypt("dec-key", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt with legacy fallback failed: %v", err)
	}
	if string(plaintext) != "secret" {
		t.Fatalf("expected 'secret', got %q", string(plaintext))
	}
}

func TestYubiKey_Decrypt_AllMethodsFail(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	fakeRunner := func(name string, stdin string, args ...string) ([]byte, error) {
		if hasAction(args, "test-decipher") {
			return nil, fmt.Errorf("decipher not supported")
		}
		return []byte("ok"), nil
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fakeRunner
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.connected = true
	reader.authenticated = true
	reader.sessionPIN = "123456"
	reader.keys["dec-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_RSA_2048,
		publicKey: &priv.PublicKey,
	}

	_, err = reader.Decrypt("dec-key", []byte("fake-ciphertext"))
	if err == nil {
		t.Fatal("expected error when all decrypt methods fail")
	}
}

// ---------------------------------------------------------------------------
// Connect - edge cases
// ---------------------------------------------------------------------------

func TestYubiKey_Connect_PivToolNotFound(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.lookPath = func(file string) (string, error) { return "", fmt.Errorf("not found") }
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) { return []byte("ok"), nil }

	err := reader.Connect(map[string]string{"slot": "9d"})
	if err == nil {
		t.Fatal("expected Connect() to fail when piv tool is not found")
	}
}

func TestYubiKey_Connect_WithDeviceID(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	if err := reader.Connect(map[string]string{
		"slot":      "9d",
		"device_id": "device-55",
	}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if reader.selectedDevice != "device-55" {
		t.Fatalf("expected selectedDevice=device-55, got %s", reader.selectedDevice)
	}
}

func TestYubiKey_Connect_WithPKCS11Library_NotExist(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	err := reader.Connect(map[string]string{
		"slot":           "9d",
		"pkcs11_library": "/nonexistent/path/to/library.so",
	})
	if err == nil {
		t.Fatal("expected Connect() to fail for nonexistent pkcs11_library")
	}
}

func TestYubiKey_Connect_SkipsPINKey(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	if err := reader.Connect(map[string]string{
		"slot": "9d",
		"pin":  "should-be-skipped",
	}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if _, exists := reader.config["pin"]; exists {
		t.Fatal("expected 'pin' to not be stored in config")
	}
}

// ---------------------------------------------------------------------------
// GetDeviceInfo - with pkcs11_library set
// ---------------------------------------------------------------------------

func TestYubiKey_GetDeviceInfo_WithPKCS11Library(t *testing.T) {
	tmp := t.TempDir()
	libPath := filepath.Join(tmp, "opensc-pkcs11.so")
	if err := os.WriteFile(libPath, []byte("stub"), 0600); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	reader, _ := newFakeYubiKeyReader(t, "123456")
	if err := reader.Connect(map[string]string{
		"slot":           "9d",
		"pkcs11_library": libPath,
	}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	info, err := reader.GetDeviceInfo()
	if err != nil {
		t.Fatalf("GetDeviceInfo() failed: %v", err)
	}
	if info["pkcs11_library"] != libPath {
		t.Fatalf("expected pkcs11_library in device info, got %v", info)
	}
}

// ---------------------------------------------------------------------------
// ListDevices - with ykman returning serial numbers
// ---------------------------------------------------------------------------

func TestYubiKey_ListDevices_YkmanReturnsSerials(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		if strings.Contains(name, "ykman") && containsArg(args, "--serials") {
			return []byte("12345678\n87654321\n"), nil
		}
		return []byte("ok"), nil
	}
	reader.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	reader.connected = true

	devices, err := reader.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices() failed: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("expected devices from ykman serial output")
	}
}

// ---------------------------------------------------------------------------
// keyTypeFromPublicKey - additional branches
// ---------------------------------------------------------------------------

func TestKeyTypeFromPublicKey_RSA3072(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey 3072: %v", err)
	}
	kt := keyTypeFromPublicKey(&priv.PublicKey)
	if kt != KeyType_KEY_TYPE_RSA_3072 {
		t.Fatalf("expected RSA-3072 key type, got %v", kt)
	}
}

func TestKeyTypeFromPublicKey_RSA4096_YubikeyExtra(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("rsa.GenerateKey 4096: %v", err)
	}
	kt := keyTypeFromPublicKey(&priv.PublicKey)
	if kt != KeyType_KEY_TYPE_RSA_4096 {
		t.Fatalf("expected RSA-4096 key type, got %v", kt)
	}
}

