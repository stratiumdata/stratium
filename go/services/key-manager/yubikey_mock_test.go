package key_manager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"
)

// newFakeYubiKeyReader creates a YubiKeyPIVCardReader pre-wired with a
// fakeYubiPIVRunner and a no-op lookPath.  The reader is NOT yet connected
// or authenticated; callers must do that themselves if needed.
func newFakeYubiKeyReader(t *testing.T, pin string) (*YubiKeyPIVCardReader, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	fake := &fakeYubiPIVRunner{
		t:           t,
		privateKey:  priv,
		expectedPIN: pin,
	}

	reader := NewYubiKeyPIVCardReader()
	reader.runner = fake.run
	reader.lookPath = func(file string) (string, error) {
		return "/usr/bin/" + strings.TrimSpace(file), nil
	}

	return reader, priv
}

// connectAndAuthenticate connects and authenticates the reader with the given pin and slot.
func connectAndAuthenticate(t *testing.T, reader *YubiKeyPIVCardReader, pin, slot string) {
	t.Helper()
	cfg := map[string]string{"slot": slot}
	if err := reader.Connect(cfg); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if err := reader.Authenticate(pin); err != nil {
		t.Fatalf("Authenticate() failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Connect / Disconnect / IsConnected
// ---------------------------------------------------------------------------

func TestYubiKey_Connect_WithMockRunner(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "111111")

	if err := reader.Connect(map[string]string{"slot": "9a"}); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if !reader.IsConnected() {
		t.Fatal("expected IsConnected() to be true after Connect()")
	}
}

func TestYubiKey_Disconnect(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "111111")

	reader.Connect(map[string]string{"slot": "9a"}) //nolint:errcheck
	if err := reader.Disconnect(); err != nil {
		t.Fatalf("Disconnect() failed: %v", err)
	}
	if reader.IsConnected() {
		t.Fatal("expected IsConnected() to be false after Disconnect()")
	}
	if reader.IsAuthenticated() {
		t.Fatal("expected IsAuthenticated() to be false after Disconnect()")
	}
}

func TestYubiKey_Connect_Reconnect(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "111111")
	reader.Connect(map[string]string{"slot": "9a"}) //nolint:errcheck
	reader.Disconnect()                              //nolint:errcheck

	// Reconnect should succeed.
	if err := reader.Connect(map[string]string{"slot": "9a"}); err != nil {
		t.Fatalf("second Connect() failed: %v", err)
	}
	if !reader.IsConnected() {
		t.Fatal("expected IsConnected() after second Connect()")
	}
}

// ---------------------------------------------------------------------------
// Authenticate / IsAuthenticated
// ---------------------------------------------------------------------------

func TestYubiKey_Authenticate(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck

	if err := reader.Authenticate("123456"); err != nil {
		t.Fatalf("Authenticate() failed: %v", err)
	}
	if !reader.IsAuthenticated() {
		t.Fatal("expected IsAuthenticated() to be true")
	}
}

func TestYubiKey_Authenticate_WrongPIN(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "correct-pin")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck

	err := reader.Authenticate("wrong-pin")
	if err == nil {
		t.Fatal("expected Authenticate() to fail for wrong PIN")
	}
}

func TestYubiKey_Authenticate_EmptyPIN(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "somepin")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck

	err := reader.Authenticate("")
	if err == nil {
		t.Fatal("expected Authenticate() to fail for empty PIN")
	}
}

func TestYubiKey_Authenticate_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "somepin")
	err := reader.Authenticate("somepin")
	if err == nil {
		t.Fatal("expected Authenticate() to fail when not connected")
	}
}

// ---------------------------------------------------------------------------
// ListDevices
// ---------------------------------------------------------------------------

func TestYubiKey_ListDevices_WithMockRunner(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")

	// The fake runner returns "ok" for most commands (no serial list output), so
	// ListDevices falls back to the default "yubikey-default" value.
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck

	devices, err := reader.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices() failed: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("expected at least one device from ListDevices()")
	}
}

func TestYubiKey_ListDevices_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	_, err := reader.ListDevices()
	if err == nil {
		t.Fatal("expected ListDevices() to fail when not connected")
	}
}

func TestYubiKey_ListDevices_WithSelectedDevice(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	reader.Connect(map[string]string{"slot": "9d", "device_id": "device-99"}) //nolint:errcheck

	devices, err := reader.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices() failed: %v", err)
	}
	// Should contain either the device found by ykman or the selected one.
	if len(devices) == 0 {
		t.Fatal("expected at least one device")
	}
}

// ---------------------------------------------------------------------------
// SelectDevice
// ---------------------------------------------------------------------------

func TestYubiKey_SelectDevice(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck

	if err := reader.SelectDevice("device-42"); err != nil {
		t.Fatalf("SelectDevice() failed: %v", err)
	}
	if reader.selectedDevice != "device-42" {
		t.Fatalf("expected selectedDevice=device-42, got %s", reader.selectedDevice)
	}
}

func TestYubiKey_SelectDevice_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	err := reader.SelectDevice("device-42")
	if err == nil {
		t.Fatal("expected SelectDevice() to fail when not connected")
	}
}

func TestYubiKey_SelectDevice_EmptyID(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck
	err := reader.SelectDevice("")
	if err == nil {
		t.Fatal("expected SelectDevice() to fail for empty device ID")
	}
}

// ---------------------------------------------------------------------------
// GetDeviceInfo
// ---------------------------------------------------------------------------

func TestYubiKey_GetDeviceInfo(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck

	info, err := reader.GetDeviceInfo()
	if err != nil {
		t.Fatalf("GetDeviceInfo() failed: %v", err)
	}
	if info["name"] == "" {
		t.Fatal("expected non-empty 'name' in device info")
	}
	if info["slot"] == "" {
		t.Fatal("expected non-empty 'slot' in device info")
	}
}

func TestYubiKey_GetDeviceInfo_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	_, err := reader.GetDeviceInfo()
	if err == nil {
		t.Fatal("expected GetDeviceInfo() to fail when not connected")
	}
}

// ---------------------------------------------------------------------------
// GenerateKey
// ---------------------------------------------------------------------------

func TestYubiKey_GenerateKey_RSA2048(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	if err := reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "my-key", map[string]interface{}{}); err != nil {
		t.Fatalf("GenerateKey RSA-2048 failed: %v", err)
	}
	if _, exists := reader.keys["my-key"]; !exists {
		t.Fatal("expected key binding to exist after GenerateKey")
	}
}

func TestYubiKey_GenerateKey_ECC_P256(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	if err := reader.GenerateKey(KeyType_KEY_TYPE_ECC_P256, "ecc-key", map[string]interface{}{}); err != nil {
		t.Fatalf("GenerateKey ECC P-256 failed: %v", err)
	}
}

func TestYubiKey_GenerateKey_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	err := reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "k1", nil)
	if err == nil {
		t.Fatal("expected GenerateKey to fail when not connected")
	}
}

func TestYubiKey_GenerateKey_EmptyKeyID(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	err := reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "", nil)
	if err == nil {
		t.Fatal("expected GenerateKey to fail for empty key ID")
	}
}

func TestYubiKey_GenerateKey_WithSlotOption(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	if err := reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "slot-key", map[string]interface{}{"slot": "9a"}); err != nil {
		t.Fatalf("GenerateKey with slot option failed: %v", err)
	}
	binding, exists := reader.keys["slot-key"]
	if !exists {
		t.Fatal("expected key binding to exist")
	}
	if binding.slot != "9a" {
		t.Fatalf("expected slot 9a, got %s", binding.slot)
	}
}

// ---------------------------------------------------------------------------
// GetPublicKey
// ---------------------------------------------------------------------------

func TestYubiKey_GetPublicKey_ExistingBinding(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "pk-key", nil) //nolint:errcheck

	pub, err := reader.GetPublicKey("pk-key")
	if err != nil {
		t.Fatalf("GetPublicKey() failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestYubiKey_GetPublicKey_ReadFromSlot(t *testing.T) {
	// GetPublicKey for a key with no binding falls back to readPublicKeyFromSlot.
	reader, _ := newFakeYubiKeyReader(t, "123456")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck

	// The fake runner handles "read-certificate" by writing a valid cert PEM.
	pub, err := reader.GetPublicKey("9d")
	if err != nil {
		t.Fatalf("GetPublicKey (read-from-slot) failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key from slot read")
	}
}

// ---------------------------------------------------------------------------
// DeleteKey
// ---------------------------------------------------------------------------

func TestYubiKey_DeleteKey(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")
	reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "del-key", nil) //nolint:errcheck

	if err := reader.DeleteKey("del-key"); err != nil {
		t.Fatalf("DeleteKey() failed: %v", err)
	}
	if _, exists := reader.keys["del-key"]; exists {
		t.Fatal("expected key to be removed after DeleteKey")
	}
}

func TestYubiKey_DeleteKey_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	err := reader.DeleteKey("k1")
	if err == nil {
		t.Fatal("expected DeleteKey to fail when not connected")
	}
}

// ---------------------------------------------------------------------------
// ListKeys
// ---------------------------------------------------------------------------

func TestYubiKey_ListKeys(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "list-key-a", nil) //nolint:errcheck
	reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "list-key-b", nil) //nolint:errcheck

	keys, err := reader.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() failed: %v", err)
	}
	if len(keys) < 2 {
		t.Fatalf("expected at least 2 keys, got %d", len(keys))
	}
}

func TestYubiKey_ListKeys_Empty(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	keys, err := reader.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() failed: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
}

func TestYubiKey_ListKeys_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	_, err := reader.ListKeys()
	if err == nil {
		t.Fatal("expected ListKeys to fail when not connected")
	}
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

func TestYubiKey_Sign(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")
	reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "sign-key", nil) //nolint:errcheck

	sig, err := reader.Sign("sign-key", []byte("payload"))
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}
}

func TestYubiKey_Sign_NoPIN(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck
	// Inject a key binding directly so we can test the no-PIN path.
	reader.authenticated = true // pretend authenticated but no sessionPIN set

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	reader.keys["sign-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_RSA_2048,
		publicKey: &priv.PublicKey,
	}

	// Without a sessionPIN, Sign should fail.
	_, err := reader.Sign("sign-key", []byte("payload"))
	if err == nil {
		t.Fatal("expected Sign to fail when no PIN is cached")
	}
}

func TestYubiKey_Sign_KeyNotFound(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	_, err := reader.Sign("nonexistent", []byte("payload"))
	if err == nil {
		t.Fatal("expected Sign to fail for nonexistent key")
	}
}

func TestYubiKey_Sign_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	_, err := reader.Sign("k1", []byte("data"))
	if err == nil {
		t.Fatal("expected Sign to fail when not connected")
	}
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

func TestYubiKey_Decrypt(t *testing.T) {
	reader, priv := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")
	reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "dec-key", nil) //nolint:errcheck

	// Encrypt plaintext with the public key (matches what the fake runner decrypts).
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&priv.PublicKey,
		[]byte("secret-payload"),
		nil,
	)
	if err != nil {
		t.Fatalf("test encrypt failed: %v", err)
	}

	plaintext, err := reader.Decrypt("dec-key", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if string(plaintext) != "secret-payload" {
		t.Fatalf("unexpected plaintext: %q", string(plaintext))
	}
}

func TestYubiKey_Decrypt_NoPIN(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	reader.Connect(map[string]string{"slot": "9d"}) //nolint:errcheck
	reader.authenticated = true

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	reader.keys["dec-key"] = &yubiKeySlotBinding{
		slot:      "9d",
		keyType:   KeyType_KEY_TYPE_RSA_2048,
		publicKey: &priv.PublicKey,
	}

	_, err := reader.Decrypt("dec-key", []byte("ciphertext"))
	if err == nil {
		t.Fatal("expected Decrypt to fail when no PIN is cached")
	}
}

func TestYubiKey_Decrypt_KeyNotFound(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	_, err := reader.Decrypt("nonexistent", []byte("c"))
	if err == nil {
		t.Fatal("expected Decrypt to fail for nonexistent key")
	}
}

func TestYubiKey_Decrypt_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	_, err := reader.Decrypt("k1", []byte("c"))
	if err == nil {
		t.Fatal("expected Decrypt to fail when not connected")
	}
}

// ---------------------------------------------------------------------------
// Encrypt (software-side; uses the public key in the binding)
// ---------------------------------------------------------------------------

func TestYubiKey_Encrypt(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")
	reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "enc-key", nil) //nolint:errcheck

	ct, err := reader.Encrypt("enc-key", []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}
}

func TestYubiKey_Encrypt_KeyNotFound(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	_, err := reader.Encrypt("nonexistent", []byte("p"))
	if err == nil {
		t.Fatal("expected Encrypt to fail for nonexistent key")
	}
}

// ---------------------------------------------------------------------------
// GetKeyInfo
// ---------------------------------------------------------------------------

func TestYubiKey_GetKeyInfo(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")
	reader.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "info-key", nil) //nolint:errcheck

	info, err := reader.GetKeyInfo("info-key")
	if err != nil {
		t.Fatalf("GetKeyInfo() failed: %v", err)
	}
	if info["slot"] == "" {
		t.Fatal("expected non-empty slot in key info")
	}
}

func TestYubiKey_GetKeyInfo_NotConnected(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	_, err := reader.GetKeyInfo("k1")
	if err == nil {
		t.Fatal("expected GetKeyInfo to fail when not connected")
	}
}

func TestYubiKey_GetKeyInfo_NotFound(t *testing.T) {
	reader, _ := newFakeYubiKeyReader(t, "123456")
	connectAndAuthenticate(t, reader, "123456", "9d")

	_, err := reader.GetKeyInfo("nonexistent")
	if err == nil {
		t.Fatal("expected GetKeyInfo to fail for nonexistent key")
	}
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

// isPIVSlotIdentifier is already defined in the production code so we test it here.
func TestIsPIVSlotIdentifier(t *testing.T) {
	cases := []struct {
		input  string
		expect bool
	}{
		{"9d", true},
		{"9a", true},
		{"9c", true},
		{"", false},
		{"9D", true}, // uppercase hex
		{"9g", false}, // invalid hex
		{"9da", false}, // too long
		{"x", false},  // too short
	}
	for _, tc := range cases {
		got := isPIVSlotIdentifier(tc.input)
		if got != tc.expect {
			t.Errorf("isPIVSlotIdentifier(%q) = %v, want %v", tc.input, got, tc.expect)
		}
	}
}

func TestKeyTypeFromPublicKey_RSA(t *testing.T) {
	priv2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	if keyTypeFromPublicKey(&priv2048.PublicKey) != KeyType_KEY_TYPE_RSA_2048 {
		t.Fatal("expected RSA-2048 key type")
	}
}

func TestKeyTypeFromPublicKey_Unknown(t *testing.T) {
	// Passing a nil or unsupported type returns UNSPECIFIED.
	kt := keyTypeFromPublicKey(nil)
	if kt != KeyType_KEY_TYPE_UNSPECIFIED {
		t.Fatalf("expected UNSPECIFIED for nil key, got %v", kt)
	}
}

func TestParsePublicKeyFromPEMBlob_Certificate(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	certPEM, err := createCertificatePEM(priv)
	if err != nil {
		t.Fatalf("createCertificatePEM failed: %v", err)
	}

	pub, err := parsePublicKeyFromPEMBlob(certPEM)
	if err != nil {
		t.Fatalf("parsePublicKeyFromPEMBlob failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key from certificate PEM")
	}
}

func TestParsePublicKeyFromPEMBlob_Invalid(t *testing.T) {
	_, err := parsePublicKeyFromPEMBlob([]byte("not-a-pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM data")
	}
}

func TestParseBoolConfigValue(t *testing.T) {
	if !parseBoolConfigValue("true") {
		t.Fatal("expected true")
	}
	if parseBoolConfigValue("false") {
		t.Fatal("expected false")
	}
	if parseBoolConfigValue("invalid") {
		t.Fatal("expected false for invalid value")
	}
	if parseBoolConfigValue("") {
		t.Fatal("expected false for empty value")
	}
}
