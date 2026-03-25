package ztdf

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	keyManager "stratium/services/key-manager"
	"testing"
)

type fakeCardReader struct {
	publicKey         crypto.PublicKey
	decryptOutput     []byte
	signOutput        []byte
	connectCalls      int
	authenticateCalls int
	lastConnectConfig map[string]string
	lastDecryptKeyID  string
	lastSignKeyID     string
	lastSignPayload   []byte
}

func (f *fakeCardReader) Connect(config map[string]string) error {
	f.connectCalls++
	f.lastConnectConfig = make(map[string]string, len(config))
	for k, v := range config {
		f.lastConnectConfig[k] = v
	}
	return nil
}

func (f *fakeCardReader) Disconnect() error {
	return nil
}

func (f *fakeCardReader) IsConnected() bool {
	return true
}

func (f *fakeCardReader) ListDevices() ([]string, error) {
	return []string{"fake-yubikey"}, nil
}

func (f *fakeCardReader) SelectDevice(deviceID string) error {
	return nil
}

func (f *fakeCardReader) GetDeviceInfo() (map[string]string, error) {
	return map[string]string{"id": "fake-yubikey"}, nil
}

func (f *fakeCardReader) Authenticate(pin string) error {
	f.authenticateCalls++
	return nil
}

func (f *fakeCardReader) IsAuthenticated() bool {
	return true
}

func (f *fakeCardReader) GenerateKey(keyType keyManager.KeyType, keyID string, options map[string]interface{}) error {
	return nil
}

func (f *fakeCardReader) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	return f.publicKey, nil
}

func (f *fakeCardReader) DeleteKey(keyID string) error {
	return nil
}

func (f *fakeCardReader) ListKeys() ([]string, error) {
	return []string{"9d"}, nil
}

func (f *fakeCardReader) Sign(keyID string, data []byte) ([]byte, error) {
	f.lastSignKeyID = keyID
	f.lastSignPayload = append([]byte(nil), data...)
	return f.signOutput, nil
}

func (f *fakeCardReader) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	f.lastDecryptKeyID = keyID
	return f.decryptOutput, nil
}

func (f *fakeCardReader) Encrypt(keyID string, plaintext []byte) ([]byte, error) {
	return nil, nil
}

func (f *fakeCardReader) GetKeyInfo(keyID string) (map[string]interface{}, error) {
	return map[string]interface{}{"slot": keyID}, nil
}

func TestYubiKeyKeyManager_LoadOrGenerate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	tmp := t.TempDir()
	kmIface, err := NewYubiKeyKeyManager(tmp, &YubiKeyKeyManagerOptions{
		Slot: "9d",
		PIN:  "123456",
	})
	if err != nil {
		t.Fatalf("NewYubiKeyKeyManager() failed: %v", err)
	}

	km := kmIface.(*YubiKeyKeyManager)
	fake := &fakeCardReader{publicKey: &key.PublicKey}
	km.cardReader = fake

	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() failed: %v", err)
	}
	if km.GetKeyID() == "" {
		t.Fatalf("expected key id to be populated")
	}
	if km.GetMetadata() == nil {
		t.Fatalf("expected metadata to be populated")
	}
	if fake.connectCalls == 0 || fake.authenticateCalls == 0 {
		t.Fatalf("expected reader connect/authenticate to be called")
	}
}

func TestYubiKeyKeyManager_LoadOrGenerate_RequireTouchConfig(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	tmp := t.TempDir()
	kmIface, err := NewYubiKeyKeyManager(tmp, &YubiKeyKeyManagerOptions{
		Slot:         "9d",
		PIN:          "123456",
		RequireTouch: true,
	})
	if err != nil {
		t.Fatalf("NewYubiKeyKeyManager() failed: %v", err)
	}

	km := kmIface.(*YubiKeyKeyManager)
	fake := &fakeCardReader{publicKey: &key.PublicKey}
	km.cardReader = fake

	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() failed: %v", err)
	}

	if fake.lastConnectConfig["require_touch"] != "true" {
		t.Fatalf("expected require_touch=true in card reader config, got %q", fake.lastConnectConfig["require_touch"])
	}
}

func TestYubiKeyKeyManager_DecryptDEK(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	tmp := t.TempDir()
	kmIface, err := NewYubiKeyKeyManager(tmp, &YubiKeyKeyManagerOptions{
		Slot: "9d",
		PIN:  "123456",
	})
	if err != nil {
		t.Fatalf("NewYubiKeyKeyManager() failed: %v", err)
	}

	km := kmIface.(*YubiKeyKeyManager)
	want := []byte("plaintext-dek")
	fake := &fakeCardReader{
		publicKey:     &key.PublicKey,
		decryptOutput: want,
	}
	km.cardReader = fake

	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() failed: %v", err)
	}

	got, err := km.DecryptDEK([]byte("ciphertext"))
	if err != nil {
		t.Fatalf("DecryptDEK() failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected decrypted output: got %q want %q", got, want)
	}
	if fake.lastDecryptKeyID != "9d" {
		t.Fatalf("expected decrypt key id to use slot 9d, got %q", fake.lastDecryptKeyID)
	}
}

func TestYubiKeyKeyManager_WrapDEK_NonFIPS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	tmp := t.TempDir()
	kmIface, err := NewYubiKeyKeyManager(tmp, &YubiKeyKeyManagerOptions{
		Slot: "9d",
		PIN:  "123456",
	})
	if err != nil {
		t.Fatalf("NewYubiKeyKeyManager() failed: %v", err)
	}

	km := kmIface.(*YubiKeyKeyManager)
	fake := &fakeCardReader{
		publicKey:  &key.PublicKey,
		signOutput: []byte("sig-bytes"),
	}
	km.cardReader = fake

	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() failed: %v", err)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := km.WrapDEK(dek)
	if err != nil {
		t.Fatalf("WrapDEK() failed: %v", err)
	}

	var envelope yubiKeySignedDEKEnvelope
	if err := json.Unmarshal(wrapped, &envelope); err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}

	if envelope.Version != yubiKeySignedDEKEnvelopeVersion {
		t.Fatalf("unexpected envelope version: %s", envelope.Version)
	}
	if envelope.DEK != base64.StdEncoding.EncodeToString(dek) {
		t.Fatalf("unexpected encoded DEK")
	}
	if envelope.Signature != base64.StdEncoding.EncodeToString(fake.signOutput) {
		t.Fatalf("unexpected encoded signature")
	}
	if fake.lastSignKeyID != "9d" {
		t.Fatalf("expected sign key id 9d, got %q", fake.lastSignKeyID)
	}
	if !bytes.Equal(fake.lastSignPayload, dek) {
		t.Fatalf("expected sign payload to match DEK")
	}
}

func TestYubiKeyKeyManager_WrapDEK_FIPSPassthrough(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	tmp := t.TempDir()
	kmIface, err := NewYubiKeyKeyManager(tmp, &YubiKeyKeyManagerOptions{
		Slot:        "9d",
		PIN:         "123456",
		FIPSEnabled: true,
	})
	if err != nil {
		t.Fatalf("NewYubiKeyKeyManager() failed: %v", err)
	}

	km := kmIface.(*YubiKeyKeyManager)
	fake := &fakeCardReader{
		publicKey:  &key.PublicKey,
		signOutput: []byte("sig-bytes"),
	}
	km.cardReader = fake

	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() failed: %v", err)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := km.WrapDEK(dek)
	if err != nil {
		t.Fatalf("WrapDEK() failed: %v", err)
	}
	if !bytes.Equal(wrapped, dek) {
		t.Fatalf("expected FIPS passthrough payload")
	}
	if fake.lastSignKeyID != "" {
		t.Fatalf("expected no YubiKey sign call in FIPS passthrough mode")
	}
}

func TestYubiKeyKeyManager_DecryptDEK_NonFIPSPlainEnvelope(t *testing.T) {
	tmp := t.TempDir()
	kmIface, err := NewYubiKeyKeyManager(tmp, &YubiKeyKeyManagerOptions{
		Slot: "9d",
		PIN:  "123456",
	})
	if err != nil {
		t.Fatalf("NewYubiKeyKeyManager() failed: %v", err)
	}

	km := kmIface.(*YubiKeyKeyManager)
	dek := []byte("0123456789abcdef0123456789abcdef")
	payload, err := json.Marshal(yubiKeyPlainDEKEnvelope{
		Version: yubiKeyPlainDEKEnvelopeVersion,
		DEK:     base64.StdEncoding.EncodeToString(dek),
	})
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	got, err := km.DecryptDEK(payload)
	if err != nil {
		t.Fatalf("DecryptDEK() failed: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("unexpected decrypted output: got %x want %x", got, dek)
	}
}

func TestYubiKeyKeyManager_DecryptDEK_NonFIPSPlainEnvelopeRequireTouch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	tmp := t.TempDir()
	kmIface, err := NewYubiKeyKeyManager(tmp, &YubiKeyKeyManagerOptions{
		Slot:         "9d",
		PIN:          "123456",
		RequireTouch: true,
	})
	if err != nil {
		t.Fatalf("NewYubiKeyKeyManager() failed: %v", err)
	}

	km := kmIface.(*YubiKeyKeyManager)
	dek := []byte("0123456789abcdef0123456789abcdef")
	payload, err := json.Marshal(yubiKeyPlainDEKEnvelope{
		Version: yubiKeyPlainDEKEnvelopeVersion,
		DEK:     base64.StdEncoding.EncodeToString(dek),
	})
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	fake := &fakeCardReader{
		publicKey:  &key.PublicKey,
		signOutput: []byte("touch-proof-signature"),
	}
	km.cardReader = fake

	got, err := km.DecryptDEK(payload)
	if err != nil {
		t.Fatalf("DecryptDEK() failed: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("unexpected decrypted output: got %x want %x", got, dek)
	}
	if fake.lastSignKeyID != "9d" {
		t.Fatalf("expected touch verification sign on slot 9d, got %q", fake.lastSignKeyID)
	}
	if !bytes.Equal(fake.lastSignPayload, dek) {
		t.Fatalf("expected touch verification sign payload to match DEK")
	}
}
