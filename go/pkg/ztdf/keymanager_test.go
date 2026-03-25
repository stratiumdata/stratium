package ztdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	keyManager "stratium/services/key-manager"
)

// TestNewLocalKeyManager verifies constructor with explicit and default paths.
func TestNewLocalKeyManager(t *testing.T) {
	dir := t.TempDir()

	km, err := NewLocalKeyManager(dir)
	if err != nil {
		t.Fatalf("NewLocalKeyManager() error = %v", err)
	}
	if km == nil {
		t.Fatal("NewLocalKeyManager() returned nil")
	}
}

// TestNewLocalKeyManager_DefaultPath verifies empty path uses home dir.
func TestNewLocalKeyManager_DefaultPath(t *testing.T) {
	km, err := NewLocalKeyManager("")
	if err != nil {
		t.Fatalf("NewLocalKeyManager('') error = %v", err)
	}
	if km == nil {
		t.Fatal("NewLocalKeyManager('') returned nil")
	}
}

// TestLocalKeyManager_LoadOrGenerate_GeneratesKeys verifies key generation in a fresh dir.
func TestLocalKeyManager_LoadOrGenerate_GeneratesKeys(t *testing.T) {
	dir := t.TempDir()
	km, err := NewLocalKeyManager(dir)
	if err != nil {
		t.Fatalf("NewLocalKeyManager() error = %v", err)
	}

	lkm := km.(*LocalKeyManager)
	if err := lkm.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() error = %v", err)
	}

	// Key files should be written
	if _, err := os.Stat(filepath.Join(dir, "private_key.pem")); err != nil {
		t.Errorf("private_key.pem not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "public_key.pem")); err != nil {
		t.Errorf("public_key.pem not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key_metadata.json")); err != nil {
		t.Errorf("key_metadata.json not created: %v", err)
	}

	if lkm.GetKeyID() == "" {
		t.Error("GetKeyID() should return non-empty after LoadOrGenerate")
	}
}

// TestLocalKeyManager_LoadOrGenerate_LoadsExisting verifies loading persisted keys.
func TestLocalKeyManager_LoadOrGenerate_LoadsExisting(t *testing.T) {
	dir := t.TempDir()

	// First pass: generate
	km1, _ := NewLocalKeyManager(dir)
	lkm1 := km1.(*LocalKeyManager)
	if err := lkm1.LoadOrGenerate(); err != nil {
		t.Fatalf("first LoadOrGenerate() error = %v", err)
	}
	keyID1 := lkm1.GetKeyID()

	// Second pass: reload from disk
	km2, _ := NewLocalKeyManager(dir)
	lkm2 := km2.(*LocalKeyManager)
	if err := lkm2.LoadOrGenerate(); err != nil {
		t.Fatalf("second LoadOrGenerate() error = %v", err)
	}

	if lkm2.GetKeyID() != keyID1 {
		t.Errorf("reloaded keyID = %q, want %q", lkm2.GetKeyID(), keyID1)
	}
}

// TestLocalKeyManager_GetPublicKey_BeforeLoad verifies error before LoadOrGenerate.
func TestLocalKeyManager_GetPublicKey_BeforeLoad(t *testing.T) {
	dir := t.TempDir()
	km, _ := NewLocalKeyManager(dir)
	lkm := km.(*LocalKeyManager)

	_, err := lkm.GetPublicKey()
	if err == nil {
		t.Error("GetPublicKey() before LoadOrGenerate should return error")
	}
}

// TestLocalKeyManager_GetPrivateKey_BeforeLoad verifies error before LoadOrGenerate.
func TestLocalKeyManager_GetPrivateKey_BeforeLoad(t *testing.T) {
	dir := t.TempDir()
	km, _ := NewLocalKeyManager(dir)
	lkm := km.(*LocalKeyManager)

	_, err := lkm.GetPrivateKey()
	if err == nil {
		t.Error("GetPrivateKey() before LoadOrGenerate should return error")
	}
}

// TestLocalKeyManager_GetPublicKey_AfterLoad verifies public key is returned after load.
func TestLocalKeyManager_GetPublicKey_AfterLoad(t *testing.T) {
	dir := t.TempDir()
	km, _ := NewLocalKeyManager(dir)
	lkm := km.(*LocalKeyManager)
	if err := lkm.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() error = %v", err)
	}

	pub, err := lkm.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}
	if pub == nil {
		t.Error("GetPublicKey() returned nil")
	}
}

// TestLocalKeyManager_GetPrivateKey_AfterLoad verifies private key is returned after load.
func TestLocalKeyManager_GetPrivateKey_AfterLoad(t *testing.T) {
	dir := t.TempDir()
	km, _ := NewLocalKeyManager(dir)
	lkm := km.(*LocalKeyManager)
	if err := lkm.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() error = %v", err)
	}

	priv, err := lkm.GetPrivateKey()
	if err != nil {
		t.Fatalf("GetPrivateKey() error = %v", err)
	}
	if priv == nil {
		t.Error("GetPrivateKey() returned nil")
	}
}

// TestLocalKeyManager_GetMetadata verifies metadata is populated after load.
func TestLocalKeyManager_GetMetadata(t *testing.T) {
	dir := t.TempDir()
	km, _ := NewLocalKeyManager(dir)
	lkm := km.(*LocalKeyManager)
	if err := lkm.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate() error = %v", err)
	}

	meta := lkm.GetMetadata()
	if meta == nil {
		t.Fatal("GetMetadata() returned nil")
	}
	if meta.KeyID == "" {
		t.Error("metadata.KeyID should not be empty")
	}
	if meta.Status != "active" {
		t.Errorf("metadata.Status = %q, want 'active'", meta.Status)
	}
}

// TestLocalKeyManager_DecryptDEK_BeforeLoad verifies error before LoadOrGenerate.
func TestLocalKeyManager_DecryptDEK_BeforeLoad(t *testing.T) {
	dir := t.TempDir()
	km, _ := NewLocalKeyManager(dir)
	lkm := km.(*LocalKeyManager)

	_, err := lkm.DecryptDEK([]byte("fake"))
	if err == nil {
		t.Error("DecryptDEK() before LoadOrGenerate should return error")
	}
}

// TestLocalKeyManager_WrapDEK_BeforeLoad verifies error before LoadOrGenerate.
func TestLocalKeyManager_WrapDEK_BeforeLoad(t *testing.T) {
	dir := t.TempDir()
	km, _ := NewLocalKeyManager(dir)
	lkm := km.(*LocalKeyManager)

	_, err := lkm.WrapDEK([]byte("fake"))
	if err == nil {
		t.Error("WrapDEK() before LoadOrGenerate should return error")
	}
}

// TestParseMetadataFile_CurrentFormat verifies parsing models.KeyMetadata JSON.
func TestParseMetadataFile_CurrentFormat(t *testing.T) {
	meta := map[string]interface{}{
		"key_id":    "test-key-123",
		"status":    "active",
		"key_size":  2048,
		"key_type":  float64(keyManager.KeyType_KEY_TYPE_RSA_2048),
		"client":    "test-client",
		"created_at": "2024-01-01T00:00:00Z",
	}
	data, _ := json.Marshal(meta)

	result, err := parseMetadataFile(data)
	if err != nil {
		t.Fatalf("parseMetadataFile() error = %v", err)
	}
	if result.KeyID != "test-key-123" {
		t.Errorf("KeyID = %q, want 'test-key-123'", result.KeyID)
	}
	if result.Status != "active" {
		t.Errorf("Status = %q, want 'active'", result.Status)
	}
}

// TestParseMetadataFile_InvalidJSON verifies error on malformed input.
func TestParseMetadataFile_InvalidJSON(t *testing.T) {
	_, err := parseMetadataFile([]byte("not json"))
	if err == nil {
		t.Error("parseMetadataFile() with invalid JSON should return error")
	}
}

// TestParseKeyTypeRaw_Numeric verifies integer key type values.
func TestParseKeyTypeRaw_Numeric(t *testing.T) {
	data, _ := json.Marshal(int32(keyManager.KeyType_KEY_TYPE_RSA_2048))
	kt, err := parseKeyTypeRaw(data)
	if err != nil {
		t.Fatalf("parseKeyTypeRaw() error = %v", err)
	}
	if kt != keyManager.KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("parseKeyTypeRaw() = %v, want RSA_2048", kt)
	}
}

// TestParseKeyTypeRaw_String verifies string key type names.
func TestParseKeyTypeRaw_String(t *testing.T) {
	data, _ := json.Marshal("KEY_TYPE_ECC_P256")
	kt, err := parseKeyTypeRaw(data)
	if err != nil {
		t.Fatalf("parseKeyTypeRaw() error = %v", err)
	}
	if kt != keyManager.KeyType_KEY_TYPE_ECC_P256 {
		t.Errorf("parseKeyTypeRaw() = %v, want ECC_P256", kt)
	}
}

// TestParseKeyTypeRaw_Empty verifies empty raw defaults to RSA_2048.
func TestParseKeyTypeRaw_Empty(t *testing.T) {
	kt, err := parseKeyTypeRaw(nil)
	if err != nil {
		t.Fatalf("parseKeyTypeRaw(nil) error = %v", err)
	}
	if kt != keyManager.KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("parseKeyTypeRaw(nil) = %v, want RSA_2048 (default)", kt)
	}
}

// TestParseKeyTypeRaw_UnknownString verifies error for unknown string names.
func TestParseKeyTypeRaw_UnknownString(t *testing.T) {
	data, _ := json.Marshal("UNKNOWN_KEY_TYPE")
	_, err := parseKeyTypeRaw(data)
	if err == nil {
		t.Error("parseKeyTypeRaw() with unknown string should return error")
	}
}
