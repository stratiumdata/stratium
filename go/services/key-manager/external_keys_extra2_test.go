package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"stratium/config"
)

// ---------------------------------------------------------------------------
// loadSource - unsupported type branch
// ---------------------------------------------------------------------------

func TestLoadSource_UnsupportedType(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{
		Name: "test",
		Type: "s3", // unsupported
	}
	report := loader.loadSource(context.Background(), source)
	if len(report.Errors) == 0 {
		t.Error("loadSource() should report error for unsupported type")
	}
	if report.KeysFailed == 0 {
		t.Error("loadSource() should report failure for unsupported type")
	}
}

func TestLoadSource_EmptyTypeFallsBackToVolume(t *testing.T) {
	// Empty type should default to "volume"; with nil volume config it should
	// return an error about missing volume config (not "unsupported type").
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{
		Name:   "test",
		Type:   "", // empty → defaults to volume
		Volume: nil,
	}
	report := loader.loadSource(context.Background(), source)
	if len(report.Errors) == 0 {
		t.Error("loadSource() should report error when volume config is nil")
	}
	found := false
	for _, e := range report.Errors {
		if e == "volume configuration missing" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'volume configuration missing' error, got: %v", report.Errors)
	}
}

// ---------------------------------------------------------------------------
// loadVolumeSource - context cancellation during manifest processing
// ---------------------------------------------------------------------------

func TestLoadVolumeSource_ContextCancelledDuringManifests(t *testing.T) {
	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, "key1")
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, filepath.Join(keyDir, "manifest.json"), []byte(`{"key_id":"x"}`))

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{
		Name: "test",
		Type: "volume",
		Volume: &config.ExternalVolumeSourceConfig{
			BasePath: tmp,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before processing

	report := loader.loadVolumeSource(ctx, source)
	// Should have context-cancelled error or process 0 keys
	_ = report // Just ensure it doesn't panic
}

// ---------------------------------------------------------------------------
// processManifestDirectory - error branches
// ---------------------------------------------------------------------------

func makeFullManifestDir(t *testing.T, baseDir string, manifest ExternalKeyManifest) string {
	t.Helper()
	dir := filepath.Join(baseDir, manifest.KeyID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Write manifest
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	writeFile(t, filepath.Join(dir, "manifest.json"), data)

	// Write public key
	privRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privRSA.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	writeFile(t, filepath.Join(dir, "public.pem"), pubPEM)

	// Write private key
	privDER := x509.MarshalPKCS1PrivateKey(privRSA)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	writeFile(t, filepath.Join(dir, "private.pem"), privPEM)

	return dir
}

func TestProcessManifestDirectory_InvalidJSON(t *testing.T) {
	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, []byte("not valid json"))

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		manifest: "manifest.json",
		public:   "public.pem",
		private:  "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for invalid JSON")
	}
}

func TestProcessManifestDirectory_ManifestValidationFails(t *testing.T) {
	tmp := t.TempDir()
	// Manifest missing required fields
	manifest := ExternalKeyManifest{KeyID: "k1"} // missing Name, KeyType, ProviderType
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for invalid manifest")
	}
}

func TestProcessManifestDirectory_UnsupportedKeyType(t *testing.T) {
	tmp := t.TempDir()
	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "UNSUPPORTED_TYPE",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for unsupported key type")
	}
}

func TestProcessManifestDirectory_UnsupportedProviderType(t *testing.T) {
	tmp := t.TempDir()
	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "RSA2048",
		ProviderType:   "unknown_provider",
		PrivateKeyFile: "private.pem",
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for unsupported provider type")
	}
}

func TestProcessManifestDirectory_InvalidStatus(t *testing.T) {
	tmp := t.TempDir()
	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		Status:         "not_a_valid_status",
		PrivateKeyFile: "private.pem",
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for invalid status")
	}
}

func TestProcessManifestDirectory_InvalidRotationPolicy(t *testing.T) {
	tmp := t.TempDir()
	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		Status:         "active",
		RotationPolicy: "not_a_valid_policy",
		PrivateKeyFile: "private.pem",
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for invalid rotation policy")
	}
}

func TestProcessManifestDirectory_MissingPublicKey(t *testing.T) {
	tmp := t.TempDir()
	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
		PublicKeyFile:  "nonexistent_public.pem",
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail when public key is missing")
	}
}

func TestProcessManifestDirectory_InvalidCreatedAt(t *testing.T) {
	tmp := t.TempDir()
	privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&privRSA.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	privDER := x509.MarshalPKCS1PrivateKey(privRSA)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	writeFile(t, filepath.Join(tmp, "public.pem"), pubPEM)
	writeFile(t, filepath.Join(tmp, "private.pem"), privPEM)

	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
		PublicKeyFile:  "public.pem",
		CreatedAt:      "not-a-timestamp",
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for invalid created_at")
	}
}

func TestProcessManifestDirectory_InvalidExpiresAt(t *testing.T) {
	tmp := t.TempDir()
	privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&privRSA.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	privDER := x509.MarshalPKCS1PrivateKey(privRSA)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	writeFile(t, filepath.Join(tmp, "public.pem"), pubPEM)
	writeFile(t, filepath.Join(tmp, "private.pem"), privPEM)

	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
		PublicKeyFile:  "public.pem",
		ExpiresAt:      "not-a-timestamp",
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for invalid expires_at")
	}
}

func TestProcessManifestDirectory_InvalidLastRotated(t *testing.T) {
	tmp := t.TempDir()
	privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&privRSA.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	privDER := x509.MarshalPKCS1PrivateKey(privRSA)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	writeFile(t, filepath.Join(tmp, "public.pem"), pubPEM)
	writeFile(t, filepath.Join(tmp, "private.pem"), privPEM)

	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
		PublicKeyFile:  "public.pem",
		LastRotated:    "not-a-timestamp",
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err == nil {
		t.Fatal("processManifestDirectory() should fail for invalid last_rotated")
	}
}

func TestProcessManifestDirectory_WithMetadataTagsAndManifestMetadata(t *testing.T) {
	tmp := t.TempDir()
	privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&privRSA.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	privDER := x509.MarshalPKCS1PrivateKey(privRSA)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	writeFile(t, filepath.Join(tmp, "public.pem"), pubPEM)
	writeFile(t, filepath.Join(tmp, "private.pem"), privPEM)

	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		Name:           "Test",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
		PublicKeyFile:  "public.pem",
		Description:    "test key description",
		Tags:           map[string]string{"env": "test"},
		ManifestMetadata: map[string]string{"version": "1"},
		Metadata:       map[string]string{"custom": "value"},
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmp, "manifest.json")
	writeFile(t, manifestPath, data)

	store := NewInMemoryKeyStore()
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, store)
	source := config.ExternalKeySourceConfig{Name: "test", Type: "volume"}

	err := loader.processManifestDirectory(context.Background(), source, tmp, manifestPath, fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	})
	if err != nil {
		t.Fatalf("processManifestDirectory() failed: %v", err)
	}

	key, err := store.GetKey(context.Background(), "k1")
	if err != nil {
		t.Fatalf("GetKey() failed: %v", err)
	}
	if key.Metadata["tag.env"] != "test" {
		t.Errorf("expected tag.env=test, got %v", key.Metadata["tag.env"])
	}
	if key.Metadata["manifest.version"] != "1" {
		t.Errorf("expected manifest.version=1, got %v", key.Metadata["manifest.version"])
	}
	if key.Metadata["description"] != "test key description" {
		t.Errorf("expected description in metadata, got %v", key.Metadata["description"])
	}
}

// ---------------------------------------------------------------------------
// resolvePrivateKey - missing branches
// ---------------------------------------------------------------------------

func TestResolvePrivateKey_FileReadError(t *testing.T) {
	// Write a directory instead of a file at the private key path to cause a read error
	// that's NOT ErrNotExist (it should be a different OS error).
	tmp := t.TempDir()
	// Create a directory with the private key filename - reading it as a file should fail
	privKeyPath := filepath.Join(tmp, "private.pem")
	if err := os.MkdirAll(privKeyPath, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		PrivateKeyFile: "private.pem",
	}
	source := config.ExternalKeySourceConfig{Name: "test"}

	_, _, err := loader.resolvePrivateKey(context.Background(), manifest, tmp, source)
	if err == nil {
		t.Fatal("resolvePrivateKey() should fail when private key path is a directory")
	}
}

func TestResolvePrivateKey_NoFileAndNoSecretRef(t *testing.T) {
	tmp := t.TempDir()
	// No private.pem file present, no secret ref
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		PrivateKeyFile: "private.pem",
		// PrivateKeySecretRef is nil
	}
	source := config.ExternalKeySourceConfig{Name: "test"}

	_, _, err := loader.resolvePrivateKey(context.Background(), manifest, tmp, source)
	if err == nil {
		t.Fatal("resolvePrivateKey() should fail when file not found and no secret ref")
	}
}

func TestResolvePrivateKey_SecretRefMissingName(t *testing.T) {
	tmp := t.TempDir()
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		PrivateKeyFile: "private.pem",
		PrivateKeySecretRef: &ManifestSecretReference{
			Name: "", // empty name
		},
	}
	source := config.ExternalKeySourceConfig{Name: "test"}

	_, _, err := loader.resolvePrivateKey(context.Background(), manifest, tmp, source)
	if err == nil {
		t.Fatal("resolvePrivateKey() should fail when secret ref name is empty")
	}
}

func TestResolvePrivateKey_SecretFetcherError(t *testing.T) {
	tmp := t.TempDir()
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	loader.secretsFetcher = &mockSecretFetcher{err: errors.New("fetch failed")}

	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		PrivateKeyFile: "private.pem",
		PrivateKeySecretRef: &ManifestSecretReference{
			Name:   "my-secret",
			Region: "us-east-1",
		},
	}
	source := config.ExternalKeySourceConfig{Name: "test"}

	_, _, err := loader.resolvePrivateKey(context.Background(), manifest, tmp, source)
	if err == nil {
		t.Fatal("resolvePrivateKey() should fail when secret fetcher returns error")
	}
}

func TestResolvePrivateKey_EmptySecretPayload(t *testing.T) {
	tmp := t.TempDir()
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	loader.secretsFetcher = &mockSecretFetcher{payload: "   "} // whitespace only

	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		PrivateKeyFile: "private.pem",
		PrivateKeySecretRef: &ManifestSecretReference{
			Name:   "my-secret",
			Region: "us-east-1",
		},
	}
	source := config.ExternalKeySourceConfig{Name: "test"}

	_, _, err := loader.resolvePrivateKey(context.Background(), manifest, tmp, source)
	if err == nil {
		t.Fatal("resolvePrivateKey() should fail for empty secret payload")
	}
}

func TestResolvePrivateKey_WithAWSSecretsManagerSourceConfig(t *testing.T) {
	tmp := t.TempDir()
	_, privatePEM := generateTestKeyPair(t)
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	loader.secretsFetcher = &mockSecretFetcher{payload: privatePEM}

	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		PrivateKeyFile: "private.pem",
		PrivateKeySecretRef: &ManifestSecretReference{
			Name: "my-secret",
			// Region and KeyField intentionally empty - should be filled from source config
		},
	}
	source := config.ExternalKeySourceConfig{
		Name: "test",
		AWSSecretsManager: &config.AWSSecretsManagerSourceConfig{
			Region:         "eu-west-1",
			Endpoint:       "http://localhost:4566",
			SecretKeyField: "",
		},
	}

	payload, src, err := loader.resolvePrivateKey(context.Background(), manifest, tmp, source)
	if err != nil {
		t.Fatalf("resolvePrivateKey() failed: %v", err)
	}
	if payload == "" {
		t.Fatal("expected non-empty payload")
	}
	if src == "" {
		t.Fatal("expected non-empty source descriptor")
	}
}

func TestResolvePrivateKey_WithKeyFieldExtraction(t *testing.T) {
	tmp := t.TempDir()
	_, privatePEM := generateTestKeyPair(t)
	secretPayload, _ := json.Marshal(map[string]string{"pem": privatePEM})
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	loader.secretsFetcher = &mockSecretFetcher{payload: string(secretPayload)}

	manifest := ExternalKeyManifest{
		KeyID:          "k1",
		PrivateKeyFile: "private.pem",
		PrivateKeySecretRef: &ManifestSecretReference{
			Name:     "my-secret",
			Region:   "us-east-1",
			KeyField: "pem",
		},
	}
	source := config.ExternalKeySourceConfig{Name: "test"}

	payload, _, err := loader.resolvePrivateKey(context.Background(), manifest, tmp, source)
	if err != nil {
		t.Fatalf("resolvePrivateKey() with key field failed: %v", err)
	}
	if payload != privatePEM {
		t.Fatalf("expected private PEM, got %q", payload)
	}
}

// ---------------------------------------------------------------------------
// getSecretFetcher - nil branch (lazy initialization)
// ---------------------------------------------------------------------------

func TestGetSecretFetcher_LazyInit(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	// secretsFetcher starts nil
	if loader.secretsFetcher != nil {
		t.Fatal("expected secretsFetcher to be nil before first call")
	}
	fetcher := loader.getSecretFetcher()
	if fetcher == nil {
		t.Fatal("getSecretFetcher() should return non-nil fetcher")
	}
	// Second call should return the same (now-initialized) fetcher
	fetcher2 := loader.getSecretFetcher()
	if fetcher2 != fetcher {
		t.Fatal("getSecretFetcher() should return the same fetcher on subsequent calls")
	}
}

// ---------------------------------------------------------------------------
// discoverManifestDirs - additional branches
// ---------------------------------------------------------------------------

func TestDiscoverManifestDirs_RecursiveWithNoManifests(t *testing.T) {
	tmp := t.TempDir()
	subDir := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// No manifest.json anywhere

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	dirs, err := loader.discoverManifestDirs(tmp, "manifest.json", true)
	if err != nil {
		t.Fatalf("discoverManifestDirs() error = %v", err)
	}
	if len(dirs) != 0 {
		t.Errorf("expected 0 dirs, got %d", len(dirs))
	}
}

func TestDiscoverManifestDirs_NonRecursiveSubdirManifest(t *testing.T) {
	tmp := t.TempDir()
	subDir := filepath.Join(tmp, "keydir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, filepath.Join(subDir, "manifest.json"), []byte("{}"))

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	dirs, err := loader.discoverManifestDirs(tmp, "manifest.json", false)
	if err != nil {
		t.Fatalf("discoverManifestDirs() error = %v", err)
	}
	if len(dirs) != 1 {
		t.Errorf("expected 1 dir, got %d", len(dirs))
	}
	if dirs[0] != subDir {
		t.Errorf("expected %s, got %s", subDir, dirs[0])
	}
}

func TestDiscoverManifestDirs_NonRecursiveSubdirWithoutManifest(t *testing.T) {
	tmp := t.TempDir()
	subDir := filepath.Join(tmp, "emptydir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// No manifest in subDir

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	dirs, err := loader.discoverManifestDirs(tmp, "manifest.json", false)
	if err != nil {
		t.Fatalf("discoverManifestDirs() error = %v", err)
	}
	if len(dirs) != 0 {
		t.Errorf("expected 0 dirs (subdir has no manifest), got %d", len(dirs))
	}
}

func TestDiscoverManifestDirs_NonRecursiveBothRootAndSubdir(t *testing.T) {
	tmp := t.TempDir()
	// Manifest at root
	writeFile(t, filepath.Join(tmp, "manifest.json"), []byte("{}"))
	// Manifest in subdir
	subDir := filepath.Join(tmp, "keydir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, filepath.Join(subDir, "manifest.json"), []byte("{}"))

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	dirs, err := loader.discoverManifestDirs(tmp, "manifest.json", false)
	if err != nil {
		t.Fatalf("discoverManifestDirs() error = %v", err)
	}
	if len(dirs) != 2 {
		t.Errorf("expected 2 dirs, got %d: %v", len(dirs), dirs)
	}
}

// ---------------------------------------------------------------------------
// Full end-to-end with ECC key
// ---------------------------------------------------------------------------

func TestExternalKeyLoaderLoadsECCKey(t *testing.T) {
	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, "ecc-partner")
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Generate ECC P-256 key pair
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privEC.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	privDER, err := x509.MarshalECPrivateKey(privEC)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	writeFile(t, filepath.Join(keyDir, "public.pem"), pubPEM)
	writeFile(t, filepath.Join(keyDir, "private.pem"), privPEM)

	manifest := ExternalKeyManifest{
		KeyID:        "ecc-ext-key",
		Name:         "ecc-partner",
		KeyType:      "ECC256",
		ProviderType: "software",
		Status:       "active",
	}
	writeManifest(t, filepath.Join(keyDir, "manifest.json"), manifest)

	cfg := config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{
				Name: "partners",
				Type: "volume",
				Volume: &config.ExternalVolumeSourceConfig{
					BasePath: keyDir,
				},
			},
		},
	}

	store := NewInMemoryKeyStore()
	loader := NewExternalKeyLoader(cfg, store)
	report := loader.Load(context.Background())
	if report == nil {
		t.Fatal("expected report")
	}
	if report.KeysImported != 1 {
		t.Fatalf("expected 1 ECC key imported, got %d (failures=%d, errors=%v)",
			report.KeysImported, report.KeysFailed, report.SourceReports)
	}
}

// ---------------------------------------------------------------------------
// parseKeyTypeString - additional cases
// ---------------------------------------------------------------------------

func TestParseKeyTypeString_AllVariants(t *testing.T) {
	cases := []struct {
		input    string
		expected KeyType
	}{
		{"RSA3072", KeyType_KEY_TYPE_RSA_3072},
		{"RSA4096", KeyType_KEY_TYPE_RSA_4096},
		{"ECC384", KeyType_KEY_TYPE_ECC_P384},
		{"P384", KeyType_KEY_TYPE_ECC_P384},
		{"ECC521", KeyType_KEY_TYPE_ECC_P521},
		{"P521", KeyType_KEY_TYPE_ECC_P521},
		{"KYBER512", KeyType_KEY_TYPE_KYBER_512},
		{"KYBER768", KeyType_KEY_TYPE_KYBER_768},
		{"KYBER1024", KeyType_KEY_TYPE_KYBER_1024},
		{"KEY_TYPE_RSA_2048", KeyType_KEY_TYPE_RSA_2048},
		{"KEY_TYPE_ECC_P256", KeyType_KEY_TYPE_ECC_P256},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseKeyTypeString(tc.input)
			if err != nil {
				t.Fatalf("parseKeyTypeString(%q) error = %v", tc.input, err)
			}
			if got != tc.expected {
				t.Fatalf("parseKeyTypeString(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseKeyTypeString_Unknown(t *testing.T) {
	_, err := parseKeyTypeString("UNKNOWN_TYPE_XYZ")
	if err == nil {
		t.Fatal("parseKeyTypeString() should fail for unknown type")
	}
}

// ---------------------------------------------------------------------------
// parseProviderTypeString - additional cases
// ---------------------------------------------------------------------------

func TestParseProviderTypeString_AllVariants(t *testing.T) {
	cases := []struct {
		input    string
		expected KeyProviderType
	}{
		{"software", KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE},
		{"hsm", KeyProviderType_KEY_PROVIDER_TYPE_HSM},
		{"smart_card", KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD},
		{"smartcard", KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD},
		{"usb_token", KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN},
		{"usb", KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseProviderTypeString(tc.input)
			if err != nil {
				t.Fatalf("parseProviderTypeString(%q) error = %v", tc.input, err)
			}
			if got != tc.expected {
				t.Fatalf("parseProviderTypeString(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseProviderTypeString_Unknown(t *testing.T) {
	_, err := parseProviderTypeString("unknown_provider")
	if err == nil {
		t.Fatal("parseProviderTypeString() should fail for unknown provider type")
	}
}

// ---------------------------------------------------------------------------
// parseKeyStatusString - all branches
// ---------------------------------------------------------------------------

func TestParseKeyStatusString_AllVariants(t *testing.T) {
	cases := []struct {
		input    string
		expected KeyStatus
	}{
		{"active", KeyStatus_KEY_STATUS_ACTIVE},
		{"", KeyStatus_KEY_STATUS_ACTIVE},
		{"inactive", KeyStatus_KEY_STATUS_INACTIVE},
		{"pending_rotation", KeyStatus_KEY_STATUS_PENDING_ROTATION},
		{"deprecated", KeyStatus_KEY_STATUS_DEPRECATED},
		{"compromised", KeyStatus_KEY_STATUS_COMPROMISED},
		{"revoked", KeyStatus_KEY_STATUS_REVOKED},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseKeyStatusString(tc.input)
			if err != nil {
				t.Fatalf("parseKeyStatusString(%q) error = %v", tc.input, err)
			}
			if got != tc.expected {
				t.Fatalf("parseKeyStatusString(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseKeyStatusString_Unknown(t *testing.T) {
	_, err := parseKeyStatusString("bad_status")
	if err == nil {
		t.Fatal("parseKeyStatusString() should fail for unknown status")
	}
}

// ---------------------------------------------------------------------------
// parseRotationPolicyString - all branches
// ---------------------------------------------------------------------------

func TestParseRotationPolicyString_AllVariants(t *testing.T) {
	cases := []struct {
		input    string
		expected RotationPolicy
	}{
		{"manual", RotationPolicy_ROTATION_POLICY_MANUAL},
		{"", RotationPolicy_ROTATION_POLICY_MANUAL},
		{"time_based", RotationPolicy_ROTATION_POLICY_TIME_BASED},
		{"time-based", RotationPolicy_ROTATION_POLICY_TIME_BASED},
		{"usage_based", RotationPolicy_ROTATION_POLICY_USAGE_BASED},
		{"usage-based", RotationPolicy_ROTATION_POLICY_USAGE_BASED},
		{"combined", RotationPolicy_ROTATION_POLICY_COMBINED},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseRotationPolicyString(tc.input)
			if err != nil {
				t.Fatalf("parseRotationPolicyString(%q) error = %v", tc.input, err)
			}
			if got != tc.expected {
				t.Fatalf("parseRotationPolicyString(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseRotationPolicyString_Unknown(t *testing.T) {
	_, err := parseRotationPolicyString("bad_policy")
	if err == nil {
		t.Fatal("parseRotationPolicyString() should fail for unknown policy")
	}
}

// ---------------------------------------------------------------------------
// parsePrivateKeyPEM - additional branches not covered by parse_funcs_test.go
// ---------------------------------------------------------------------------

func TestParsePrivateKeyPEM_InvalidRSAData_Extra2(t *testing.T) {
	// RSA PRIVATE KEY block with garbage bytes - exercises RSA parse failure path
	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("invalid")}))
	_, err := parsePrivateKeyPEM(badPEM, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("parsePrivateKeyPEM() should fail for invalid RSA PRIVATE KEY data")
	}
}

func TestParsePrivateKeyPEM_InvalidECCData_Extra2(t *testing.T) {
	// EC PRIVATE KEY block with garbage bytes - exercises ECC parse failure path
	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("invalid")}))
	_, err := parsePrivateKeyPEM(badPEM, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("parsePrivateKeyPEM() should fail for invalid EC PRIVATE KEY data")
	}
}
