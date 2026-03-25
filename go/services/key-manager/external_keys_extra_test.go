package key_manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"stratium/config"
)

// TestValidateManifest_Valid verifies a complete manifest passes validation.
func TestValidateManifest_Valid(t *testing.T) {
	manifest := ExternalKeyManifest{
		KeyID:          "key-001",
		Name:           "Test Key",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
	}

	if err := validateManifest(manifest); err != nil {
		t.Fatalf("validateManifest() error = %v, want nil", err)
	}
}

// TestValidateManifest_MissingKeyID verifies error when KeyID is empty.
func TestValidateManifest_MissingKeyID(t *testing.T) {
	manifest := ExternalKeyManifest{
		Name:           "Test Key",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
	}

	if err := validateManifest(manifest); err == nil {
		t.Fatal("validateManifest() should fail when KeyID is missing")
	}
}

// TestValidateManifest_MissingName verifies error when Name is empty.
func TestValidateManifest_MissingName(t *testing.T) {
	manifest := ExternalKeyManifest{
		KeyID:          "key-001",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
	}

	if err := validateManifest(manifest); err == nil {
		t.Fatal("validateManifest() should fail when Name is missing")
	}
}

// TestValidateManifest_MissingKeyType verifies error when KeyType is empty.
func TestValidateManifest_MissingKeyType(t *testing.T) {
	manifest := ExternalKeyManifest{
		KeyID:          "key-001",
		Name:           "Test Key",
		ProviderType:   "software",
		PrivateKeyFile: "private.pem",
	}

	if err := validateManifest(manifest); err == nil {
		t.Fatal("validateManifest() should fail when KeyType is missing")
	}
}

// TestValidateManifest_MissingProviderType verifies error when ProviderType is empty.
func TestValidateManifest_MissingProviderType(t *testing.T) {
	manifest := ExternalKeyManifest{
		KeyID:          "key-001",
		Name:           "Test Key",
		KeyType:        "RSA2048",
		PrivateKeyFile: "private.pem",
	}

	if err := validateManifest(manifest); err == nil {
		t.Fatal("validateManifest() should fail when ProviderType is missing")
	}
}

// TestValidateManifest_MissingPrivateKeySource verifies error when no private key source.
func TestValidateManifest_MissingPrivateKeySource(t *testing.T) {
	manifest := ExternalKeyManifest{
		KeyID:        "key-001",
		Name:         "Test Key",
		KeyType:      "RSA2048",
		ProviderType: "software",
		// No PrivateKeyFile and no PrivateKeySecretRef
	}

	if err := validateManifest(manifest); err == nil {
		t.Fatal("validateManifest() should fail when no private key source is provided")
	}
}

// TestValidateManifest_WithSecretRef verifies manifest with secret ref passes validation.
func TestValidateManifest_WithSecretRef(t *testing.T) {
	manifest := ExternalKeyManifest{
		KeyID:        "key-001",
		Name:         "Test Key",
		KeyType:      "RSA2048",
		ProviderType: "software",
		PrivateKeySecretRef: &ManifestSecretReference{
			Name: "my-secret",
		},
	}

	if err := validateManifest(manifest); err != nil {
		t.Fatalf("validateManifest() error = %v, want nil", err)
	}
}

// TestDiscoverManifestDirs_NonExistentPath verifies error on invalid base path.
func TestDiscoverManifestDirs_NonExistentPath(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())

	_, err := loader.discoverManifestDirs("/nonexistent/path/xyz", "manifest.json", false)
	if err == nil {
		t.Fatal("discoverManifestDirs() should fail for nonexistent path")
	}
}

// TestDiscoverManifestDirs_FileNotDir verifies error when base path is a file.
func TestDiscoverManifestDirs_FileNotDir(t *testing.T) {
	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "notadir.txt")
	writeFile(t, filePath, []byte("content"))

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())

	_, err := loader.discoverManifestDirs(filePath, "manifest.json", false)
	if err == nil {
		t.Fatal("discoverManifestDirs() should fail when base path is a file")
	}
}

// TestDiscoverManifestDirs_NoManifests verifies empty result when no manifests exist.
func TestDiscoverManifestDirs_NoManifests(t *testing.T) {
	tmp := t.TempDir()

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())

	dirs, err := loader.discoverManifestDirs(tmp, "manifest.json", false)
	if err != nil {
		t.Fatalf("discoverManifestDirs() error = %v", err)
	}
	if len(dirs) != 0 {
		t.Errorf("discoverManifestDirs() returned %d dirs, want 0", len(dirs))
	}
}

// TestDiscoverManifestDirs_ManifestAtRoot verifies discovery when manifest is at base path.
func TestDiscoverManifestDirs_ManifestAtRoot(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "manifest.json"), []byte("{}"))

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())

	dirs, err := loader.discoverManifestDirs(tmp, "manifest.json", false)
	if err != nil {
		t.Fatalf("discoverManifestDirs() error = %v", err)
	}
	if len(dirs) != 1 {
		t.Errorf("discoverManifestDirs() returned %d dirs, want 1", len(dirs))
	}
	if dirs[0] != tmp {
		t.Errorf("discoverManifestDirs() = %v, want %v", dirs[0], tmp)
	}
}

// TestDiscoverManifestDirs_Recursive verifies recursive manifest discovery.
func TestDiscoverManifestDirs_Recursive(t *testing.T) {
	tmp := t.TempDir()

	// Create nested directories with manifests
	subDir1 := filepath.Join(tmp, "partner-a")
	subDir2 := filepath.Join(tmp, "subdir", "partner-b")
	if err := os.MkdirAll(subDir1, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(subDir2, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	writeFile(t, filepath.Join(subDir1, "manifest.json"), []byte("{}"))
	writeFile(t, filepath.Join(subDir2, "manifest.json"), []byte("{}"))

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())

	dirs, err := loader.discoverManifestDirs(tmp, "manifest.json", true)
	if err != nil {
		t.Fatalf("discoverManifestDirs() error = %v", err)
	}
	if len(dirs) != 2 {
		t.Errorf("discoverManifestDirs() returned %d dirs, want 2", len(dirs))
	}
}

// TestLoadVolumeSource_NilVolumeConfig verifies error when volume config is nil.
func TestLoadVolumeSource_NilVolumeConfig(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())

	source := config.ExternalKeySourceConfig{
		Name:   "test",
		Type:   "volume",
		Volume: nil,
	}

	report := loader.loadVolumeSource(context.Background(), source)
	if len(report.Errors) == 0 {
		t.Error("loadVolumeSource() should report error with nil volume config")
	}
	if report.KeysFailed == 0 {
		t.Error("loadVolumeSource() should report failure with nil volume config")
	}
}

// TestLoadVolumeSource_InvalidBasePath verifies error when base path doesn't exist.
func TestLoadVolumeSource_InvalidBasePath(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())

	source := config.ExternalKeySourceConfig{
		Name: "test",
		Type: "volume",
		Volume: &config.ExternalVolumeSourceConfig{
			BasePath: "/nonexistent/path/that/does/not/exist",
		},
	}

	report := loader.loadVolumeSource(context.Background(), source)
	if len(report.Errors) == 0 {
		t.Error("loadVolumeSource() should report error with invalid base path")
	}
}

// TestLoad_Disabled verifies nil report when loading is disabled.
func TestLoad_Disabled(t *testing.T) {
	cfg := config.ExternalKeysConfig{
		Enabled: false,
	}
	loader := NewExternalKeyLoader(cfg, NewInMemoryKeyStore())
	report := loader.Load(context.Background())
	if report != nil {
		t.Error("Load() should return nil when disabled")
	}
}

// TestLoad_EmergencyDisable verifies nil report when emergency disable is set.
func TestLoad_EmergencyDisable(t *testing.T) {
	cfg := config.ExternalKeysConfig{
		Enabled:          true,
		EmergencyDisable: true,
	}
	loader := NewExternalKeyLoader(cfg, NewInMemoryKeyStore())
	report := loader.Load(context.Background())
	if report != nil {
		t.Error("Load() should return nil when emergency disable is set")
	}
}

// TestLoad_NoSources verifies nil report when no sources are configured.
func TestLoad_NoSources(t *testing.T) {
	cfg := config.ExternalKeysConfig{
		Enabled:  true,
		Sources:  nil,
	}
	loader := NewExternalKeyLoader(cfg, NewInMemoryKeyStore())
	report := loader.Load(context.Background())
	if report != nil {
		t.Error("Load() should return nil when no sources are configured")
	}
}

// TestLoad_UnsupportedSourceType verifies error report for unknown source type.
func TestLoad_UnsupportedSourceType(t *testing.T) {
	cfg := config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{
				Name: "test",
				Type: "unknown-type",
			},
		},
	}
	loader := NewExternalKeyLoader(cfg, NewInMemoryKeyStore())
	report := loader.Load(context.Background())
	if report == nil {
		t.Fatal("Load() should return a report even for errors")
	}
	if report.KeysFailed == 0 {
		t.Error("Load() should report failure for unsupported source type")
	}
}

// TestLoad_ContextCancelled verifies graceful handling of cancelled context.
func TestLoad_ContextCancelled(t *testing.T) {
	tmp := t.TempDir()

	cfg := config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{
				Name: "test",
				Type: "volume",
				Volume: &config.ExternalVolumeSourceConfig{
					BasePath: tmp,
				},
			},
		},
	}
	loader := NewExternalKeyLoader(cfg, NewInMemoryKeyStore())

	// Cancel the context before loading
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	report := loader.Load(ctx)
	if report == nil {
		t.Fatal("Load() should return a report even with cancelled context")
	}
}

// TestApplyManifestDefaults verifies default values are applied correctly.
func TestApplyManifestDefaults(t *testing.T) {
	manifest := &ExternalKeyManifest{}
	defs := fileDefaults{
		manifest: "manifest.json",
		public:   "public.pem",
		private:  "private.pem",
	}

	applyManifestDefaults(manifest, defs)

	if manifest.PublicKeyFile != "public.pem" {
		t.Errorf("PublicKeyFile = %q, want %q", manifest.PublicKeyFile, "public.pem")
	}
	if manifest.PrivateKeyFile != "private.pem" {
		t.Errorf("PrivateKeyFile = %q, want %q", manifest.PrivateKeyFile, "private.pem")
	}
	if manifest.Status != "active" {
		t.Errorf("Status = %q, want %q", manifest.Status, "active")
	}
	if manifest.RotationPolicy != "manual" {
		t.Errorf("RotationPolicy = %q, want %q", manifest.RotationPolicy, "manual")
	}
}

// TestApplyManifestDefaults_PreservesExisting verifies existing values are not overwritten.
func TestApplyManifestDefaults_PreservesExisting(t *testing.T) {
	manifest := &ExternalKeyManifest{
		PublicKeyFile:  "my-public.pem",
		PrivateKeyFile: "my-private.pem",
		Status:         "inactive",
		RotationPolicy: "time_based",
	}
	defs := fileDefaults{
		public:  "public.pem",
		private: "private.pem",
	}

	applyManifestDefaults(manifest, defs)

	if manifest.PublicKeyFile != "my-public.pem" {
		t.Errorf("PublicKeyFile = %q, want %q", manifest.PublicKeyFile, "my-public.pem")
	}
	if manifest.PrivateKeyFile != "my-private.pem" {
		t.Errorf("PrivateKeyFile = %q, want %q", manifest.PrivateKeyFile, "my-private.pem")
	}
	if manifest.Status != "inactive" {
		t.Errorf("Status = %q, want %q", manifest.Status, "inactive")
	}
	if manifest.RotationPolicy != "time_based" {
		t.Errorf("RotationPolicy = %q, want %q", manifest.RotationPolicy, "time_based")
	}
}

// TestDefaultOr verifies fallback behavior.
func TestDefaultOr(t *testing.T) {
	if defaultOr("value", "fallback") != "value" {
		t.Error("defaultOr() should return the first value when non-empty")
	}
	if defaultOr("", "fallback") != "fallback" {
		t.Error("defaultOr() should return fallback when value is empty")
	}
	if defaultOr("  ", "fallback") != "fallback" {
		t.Error("defaultOr() should return fallback when value is whitespace-only")
	}
}

// TestCopyMetadata verifies deep copy behavior.
func TestCopyMetadata(t *testing.T) {
	src := map[string]string{"key1": "val1", "key2": "val2"}
	dst := copyMetadata(src)

	if len(dst) != len(src) {
		t.Errorf("copyMetadata() returned %d entries, want %d", len(dst), len(src))
	}

	// Mutate dst - should not affect src
	dst["key1"] = "mutated"
	if src["key1"] != "val1" {
		t.Error("copyMetadata() did not deep-copy - mutation affected source")
	}
}

// TestCopyMetadata_Nil verifies nil input returns empty map.
func TestCopyMetadata_Nil(t *testing.T) {
	dst := copyMetadata(nil)
	if dst == nil {
		t.Error("copyMetadata(nil) returned nil, want empty map")
	}
	if len(dst) != 0 {
		t.Errorf("copyMetadata(nil) returned %d entries, want 0", len(dst))
	}
}
