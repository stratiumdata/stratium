//go:build !fips

package key_manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"stratium/config"
)

func TestCoverageFinal80_ValidateManifest(t *testing.T) {
	tests := []struct {
		name    string
		m       ExternalKeyManifest
		wantErr bool
	}{
		{"missing key_id", ExternalKeyManifest{Name: "n", KeyType: "RSA2048", ProviderType: "software", PrivateKeyFile: "f"}, true},
		{"missing name", ExternalKeyManifest{KeyID: "k", KeyType: "RSA2048", ProviderType: "software", PrivateKeyFile: "f"}, true},
		{"missing key_type", ExternalKeyManifest{KeyID: "k", Name: "n", ProviderType: "software", PrivateKeyFile: "f"}, true},
		{"missing provider_type", ExternalKeyManifest{KeyID: "k", Name: "n", KeyType: "RSA2048", PrivateKeyFile: "f"}, true},
		{"missing private key", ExternalKeyManifest{KeyID: "k", Name: "n", KeyType: "RSA2048", ProviderType: "software"}, true},
		{"valid", ExternalKeyManifest{KeyID: "k", Name: "n", KeyType: "RSA2048", ProviderType: "software", PrivateKeyFile: "f"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateManifest(tc.m)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateManifest(%s): err=%v, wantErr=%t", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestCoverageFinal80_ParseKeyTypeString(t *testing.T) {
	if _, err := parseKeyTypeString("UNKNOWN"); err == nil {
		t.Fatal("expected error for unknown key type")
	}
	if kt, err := parseKeyTypeString("RSA2048"); err != nil || kt != KeyType_KEY_TYPE_RSA_2048 {
		t.Fatalf("unexpected: kt=%v err=%v", kt, err)
	}
}

func TestCoverageFinal80_ParseProviderTypeString(t *testing.T) {
	if _, err := parseProviderTypeString("unknown"); err == nil {
		t.Fatal("expected error")
	}
	if pt, err := parseProviderTypeString("software"); err != nil || pt != KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE {
		t.Fatalf("unexpected: pt=%v err=%v", pt, err)
	}
}

func TestCoverageFinal80_ParseKeyStatusString(t *testing.T) {
	if _, err := parseKeyStatusString("bogus"); err == nil {
		t.Fatal("expected error")
	}
	if s, err := parseKeyStatusString("active"); err != nil || s != KeyStatus_KEY_STATUS_ACTIVE {
		t.Fatalf("unexpected: s=%v err=%v", s, err)
	}
}

func TestCoverageFinal80_ParseRotationPolicyString(t *testing.T) {
	if _, err := parseRotationPolicyString("bogus"); err == nil {
		t.Fatal("expected error")
	}
	if rp, err := parseRotationPolicyString("manual"); err != nil || rp != RotationPolicy_ROTATION_POLICY_MANUAL {
		t.Fatalf("unexpected: rp=%v err=%v", rp, err)
	}
}

func TestCoverageFinal80_DiscoverManifestDirs_NonRecursive(t *testing.T) {
	base := t.TempDir()

	// Create a subdirectory with a manifest
	subDir := filepath.Join(base, "key1")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "manifest.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	dirs, err := loader.discoverManifestDirs(base, "manifest.json", false)
	if err != nil {
		t.Fatalf("discoverManifestDirs: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("expected 1 dir, got %d", len(dirs))
	}
}

func TestCoverageFinal80_DiscoverManifestDirs_Recursive(t *testing.T) {
	base := t.TempDir()

	nested := filepath.Join(base, "a", "b")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "manifest.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	dirs, err := loader.discoverManifestDirs(base, "manifest.json", true)
	if err != nil {
		t.Fatalf("discoverManifestDirs recursive: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("expected 1 dir, got %d", len(dirs))
	}
}

func TestCoverageFinal80_DiscoverManifestDirs_NotADir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	_, err := loader.discoverManifestDirs(f, "manifest.json", false)
	if err == nil {
		t.Fatal("expected error for non-directory")
	}
}

func TestCoverageFinal80_DiscoverManifestDirs_EmptyNoDirs(t *testing.T) {
	base := t.TempDir()
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{}, NewInMemoryKeyStore())
	dirs, err := loader.discoverManifestDirs(base, "manifest.json", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 0 {
		t.Fatalf("expected 0 dirs, got %d", len(dirs))
	}
}

func TestCoverageFinal80_LoadVolumeSource_ManifestError(t *testing.T) {
	// Create a valid directory structure with a bad manifest to hit processManifestDirectory error
	base := t.TempDir()
	keyDir := filepath.Join(base, "key1")
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Bad JSON manifest
	if err := os.WriteFile(filepath.Join(keyDir, "manifest.json"), []byte("NOT JSON"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{
				Name: "test",
				Type: "volume",
				Volume: &config.ExternalVolumeSourceConfig{
					BasePath: base,
				},
			},
		},
	}, NewInMemoryKeyStore())

	report := loader.Load(context.Background())
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	// The key should fail to import because of invalid JSON
	if report.KeysFailed == 0 {
		t.Fatal("expected at least one key failure")
	}
}

func TestCoverageFinal80_LoadVolumeSource_FullImport(t *testing.T) {
	base := t.TempDir()
	keyDir := filepath.Join(base, "key1")
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Generate an RSA key pair for the manifest
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	privPEM, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM, _, err := publicKeyToPEM(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	manifest := ExternalKeyManifest{
		KeyID:          "ext-key-1",
		Name:           "Test External Key",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		Status:         "active",
		RotationPolicy: "manual",
		PublicKeyFile:  "public.pem",
		PrivateKeyFile: "private.pem",
	}
	manifestJSON, _ := json.Marshal(manifest)

	if err := os.WriteFile(filepath.Join(keyDir, "manifest.json"), manifestJSON, 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "public.pem"), []byte(pubPEM), 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "private.pem"), []byte(privPEM), 0600); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{
				Name: "test-volume",
				Type: "volume",
				Volume: &config.ExternalVolumeSourceConfig{
					BasePath: base,
				},
			},
		},
	}, NewInMemoryKeyStore())

	report := loader.Load(context.Background())
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.KeysImported != 1 {
		t.Fatalf("expected 1 key imported, got %d (errors: %v)", report.KeysImported, report.SourceReports)
	}
}

func TestCoverageFinal80_LoadVolumeSource_BadTimestamp(t *testing.T) {
	base := t.TempDir()
	keyDir := filepath.Join(base, "key1")
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatal(err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM, _ := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	pubPEM, _, _ := publicKeyToPEM(&rsaKey.PublicKey)

	manifest := ExternalKeyManifest{
		KeyID:          "ext-key-ts",
		Name:           "Test Key",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		Status:         "active",
		RotationPolicy: "manual",
		PublicKeyFile:  "public.pem",
		PrivateKeyFile: "private.pem",
		ExpiresAt:      "not-a-date", // invalid timestamp
	}
	manifestJSON, _ := json.Marshal(manifest)

	if err := os.WriteFile(filepath.Join(keyDir, "manifest.json"), manifestJSON, 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "public.pem"), []byte(pubPEM), 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "private.pem"), []byte(privPEM), 0600); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{
				Name:   "ts-test",
				Type:   "volume",
				Volume: &config.ExternalVolumeSourceConfig{BasePath: base},
			},
		},
	}, NewInMemoryKeyStore())

	report := loader.Load(context.Background())
	if report.KeysFailed == 0 {
		t.Fatal("expected failure for bad timestamp")
	}
}

func TestCoverageFinal80_LoadSource_UnsupportedType(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{Name: "s", Type: "s3"},
		},
	}, NewInMemoryKeyStore())

	report := loader.Load(context.Background())
	if report == nil || len(report.SourceReports) == 0 {
		t.Fatal("expected report")
	}
	if len(report.SourceReports[0].Errors) == 0 {
		t.Fatal("expected error for unsupported source type")
	}
}

func TestCoverageFinal80_ExternalKeyLoader_Disabled(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{Enabled: false}, NewInMemoryKeyStore())
	if report := loader.Load(context.Background()); report != nil {
		t.Fatal("expected nil report when disabled")
	}
}

func TestCoverageFinal80_ExternalKeyLoader_EmergencyDisable(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled:          true,
		EmergencyDisable: true,
	}, NewInMemoryKeyStore())
	if report := loader.Load(context.Background()); report != nil {
		t.Fatal("expected nil report for emergency disable")
	}
}

func TestCoverageFinal80_ExternalKeyLoader_NoSources(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: nil,
	}, NewInMemoryKeyStore())
	if report := loader.Load(context.Background()); report != nil {
		t.Fatal("expected nil report for no sources")
	}
}

func TestCoverageFinal80_ExternalKeyLoader_VolumeNilConfig(t *testing.T) {
	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{Name: "s", Type: "volume", Volume: nil},
		},
	}, NewInMemoryKeyStore())
	report := loader.Load(context.Background())
	if report == nil {
		t.Fatal("expected report")
	}
	if len(report.SourceReports[0].Errors) == 0 {
		t.Fatal("expected error for nil volume config")
	}
}

func TestCoverageFinal80_LoadVolumeSource_WithTimestamps(t *testing.T) {
	base := t.TempDir()
	keyDir := filepath.Join(base, "key1")
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatal(err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM, _ := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	pubPEM, _, _ := publicKeyToPEM(&rsaKey.PublicKey)

	manifest := ExternalKeyManifest{
		KeyID:          "ext-key-ts2",
		Name:           "Test Key TS",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		Status:         "active",
		RotationPolicy: "manual",
		PublicKeyFile:  "public.pem",
		PrivateKeyFile: "private.pem",
		CreatedAt:      "2025-01-01T00:00:00Z",
		ExpiresAt:      "2030-12-31T23:59:59Z",
		LastRotated:    "2025-06-15T12:00:00Z",
	}
	manifestJSON, _ := json.Marshal(manifest)

	if err := os.WriteFile(filepath.Join(keyDir, "manifest.json"), manifestJSON, 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "public.pem"), []byte(pubPEM), 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "private.pem"), []byte(privPEM), 0600); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{
				Name:   "ts2",
				Type:   "volume",
				Volume: &config.ExternalVolumeSourceConfig{BasePath: base},
			},
		},
	}, NewInMemoryKeyStore())

	report := loader.Load(context.Background())
	if report == nil {
		t.Fatal("expected report")
	}
	if report.KeysImported != 1 {
		t.Fatalf("expected 1 imported, got %d (errors: %v)", report.KeysImported, report.SourceReports)
	}
}

func TestCoverageFinal80_LoadVolumeSource_BadCreatedAt(t *testing.T) {
	base := t.TempDir()
	keyDir := filepath.Join(base, "key1")
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatalf("setup: mkdir: %v", err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM, _ := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	pubPEM, _, _ := publicKeyToPEM(&rsaKey.PublicKey)

	manifest := ExternalKeyManifest{
		KeyID:          "ext-key-bad-ca",
		Name:           "Bad CreatedAt",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		Status:         "active",
		RotationPolicy: "manual",
		PublicKeyFile:  "public.pem",
		PrivateKeyFile: "private.pem",
		CreatedAt:      "not-a-date",
	}
	manifestJSON, _ := json.Marshal(manifest)

	if err := os.WriteFile(filepath.Join(keyDir, "manifest.json"), manifestJSON, 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "public.pem"), []byte(pubPEM), 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "private.pem"), []byte(privPEM), 0600); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{Name: "ca", Type: "volume", Volume: &config.ExternalVolumeSourceConfig{BasePath: base}},
		},
	}, NewInMemoryKeyStore())

	report := loader.Load(context.Background())
	if report.KeysFailed == 0 {
		t.Fatal("expected failure for bad created_at")
	}
}

func TestCoverageFinal80_LoadVolumeSource_BadLastRotated(t *testing.T) {
	base := t.TempDir()
	keyDir := filepath.Join(base, "key1")
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatalf("setup: mkdir: %v", err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM, _ := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	pubPEM, _, _ := publicKeyToPEM(&rsaKey.PublicKey)

	manifest := ExternalKeyManifest{
		KeyID:          "ext-key-bad-lr",
		Name:           "Bad LastRotated",
		KeyType:        "RSA2048",
		ProviderType:   "software",
		Status:         "active",
		RotationPolicy: "manual",
		PublicKeyFile:  "public.pem",
		PrivateKeyFile: "private.pem",
		LastRotated:    "not-a-date",
	}
	manifestJSON, _ := json.Marshal(manifest)

	if err := os.WriteFile(filepath.Join(keyDir, "manifest.json"), manifestJSON, 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "public.pem"), []byte(pubPEM), 0644); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "private.pem"), []byte(privPEM), 0600); err != nil {
		t.Fatalf("setup: write file: %v", err)
	}

	loader := NewExternalKeyLoader(config.ExternalKeysConfig{
		Enabled: true,
		Sources: []config.ExternalKeySourceConfig{
			{Name: "lr", Type: "volume", Volume: &config.ExternalVolumeSourceConfig{BasePath: base}},
		},
	}, NewInMemoryKeyStore())

	report := loader.Load(context.Background())
	if report.KeysFailed == 0 {
		t.Fatal("expected failure for bad last_rotated")
	}
}

func TestCoverageFinal80_ExtractFieldFromJSON(t *testing.T) {
	// No field
	val, err := extractFieldFromJSON("raw-payload", "")
	if err != nil || val != "raw-payload" {
		t.Fatalf("unexpected: val=%s err=%v", val, err)
	}

	// Valid field
	val, err = extractFieldFromJSON(`{"key":"value"}`, "key")
	if err != nil || val != "value" {
		t.Fatalf("unexpected: val=%s err=%v", val, err)
	}

	// Missing field
	_, err = extractFieldFromJSON(`{"key":"value"}`, "other")
	if err == nil {
		t.Fatal("expected error for missing field")
	}

	// Non-string field
	_, err = extractFieldFromJSON(`{"key":123}`, "key")
	if err == nil {
		t.Fatal("expected error for non-string field")
	}

	// Invalid JSON
	_, err = extractFieldFromJSON("not-json", "key")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
