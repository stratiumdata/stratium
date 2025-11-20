package key_manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"stratium/config"
)

type mockSecretFetcher struct {
	payload string
	err     error
}

func (m *mockSecretFetcher) FetchSecret(ctx context.Context, region, endpoint, secretID, versionID, versionStage string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.payload, nil
}

func TestExternalKeyLoaderLoadsFromVolume(t *testing.T) {
	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, "partner-a")
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	publicPEM, privatePEM := generateTestKeyPair(t)
	writeFile(t, filepath.Join(keyDir, "public.pem"), []byte(publicPEM))
	writeFile(t, filepath.Join(keyDir, "private.pem"), []byte(privatePEM))

	manifest := ExternalKeyManifest{
		KeyID:        "ext-key-1",
		Name:         "partner-a",
		KeyType:      "RSA2048",
		ProviderType: "software",
		Status:       "active",
		Metadata: map[string]string{
			"partner": "A",
		},
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
		t.Fatalf("expected report")
	}
	if report.KeysImported != 1 {
		t.Fatalf("expected 1 key imported, got %d", report.KeysImported)
	}

	key, err := store.GetKey(context.Background(), "ext-key-1")
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if !key.ExternallyManaged {
		t.Fatalf("expected key to be externally managed")
	}
	if key.ExternalSource != "partners" {
		t.Fatalf("unexpected source %s", key.ExternalSource)
	}
	if !strings.HasPrefix(key.PrivateKeySource, "file:") {
		t.Fatalf("expected file private key source, got %s", key.PrivateKeySource)
	}
}

func TestExternalKeyLoaderUsesSecretReference(t *testing.T) {
	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, "partner-b")
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	publicPEM, privatePEM := generateTestKeyPair(t)
	writeFile(t, filepath.Join(keyDir, "public.pem"), []byte(publicPEM))

	secretPayload := map[string]string{"pem": privatePEM}
	payloadBytes, err := json.Marshal(secretPayload)
	if err != nil {
		t.Fatalf("marshal secret payload: %v", err)
	}

	manifest := ExternalKeyManifest{
		KeyID:        "ext-key-2",
		Name:         "partner-b",
		KeyType:      "RSA2048",
		ProviderType: "software",
		Status:       "active",
		PrivateKeySecretRef: &ManifestSecretReference{
			Name:     "arn:aws:secretsmanager:us-east-1:111111111111:secret:partner",
			Region:   "us-east-1",
			KeyField: "pem",
		},
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
	loader.secretsFetcher = &mockSecretFetcher{payload: string(payloadBytes)}

	report := loader.Load(context.Background())
	if report == nil || report.KeysImported != 1 {
		t.Fatalf("expected 1 key imported")
	}

	key, err := store.GetKey(context.Background(), "ext-key-2")
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if key.PrivateKeySource != "aws-secrets-manager:arn:aws:secretsmanager:us-east-1:111111111111:secret:partner" {
		t.Fatalf("unexpected private key source %s", key.PrivateKeySource)
	}
}

func generateTestKeyPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return string(pubPEM), string(privPEM)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}

func writeManifest(t *testing.T, path string, manifest ExternalKeyManifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}
