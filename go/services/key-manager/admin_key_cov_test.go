//go:build !fips

package key_manager

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverageFinal80_FileAdminKeyProvider_SaveAndGet(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "sub", "admin-key")
	provider := NewFileAdminKeyProvider(filePath)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	if err := provider.SaveAdminKey(ctx, key); err != nil {
		t.Fatalf("SaveAdminKey: %v", err)
	}

	got, err := provider.GetAdminKey(ctx)
	if err != nil {
		t.Fatalf("GetAdminKey: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(got))
	}
}

func TestCoverageFinal80_FileAdminKeyProvider_SaveOverDir(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-key")

	// Pre-create a directory at the target path (legacy edge case)
	if err := os.MkdirAll(filePath, 0700); err != nil {
		t.Fatal(err)
	}

	provider := NewFileAdminKeyProvider(filePath)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	if err := provider.SaveAdminKey(context.Background(), key); err != nil {
		t.Fatalf("SaveAdminKey over dir: %v", err)
	}
}

func TestCoverageFinal80_FileAdminKeyProvider_GetBadLength(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "admin-key")

	// Write a key with wrong length
	shortKey := make([]byte, 16)
	encoded := base64.StdEncoding.EncodeToString(shortKey)
	if err := os.WriteFile(filePath, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}

	provider := NewFileAdminKeyProvider(filePath)
	_, err := provider.GetAdminKey(context.Background())
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}
