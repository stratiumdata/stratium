package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWarnIfBuiltInSigningKey(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sum := sha256.Sum256([]byte("built-in key"))
	digest := write("digest", hex.EncodeToString(sum[:])+"\n")
	builtIn := write("built-in.pem", "built-in key")
	own := write("own.pem", "an operator's key")

	for _, tc := range []struct {
		name, key, digest string
		warns             bool
	}{
		{"the image's own key", builtIn, digest, true},
		{"a different key at any path", own, digest, false},
		{"no digest file, as outside the image", builtIn, filepath.Join(dir, "absent"), false},
		{"a key that cannot be read", filepath.Join(dir, "absent.pem"), digest, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			warnIfBuiltInSigningKey(slog.New(slog.NewTextHandler(&out, nil)), tc.key, tc.digest)
			if got := strings.Contains(out.String(), "built into this image"); got != tc.warns {
				t.Errorf("warned = %v, want %v; log: %s", got, tc.warns, out.String())
			}
		})
	}
}
