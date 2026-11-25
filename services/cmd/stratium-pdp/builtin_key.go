package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
)

// builtInKeyDigestPath is where deploy/docker/Dockerfile records the SHA-256
// of the signing key it generates into the image.
const builtInKeyDigestPath = "/etc/stratium/built-in-key.sha256"

// warnIfBuiltInSigningKey logs a warning when the signing key at keyPath is
// the one the image was built with. That key is in the image, so anyone who
// holds the image can sign a token this PDP accepts. It is compared by
// content, not by path, because a deployment's own key is normally mounted at
// the same path. No digest file (any install but that image), or a key that
// cannot be read (token.Load reports it next), warns about nothing.
func warnIfBuiltInSigningKey(logger *slog.Logger, keyPath, digestPath string) {
	want, err := os.ReadFile(digestPath) //nolint:gosec // G304: a fixed path in production, a temp file in tests
	if err != nil {
		return
	}
	key, err := os.ReadFile(keyPath) //nolint:gosec // G304: operator configuration, the path token.Load reads next
	if err != nil {
		return
	}
	sum := sha256.Sum256(key)
	if hex.EncodeToString(sum[:]) == strings.TrimSpace(string(want)) {
		logger.Warn("the token signing key is the one built into this image: anyone with the image can sign " +
			"tokens this PDP accepts; use only for local development, and mount your own key " +
			"(STRATIUM_TOKEN_SIGNING_KEY_PATH) for anything else")
	}
}
