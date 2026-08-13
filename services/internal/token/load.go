package token

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// Load builds a Signer from the current key at currentPath (required) and,
// if previousPath is non-empty, a previous verify-only key at previousPath.
// Both name PEM files holding an EC private key — K1: the environment (and
// therefore currentPath/previousPath, which callers read from it) carries
// only the path, never the key itself. Load reads the previous key exactly
// the way it reads the current one (a full EC private key, because that is
// what a key mounted for rotation actually is on disk — the same file that
// was STRATIUM_TOKEN_SIGNING_KEY_PATH before the operator rotated it out)
// and immediately discards its private half, keeping only the public key.
// That discard is what makes the previous key structurally unable to sign —
// see Signer's own doc comment.
//
// Every failure here is a startup failure: this function runs once, at
// process startup, and every error path returns immediately with nothing
// else attempted. A missing file, a file this process cannot read, content
// that is not PEM, or a key that is not EC all produce a descriptive error
// naming the path and the problem — never the key material, which never
// appears in any error this function returns — and Load never falls back to
// "no signing key" and continues. cmd/stratium-pdp's own buildRegistry
// (registry.go) fails the same way for the same reason: a bad configuration
// that only fails on first use, rather than at startup, looks to an
// operator like a policy problem instead of a deployment one, at exactly
// the moment — a fresh rollout or a key rotation — when that
// misdiagnosis is most expensive.
func Load(currentPath, previousPath string) (*Signer, error) {
	if currentPath == "" {
		// A caller-level bug, not an operator one: internal/config.Load
		// already refuses to return a Config with this empty (it has no
		// default). Checked anyway so Load fails the same clear way when
		// called directly, e.g. from this package's own tests, rather than
		// producing the more confusing "open : no such file or directory"
		// os.ReadFile would give an empty path.
		return nil, errors.New("token: current signing key path is required")
	}
	current, err := readECPrivateKey(currentPath)
	if err != nil {
		return nil, fmt.Errorf("token: current signing key %s: %w", currentPath, err)
	}

	var previous *ecdsa.PublicKey
	if previousPath != "" {
		prev, err := readECPrivateKey(previousPath)
		if err != nil {
			return nil, fmt.Errorf("token: previous key %s: %w", previousPath, err)
		}
		previous = &prev.PublicKey
	}

	return &Signer{current: current, previous: previous}, nil
}

// readECPrivateKey reads path and parses it as a PEM-encoded EC private key,
// trying SEC1 then PKCS8 (ParseECPrivateKeyFromPEM's own order) and
// rejecting any other key type. Rejection matters here specifically: an RSA
// key in PKCS8 form parses without error at the ASN.1 level (PKCS8 is a
// generic container for several key algorithms), so "parses" alone is not
// enough to prove "is the EC key ES256 needs" — ParseECPrivateKeyFromPEM's
// own type assertion is what actually catches an RSA key handed to a config
// that requires EC, and this function relies on that rather than
// re-checking the type itself.
func readECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is operator configuration (STRATIUM_TOKEN_SIGNING_KEY_PATH / STRATIUM_TOKEN_PREVIOUS_KEY_PATH), not attacker-supplied request data -- the same trust level as internal/config.Config's other file/URL fields (see cmd/stratium-pep/session_file.go for the identical justification).
	if err != nil {
		return nil, err
	}
	return jwt.ParseECPrivateKeyFromPEM(data)
}
