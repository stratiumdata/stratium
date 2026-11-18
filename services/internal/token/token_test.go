package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateECKey returns a fresh, random P-256 key. Every call produces a
// genuinely distinct key (crypto/rand, never a fixed seed) — deliberately,
// so tests that need two DIFFERENT keys (current vs. previous, or "some
// other key entirely") cannot pass by accident because two fixtures turned
// out to be the same key. This project has been bitten by exactly that
// fixture shape before (see the Phase 7 Task 1 report); calling this twice
// is how that class of bug is avoided here rather than merely hoped against.
func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

// writeECKeyPEM PEM-encodes key as PKCS8 and writes it to a fresh file under
// t.TempDir(), returning the path. Nothing this test suite generates is
// written into the repository — t.TempDir() is cleaned up by the testing
// package itself once the test ends.
func writeECKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	return writePEMFile(t, "PRIVATE KEY", der)
}

func writePEMFile(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// signRaw signs claims with key directly via the jwt library, bypassing
// Signer entirely. Tests use this to produce tokens Signer's own public API
// has no way to produce (a token "signed by the previous key," or by a key
// Signer has never heard of at all) — reaching around Signer here is the
// point, not a shortcut: it is what lets these tests observe Verify's
// behavior against inputs Sign itself would never generate.
func signRaw(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("signRaw: %v", err)
	}
	return signed
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "delegation-abc-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

// TestSign_Verify_RoundTrip is the property Task 1 is built around at the
// narrowest scope: a key loaded from a PEM file can sign, and the same
// Signer can verify what it signed, with claims surviving the round trip
// unchanged.
func TestSign_Verify_RoundTrip(t *testing.T) {
	key := generateECKey(t)
	path := writeECKeyPEM(t, key)
	signer, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() = %v, want success", err)
	}

	claims := validClaims()
	tok, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign() = %v, want success", err)
	}

	got, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify() = %v, want success", err)
	}
	if got["sub"] != claims["sub"] {
		t.Errorf("Verify() sub = %v, want %v", got["sub"], claims["sub"])
	}
}

// TestVerify_PreviousKeySignedToken_Verifies is K1's rotation promise: a
// token signed by what is NOW the previous key — because it used to be the
// current key, before an operator rotated it out — still verifies. current
// and previous are deliberately two DIFFERENT generated keys (not the same
// key loaded twice under two names): if Load ever regressed to ignoring
// previousPath and reusing the current key for both roles, this test would
// still see a token verify, but for the wrong reason — the assertion below
// that the two keys' public halves differ is what rules that out.
func TestVerify_PreviousKeySignedToken_Verifies(t *testing.T) {
	currentKey := generateECKey(t)
	previousKey := generateECKey(t)
	if previousKey.PublicKey.Equal(&currentKey.PublicKey) {
		t.Fatal("fixture bug: generateECKey produced the same key twice")
	}

	signer, err := Load(writeECKeyPEM(t, currentKey), writeECKeyPEM(t, previousKey))
	if err != nil {
		t.Fatalf("Load() = %v, want success", err)
	}

	claims := validClaims()
	tok := signRaw(t, previousKey, claims) // "issued moments before the rotation"

	got, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify() of a token signed by the previous key = %v, want success", err)
	}
	if got["sub"] != claims["sub"] {
		t.Errorf("Verify() sub = %v, want %v", got["sub"], claims["sub"])
	}
}

// TestVerify_UnknownKeySignature_Rejected: a token signed by a key this
// Signer was never given — neither current nor previous — must not verify.
// Without this, Verify would only ever have been proven to accept the right
// signatures, never shown to reject a wrong one.
func TestVerify_UnknownKeySignature_Rejected(t *testing.T) {
	currentKey := generateECKey(t)
	strangerKey := generateECKey(t)

	signer, err := Load(writeECKeyPEM(t, currentKey), "")
	if err != nil {
		t.Fatalf("Load() = %v, want success", err)
	}

	tok := signRaw(t, strangerKey, validClaims())
	if _, err := signer.Verify(tok); err == nil {
		t.Fatal("Verify() of a token signed by an unrecognized key: want error, got success")
	}
}

// TestVerify_NoExpiry_Rejected: every token this system issues carries an
// expiry (Task 2's claim set includes one unconditionally), so a token with
// none is never a legitimate one from this system — Verify must fail closed
// on it rather than accept a token with no expiry as though that were a
// token that happens to never expire.
func TestVerify_NoExpiry_Rejected(t *testing.T) {
	key := generateECKey(t)
	signer, err := Load(writeECKeyPEM(t, key), "")
	if err != nil {
		t.Fatalf("Load() = %v, want success", err)
	}

	tok := signRaw(t, key, jwt.MapClaims{"sub": "delegation-abc-123"}) // no "exp"
	if _, err := signer.Verify(tok); err == nil {
		t.Fatal("Verify() of a token with no expiry claim: want error, got success")
	}
}

// TestVerify_AlgNoneRejected: a hand-built token asserting "alg: none" (no
// signature at all) must not verify, however its claims read. This is the
// classic JWT "alg confusion" attack; jwt.WithValidMethods([]string{"ES256"})
// is what closes it, and this test is what proves that configuration is
// actually wired up rather than merely intended.
func TestVerify_AlgNoneRejected(t *testing.T) {
	key := generateECKey(t)
	signer, err := Load(writeECKeyPEM(t, key), "")
	if err != nil {
		t.Fatalf("Load() = %v, want success", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"delegation-abc-123","exp":9999999999}`))
	forged := header + "." + payload + "."

	if _, err := signer.Verify(forged); err == nil {
		t.Fatal("Verify() of an alg=none token: want error, got success")
	}
}

// TestSigner_PreviousKeyDoesNotImplementCryptoSigner asserts the structural
// guarantee by the standard library's own vocabulary for "can produce a
// signature": crypto.Signer. *ecdsa.PrivateKey implements it; *ecdsa.PublicKey
// — what Signer.previous actually holds — does not, and cannot without
// gaining a private scalar it does not have. This is checked on the type,
// not on any particular *Signer value, so it holds even for a nil previous
// key.
func TestSigner_PreviousKeyDoesNotImplementCryptoSigner(t *testing.T) {
	var s Signer
	if _, ok := any(s.previous).(crypto.Signer); ok {
		t.Fatal("Signer.previous's type implements crypto.Signer; the previous key must be verify-only")
	}
}

// TestSigner_ExactlyOnePrivateKeyField is the second half of the same
// structural proof, from the opposite direction: not just "previous can't
// sign" but "there is nowhere else on Signer a signing key could be hiding
// either." Walks Signer's fields by reflection rather than naming "current"
// and "previous" directly, so it still catches a future field added under a
// different name that also happens to hold private key material.
func TestSigner_ExactlyOnePrivateKeyField(t *testing.T) {
	typ := reflect.TypeFor[Signer]()
	privKeyType := reflect.TypeFor[*ecdsa.PrivateKey]()

	var privateFields []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Type == privKeyType {
			privateFields = append(privateFields, f.Name)
		}
	}
	if len(privateFields) != 1 {
		t.Fatalf("Signer has %d *ecdsa.PrivateKey field(s) (%v), want exactly 1 (the current signing key); "+
			"a previous key must be stored as *ecdsa.PublicKey, which cannot sign",
			len(privateFields), privateFields)
	}
}

// VerifySignature exists for re-issuance, where the token being replaced has
// usually expired. It must relax exactly one check, expiry, and nothing else.
func TestVerifySignature_AcceptsExpiredButNothingElseVerifyRejects(t *testing.T) {
	currentKey, previousKey, strangerKey := generateECKey(t), generateECKey(t), generateECKey(t)
	signer, err := Load(writeECKeyPEM(t, currentKey), writeECKeyPEM(t, previousKey))
	if err != nil {
		t.Fatalf("Load() = %v, want success", err)
	}
	expired := jwt.MapClaims{"sub": "delegation-abc-123", "exp": time.Now().Add(-time.Hour).Unix()}

	tok := signRaw(t, currentKey, expired)
	if _, err := signer.Verify(tok); err == nil {
		t.Fatal("Verify() accepted an expired token: this test's premise is broken")
	}
	claims, err := signer.VerifySignature(tok)
	if err != nil {
		t.Fatalf("VerifySignature() of an expired, correctly signed token = %v, want success", err)
	}
	if claims["sub"] != "delegation-abc-123" {
		t.Errorf("claims[sub] = %v, want the token's own", claims["sub"])
	}
	if _, err := signer.VerifySignature(signRaw(t, previousKey, expired)); err != nil {
		t.Errorf("VerifySignature() of a previous-key token = %v, want success (rotation)", err)
	}

	if _, err := signer.VerifySignature(signRaw(t, strangerKey, expired)); err == nil {
		t.Error("VerifySignature() accepted a token signed by an unknown key")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"delegation-abc-123","exp":1}`))
	if _, err := signer.VerifySignature(header + "." + payload + "."); err == nil {
		t.Error("VerifySignature() accepted an alg=none token")
	}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, expired)
	hsTok, err := hs.SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.VerifySignature(hsTok); err == nil {
		t.Error("VerifySignature() accepted an HS256 token")
	}
	if _, err := signer.VerifySignature(tok[:len(tok)-4] + "AAAA"); err == nil {
		t.Error("VerifySignature() accepted a token with a tampered signature")
	}
}
