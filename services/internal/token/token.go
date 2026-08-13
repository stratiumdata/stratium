// Package token signs and verifies the PDP's delegation tokens: ES256 over a
// key loaded once at startup from a PEM file whose PATH comes from the
// environment (spec §4.7.1 K1). The environment variable never holds key
// material itself — see Load's own doc comment — so a leaked environment or
// crash dump never leaks a signing key, only wherever the file happens to be
// mounted.
//
// A Signer holds two keys with deliberately different capabilities: the
// current key signs and verifies, and an optional previous key verifies
// only, so a token issued moments before a rotation still passes Verify
// after an operator mounts a new current key and restarts (K1's rotation
// story: mount a new file, restart — nothing about an in-flight token
// breaks). The previous key's inability to sign is structural, not a
// convention this package merely upholds by not calling a method — see
// Signer's own doc comment for the type-level reason, and why that matters
// more than it might first appear: a previous key that COULD sign would
// double the window in which a compromised old key keeps minting authority,
// counting from whenever the compromise happened rather than from the
// rotation that was supposed to end it.
//
// This package does no key management beyond signing and verifying: no JWKS
// document (spec K2 — the PDP verifies its own tokens, so JWKS is never on
// the enforcement path; A5's assignment of JWKS to a PAP stands for when one
// exists), no claims policy (what a token names is a later task's
// responsibility, not this package's), and no delegation lookup (a verified
// token's claims are only ever a reference — see spec K3 — and resolving
// that reference against a stored delegation happens above this package,
// never inside it). internal/authz itself never imports this package at
// all: it stays pure, with no cryptography of its own, per the phase's
// global constraints.
package token

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// signingAlg is the only algorithm this package signs or accepts. Fixed, not
// configurable: accepting a caller-chosen algorithm is how JWT libraries
// have historically been tricked into verifying a forged token against the
// wrong kind of key (an "alg confusion" attack) — narrowing Verify's
// jwt.WithValidMethods to exactly this one value closes that off rather than
// trusting every caller to configure it correctly.
const signingAlg = "ES256"

// Signer signs and verifies ES256 tokens using a required current key and an
// optional previous key retained for verification only.
//
// The two keys are stored as different Go types on purpose: current is
// *ecdsa.PrivateKey (able to sign — golang-jwt's own ECDSA signer type-
// asserts to exactly this type, see jwt.SigningMethodECDSA.Sign), and
// previous is *ecdsa.PublicKey, the standard library's public-key type. A
// *ecdsa.PublicKey holds no private scalar and implements no signing
// interface (crypto.Signer is satisfied by *ecdsa.PrivateKey, never by
// *ecdsa.PublicKey) — there is no field here from which a signature could be
// produced, by this package's code or any other. That is the structural
// guarantee the design calls for: not a comment saying "we don't sign with
// this," which the next change could quietly violate by adding a method,
// but a value that could not produce a signature no matter what code called
// it, because the private half was discarded the moment Load read it (see
// Load's own doc comment). TestSigner_PreviousKeyDoesNotImplementCryptoSigner
// and TestSigner_ExactlyOnePrivateKeyField check this by reflection rather
// than trusting it to hold by convention.
type Signer struct {
	current  *ecdsa.PrivateKey
	previous *ecdsa.PublicKey
}

// Sign signs claims with the current key and returns the compact token.
//
// Sign stamps nothing into claims itself — no issued-at, no expiry, no
// token id. What a token names is a later task's concern (spec K3: a token
// is a reference, and the fields that make it one belong to whoever mints
// that reference), and baking a default here would be this package quietly
// making a claims-policy decision it has no business making.
func (s *Signer) Sign(claims jwt.MapClaims) (string, error) {
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(s.current)
	if err != nil {
		return "", fmt.Errorf("token: sign: %w", err)
	}
	return signed, nil
}

// Verify parses and validates tokenString: signature against the current
// key or, if configured, the previous key; algorithm restricted to ES256
// (see signingAlg); and an expiry claim required and not yet passed. Claims
// otherwise unvalidated — issuer, audience, subject, and every claim beyond
// "this token was genuinely signed by a key this process trusts and has not
// expired" are a caller's concern, not this package's (see the package doc
// for why: what a token's claims mean belongs to whoever defines them).
//
// The current key is tried first — the common case, since most live tokens
// were signed by whichever key is current right now — and the previous key
// only if configured and the first attempt fails. Trying both is what makes
// K1's rotation promise true: a token signed seconds before a restart that
// swapped the current key still verifies, without this package needing a
// "kid" header or any other bookkeeping to know which key to try.
func (s *Signer) Verify(tokenString string) (jwt.MapClaims, error) {
	claims, err := s.verifyWith(tokenString, &s.current.PublicKey)
	if err == nil {
		return claims, nil
	}
	if s.previous != nil {
		if prevClaims, prevErr := s.verifyWith(tokenString, s.previous); prevErr == nil {
			return prevClaims, nil
		}
	}
	// Reports the current-key attempt's error: previous is the exceptional
	// case (only present during a rotation window), so its failure is never
	// more informative than current's own when neither verifies.
	return nil, fmt.Errorf("token: verify: %w", err)
}

// verifyWith attempts one candidate key. A fresh jwt.MapClaims per attempt:
// reusing one across the current/previous retry in Verify would let a
// partially-populated map from a failed first attempt leak into the result
// of a successful second one.
func (s *Signer) verifyWith(tokenString string, pub *ecdsa.PublicKey) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (interface{}, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{signingAlg}), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	return claims, nil
}
