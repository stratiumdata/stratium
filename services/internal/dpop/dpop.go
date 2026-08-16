// Package dpop verifies RFC 9449 DPoP proof JWTs. It answers exactly one
// question — is this proof well-formed, correctly self-signed, and fresh? —
// and it answers it about the proof alone.
//
// This package decides nothing about authorization. It reports facts. The
// compound decision (principal ∧ agent ∧ delegation) lives in internal/authz
// and never imports this package; a credential that fails verification is
// refused before any leg is evaluated, rather than becoming a fourth leg.
//
// Two checks that a reader will expect to find here are deliberately absent,
// because neither can be made from the proof alone:
//
//   - Whether the proof was made with the RIGHT key. Verify checks the
//     signature against the JWK carried in the proof's own header, which
//     sounds circular and is not: it establishes that the sender holds the
//     private half of THAT key, and nothing more. Binding that key to the
//     credential being presented is a comparison of Proof.JKT against the
//     token's cnf.jkt claim (RFC 9449 §6.1), which the PDP makes.
//   - Whether the proof has already been spent. A jti is unique per proof but
//     uniqueness is a property of a set this package cannot see. Spending it
//     is a database write, and this package does no I/O.
//
// # Purity
//
// No I/O, no network, and no ambient clock: Verify takes the current time and
// the freshness window as parameters, the way internal/authz already does.
// The window is configuration (spec §4.7.2 K9), not a constant, so that an
// operator can widen it for a fleet with poor clock discipline without a
// rebuild — and so that a test can pin time exactly rather than sleeping.
//
// # htu comparison
//
// MatchesRequest does NOT compare htu by string equality, and a reader will
// assume that it does. RFC 9449 §4.3 item 9 requires the claim to match the
// request URI "ignoring any query and fragment parts", and the same section
// asks servers to apply RFC 3986 §6.2.2 syntax-based and §6.2.3 scheme-based
// normalization first, to avoid rejecting a request that named the same
// resource differently. So: scheme and host are compared case-insensitively
// (RFC 3986 §6.2.2.1 — only those two components are case-insensitive), a
// default port for the scheme is dropped, an empty path becomes "/", and the
// path is otherwise compared exactly, in its percent-encoded form. Query and
// fragment are discarded on both sides.
//
// Path case-sensitivity is not an oversight. Lowercasing the path would let a
// proof minted for /v1/read satisfy a request to /V1/READ, which on a
// case-sensitive origin server is a different resource — the exact class of
// substitution binding exists to prevent.
package dpop

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// proofType is the required "typ" JOSE header value (RFC 9449 §4.2). It is
// what stops a JWT minted for some other purpose — an ID token, one of this
// system's own delegation tokens — from being replayed as a proof, so the
// check is on presence AND value, never presence alone.
const proofType = "dpop+jwt"

// allowedAlgorithms is the complete set of signature algorithms a proof may
// use. It is an allowlist, and that is the point: RFC 9449 §4.3 item 5
// requires the alg to be a registered asymmetric algorithm and "not none",
// and an allowlist rejects `none`, every HMAC variant, and anything else a
// future library release might start supporting, without this package having
// to enumerate what it forbids.
//
// Passing it to jose.ParseSignedCompact makes the rejection happen before any
// signature verification is attempted, which closes the classic alg-confusion
// defeat at its root: with HS256 absent from this list there is no path on
// which the public key in the header is handed to an HMAC verifier as a
// shared secret. TestVerify_RejectsAlgNone and TestVerify_RejectsSymmetricAlg
// hold that shut.
//
// This list is not a parameter. A caller that could widen it could accept
// `none`, and a proof this package "verified" under `none` proves possession
// of nothing at all.
var allowedAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.EdDSA,
}

// minRSABits is RFC 7518 §3.3's floor for the RS* and PS* algorithms: "A key
// of size 2048 bits or larger MUST be used with these algorithms." go-jose
// verifies against whatever modulus it is handed and does not enforce this,
// and the JWK in a proof header is entirely attacker-chosen, so the floor is
// enforced here or nowhere.
const minRSABits = 2048

// Proof is what a verified proof asserts. Every field is a fact about the
// proof itself; none of them is a decision.
type Proof struct {
	// JKT is the RFC 7638 thumbprint of the proof's public key: SHA-256 over
	// the key's required members, ordered lexicographically with no
	// whitespace, base64url-encoded without padding. It is the value the PDP
	// compares against the presented token's cnf.jkt.
	JKT string

	// HTM and HTU are the HTTP method and target URI the proof was made for
	// (RFC 9449 §4.2). They are reported verbatim; use MatchesRequest to
	// compare them against an observed request, because htu comparison is not
	// string equality — see the package doc.
	HTM string
	HTU string

	// JTI is the proof's unique identifier. Replay prevention is the caller's
	// (spec §4.7.2 K8); this package only reports the value.
	JTI string

	// IssuedAt is the iat claim, already checked against the caller's clock
	// and window.
	IssuedAt time.Time
}

// Verify parses proof as a JWS in compact serialization, checks the header,
// verifies the signature against the JWK the header carries, and checks that
// the required claims are present and that iat falls within window of now, in
// either direction. It returns the facts the proof asserts.
//
// The window is symmetric and inclusive: a proof is fresh when
// |now - iat| <= window. Symmetry is not decoration — a client whose clock
// runs fast produces an iat in the future, and RFC 9449 §11.1 names clock
// skew as exactly what this window absorbs. A one-sided check would deny
// every request from such a client while claiming to be a freshness check.
//
// Compact serialization only. RFC 9449 §4.1 puts the proof in an HTTP header
// field value, where the JWS JSON serialization has no place; accepting it
// would mean accepting a message with multiple signatures, and "which
// signature was verified" is not a question a proof should raise.
//
// Verify does NOT check htm or htu against a request — call MatchesRequest —
// and does not know whether this is the right key or a fresh jti. See the
// package doc for why both are elsewhere.
func Verify(proof string, now time.Time, window time.Duration) (Proof, error) {
	jws, err := jose.ParseSignedCompact(proof, allowedAlgorithms)
	if err != nil {
		return Proof{}, fmt.Errorf("dpop: parse proof: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return Proof{}, fmt.Errorf("dpop: proof carries %d signatures, want exactly 1", len(jws.Signatures))
	}
	header := jws.Signatures[0].Header

	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != proofType {
		return Proof{}, fmt.Errorf("dpop: typ header is %q, want %q", typ, proofType)
	}

	// RFC 9449 §4.3 item 7 — "the jwk JOSE header parameter does not contain a
	// private key" — is enforced by ParseSignedCompact above, which refuses a
	// header JWK that is not both valid and public (go-jose jws.go, sanitized).
	// Repeating the check here would be unreachable code; what holds the
	// property is TestVerify_RejectsPrivateKeyInHeader, which asserts the
	// rejection without caring which layer makes it. The nil check IS
	// load-bearing: go-jose skips its own check when there is no jwk at all.
	key := header.JSONWebKey
	if key == nil {
		return Proof{}, errors.New("dpop: header carries no jwk")
	}
	if err := checkKeyStrength(key); err != nil {
		return Proof{}, err
	}

	payload, err := jws.Verify(key)
	if err != nil {
		return Proof{}, fmt.Errorf("dpop: verify signature: %w", err)
	}

	var claims struct {
		HTM string           `json:"htm"`
		HTU string           `json:"htu"`
		JTI string           `json:"jti"`
		IAT *jwt.NumericDate `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Proof{}, fmt.Errorf("dpop: parse claims: %w", err)
	}
	// A pointer for iat so that an absent claim is distinguishable from
	// "iat": 0; the two deserve different errors, and only one of them
	// suggests a misconfigured client rather than a broken one.
	switch {
	case claims.HTM == "":
		return Proof{}, errors.New("dpop: proof has no htm claim")
	case claims.HTU == "":
		return Proof{}, errors.New("dpop: proof has no htu claim")
	case claims.JTI == "":
		return Proof{}, errors.New("dpop: proof has no jti claim")
	case claims.IAT == nil:
		return Proof{}, errors.New("dpop: proof has no iat claim")
	}

	issuedAt := claims.IAT.Time()
	if age := now.Sub(issuedAt); age > window || age < -window {
		return Proof{}, fmt.Errorf("dpop: iat is %s from now, outside the ±%s freshness window", age, window)
	}

	jkt, err := thumbprint(key)
	if err != nil {
		return Proof{}, err
	}

	return Proof{
		JKT:      jkt,
		HTM:      claims.HTM,
		HTU:      claims.HTU,
		JTI:      claims.JTI,
		IssuedAt: issuedAt,
	}, nil
}

// MatchesRequest reports whether this proof was made for the request the
// enforcement surface actually observed: htm against method, htu against uri.
// A nil return means it matches.
//
// It is separate from Verify because the two answer different questions and
// the PDP needs them at different points: a proof can be perfectly well-formed
// and fresh and still have been minted for somewhere else entirely, which is
// the theft-and-replay case this whole mechanism exists to catch.
//
// method is compared exactly — HTTP methods are case-sensitive (RFC 9110
// §9.1), so "get" is not "GET". uri is compared under the normalization
// described in the package doc, which is not string equality. Both arguments
// are what the surface observed, never what the client asserted.
func (p Proof) MatchesRequest(method, uri string) error {
	if p.HTM != method {
		return fmt.Errorf("dpop: htm %q does not match the observed method %q", p.HTM, method)
	}
	claimed, err := canonicalURI(p.HTU)
	if err != nil {
		return fmt.Errorf("dpop: htu claim: %w", err)
	}
	observed, err := canonicalURI(uri)
	if err != nil {
		return fmt.Errorf("dpop: observed uri: %w", err)
	}
	if claimed != observed {
		return fmt.Errorf("dpop: htu %q does not match the observed uri %q", p.HTU, uri)
	}
	return nil
}

// Thumbprint returns the RFC 7638 thumbprint of a JSON JWK document, in the
// form a cnf.jkt claim carries it: SHA-256, base64url, unpadded.
//
// It is exported so that whatever binds a token to a key at issuance computes
// the thumbprint with the same code that will later recompute it from a
// proof. Two implementations of RFC 7638 in one system is two chances to
// disagree, and a token bound to a thumbprint the verifier does not reproduce
// is a token that can never be used.
//
// A JWK that is malformed, symmetric, or carries private key material is an
// error rather than a thumbprint. Binding a credential to a key nobody can
// hold — or to one the server has now been handed a copy of — should fail
// where it is cheap to diagnose.
func Thumbprint(jwkJSON []byte) (string, error) {
	var key jose.JSONWebKey
	if err := json.Unmarshal(jwkJSON, &key); err != nil {
		return "", fmt.Errorf("dpop: parse jwk: %w", err)
	}
	if !key.Valid() || !key.IsPublic() {
		return "", errors.New("dpop: jwk is not a valid public key")
	}
	if err := checkKeyStrength(&key); err != nil {
		return "", err
	}
	return thumbprint(&key)
}

// thumbprint computes RFC 7638 §3 over an already-validated key.
//
// The canonicalization — required members only, ordered lexicographically,
// no whitespace — is go-jose's, which builds the hash input from the parsed
// key material rather than from however the sender happened to format its
// JSON. That is what RFC 7638 specifies and it is why a proof whose JWK
// carries extra members, or the same members in a different order, still
// yields the same thumbprint. TestThumbprint_MatchesRFC7638Example checks the
// result against the value RFC 7638 §3.1 publishes for its own example key,
// so the expectation comes from the RFC rather than from a second run of this
// code.
func thumbprint(key *jose.JSONWebKey) (string, error) {
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop: thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// checkKeyStrength rejects a key too weak for the algorithms this package
// accepts. See minRSABits. Elliptic-curve and Ed25519 keys have no equivalent
// knob — the curve fixes the strength, and go-jose rejects an unknown one at
// parse time.
func checkKeyStrength(key *jose.JSONWebKey) error {
	if pub, ok := key.Key.(*rsa.PublicKey); ok && pub.N.BitLen() < minRSABits {
		return fmt.Errorf("dpop: rsa key is %d bits, RFC 7518 §3.3 requires at least %d",
			pub.N.BitLen(), minRSABits)
	}
	return nil
}

// canonicalURI reduces a URI to the parts htu comparison is defined over —
// scheme, host, path — with RFC 3986 §6.2.2.1 case normalization and §6.2.3
// scheme-based normalization applied, as RFC 9449 §4.3 asks. Query and
// fragment are dropped: RFC 9449 §4.3 item 9 compares "ignoring any query and
// fragment parts", so a request that carries them still matches a proof that
// does not.
//
// A relative or schemeless string is an error, not a canonical form. htu is
// defined as the HTTP target URI (RFC 9449 §4.2), and silently comparing two
// path fragments would make a proof for one origin satisfy a request to
// another.
func canonicalURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%q is not a URI: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q is not an absolute URI", raw)
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	// Scheme-based normalization (RFC 3986 §6.2.3): a default port is
	// equivalent to no port. url.Host is host[:port] with any userinfo
	// already split off, so a ":443" suffix is always the port, including
	// for a bracketed IPv6 literal.
	switch {
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	}

	// EscapedPath, not Path: url.Path is percent-DECODED, which would make
	// /a%2Fb compare equal to /a/b. Those are different resources on any
	// origin server that routes on path segments.
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}
