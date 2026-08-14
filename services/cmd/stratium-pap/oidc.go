// oidc.go verifies an operator's bearer token against the customer's IdP --
// discovery, signature, issuer, and audience, all real, all the time. Spec
// §8 / N2: "no bundled IdP and no fallback" -- the deleted
// MockValidateToken / jwt.ParseUnverified path does not reappear here in
// any form, including behind a dev-mode flag. Nothing in this file returns
// claims without coreos/go-oidc's own IDTokenVerifier.Verify succeeding
// first; there is no second, weaker path.
//
// Library choice: coreos/go-oidc/v3, over hand-rolling JWKS fetch and
// verification on golang-jwt (already a dependency, but used by
// internal/token for signing this system's OWN delegation tokens -- a
// fixed key pair this process loads from a file, nothing like verifying an
// arbitrary third-party IdP's rotating JWKS). This project takes
// dependencies sparingly and has said no before: two MCP libraries,
// cedar-go's own schema facility, both cases where the library's shape
// didn't fit or the logic was thin enough to hand-roll better. This is not
// that case -- it is the go-control-plane case (accepted, "because Envoy
// owns that contract"). An OIDC IdP's discovery document and key-rotation
// behavior is a contract this codebase does not define and a customer's
// IdP was never going to bend to accommodate a hand-rolled
// reimplementation of. coreos/go-oidc is the reference client many IdPs
// are themselves tested against, and it is what actually owns the fiddly
// parts: RFC-compliant discovery, JWKS caching with re-fetch on an unknown
// kid, and per-algorithm signature verification (see NewVerifier's own
// comment for one specific correctness property this buys: bounding a
// background JWKS refresh so a hung IdP cannot silently and permanently
// break key rotation).
//
// The dependency-tree cost this project's own "sparingly" rule asks to
// weigh turned out to be close to zero: go-oidc's own two dependencies,
// go-jose/go-jose/v4 and golang.org/x/oauth2, are already in this module's
// build list -- required by google.golang.org/grpc and
// golang-migrate/migrate/v4, both already direct dependencies (confirmed
// with `go mod graph` before adding this import). Adding go-oidc adds one
// new module to go.sum, not a new subtree.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// errTokenInvalid is the one error Verify ever returns for a rejected
// token -- see Verify's own doc comment for why the detail behind it is
// never surfaced.
var errTokenInvalid = errors.New("token invalid")

// Verifier checks bearer tokens against one issuer/audience pair, both
// fixed at construction from startup configuration. No method here takes
// either as a per-call argument: an operator's token is checked against
// the one IdP and audience this deployment trusts, never one the request
// names.
type Verifier struct {
	inner *oidc.IDTokenVerifier
}

// NewVerifier performs OIDC discovery against issuer (a GET to
// "<issuer>/.well-known/openid-configuration", handled inside
// oidc.NewProvider) and returns a Verifier backed by the discovered JWKS.
// This is the semantic half of validating STRATIUM_PAP_OIDC_ISSUER --
// config.go's own Load only checks that a value is present; discovery
// either succeeds against a real OIDC provider or this returns an error,
// before the process serves a single request.
//
// timeout bounds every HTTP call go-oidc makes for the lifetime of the
// returned Verifier -- not only this discovery request. oidc.ClientContext
// stores the client on ctx; oidc.NewProvider captures ctx's client onto
// the Provider it returns; and Provider.Verifier's own doc comment says
// its remote key set "uses a background context for all requests to the
// upstream JWKs endpoint" -- built, per go-oidc's own source
// (oidc/jwks.go's newRemoteKeySet), from that captured client wrapped in
// context.WithoutCancel, detached from any request's cancellation. A later
// Verify call's context bounds how long THAT call waits on an in-flight
// JWKS refresh (oidc/jwks.go's keysFromRemote selects on ctx.Done()), but
// not the refresh's own HTTP round trip once started -- only this client's
// Timeout does. Without it, one slow or hung IdP JWKS endpoint could leave
// a fetch goroutine blocked indefinitely on an unrecognised kid, and
// because RemoteKeySet runs only one refresh at a time (its own inflight
// field), every subsequent verification of a token signed by a newly
// rotated key would queue behind that stuck goroutine forever -- a key
// rotation silently and permanently breaking verification, discoverable
// only by restarting the process.
func NewVerifier(ctx context.Context, issuer, audience string, timeout time.Duration) (*Verifier, error) {
	client := &http.Client{Timeout: timeout}
	ctx = oidc.ClientContext(ctx, client)

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider %s: %w", issuer, err)
	}
	// ClientID + the default SkipClientIDCheck=false is what makes the
	// audience check happen at all -- see verify.go's own Verify: with
	// SkipClientIDCheck true (never set here) or ClientID empty (never
	// possible here; config.go requires STRATIUM_PAP_OIDC_AUDIENCE),
	// go-oidc would either skip comparing aud entirely or refuse to
	// construct a working verifier. SupportedSigningAlgs is left unset
	// deliberately: provider.Verifier defaults it to whatever the
	// discovery document advertised (id_token_signing_alg_values_supported)
	// and falls back to the spec's mandatory RS256 if the document names
	// none, rather than this file guessing an algorithm list a customer's
	// IdP might not actually support.
	return &Verifier{inner: provider.Verifier(&oidc.Config{ClientID: audience})}, nil
}

// Verify checks rawToken's signature against the IdP's published JWKS,
// then its issuer, audience, and expiry, then decodes its claims into a
// plain map for resolveRole to read the configured role claim from.
//
// The returned error is always the fixed errTokenInvalid, never go-oidc's
// own error -- its text routinely echoes the rejected token's actual claim
// values (e.g. an issuer mismatch's message is "expected %q got %q",
// naming the token's real iss), which is exactly what this phase's "never
// log a bearer token, an operator's claims, or anything derived from them"
// rule forbids. Swallowing the detail HERE, at the one place it would
// otherwise leak, means no caller up the stack -- today or in a future
// task -- has to remember not to log it; there is nothing left to log.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (map[string]any, error) {
	idToken, err := v.inner.Verify(ctx, rawToken)
	if err != nil {
		return nil, errTokenInvalid
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, errTokenInvalid
	}
	return claims, nil
}
