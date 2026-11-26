package principal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrNotIdentified is returned for every token that does not identify a
// person: unverifiable, expired, for another audience, or carrying no usable
// identity claim. One error for all of them, with no detail from the token,
// so a caller's log line cannot echo an attacker-supplied claim and a prober
// learns nothing about which check failed.
var ErrNotIdentified = errors.New("principal token does not identify a principal")

// Verifier turns a raw OIDC token into the identity it proves.
type Verifier struct {
	inner *oidc.IDTokenVerifier
	claim string
}

// NewVerifier discovers issuer and returns a Verifier for tokens it issued
// for audience, reading the identity from claim.
//
// Discovery happens here, once, so a PDP pointed at an unreachable or wrong
// issuer fails at startup rather than refusing every session later. Keys are
// fetched and cached by go-oidc, which also re-fetches when a signature does
// not verify, so a provider's key rotation needs no restart; keyRefresh is
// the least time between two such fetches.
func NewVerifier(ctx context.Context, issuer, audience, claim string, timeout, keyRefresh time.Duration) (*Verifier, error) {
	if claim == "" {
		return nil, errors.New("principal: identity claim name is empty")
	}
	client := &http.Client{Timeout: timeout}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider %s: %w", issuer, err)
	}
	// The key set fetches signing keys later, on demand, for as long as the
	// process runs. ctx is a startup context its caller cancels on return,
	// so the key set gets one that keeps ctx's values but not its
	// cancellation or deadline; each fetch is bounded by timeout, and they
	// are at least keyRefresh apart (KeyFetchClient).
	keyCtx := oidc.ClientContext(context.WithoutCancel(ctx), KeyFetchClient(timeout, keyRefresh))
	return &Verifier{
		inner: provider.VerifierContext(keyCtx, &oidc.Config{ClientID: audience}),
		claim: claim,
	}, nil
}

// Identify verifies rawToken (signature, issuer, audience, expiry) and
// returns the identity its claims name. Any failure is ErrNotIdentified.
func (v *Verifier) Identify(ctx context.Context, rawToken string) (string, error) {
	if rawToken == "" {
		return "", ErrNotIdentified
	}
	tok, err := v.inner.Verify(ctx, rawToken)
	if err != nil {
		return "", ErrNotIdentified
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return "", ErrNotIdentified
	}
	id := Identity(claims, v.claim)
	if id == "" {
		return "", ErrNotIdentified
	}
	return id, nil
}
