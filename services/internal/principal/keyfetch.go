package principal

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// errKeyFetchTooSoon is what a key fetch inside the interval fails with. It
// never reaches a caller: the verifier reports every failure as one error.
var errKeyFetchTooSoon = errors.New("principal: signing keys were fetched too recently to fetch again")

// KeyFetchClient returns the HTTP client a verifier's key set fetches an
// issuer's signing keys with. Each request is bounded by timeout, and a
// request less than minInterval after the previous one fails without
// touching the network.
//
// go-oidc fetches the keys again whenever a token's signature does not
// verify, in case the issuer rotated them. A token needs no valid signature
// to get that far, only the right issuer and audience, so without the
// interval every such token is a request to the identity provider. With it,
// keys already held keep verifying real tokens, and a rotated key is picked
// up by the first failing token after the interval has passed.
//
// Use it for the key set only, never for discovery: the interval is one
// counter across every URL the client is asked for.
func KeyFetchClient(timeout, minInterval time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &spacedTransport{next: http.DefaultTransport, minInterval: minInterval},
	}
}

type spacedTransport struct {
	next        http.RoundTripper
	minInterval time.Duration

	mu   sync.Mutex
	last time.Time
}

func (t *spacedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	now := time.Now()
	if !t.last.IsZero() && now.Sub(t.last) < t.minInterval {
		t.mu.Unlock()
		return nil, errKeyFetchTooSoon
	}
	t.last = now
	t.mu.Unlock()
	return t.next.RoundTrip(r)
}
