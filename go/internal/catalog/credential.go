// go/internal/catalog/credential.go
package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrCredentialUnavailable signals that no usable token could be obtained for a
// provider (e.g. the user has not linked the account, or the broker rejected the
// request). Handlers surface this as a "link your account" message, distinct from
// an authorization denial.
var ErrCredentialUnavailable = errors.New("credential unavailable")

// CredentialProvider returns a usable third-party access token for a provider.
//
// subjectToken is the caller's Keycloak access token; brokered providers use it
// to authenticate to the /broker/{alias}/token endpoint. Static providers ignore it.
type CredentialProvider interface {
	GetToken(ctx context.Context, subjectToken, provider string) (string, error)
}

// StaticToken serves pre-configured tokens (PATs, bearer tokens). Fallback only.
type StaticToken struct {
	Tokens map[string]string
}

func (s StaticToken) GetToken(_ context.Context, _ string, provider string) (string, error) {
	if t, ok := s.Tokens[provider]; ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: no static token for provider %q", ErrCredentialUnavailable, provider)
}

// KeycloakBroker retrieves a brokered external-IdP token via Keycloak.
// See: GET {RealmURL}/broker/{provider}/token (requires the broker read-token role).
type KeycloakBroker struct {
	RealmURL string // e.g. http://localhost:8080/realms/stratium
	HTTP     *http.Client
}

func (b *KeycloakBroker) GetToken(ctx context.Context, subjectToken, provider string) (string, error) {
	client := b.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(b.RealmURL, "/") + "/broker/" + url.PathEscape(provider) + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build broker request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+subjectToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("broker request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read broker response body: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return parseBrokerToken(resp.Header.Get("Content-Type"), body)
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return "", fmt.Errorf("%w: provider %q not linked or token not readable (status %d)", ErrCredentialUnavailable, provider, resp.StatusCode)
	default:
		return "", fmt.Errorf("broker returned status %d", resp.StatusCode)
	}
}

// parseBrokerToken extracts a usable access token from a /broker/{alias}/token
// response. Handles both JSON ({"access_token":...} or {"token":...}) and
// form-encoded (access_token=...) bodies, since the shape depends on the IdP.
func parseBrokerToken(contentType string, body []byte) (string, error) {
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return "", fmt.Errorf("parse form broker body: %w", err)
		}
		if t := vals.Get("access_token"); t != "" {
			return t, nil
		}
		return "", fmt.Errorf("%w: no access_token in broker response", ErrCredentialUnavailable)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("parse json broker body: %w", err)
	}
	if parsed.AccessToken != "" {
		return parsed.AccessToken, nil
	}
	if parsed.Token != "" {
		return parsed.Token, nil
	}
	return "", fmt.Errorf("%w: empty broker token response", ErrCredentialUnavailable)
}
