package stratium

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// authManager handles OIDC authentication and token management.
type authManager struct {
	config       *OIDCConfig
	oauth2Config *oauth2.Config

	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	expiresAt    time.Time

	httpClient *http.Client
}

// tokenResponse represents the OIDC token endpoint response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// newAuthManager creates a new authentication manager.
func newAuthManager(config *OIDCConfig) (*authManager, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	am := &authManager{
		config: config,
		oauth2Config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       config.Scopes,
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Perform initial authentication
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if config.Username != "" && config.Password != "" {
		if err := am.authenticatePasswordGrant(ctx, config.Username, config.Password); err != nil {
			return nil, fmt.Errorf("initial authentication failed: %w", err)
		}
	} else {
		if err := am.authenticate(ctx); err != nil {
			return nil, fmt.Errorf("initial authentication failed: %w", err)
		}
	}

	return am, nil
}

// GetToken returns a valid access token, refreshing if necessary.
func (am *authManager) GetToken(ctx context.Context) (string, error) {
	am.mu.RLock()
	// Check if token is still valid (with 30s buffer)
	if time.Now().Add(30 * time.Second).Before(am.expiresAt) {
		token := am.accessToken
		am.mu.RUnlock()
		return token, nil
	}
	am.mu.RUnlock()

	// Token expired or about to expire, refresh it
	if err := am.RefreshToken(ctx); err != nil {
		return "", err
	}

	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.accessToken, nil
}

// RefreshToken refreshes the access token.
func (am *authManager) RefreshToken(ctx context.Context) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Try refresh token first if available
	if am.refreshToken != "" {
		err := am.refreshWithRefreshToken(ctx)
		if err == nil {
			return nil
		}
		// If refresh token fails, fall back to client credentials
	}

	// Use client credentials flow
	return am.authenticate(ctx)
}

// authenticate performs client credentials authentication.
func (am *authManager) authenticate(ctx context.Context) error {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", am.config.IssuerURL)

	// Prepare request body
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", am.config.ClientID)
	data.Set("client_secret", am.config.ClientSecret)
	if len(am.config.Scopes) > 0 {
		data.Set("scope", strings.Join(am.config.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := am.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	// Update tokens
	am.accessToken = tokenResp.AccessToken
	am.refreshToken = tokenResp.RefreshToken
	am.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}

// authenticatePasswordGrant uses Resource Owner Password Credentials grant
func (am *authManager) authenticatePasswordGrant(ctx context.Context, username, password string) error {
	token, err := am.oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return fmt.Errorf("password authentication failed: %w", err)
	}

	am.accessToken = token.AccessToken
	am.refreshToken = token.RefreshToken
	am.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	return nil
}

// refreshWithRefreshToken uses the refresh token to get a new access token.
func (am *authManager) refreshWithRefreshToken(ctx context.Context) error {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", am.config.IssuerURL)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", am.config.ClientID)
	data.Set("client_secret", am.config.ClientSecret)
	data.Set("refresh_token", am.refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := am.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode refresh response: %w", err)
	}

	// Update tokens
	am.accessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		am.refreshToken = tokenResp.RefreshToken
	}
	am.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}
