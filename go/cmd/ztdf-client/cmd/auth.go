package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TokenResponse represents the OAuth2 token response from Keycloak
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope"`
}

// TokenStore represents stored authentication tokens
type TokenStore struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Issuer       string    `json:"issuer"`
}

// AuthConfig holds Keycloak authentication configuration
type AuthConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	TokenFile    string
}

// LoginToKeycloak performs password grant authentication with Keycloak
func LoginToKeycloak(config *AuthConfig) (*TokenStore, error) {
	// Construct token endpoint URL
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", strings.TrimSuffix(config.IssuerURL, "/"))

	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", config.ClientID)
	data.Set("username", config.Username)
	data.Set("password", config.Password)
	data.Set("scope", "openid profile email")

	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Make the request
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Create token store
	store := &TokenStore{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Issuer:       config.IssuerURL,
	}

	// Save tokens to file if specified
	if config.TokenFile != "" {
		if err := SaveTokenStore(config.TokenFile, store); err != nil {
			fmt.Printf("Warning: failed to save token: %v\n", err)
		}
	}

	return store, nil
}

// RefreshAccessToken refreshes an expired access token using the refresh token
func RefreshAccessToken(config *AuthConfig, refreshToken string) (*TokenStore, error) {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", strings.TrimSuffix(config.IssuerURL, "/"))

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", config.ClientID)
	data.Set("refresh_token", refreshToken)

	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	store := &TokenStore{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Issuer:       config.IssuerURL,
	}

	if config.TokenFile != "" {
		if err := SaveTokenStore(config.TokenFile, store); err != nil {
			fmt.Printf("Warning: failed to save token: %v\n", err)
		}
	}

	return store, nil
}

// LoadTokenStore loads saved tokens from a file
func LoadTokenStore(tokenFile string) (*TokenStore, error) {
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	var store TokenStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	return &store, nil
}

// SaveTokenStore saves tokens to a file
func SaveTokenStore(tokenFile string, store *TokenStore) error {
	// Ensure directory exists
	dir := filepath.Dir(tokenFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token store: %w", err)
	}

	if err := os.WriteFile(tokenFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// GetValidToken retrieves a valid access token, refreshing if necessary
func GetValidToken(config *AuthConfig) (string, error) {

	// Try to load existing token
	if config.TokenFile != "" {
		store, err := LoadTokenStore(config.TokenFile)
		if err == nil {
			// Check if token is still valid (with 1 minute buffer)
			if time.Now().Before(store.ExpiresAt.Add(-1 * time.Minute)) {
				return store.IDToken, nil
			}

			// Try to refresh the token
			if store.RefreshToken != "" {
				newStore, err := RefreshAccessToken(config, store.RefreshToken)
				if err == nil {
					return newStore.IDToken, nil
				}
				fmt.Printf("Token refresh failed: %v. Re-authenticating...\n", err)
			}
		}
	}

	// Need to login
	if config.Username == "" || config.Password == "" {
		return "", fmt.Errorf("username and password required for authentication")
	}

	store, err := LoginToKeycloak(config)
	if err != nil {
		return "", err
	}

	return store.IDToken, nil
}

// CreateAuthContext creates a context with authentication token
func CreateAuthContext(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, "auth_token", token)
}
