package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KeycloakAuthProvider implements AuthProvider for Keycloak/OIDC
type KeycloakAuthProvider struct {
	issuerURL    string
	clientID     string
	clientSecret string
	username     string
	password     string
	tokenFile    string
	tokenStore   *tokenStore
}

// tokenStore holds cached tokens
type tokenStore struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Issuer       string    `json:"issuer"`
}

// tokenResponse from Keycloak OAuth2 endpoint
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope"`
}

// NewKeycloakAuthProvider creates a Keycloak auth provider
func NewKeycloakAuthProvider(config *AuthConfig) (AuthProvider, error) {
	if config == nil {
		return nil, errors.New("auth config is required")
	}

	if config.IssuerURL == "" {
		return nil, errors.New("issuer url is required")
	}

	if config.ClientID == "" {
		return nil, errors.New("client id is required")
	}

	tokenFile := config.TokenFile
	if tokenFile == "" {
		// Default to ~/.ztdf/token.json
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		tokenFile = filepath.Join(home, ".ztdf", "token.json")
	}

	return &KeycloakAuthProvider{
		issuerURL:    config.IssuerURL,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		username:     config.Username,
		password:     config.Password,
		tokenFile:    tokenFile,
	}, nil
}

// Authenticate gets a valid JWT token
func (k *KeycloakAuthProvider) Authenticate(ctx context.Context) (string, error) {
	// Try to load cached token
	if err := k.loadToken(); err == nil {
		// Check if token is still valid
		if k.IsTokenValid() {
			return k.tokenStore.IDToken, nil
		}

		// Try to refresh
		if k.tokenStore.RefreshToken != "" {
			token, err := k.RefreshToken(ctx)
			if err == nil {
				return token, nil
			}
			// Refresh failed, fall through to password grant
		}
	}

	// Need to authenticate with password grant
	if k.username == "" || k.password == "" {
		return "", errors.New("username or password is required")
	}

	return k.passwordGrant(ctx)
}

// passwordGrant performs OAuth2 password grant flow
func (k *KeycloakAuthProvider) passwordGrant(ctx context.Context) (string, error) {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", strings.TrimSuffix(k.issuerURL, "/"))

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", k.clientID)
	data.Set("username", k.username)
	data.Set("password", k.password)
	data.Set("scope", "openid profile email")

	if k.clientSecret != "" {
		data.Set("client_secret", k.clientSecret)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", errors.New("failed to create token request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("failed to request token")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("failed to read token response")
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("authentication failed (status %d): %s", resp.StatusCode, string(body)))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", errors.New("failed to parse token response")
	}

	// Store token
	k.tokenStore = &tokenStore{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Issuer:       k.issuerURL,
	}

	if err := k.saveToken(); err != nil {
		// Log warning but don't fail
		fmt.Printf("Warning: failed to save token: %v\n", err)
	}

	return k.tokenStore.IDToken, nil
}

// RefreshToken refreshes an expired token
func (k *KeycloakAuthProvider) RefreshToken(ctx context.Context) (string, error) {
	if k.tokenStore == nil || k.tokenStore.RefreshToken == "" {
		return "", errors.New("refresh token is required")
	}

	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", strings.TrimSuffix(k.issuerURL, "/"))

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", k.clientID)
	data.Set("refresh_token", k.tokenStore.RefreshToken)

	if k.clientSecret != "" {
		data.Set("client_secret", k.clientSecret)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", errors.New("failed to create refresh request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("failed to refresh token")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("failed to read refresh response")
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("refresh failed (status %d): %s", resp.StatusCode, string(body)))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", errors.New("failed to parse refresh response")
	}

	// Update token store
	k.tokenStore.AccessToken = tokenResp.AccessToken
	k.tokenStore.RefreshToken = tokenResp.RefreshToken
	k.tokenStore.IDToken = tokenResp.IDToken
	k.tokenStore.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	if err := k.saveToken(); err != nil {
		fmt.Printf("Warning: failed to save refreshed token: %v\n", err)
	}

	return k.tokenStore.IDToken, nil
}

// IsTokenValid checks if current token is valid
func (k *KeycloakAuthProvider) IsTokenValid() bool {
	if k.tokenStore == nil {
		return false
	}
	// Add 1 minute buffer
	return time.Now().Before(k.tokenStore.ExpiresAt.Add(-1 * time.Minute))
}

// GetUserClaims extracts user claims from token
func (k *KeycloakAuthProvider) GetUserClaims() (*UserClaims, error) {
	if k.tokenStore == nil || k.tokenStore.IDToken == "" {
		return nil, errors.New("no token available")
	}

	// Parse JWT (simple parsing, not validating signature)
	// In production, you should use a proper JWT library to validate the signature
	parts := strings.Split(k.tokenStore.IDToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	// Decode claims (base64url)
	claimsJSON, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, errors.New("failed to decode JWT claims")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, errors.New("failed to parse JWT claims")
	}

	userClaims := &UserClaims{}

	if sub, ok := claims["sub"].(string); ok {
		userClaims.Sub = sub
	}
	if email, ok := claims["email"].(string); ok {
		userClaims.Email = email
	}
	if username, ok := claims["preferred_username"].(string); ok {
		userClaims.PreferredUsername = username
	}
	if name, ok := claims["name"].(string); ok {
		userClaims.Name = name
	}
	if givenName, ok := claims["given_name"].(string); ok {
		userClaims.GivenName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		userClaims.FamilyName = familyName
	}

	return userClaims, nil
}

// loadToken loads token from disk
func (k *KeycloakAuthProvider) loadToken() error {
	data, err := os.ReadFile(k.tokenFile)
	if err != nil {
		return err
	}

	var store tokenStore
	if err := json.Unmarshal(data, &store); err != nil {
		return err
	}

	k.tokenStore = &store
	return nil
}

// saveToken saves token to disk
func (k *KeycloakAuthProvider) saveToken() error {
	// Ensure directory exists
	dir := filepath.Dir(k.tokenFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(k.tokenStore, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(k.tokenFile, data, 0600)
}

// decodeBase64URL decodes base64url encoding (used in JWT)
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	// Replace base64url characters with base64 characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return base64.StdEncoding.DecodeString(s)
}
