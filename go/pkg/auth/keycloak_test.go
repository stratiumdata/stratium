package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewKeycloakAuthProvider_NilConfig(t *testing.T) {
	_, err := NewKeycloakAuthProvider(nil)
	if err == nil {
		t.Fatal("Expected error when config is nil")
	}
	if err.Error() != "auth config is required" {
		t.Errorf("Expected 'auth config is required', got: %v", err)
	}
}

func TestNewKeycloakAuthProvider_EmptyIssuerURL(t *testing.T) {
	config := &AuthConfig{
		IssuerURL: "",
		ClientID:  "test-client",
	}
	_, err := NewKeycloakAuthProvider(config)
	if err == nil {
		t.Fatal("Expected error when issuer URL is empty")
	}
	if err.Error() != "issuer url is required" {
		t.Errorf("Expected 'issuer url is required', got: %v", err)
	}
}

func TestNewKeycloakAuthProvider_EmptyClientID(t *testing.T) {
	config := &AuthConfig{
		IssuerURL: "https://auth.example.com",
		ClientID:  "",
	}
	_, err := NewKeycloakAuthProvider(config)
	if err == nil {
		t.Fatal("Expected error when client ID is empty")
	}
	if err.Error() != "client id is required" {
		t.Errorf("Expected 'client id is required', got: %v", err)
	}
}

func TestNewKeycloakAuthProvider_Success(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token.json")

	config := &AuthConfig{
		IssuerURL:    "https://auth.example.com",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Username:     "user",
		Password:     "pass",
		TokenFile:    tokenFile,
	}

	provider, err := NewKeycloakAuthProvider(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	kp, ok := provider.(*KeycloakAuthProvider)
	if !ok {
		t.Fatal("Expected *KeycloakAuthProvider")
	}

	if kp.issuerURL != config.IssuerURL {
		t.Errorf("Expected issuerURL %s, got %s", config.IssuerURL, kp.issuerURL)
	}

	if kp.clientID != config.ClientID {
		t.Errorf("Expected clientID %s, got %s", config.ClientID, kp.clientID)
	}

	if kp.tokenFile != tokenFile {
		t.Errorf("Expected tokenFile %s, got %s", tokenFile, kp.tokenFile)
	}
}

func TestNewKeycloakAuthProvider_DefaultTokenFile(t *testing.T) {
	config := &AuthConfig{
		IssuerURL: "https://auth.example.com",
		ClientID:  "test-client",
	}

	provider, err := NewKeycloakAuthProvider(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	kp, ok := provider.(*KeycloakAuthProvider)
	if !ok {
		t.Fatal("Expected *KeycloakAuthProvider")
	}

	// Should have default token file path
	if kp.tokenFile == "" {
		t.Error("Token file should not be empty")
	}

	if !strings.Contains(kp.tokenFile, ".ztdf") {
		t.Errorf("Expected token file to contain .ztdf, got: %s", kp.tokenFile)
	}
}

func TestIsTokenValid_NoToken(t *testing.T) {
	kp := &KeycloakAuthProvider{}

	if kp.IsTokenValid() {
		t.Error("Expected token to be invalid when tokenStore is nil")
	}
}

func TestIsTokenValid_ExpiredToken(t *testing.T) {
	kp := &KeycloakAuthProvider{
		tokenStore: &tokenStore{
			IDToken:   "test-token",
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		},
	}

	if kp.IsTokenValid() {
		t.Error("Expected token to be invalid when expired")
	}
}

func TestIsTokenValid_ValidToken(t *testing.T) {
	kp := &KeycloakAuthProvider{
		tokenStore: &tokenStore{
			IDToken:   "test-token",
			ExpiresAt: time.Now().Add(2 * time.Hour), // Expires in 2 hours
		},
	}

	if !kp.IsTokenValid() {
		t.Error("Expected token to be valid")
	}
}

func TestIsTokenValid_SoonToExpire(t *testing.T) {
	kp := &KeycloakAuthProvider{
		tokenStore: &tokenStore{
			IDToken:   "test-token",
			ExpiresAt: time.Now().Add(30 * time.Second), // Expires in 30 seconds (within 1 minute buffer)
		},
	}

	// Should be invalid due to 1-minute buffer
	if kp.IsTokenValid() {
		t.Error("Expected token to be invalid when expiring within 1 minute")
	}
}

func TestSaveAndLoadToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "tokens", "test-token.json")

	kp := &KeycloakAuthProvider{
		tokenFile: tokenFile,
		tokenStore: &tokenStore{
			AccessToken:  "access-123",
			RefreshToken: "refresh-456",
			IDToken:      "id-789",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			Issuer:       "https://auth.example.com",
		},
	}

	// Save token
	err := kp.saveToken()
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		t.Fatal("Token file was not created")
	}

	// Create new provider and load token
	kp2 := &KeycloakAuthProvider{
		tokenFile: tokenFile,
	}

	err = kp2.loadToken()
	if err != nil {
		t.Fatalf("Failed to load token: %v", err)
	}

	// Verify loaded token matches
	if kp2.tokenStore.AccessToken != kp.tokenStore.AccessToken {
		t.Errorf("AccessToken mismatch: %s != %s", kp2.tokenStore.AccessToken, kp.tokenStore.AccessToken)
	}

	if kp2.tokenStore.RefreshToken != kp.tokenStore.RefreshToken {
		t.Errorf("RefreshToken mismatch")
	}

	if kp2.tokenStore.IDToken != kp.tokenStore.IDToken {
		t.Errorf("IDToken mismatch")
	}

	if kp2.tokenStore.Issuer != kp.tokenStore.Issuer {
		t.Errorf("Issuer mismatch")
	}
}

func TestLoadToken_NonExistentFile(t *testing.T) {
	kp := &KeycloakAuthProvider{
		tokenFile: "/nonexistent/path/token.json",
	}

	err := kp.loadToken()
	if err == nil {
		t.Error("Expected error when loading non-existent file")
	}
}

func TestLoadToken_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "invalid-token.json")

	// Write invalid JSON
	err := os.WriteFile(tokenFile, []byte("invalid json"), 0600)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	kp := &KeycloakAuthProvider{
		tokenFile: tokenFile,
	}

	err = kp.loadToken()
	if err == nil {
		t.Error("Expected error when loading invalid JSON")
	}
}

func TestDecodeBase64URL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "no padding needed",
			input:    "dGVzdA",
			expected: "test", // Decodes base64url to "test"
			wantErr:  false,
		},
		{
			name:     "padding needed (2 chars)",
			input:    "dGU",
			expected: "te",
			wantErr:  false,
		},
		{
			name:     "padding needed (1 char)",
			input:    "dGVz",
			expected: "tes",
			wantErr:  false,
		},
		{
			name:     "with url-safe characters",
			input:    "YS1iX2M",
			expected: "a-b_c", // Decodes base64url encoded "a-b_c"
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeBase64URL(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("decodeBase64URL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(result) != tt.expected {
				t.Errorf("decodeBase64URL() = %s, want %s", string(result), tt.expected)
			}
		})
	}
}

func TestGetUserClaims_NoToken(t *testing.T) {
	kp := &KeycloakAuthProvider{}

	_, err := kp.GetUserClaims()
	if err == nil {
		t.Fatal("Expected error when no token available")
	}

	if err.Error() != "no token available" {
		t.Errorf("Expected 'no token available', got: %v", err)
	}
}

func TestGetUserClaims_InvalidJWT(t *testing.T) {
	kp := &KeycloakAuthProvider{
		tokenStore: &tokenStore{
			IDToken: "invalid.jwt",
		},
	}

	_, err := kp.GetUserClaims()
	if err == nil {
		t.Fatal("Expected error for invalid JWT")
	}

	if err.Error() != "invalid JWT format" {
		t.Errorf("Expected 'invalid JWT format', got: %v", err)
	}
}

func TestGetUserClaims_ValidJWT(t *testing.T) {
	// Create a valid JWT structure (header.payload.signature)
	claims := map[string]interface{}{
		"sub":                "user-123",
		"email":              "user@example.com",
		"preferred_username": "testuser",
		"name":               "Test User",
		"given_name":         "Test",
		"family_name":        "User",
	}

	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create fake JWT (header.claims.signature)
	fakeJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + claimsB64 + ".signature"

	kp := &KeycloakAuthProvider{
		tokenStore: &tokenStore{
			IDToken: fakeJWT,
		},
	}

	userClaims, err := kp.GetUserClaims()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if userClaims.Sub != "user-123" {
		t.Errorf("Expected Sub 'user-123', got %s", userClaims.Sub)
	}

	if userClaims.Email != "user@example.com" {
		t.Errorf("Expected Email 'user@example.com', got %s", userClaims.Email)
	}

	if userClaims.PreferredUsername != "testuser" {
		t.Errorf("Expected PreferredUsername 'testuser', got %s", userClaims.PreferredUsername)
	}

	if userClaims.Name != "Test User" {
		t.Errorf("Expected Name 'Test User', got %s", userClaims.Name)
	}

	if userClaims.GivenName != "Test" {
		t.Errorf("Expected GivenName 'Test', got %s", userClaims.GivenName)
	}

	if userClaims.FamilyName != "User" {
		t.Errorf("Expected FamilyName 'User', got %s", userClaims.FamilyName)
	}
}

func TestPasswordGrant_Success(t *testing.T) {
	// Create mock Keycloak server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if !strings.Contains(r.URL.Path, "/protocol/openid-connect/token") {
			t.Errorf("Expected /protocol/openid-connect/token path, got %s", r.URL.Path)
		}

		// Verify Content-Type
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Expected application/x-www-form-urlencoded content type")
		}

		// Parse form data
		r.ParseForm()

		if r.FormValue("grant_type") != "password" {
			t.Errorf("Expected grant_type=password, got %s", r.FormValue("grant_type"))
		}

		if r.FormValue("client_id") != "test-client" {
			t.Errorf("Expected client_id=test-client, got %s", r.FormValue("client_id"))
		}

		if r.FormValue("username") != "testuser" {
			t.Errorf("Expected username=testuser, got %s", r.FormValue("username"))
		}

		// Return mock token response
		response := tokenResponse{
			AccessToken:  "access-token-123",
			RefreshToken: "refresh-token-456",
			IDToken:      "id-token-789",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			Scope:        "openid profile email",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	kp := &KeycloakAuthProvider{
		issuerURL:    server.URL,
		clientID:     "test-client",
		clientSecret: "test-secret",
		username:     "testuser",
		password:     "testpass",
		tokenFile:    filepath.Join(tmpDir, "token.json"),
	}

	token, err := kp.passwordGrant(context.Background())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if token != "id-token-789" {
		t.Errorf("Expected token 'id-token-789', got %s", token)
	}

	// Verify token was stored
	if kp.tokenStore == nil {
		t.Fatal("Token store should not be nil")
	}

	if kp.tokenStore.AccessToken != "access-token-123" {
		t.Errorf("AccessToken mismatch")
	}

	if kp.tokenStore.RefreshToken != "refresh-token-456" {
		t.Errorf("RefreshToken mismatch")
	}
}

func TestPasswordGrant_HTTPError(t *testing.T) {
	// Create mock server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid_grant"}`))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	kp := &KeycloakAuthProvider{
		issuerURL: server.URL,
		clientID:  "test-client",
		username:  "testuser",
		password:  "wrongpass",
		tokenFile: filepath.Join(tmpDir, "token.json"),
	}

	_, err := kp.passwordGrant(context.Background())
	if err == nil {
		t.Fatal("Expected error for failed authentication")
	}

	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("Expected 'authentication failed' error, got: %v", err)
	}
}

func TestRefreshToken_Success(t *testing.T) {
	// Create mock Keycloak server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("Expected grant_type=refresh_token, got %s", r.FormValue("grant_type"))
		}

		if r.FormValue("refresh_token") != "old-refresh-token" {
			t.Errorf("Expected refresh_token=old-refresh-token, got %s", r.FormValue("refresh_token"))
		}

		// Return new tokens
		response := tokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			IDToken:      "new-id-token",
			ExpiresIn:    3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	kp := &KeycloakAuthProvider{
		issuerURL: server.URL,
		clientID:  "test-client",
		tokenFile: filepath.Join(tmpDir, "token.json"),
		tokenStore: &tokenStore{
			AccessToken:  "old-access-token",
			RefreshToken: "old-refresh-token",
			IDToken:      "old-id-token",
			ExpiresAt:    time.Now().Add(-1 * time.Hour),
		},
	}

	token, err := kp.RefreshToken(context.Background())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if token != "new-id-token" {
		t.Errorf("Expected token 'new-id-token', got %s", token)
	}

	// Verify tokens were updated
	if kp.tokenStore.AccessToken != "new-access-token" {
		t.Errorf("AccessToken not updated")
	}

	if kp.tokenStore.RefreshToken != "new-refresh-token" {
		t.Errorf("RefreshToken not updated")
	}
}

func TestRefreshToken_NoRefreshToken(t *testing.T) {
	kp := &KeycloakAuthProvider{
		tokenStore: nil,
	}

	_, err := kp.RefreshToken(context.Background())
	if err == nil {
		t.Fatal("Expected error when no refresh token available")
	}

	if err.Error() != "refresh token is required" {
		t.Errorf("Expected 'refresh token is required', got: %v", err)
	}
}

func TestRefreshToken_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_token"}`))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	kp := &KeycloakAuthProvider{
		issuerURL: server.URL,
		clientID:  "test-client",
		tokenFile: filepath.Join(tmpDir, "token.json"),
		tokenStore: &tokenStore{
			RefreshToken: "invalid-refresh-token",
		},
	}

	_, err := kp.RefreshToken(context.Background())
	if err == nil {
		t.Fatal("Expected error for failed refresh")
	}

	if !strings.Contains(err.Error(), "refresh failed") {
		t.Errorf("Expected 'refresh failed' error, got: %v", err)
	}
}

func TestAuthenticate_WithCachedValidToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token.json")

	// Create cached token
	kp := &KeycloakAuthProvider{
		tokenFile: tokenFile,
		tokenStore: &tokenStore{
			IDToken:   "cached-token",
			ExpiresAt: time.Now().Add(2 * time.Hour),
		},
	}

	// Save the cached token
	kp.saveToken()

	// Create new provider (will load cached token)
	kp2 := &KeycloakAuthProvider{
		tokenFile: tokenFile,
	}

	token, err := kp2.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if token != "cached-token" {
		t.Errorf("Expected cached-token, got %s", token)
	}
}

func TestAuthenticate_NoCredentials(t *testing.T) {
	kp := &KeycloakAuthProvider{
		issuerURL: "https://auth.example.com",
		clientID:  "test-client",
		// No username/password
	}

	_, err := kp.Authenticate(context.Background())
	if err == nil {
		t.Fatal("Expected error when no credentials provided")
	}

	if err.Error() != "username or password is required" {
		t.Errorf("Expected 'username or password is required', got: %v", err)
	}
}

func TestTokenStore_JSONSerialization(t *testing.T) {
	store := &tokenStore{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		IDToken:      "id-789",
		ExpiresAt:    time.Now().Round(time.Second),
		Issuer:       "https://auth.example.com",
	}

	// Marshal to JSON
	data, err := json.Marshal(store)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal from JSON
	var store2 tokenStore
	err = json.Unmarshal(data, &store2)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify fields match
	if store2.AccessToken != store.AccessToken {
		t.Errorf("AccessToken mismatch")
	}

	if store2.RefreshToken != store.RefreshToken {
		t.Errorf("RefreshToken mismatch")
	}

	if store2.IDToken != store.IDToken {
		t.Errorf("IDToken mismatch")
	}

	if store2.Issuer != store.Issuer {
		t.Errorf("Issuer mismatch")
	}
}

func TestTokenResponse_Structure(t *testing.T) {
	resp := &tokenResponse{
		AccessToken:      "access-token",
		ExpiresIn:        3600,
		RefreshExpiresIn: 7200,
		RefreshToken:     "refresh-token",
		TokenType:        "Bearer",
		IDToken:          "id-token",
		Scope:            "openid profile email",
	}

	// Verify all fields
	if resp.AccessToken != "access-token" {
		t.Errorf("AccessToken mismatch")
	}

	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn mismatch")
	}

	if resp.RefreshExpiresIn != 7200 {
		t.Errorf("RefreshExpiresIn mismatch")
	}

	if resp.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken mismatch")
	}

	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType mismatch")
	}

	if resp.IDToken != "id-token" {
		t.Errorf("IDToken mismatch")
	}

	if resp.Scope != "openid profile email" {
		t.Errorf("Scope mismatch")
	}
}