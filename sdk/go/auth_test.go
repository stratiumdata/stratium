package stratium

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockOIDCServer creates a test HTTP server that simulates an OIDC provider
type mockOIDCServer struct {
	server          *httptest.Server
	tokenResponse   *tokenResponse
	shouldFailToken bool
	callCount       int
}

func newMockOIDCServer() *mockOIDCServer {
	mock := &mockOIDCServer{
		tokenResponse: &tokenResponse{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		},
	}

	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		baseURL := "http://" + r.Host
		config := map[string]interface{}{
			"issuer":                 baseURL,
			"authorization_endpoint": baseURL + "/auth",
			"token_endpoint":         baseURL + "/token",
			"jwks_uri":               baseURL + "/jwks",
		}
		json.NewEncoder(w).Encode(config)
	})

	// Token endpoint handler (shared logic)
	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		mock.callCount++

		if mock.shouldFailToken {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_client",
				"error_description": "Invalid credentials",
			})
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		grantType := r.Form.Get("grant_type")
		if grantType == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid_request",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mock.tokenResponse)
	}

	// Token endpoints (both standard and Keycloak-style)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/protocol/openid-connect/token", tokenHandler)

	// JWKS endpoint (minimal implementation)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []interface{}{},
		})
	})

	mock.server = httptest.NewServer(mux)
	return mock
}

func (m *mockOIDCServer) Close() {
	m.server.Close()
}

func (m *mockOIDCServer) URL() string {
	return m.server.URL
}

// ===== newAuthManager Tests =====

func TestNewAuthManager(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"openid", "profile"},
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("newAuthManager() error: %v", err)
	}

	if am == nil {
		t.Fatal("newAuthManager() returned nil")
	}

	if am.config != config {
		t.Error("newAuthManager() did not set config correctly")
	}

	if am.accessToken == "" {
		t.Error("newAuthManager() should have performed initial authentication")
	}

	if am.expiresAt.IsZero() {
		t.Error("newAuthManager() should have set token expiration")
	}
}

func TestNewAuthManager_WithPasswordGrant(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Username:     "test-user",
		Password:     "test-password",
		Scopes:       []string{"openid"},
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("newAuthManager() with password grant error: %v", err)
	}

	if am == nil {
		t.Fatal("newAuthManager() returned nil")
	}

	if am.accessToken == "" {
		t.Error("newAuthManager() should have authenticated with password grant")
	}
}

func TestNewAuthManager_InvalidIssuer(t *testing.T) {
	config := &OIDCConfig{
		IssuerURL:    "http://invalid-issuer-that-does-not-exist.local",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	_, err := newAuthManager(config)
	if err == nil {
		t.Error("newAuthManager() expected error for invalid issuer, got nil")
	}
}

func TestNewAuthManager_AuthenticationFailure(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	// Set server to fail authentication
	mockServer.shouldFailToken = true

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "wrong-secret",
	}

	_, err := newAuthManager(config)
	if err == nil {
		t.Error("newAuthManager() expected error for authentication failure, got nil")
	}

	if !strings.Contains(err.Error(), "initial authentication failed") {
		t.Errorf("newAuthManager() error message should mention authentication failure, got: %v", err)
	}
}

// ===== GetToken Tests =====

func TestAuthManager_GetToken(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ctx := context.Background()
	token, err := am.GetToken(ctx)
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}

	if token == "" {
		t.Fatal("GetToken() returned empty token")
	}

	if token != am.accessToken {
		t.Error("GetToken() returned different token than stored")
	}
}

func TestAuthManager_GetToken_UsesCache(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Reset call count after initial auth
	mockServer.callCount = 0

	ctx := context.Background()

	// Call GetToken multiple times
	for i := 0; i < 5; i++ {
		token, err := am.GetToken(ctx)
		if err != nil {
			t.Fatalf("GetToken() call %d error: %v", i, err)
		}
		if token == "" {
			t.Fatalf("GetToken() call %d returned empty token", i)
		}
	}

	// Should not have made additional token requests (using cached token)
	if mockServer.callCount > 0 {
		t.Errorf("GetToken() made %d token requests, expected 0 (should use cache)", mockServer.callCount)
	}
}

func TestAuthManager_GetToken_RefreshesExpiredToken(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Manually expire the token
	am.mu.Lock()
	am.expiresAt = time.Now().Add(-1 * time.Hour) // expired 1 hour ago
	am.mu.Unlock()

	// Reset call count
	mockServer.callCount = 0

	ctx := context.Background()
	token, err := am.GetToken(ctx)
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}

	if token == "" {
		t.Fatal("GetToken() returned empty token")
	}

	// Should have refreshed the token
	if mockServer.callCount == 0 {
		t.Error("GetToken() should have refreshed expired token")
	}
}

// ===== RefreshToken Tests =====

func TestAuthManager_RefreshToken(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Reset call count
	mockServer.callCount = 0

	ctx := context.Background()
	err = am.RefreshToken(ctx)
	if err != nil {
		t.Fatalf("RefreshToken() error: %v", err)
	}

	// Token should be refreshed
	if mockServer.callCount == 0 {
		t.Error("RefreshToken() should have made a token request")
	}

	// Access token should be updated
	if am.accessToken == "" {
		t.Error("RefreshToken() should have updated access token")
	}
}

func TestAuthManager_RefreshToken_WithRefreshToken(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Ensure we have a refresh token
	if am.refreshToken == "" {
		am.refreshToken = "test-refresh-token"
	}

	ctx := context.Background()
	mockServer.callCount = 0

	err = am.RefreshToken(ctx)
	if err != nil {
		t.Fatalf("RefreshToken() error: %v", err)
	}

	// Should have made a token request
	if mockServer.callCount == 0 {
		t.Error("RefreshToken() should have made a token request")
	}
}

func TestAuthManager_RefreshToken_Failure(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Set server to fail
	mockServer.shouldFailToken = true

	ctx := context.Background()
	err = am.RefreshToken(ctx)
	if err == nil {
		t.Error("RefreshToken() expected error when server fails, got nil")
	}
}

// ===== authenticate Tests =====

func TestAuthManager_authenticate(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Clear tokens
	am.mu.Lock()
	am.accessToken = ""
	am.refreshToken = ""
	am.mu.Unlock()

	mockServer.callCount = 0

	ctx := context.Background()
	err = am.authenticate(ctx)
	if err != nil {
		t.Fatalf("authenticate() error: %v", err)
	}

	// Verify token was obtained
	if am.accessToken == "" {
		t.Error("authenticate() should have set access token")
	}

	if am.expiresAt.IsZero() {
		t.Error("authenticate() should have set expiration time")
	}

	if mockServer.callCount == 0 {
		t.Error("authenticate() should have made token request")
	}
}

func TestAuthManager_authenticate_ServerError(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Set server to fail
	mockServer.shouldFailToken = true

	ctx := context.Background()
	err = am.authenticate(ctx)
	if err == nil {
		t.Error("authenticate() expected error for server failure, got nil")
	}

	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("authenticate() error should mention authentication failure, got: %v", err)
	}
}

// ===== authenticatePasswordGrant Tests =====

func TestAuthManager_authenticatePasswordGrant(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Clear tokens
	am.mu.Lock()
	am.accessToken = ""
	am.refreshToken = ""
	am.mu.Unlock()

	mockServer.callCount = 0

	ctx := context.Background()
	err = am.authenticatePasswordGrant(ctx, "test-user", "test-password")
	if err != nil {
		t.Fatalf("authenticatePasswordGrant() error: %v", err)
	}

	// Verify token was obtained
	if am.accessToken == "" {
		t.Error("authenticatePasswordGrant() should have set access token")
	}

	if am.expiresAt.IsZero() {
		t.Error("authenticatePasswordGrant() should have set expiration time")
	}
}

// ===== refreshWithRefreshToken Tests =====

func TestAuthManager_refreshWithRefreshToken(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Set a refresh token
	am.mu.Lock()
	am.refreshToken = "existing-refresh-token"
	am.mu.Unlock()

	mockServer.callCount = 0

	ctx := context.Background()
	err = am.refreshWithRefreshToken(ctx)
	if err != nil {
		t.Fatalf("refreshWithRefreshToken() error: %v", err)
	}

	// Verify token was refreshed
	if mockServer.callCount == 0 {
		t.Error("refreshWithRefreshToken() should have made token request")
	}

	// Access token should be updated
	if am.accessToken == "" {
		t.Error("refreshWithRefreshToken() should have updated access token")
	}
}

func TestAuthManager_refreshWithRefreshToken_Failure(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Set a refresh token
	am.refreshToken = "test-refresh-token"

	// Set server to fail
	mockServer.shouldFailToken = true

	ctx := context.Background()
	err = am.refreshWithRefreshToken(ctx)
	if err == nil {
		t.Error("refreshWithRefreshToken() expected error when server fails, got nil")
	}
}

// ===== Integration Tests =====

func TestAuthManager_TokenRefreshCycle(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	// Set short expiration for testing
	mockServer.tokenResponse.ExpiresIn = 2

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ctx := context.Background()

	// Get initial token
	_, err = am.GetToken(ctx)
	if err != nil {
		t.Fatalf("GetToken() initial error: %v", err)
	}

	// Wait for token to expire
	time.Sleep(3 * time.Second)

	// Get token again - should trigger refresh
	mockServer.callCount = 0
	token2, err := am.GetToken(ctx)
	if err != nil {
		t.Fatalf("GetToken() after expiry error: %v", err)
	}

	if token2 == "" {
		t.Fatal("GetToken() after expiry returned empty token")
	}

	// Should have refreshed
	if mockServer.callCount == 0 {
		t.Error("GetToken() should have refreshed expired token")
	}
}

func TestAuthManager_ConcurrentGetToken(t *testing.T) {
	mockServer := newMockOIDCServer()
	defer mockServer.Close()

	config := &OIDCConfig{
		IssuerURL:    mockServer.URL(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	am, err := newAuthManager(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ctx := context.Background()

	// Launch multiple goroutines calling GetToken concurrently
	done := make(chan bool)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func() {
			token, err := am.GetToken(ctx)
			if err != nil {
				errors <- err
			} else if token == "" {
				errors <- err
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
	close(errors)

	// Check for errors
	for err := range errors {
		if err != nil {
			t.Errorf("Concurrent GetToken() error: %v", err)
		}
	}
}
