package pap

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// AuthService handles OIDC authentication
type AuthService struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	isMock       bool
}

// OIDCConfig holds OIDC configuration
type OIDCConfig struct {
	IssuerURL           string
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	Scopes              []string
	AllowInsecureIssuer bool
}

// UserClaims represents the claims from the OIDC token
type UserClaims struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
}

// NewAuthService creates a new OIDC authentication service
func NewAuthService(config *OIDCConfig) (*AuthService, error) {
	ctx := context.Background()
	if config.AllowInsecureIssuer {
		ctx = oidc.InsecureIssuerURLContext(ctx, config.IssuerURL)
	}

	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID}, config.Scopes...),
	}

	// Configure ID token verifier with issuer skip
	verifier := provider.Verifier(&oidc.Config{
		ClientID:          config.ClientID,
		SkipIssuerCheck:   config.AllowInsecureIssuer,
		SkipClientIDCheck: config.AllowInsecureIssuer,
	})

	return &AuthService{
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
	}, nil
}

// IsMock returns true if this is a mock auth service
func (a *AuthService) IsMock() bool {
	return a.isMock
}

// ValidateToken validates a JWT token and returns the claims
func (a *AuthService) ValidateToken(ctx context.Context, tokenString string) (*UserClaims, error) {
	// Mock mode: return mock claims
	if a.isMock {
		return &UserClaims{
			Sub:               "mock-user-123",
			Email:             "mock@example.com",
			PreferredUsername: "mockuser",
			Name:              "Mock User",
		}, nil
	}

	// Real OIDC validation
	idToken, err := a.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	var claims UserClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &claims, nil
}

// authMiddleware is a Gin middleware that validates OIDC tokens
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			c.Abort()
			return
		}

		// Check for Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := s.authService.ValidateToken(c.Request.Context(), tokenString)
		if err != nil {
			logger.Error("token validation failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Store user information in context
		c.Set("user", claims.Sub)
		c.Set("user_claims", claims)
		c.Set("email", claims.Email)
		c.Set("username", claims.PreferredUsername)

		c.Next()
	}
}

// MockAuthService provides a mock implementation for development/testing
type MockAuthService struct{}

// NewMockAuthService creates a new mock auth service
func NewMockAuthService() *AuthService {
	return &AuthService{
		isMock: true,
	}
}

// ValidateToken for mock service always succeeds
func (m *MockAuthService) ValidateToken(ctx context.Context, tokenString string) (*UserClaims, error) {
	return &UserClaims{
		Sub:               "mock-user-123",
		Email:             "mock@example.com",
		PreferredUsername: "mockuser",
		Name:              "Mock User",
	}, nil
}

// mockAuthMiddleware is a simplified middleware for development without OIDC
func (s *Server) mockAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// For development: accept any token or no token
		c.Set("user", "dev-user")
		c.Set("email", "dev@example.com")
		c.Set("username", "developer")
		c.Next()
	}
}
