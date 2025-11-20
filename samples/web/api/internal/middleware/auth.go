package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/stratium/samples/micro-research-api/internal/models"
	"github.com/stratium/samples/micro-research-api/internal/repository"
	"golang.org/x/oauth2"
)

// AuthMiddleware handles OIDC authentication
type AuthMiddleware struct {
	verifier *oidc.IDTokenVerifier
	config   *oauth2.Config
	userRepo *repository.UserRepository
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(issuerURL, clientID, clientSecret string, userRepo *repository.UserRepository) (*AuthMiddleware, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &AuthMiddleware{
		verifier: verifier,
		config:   config,
		userRepo: userRepo,
	}, nil
}

// RequireAuth ensures the request has a valid JWT token
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		err, claims, done := m.getClaims(c)
		if done {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		// Get or create user from database
		user, err := m.userRepo.GetByEmail(c.Request.Context(), claims.Email)
		if err != nil {
			// User doesn't exist - this is a demo, so we could auto-create
			// For now, return unauthorized
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "user not found in system",
				"hint":  "please contact administrator to create your account",
			})
			c.Abort()
			return
		}

		// Store user in context
		c.Set("user", user)
		c.Set("user_id", user.ID.String())
		c.Set("email", user.Email)
		c.Set("claims", claims)
		c.Set("department", claims.Department)
		c.Set("role", claims.Role)

		c.Next()
	}
}

// GetUser retrieves the authenticated user from context
func GetUser(c *gin.Context) (*models.User, error) {
	userVal, exists := c.Get("user")
	if !exists {
		return nil, fmt.Errorf("user not found in context")
	}

	user, ok := userVal.(*models.User)
	if !ok {
		return nil, fmt.Errorf("invalid user type in context")
	}

	return user, nil
}

// RequireAdmin ensures the user has admin role
func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, claims, done := m.getClaims(c)
		if done {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		if claims.Role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (m *AuthMiddleware) getClaims(c *gin.Context) (error, models.UserClaims, bool) {
	emptyClaims := models.UserClaims{}

	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
		c.Abort()
		return nil, emptyClaims, true
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
		c.Abort()
		return nil, emptyClaims, true
	}

	tokenString := parts[1]

	// Verify the token
	idToken, err := m.verifier.Verify(c.Request.Context(), tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token", "details": err.Error()})
		c.Abort()
		return nil, emptyClaims, true
	}

	// Extract claims
	var claims models.UserClaims

	if err := idToken.Claims(&claims); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to parse claims"})
		c.Abort()
		return nil, emptyClaims, true
	}

	return err, claims, false
}
