package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/stratium/samples/micro-research-api/internal/models"
	"github.com/stratium/samples/micro-research-api/internal/platform"
	"golang.org/x/oauth2"
)

// ABAMiddleware handles attribute-based access control
type ABACMiddleware struct {
	verifier       *oidc.IDTokenVerifier
	config         *oauth2.Config
	platformClient *platform.Client
}

// NewABACMiddleware creates a new ABAC middleware
func NewABACMiddleware(issuerURL, clientID, clientSecret string, platformClient *platform.Client) (*ABACMiddleware, error) {
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

	return &ABACMiddleware{
		verifier:       verifier,
		config:         config,
		platformClient: platformClient,
	}, nil
}

// CheckDatasetAccess checks if the user can access a dataset
func (m *ABACMiddleware) CheckDatasetAccess(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, claims, done := m.getClaims(c)
		if done {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		user, err := GetUser(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		// Get dataset from context (should be set by handler)
		datasetVal, exists := c.Get("dataset")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "dataset not found in context"})
			c.Abort()
			return
		}

		// Extract dataset information
		var resourceID, ownerID, department string

		// Handle different dataset types
		switch dataset := datasetVal.(type) {
		case map[string]string:
			resourceID = dataset["id"]
			ownerID = dataset["owner_id"]
			department = dataset["department"]
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid dataset type in context"})
			c.Abort()
			return
		}

		// Create decision request
		req := platform.DecisionRequest{
			SubjectID:    user.ID.String(),
			SubjectEmail: user.Email,
			Department:   claims.Department,
			Role:         claims.Role,
			ResourceType: "dataset",
			ResourceID:   resourceID,
			OwnerID:      ownerID,
			ResourceDept: department,
			Action:       action,
		}

		// Check access
		allowed, reason, err := m.platformClient.CheckAccessSimple(c.Request.Context(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "failed to check access",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":  "access denied",
				"reason": reason,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CheckUserAccess checks if the user can access another user's information
func (m *ABACMiddleware) CheckUserAccess(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, claims, done := m.getClaims(c)
		if done {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		currentUser, err := GetUser(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		// Get target user from context
		targetUserVal, exists := c.Get("target_user")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "target user not found in context"})
			c.Abort()
			return
		}

		targetUser := targetUserVal.(map[string]string)

		// Admins can access all users
		if claims.Role != "admin" {
			c.Next()
			return
		}

		// Users can access their own information
		if currentUser.ID.String() == targetUser["id"] {
			c.Next()
			return
		}

		// For other cases, check with Platform service
		req := platform.DecisionRequest{
			SubjectID:    currentUser.ID.String(),
			SubjectEmail: currentUser.Email,
			Department:   claims.Department,
			Role:         claims.Role,
			ResourceType: "user",
			ResourceID:   targetUser["id"],
			ResourceDept: targetUser["department"],
			Action:       action,
		}

		allowed, reason, err := m.platformClient.CheckAccessSimple(c.Request.Context(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "failed to check access",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":  "access denied",
				"reason": reason,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (m *ABACMiddleware) getClaims(c *gin.Context) (error, models.UserClaims, bool) {
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
