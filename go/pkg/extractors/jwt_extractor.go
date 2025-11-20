package extractors

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"stratium/pkg/auth"
)

// JWTClaimsExtractor extracts claims from JWT tokens for ABAC
type JWTClaimsExtractor struct{}

// NewJWTClaimsExtractor creates a new JWT claims extractor
func NewJWTClaimsExtractor() *JWTClaimsExtractor {
	return &JWTClaimsExtractor{}
}

// ExtractSubjectAttributes extracts all claims from a JWT token as subject attributes
// This returns a map suitable for use in Platform GetDecisionRequest.SubjectAttributes
func (e *JWTClaimsExtractor) ExtractSubjectAttributes(tokenString string) (map[string]interface{}, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("token string is empty")
	}

	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	// Parse the token without verification (we just need claims)
	// In production, you should verify the token signature
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims from token")
	}

	return MapClaimsToAttributes(claims), nil
}

// ExtractSubjectAttributesFromContext extracts JWT claims from a context
// Looks for common context keys where JWT tokens or claims might be stored
func (e *JWTClaimsExtractor) ExtractSubjectAttributesFromContext(ctx context.Context) (map[string]interface{}, error) {
	// Try to get claims from context (common key: "claims")
	if claims, ok := ctx.Value("user_claims").(jwt.MapClaims); ok {
		return MapClaimsToAttributes(claims), nil
	}
	if claims, ok := ctx.Value("user_claims").(*auth.UserClaims); ok {
		return userClaimsToAttributes(claims), nil
	}

	// Try to get token string from context (common key: "token")
	if tokenString, ok := ctx.Value("user_token").(string); ok {
		return e.ExtractSubjectAttributes(tokenString)
	}

	// Try to get claims as map[string]interface{}
	if claimsMap, ok := ctx.Value("user_claims").(map[string]interface{}); ok {
		return convertMapToStringMap(claimsMap), nil
	}

	return nil, fmt.Errorf("no JWT claims found in context")
}

// MapClaimsToAttributes converts JWT MapClaims to a string map for ABAC
func MapClaimsToAttributes(claims jwt.MapClaims) map[string]interface{} {
	attributes := make(map[string]interface{})

	for key, value := range claims {
		// Convert claim value to string
		attributes[key] = value
	}

	return attributes
}

// convertClaimToString converts a claim value to a string representation
func convertClaimToString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", v)
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case bool:
		return fmt.Sprintf("%t", v)
	case []interface{}:
		// Handle arrays (like groups, roles)
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = convertClaimToString(item)
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// convertMapToStringMap converts a generic map to string map
func convertMapToStringMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}

func userClaimsToAttributes(claims *auth.UserClaims) map[string]interface{} {
	attrs := map[string]interface{}{
		"sub":                claims.Sub,
		"email":              claims.Email,
		"preferred_username": claims.PreferredUsername,
		"name":               claims.Name,
		"given_name":         claims.GivenName,
		"family_name":        claims.FamilyName,
		"scope":              claims.Scope,
		"classification":     claims.Classification,
		"client_id":          claims.ClientID,
		"azp":                claims.AuthorizedParty,
	}

	if len(claims.Roles) > 0 {
		attrs["roles"] = claims.Roles
	}

	if len(claims.Groups) > 0 {
		attrs["groups"] = claims.Groups
	}

	return attrs
}

// StandardClaims represents common JWT claims used in ABAC
type StandardClaims struct {
	// Standard JWT claims
	Subject    string `json:"sub"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`

	// Common OIDC claims
	PreferredUsername string `json:"preferred_username"`
	EmailVerified     bool   `json:"email_verified"`

	// Organization claims
	Organization string   `json:"organization"`
	Department   string   `json:"department"`
	Groups       []string `json:"groups"`
	Roles        []string `json:"roles"`

	// Security clearance claims
	Classification string `json:"classification"`
	Clearance      string `json:"clearance"`

	// Additional attributes
	Country  string `json:"country"`
	Timezone string `json:"timezone"`
}

// ExtractStandardClaims extracts standard claims into a structured format
func ExtractStandardClaims(attributes map[string]string) *StandardClaims {
	claims := &StandardClaims{
		Subject:           attributes["sub"],
		Email:             attributes["email"],
		Name:              attributes["name"],
		GivenName:         attributes["given_name"],
		FamilyName:        attributes["family_name"],
		PreferredUsername: attributes["preferred_username"],
		Organization:      attributes["organization"],
		Department:        attributes["department"],
		Classification:    attributes["classification"],
		Clearance:         attributes["clearance"],
		Country:           attributes["country"],
		Timezone:          attributes["timezone"],
	}

	// Parse groups (comma-separated)
	if groups := attributes["groups"]; groups != "" {
		claims.Groups = strings.Split(groups, ",")
	}

	// Parse roles (comma-separated)
	if roles := attributes["roles"]; roles != "" {
		claims.Roles = strings.Split(roles, ",")
	}

	// Parse email_verified
	if emailVerified := attributes["email_verified"]; emailVerified == "true" {
		claims.EmailVerified = true
	}

	return claims
}

// ValidateRequiredClaims validates that required claims are present
func ValidateRequiredClaims(attributes map[string]string, requiredClaims []string) error {
	missing := []string{}

	for _, claim := range requiredClaims {
		if value, ok := attributes[claim]; !ok || value == "" {
			missing = append(missing, claim)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required claims: %v", missing)
	}

	return nil
}
