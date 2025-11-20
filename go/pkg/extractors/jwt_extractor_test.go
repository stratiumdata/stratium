package extractors

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSubjectAttributes(t *testing.T) {
	extractor := NewJWTClaimsExtractor()

	// Create a sample JWT token
	claims := jwt.MapClaims{
		"sub":            "user123",
		"email":          "user@example.com",
		"name":           "John Doe",
		"department":     "engineering",
		"classification": "secret",
		"roles":          []interface{}{"developer", "admin"},
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	// Extract attributes
	attributes, err := extractor.ExtractSubjectAttributes(tokenString)
	require.NoError(t, err)

	// Verify attributes - they are returned as interface{} values
	assert.Equal(t, "user123", attributes["sub"])
	assert.Equal(t, "user@example.com", attributes["email"])
	assert.Equal(t, "John Doe", attributes["name"])
	assert.Equal(t, "engineering", attributes["department"])
	assert.Equal(t, "secret", attributes["classification"])
	assert.Equal(t, []interface{}{"developer", "admin"}, attributes["roles"])
}

func TestExtractSubjectAttributesWithBearerPrefix(t *testing.T) {
	extractor := NewJWTClaimsExtractor()

	claims := jwt.MapClaims{
		"sub":   "user123",
		"email": "user@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	// Add Bearer prefix
	bearerToken := "Bearer " + tokenString

	attributes, err := extractor.ExtractSubjectAttributes(bearerToken)
	require.NoError(t, err)
	assert.Equal(t, "user123", attributes["sub"])
}

func TestExtractSubjectAttributesFromContext(t *testing.T) {
	extractor := NewJWTClaimsExtractor()

	tests := []struct {
		name        string
		setupCtx    func() context.Context
		expectError bool
		expectedSub string
	}{
		{
			name: "Claims in context",
			setupCtx: func() context.Context {
				claims := jwt.MapClaims{
					"sub":   "user123",
					"email": "user@example.com",
				}
				return context.WithValue(context.Background(), "user_claims", claims)
			},
			expectError: false,
			expectedSub: "user123",
		},
		{
			name: "Token string in context",
			setupCtx: func() context.Context {
				claims := jwt.MapClaims{"sub": "user456"}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte("test-secret"))
				return context.WithValue(context.Background(), "user_token", tokenString)
			},
			expectError: false,
			expectedSub: "user456",
		},
		{
			name: "No claims in context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			attributes, err := extractor.ExtractSubjectAttributesFromContext(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSub, attributes["sub"])
			}
		})
	}
}

func TestMapClaimsToAttributes(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":            "user123",
		"email":          "user@example.com",
		"age":            float64(30),
		"verified":       true,
		"groups":         []interface{}{"admin", "developer"},
		"classification": "top-secret",
	}

	attributes := MapClaimsToAttributes(claims)

	// MapClaimsToAttributes returns map[string]interface{}, not map[string]string
	assert.Equal(t, "user123", attributes["sub"])
	assert.Equal(t, "user@example.com", attributes["email"])
	assert.Equal(t, float64(30), attributes["age"])
	assert.Equal(t, true, attributes["verified"])
	assert.Equal(t, []interface{}{"admin", "developer"}, attributes["groups"])
	assert.Equal(t, "top-secret", attributes["classification"])
}

func TestExtractStandardClaims(t *testing.T) {
	attributes := map[string]string{
		"sub":                "user123",
		"email":              "user@example.com",
		"name":               "John Doe",
		"given_name":         "John",
		"family_name":        "Doe",
		"preferred_username": "johndoe",
		"email_verified":     "true",
		"organization":       "Acme Corp",
		"department":         "engineering",
		"groups":             "admin,developer,team-lead",
		"roles":              "engineer,manager",
		"classification":     "secret",
		"clearance":          "top-secret",
		"country":            "US",
		"timezone":           "America/New_York",
	}

	standardClaims := ExtractStandardClaims(attributes)

	assert.Equal(t, "user123", standardClaims.Subject)
	assert.Equal(t, "user@example.com", standardClaims.Email)
	assert.Equal(t, "John Doe", standardClaims.Name)
	assert.Equal(t, "John", standardClaims.GivenName)
	assert.Equal(t, "Doe", standardClaims.FamilyName)
	assert.Equal(t, "johndoe", standardClaims.PreferredUsername)
	assert.True(t, standardClaims.EmailVerified)
	assert.Equal(t, "Acme Corp", standardClaims.Organization)
	assert.Equal(t, "engineering", standardClaims.Department)
	assert.Equal(t, []string{"admin", "developer", "team-lead"}, standardClaims.Groups)
	assert.Equal(t, []string{"engineer", "manager"}, standardClaims.Roles)
	assert.Equal(t, "secret", standardClaims.Classification)
	assert.Equal(t, "top-secret", standardClaims.Clearance)
	assert.Equal(t, "US", standardClaims.Country)
	assert.Equal(t, "America/New_York", standardClaims.Timezone)
}

func TestValidateRequiredClaims(t *testing.T) {
	tests := []struct {
		name          string
		attributes    map[string]string
		required      []string
		expectError   bool
		errorContains string
	}{
		{
			name: "All required claims present",
			attributes: map[string]string{
				"sub":   "user123",
				"email": "user@example.com",
			},
			required:    []string{"sub", "email"},
			expectError: false,
		},
		{
			name: "Missing required claim",
			attributes: map[string]string{
				"sub": "user123",
			},
			required:      []string{"sub", "email"},
			expectError:   true,
			errorContains: "email",
		},
		{
			name: "Empty claim value",
			attributes: map[string]string{
				"sub":   "user123",
				"email": "",
			},
			required:      []string{"sub", "email"},
			expectError:   true,
			errorContains: "email",
		},
		{
			name: "No required claims",
			attributes: map[string]string{
				"sub": "user123",
			},
			required:    []string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequiredClaims(tt.attributes, tt.required)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConvertClaimToString(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
	}{
		{"string", "test", "test"},
		{"int", 123, "123"},
		{"int64", int64(456), "456"},
		{"float64", float64(3.14), "3.14"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"array", []interface{}{"a", "b", "c"}, "a,b,c"},
		{"nested array", []interface{}{1, 2, 3}, "1,2,3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertClaimToString(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// BenchmarkExtractSubjectAttributes benchmarks JWT claim extraction
func BenchmarkExtractSubjectAttributes(b *testing.B) {
	extractor := NewJWTClaimsExtractor()

	claims := jwt.MapClaims{
		"sub":            "user123",
		"email":          "user@example.com",
		"name":           "John Doe",
		"department":     "engineering",
		"classification": "secret",
		"roles":          []interface{}{"developer", "admin"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extractor.ExtractSubjectAttributes(tokenString)
	}
}
