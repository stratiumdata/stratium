package stratium

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockAuthManager is a mock implementation of authManager for testing
type mockAuthManager struct {
	token      string
	err        error
	callCount  int
	shouldFail bool
}

func (m *mockAuthManager) GetToken(ctx context.Context) (string, error) {
	if m == nil {
		return "", nil
	}
	m.callCount++
	if m.shouldFail {
		return "", m.err
	}
	return m.token, nil
}

// TestNewAuthHelper tests the newAuthHelper function
func TestNewAuthHelper(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,
	}
	auth := &mockAuthManager{token: "test-token"}

	helper := newAuthHelper(config, auth)

	if helper == nil {
		t.Fatal("newAuthHelper() returned nil")
	}

	if helper.config != config {
		t.Error("newAuthHelper() did not set config correctly")
	}

	if helper.auth != auth {
		t.Error("newAuthHelper() did not set auth correctly")
	}
}

// TestAuthHelperGetTokenAndContext tests the authHelper.getTokenAndContext method
func TestAuthHelperGetTokenAndContext(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		auth          *mockAuthManager
		wantToken     string
		wantErr       bool
		checkDeadline bool
		checkAuth     bool
	}{
		{
			name: "successful token retrieval with auth",
			config: &Config{
				Timeout: 5 * time.Second,
			},
			auth: &mockAuthManager{
				token: "valid-token-123",
			},
			wantToken:     "valid-token-123",
			wantErr:       false,
			checkDeadline: true,
			checkAuth:     true,
		},
		{
			name: "no auth manager (nil auth)",
			config: &Config{
				Timeout: 5 * time.Second,
			},
			auth:          nil,
			wantToken:     "",
			wantErr:       false,
			checkDeadline: true,
			checkAuth:     false,
		},
		{
			name: "auth manager returns error",
			config: &Config{
				Timeout: 5 * time.Second,
			},
			auth: &mockAuthManager{
				shouldFail: true,
				err:        errors.New("OIDC authentication failed"),
			},
			wantToken:     "",
			wantErr:       true,
			checkDeadline: false,
			checkAuth:     false,
		},
		{
			name: "no timeout configured",
			config: &Config{
				Timeout: 0,
			},
			auth: &mockAuthManager{
				token: "test-token",
			},
			wantToken:     "test-token",
			wantErr:       false,
			checkDeadline: false,
			checkAuth:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper := newAuthHelper(tt.config, tt.auth)
			ctx := context.Background()

			newCtx, cancel, token, err := helper.getTokenAndContext(ctx)

			if tt.wantErr {
				if err == nil {
					t.Error("getTokenAndContext() expected error, got nil")
				}
				if cancel != nil {
					cancel() // Clean up even on error
				}
				return
			}

			if err != nil {
				t.Errorf("getTokenAndContext() unexpected error: %v", err)
				return
			}

			defer cancel()

			if token != tt.wantToken {
				t.Errorf("getTokenAndContext() token = %v, want %v", token, tt.wantToken)
			}

			if tt.checkDeadline {
				_, hasDeadline := newCtx.Deadline()
				if !hasDeadline {
					t.Error("getTokenAndContext() should create context with deadline")
				}
			}

			// Note: We can't easily check the auth context metadata here without accessing internals
			// This would require using the metadata package to inspect the context
		})
	}
}

// TestAuthHelperMultipleCalls tests that auth manager is called correctly
func TestAuthHelperMultipleCalls(t *testing.T) {
	mockAuth := &mockAuthManager{
		token: "test-token",
	}

	config := &Config{
		Timeout: 5 * time.Second,
	}

	helper := newAuthHelper(config, mockAuth)

	// Call getTokenAndContext multiple times
	for i := 0; i < 3; i++ {
		ctx := context.Background()
		_, cancel, token, err := helper.getTokenAndContext(ctx)
		if err != nil {
			t.Fatalf("Call %d: unexpected error: %v", i+1, err)
		}
		if token != "test-token" {
			t.Errorf("Call %d: token = %v, want 'test-token'", i+1, token)
		}
		cancel()
	}

	if mockAuth.callCount != 3 {
		t.Errorf("auth.GetToken() called %d times, want 3", mockAuth.callCount)
	}
}

// TestValidateSubjectIdentifier tests the validateSubjectIdentifier function
func TestValidateSubjectIdentifier(t *testing.T) {
	tests := []struct {
		name               string
		subjectAttributes  map[string]string
		wantErr            bool
		expectedErrMessage string
	}{
		{
			name: "valid with sub",
			subjectAttributes: map[string]string{
				"sub":  "user-123",
				"name": "John Doe",
			},
			wantErr: false,
		},
		{
			name: "valid with user_id",
			subjectAttributes: map[string]string{
				"user_id": "user-456",
				"email":   "john@example.com",
			},
			wantErr: false,
		},
		{
			name: "valid with id",
			subjectAttributes: map[string]string{
				"id":   "user-789",
				"role": "admin",
			},
			wantErr: false,
		},
		{
			name: "valid with all identifiers",
			subjectAttributes: map[string]string{
				"sub":     "user-123",
				"user_id": "user-456",
				"id":      "user-789",
			},
			wantErr: false,
		},
		{
			name: "invalid - no identifier",
			subjectAttributes: map[string]string{
				"name":  "John Doe",
				"email": "john@example.com",
			},
			wantErr:            true,
			expectedErrMessage: "subject_attributes must contain 'sub', 'user_id', or 'id'",
		},
		{
			name:               "invalid - empty map",
			subjectAttributes:  map[string]string{},
			wantErr:            true,
			expectedErrMessage: "subject_attributes must contain 'sub', 'user_id', or 'id'",
		},
		{
			name:               "invalid - nil map",
			subjectAttributes:  nil,
			wantErr:            true,
			expectedErrMessage: "subject_attributes must contain 'sub', 'user_id', or 'id'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSubjectIdentifier(tt.subjectAttributes)

			if tt.wantErr {
				if err == nil {
					t.Error("validateSubjectIdentifier() expected error, got nil")
					return
				}

				// Check error type
				var validationErr *ValidationError
				if !errors.As(err, &validationErr) {
					t.Errorf("validateSubjectIdentifier() error type = %T, want *ValidationError", err)
				}

				// Check error message
				if validationErr.Message != tt.expectedErrMessage {
					t.Errorf("validateSubjectIdentifier() error message = %v, want %v", validationErr.Message, tt.expectedErrMessage)
				}
			} else {
				if err != nil {
					t.Errorf("validateSubjectIdentifier() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateSubjectIdentifierPriority tests the priority order of identifiers
func TestValidateSubjectIdentifierPriority(t *testing.T) {
	// The function should accept any of the three identifiers
	// Test that having just one is sufficient

	identifiers := []string{SubjectAttrSub, SubjectAttrUserID, SubjectAttrID}

	for _, identifier := range identifiers {
		t.Run("valid_with_"+identifier, func(t *testing.T) {
			attrs := map[string]string{
				identifier: "test-value",
				"other":    "data",
			}

			err := validateSubjectIdentifier(attrs)
			if err != nil {
				t.Errorf("validateSubjectIdentifier() with %s should be valid, got error: %v", identifier, err)
			}
		})
	}
}

// TestAuthHelperContextCancellation tests that context cancellation works correctly
func TestAuthHelperContextCancellation(t *testing.T) {
	config := &Config{
		Timeout: 100 * time.Millisecond,
	}
	auth := &mockAuthManager{
		token: "test-token",
	}

	helper := newAuthHelper(config, auth)
	ctx := context.Background()

	newCtx, cancel, _, err := helper.getTokenAndContext(ctx)
	if err != nil {
		t.Fatalf("getTokenAndContext() unexpected error: %v", err)
	}

	// Cancel immediately
	cancel()

	// Check that context is cancelled
	select {
	case <-newCtx.Done():
		// Expected - context is cancelled
	case <-time.After(10 * time.Millisecond):
		t.Error("Context should be cancelled after calling cancel()")
	}
}

// TestAuthHelperWithCancelledParentContext tests behavior with already-cancelled parent context
func TestAuthHelperWithCancelledParentContext(t *testing.T) {
	config := &Config{
		Timeout: 5 * time.Second,
	}
	auth := &mockAuthManager{
		token: "test-token",
	}

	helper := newAuthHelper(config, auth)

	// Create a cancelled context
	ctx, cancelParent := context.WithCancel(context.Background())
	cancelParent() // Cancel immediately

	newCtx, cancel, _, err := helper.getTokenAndContext(ctx)
	if err != nil {
		t.Fatalf("getTokenAndContext() unexpected error: %v", err)
	}
	defer cancel()

	// The new context should inherit the cancellation
	select {
	case <-newCtx.Done():
		// Expected - context inherits cancellation
	case <-time.After(10 * time.Millisecond):
		t.Error("Context should be cancelled when parent is cancelled")
	}
}