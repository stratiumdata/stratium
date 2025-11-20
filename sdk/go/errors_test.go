package stratium

import (
	"errors"
	"strings"
	"testing"
)

// TestValidationError tests the ValidationError type
func TestValidationError(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		message  string
		expected string
	}{
		{
			name:     "error with field",
			field:    "client_id",
			message:  "is required",
			expected: "validation error: client_id: is required",
		},
		{
			name:     "error without field",
			field:    "",
			message:  "invalid request",
			expected: "validation error: invalid request",
		},
		{
			name:     "error with empty message",
			field:    "username",
			message:  "",
			expected: "validation error: username: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewValidationError(tt.field, tt.message)
			if err.Error() != tt.expected {
				t.Errorf("ValidationError.Error() = %v, want %v", err.Error(), tt.expected)
			}
			if err.Field != tt.field {
				t.Errorf("ValidationError.Field = %v, want %v", err.Field, tt.field)
			}
			if err.Message != tt.message {
				t.Errorf("ValidationError.Message = %v, want %v", err.Message, tt.message)
			}
		})
	}
}

// TestAuthenticationError tests the AuthenticationError type
func TestAuthenticationError(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		err             error
		expectedContain string
		shouldUnwrap    bool
	}{
		{
			name:            "error with wrapped error",
			message:         "failed to get token",
			err:             errors.New("OIDC error"),
			expectedContain: "authentication error: failed to get token: OIDC error",
			shouldUnwrap:    true,
		},
		{
			name:            "error without wrapped error",
			message:         "invalid credentials",
			err:             nil,
			expectedContain: "authentication error: invalid credentials",
			shouldUnwrap:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAuthenticationError(tt.message, tt.err)

			if !strings.Contains(err.Error(), tt.expectedContain) {
				t.Errorf("AuthenticationError.Error() = %v, want to contain %v", err.Error(), tt.expectedContain)
			}

			if err.Message != tt.message {
				t.Errorf("AuthenticationError.Message = %v, want %v", err.Message, tt.message)
			}

			unwrapped := err.Unwrap()
			if tt.shouldUnwrap && unwrapped != tt.err {
				t.Errorf("AuthenticationError.Unwrap() = %v, want %v", unwrapped, tt.err)
			}
			if !tt.shouldUnwrap && unwrapped != nil {
				t.Errorf("AuthenticationError.Unwrap() = %v, want nil", unwrapped)
			}
		})
	}
}

// TestAPIError tests the APIError type
func TestAPIError(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		message         string
		err             error
		expectedContain string
		shouldUnwrap    bool
	}{
		{
			name:            "error with wrapped error",
			statusCode:      500,
			message:         "internal server error",
			err:             errors.New("database connection failed"),
			expectedContain: "API error (status 500): internal server error: database connection failed",
			shouldUnwrap:    true,
		},
		{
			name:            "error without wrapped error",
			statusCode:      404,
			message:         "resource not found",
			err:             nil,
			expectedContain: "API error (status 404): resource not found",
			shouldUnwrap:    false,
		},
		{
			name:            "400 bad request",
			statusCode:      400,
			message:         "invalid input",
			err:             nil,
			expectedContain: "API error (status 400): invalid input",
			shouldUnwrap:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAPIError(tt.statusCode, tt.message, tt.err)

			if !strings.Contains(err.Error(), tt.expectedContain) {
				t.Errorf("APIError.Error() = %v, want to contain %v", err.Error(), tt.expectedContain)
			}

			if err.StatusCode != tt.statusCode {
				t.Errorf("APIError.StatusCode = %v, want %v", err.StatusCode, tt.statusCode)
			}

			if err.Message != tt.message {
				t.Errorf("APIError.Message = %v, want %v", err.Message, tt.message)
			}

			unwrapped := err.Unwrap()
			if tt.shouldUnwrap && unwrapped != tt.err {
				t.Errorf("APIError.Unwrap() = %v, want %v", unwrapped, tt.err)
			}
			if !tt.shouldUnwrap && unwrapped != nil {
				t.Errorf("APIError.Unwrap() = %v, want nil", unwrapped)
			}
		})
	}
}

// TestEncryptionError tests the EncryptionError type
func TestEncryptionError(t *testing.T) {
	tests := []struct {
		name            string
		operation       string
		message         string
		err             error
		expectedContain string
		shouldUnwrap    bool
	}{
		{
			name:            "encrypt error with wrapped error",
			operation:       "encrypt",
			message:         "failed to encrypt payload",
			err:             errors.New("invalid key size"),
			expectedContain: "encrypt error: failed to encrypt payload: invalid key size",
			shouldUnwrap:    true,
		},
		{
			name:            "decrypt error with wrapped error",
			operation:       "decrypt",
			message:         "failed to decrypt payload",
			err:             errors.New("corrupted data"),
			expectedContain: "decrypt error: failed to decrypt payload: corrupted data",
			shouldUnwrap:    true,
		},
		{
			name:            "error without wrapped error",
			operation:       "encrypt",
			message:         "key generation failed",
			err:             nil,
			expectedContain: "encrypt error: key generation failed",
			shouldUnwrap:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewEncryptionError(tt.operation, tt.message, tt.err)

			if !strings.Contains(err.Error(), tt.expectedContain) {
				t.Errorf("EncryptionError.Error() = %v, want to contain %v", err.Error(), tt.expectedContain)
			}

			if err.Operation != tt.operation {
				t.Errorf("EncryptionError.Operation = %v, want %v", err.Operation, tt.operation)
			}

			if err.Message != tt.message {
				t.Errorf("EncryptionError.Message = %v, want %v", err.Message, tt.message)
			}

			unwrapped := err.Unwrap()
			if tt.shouldUnwrap && unwrapped != tt.err {
				t.Errorf("EncryptionError.Unwrap() = %v, want %v", unwrapped, tt.err)
			}
			if !tt.shouldUnwrap && unwrapped != nil {
				t.Errorf("EncryptionError.Unwrap() = %v, want nil", unwrapped)
			}
		})
	}
}

// TestCommonValidationErrors tests the predefined validation errors
func TestCommonValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		field    string
		contains string
	}{
		{
			name:     "ErrClientIDRequired",
			err:      ErrClientIDRequired,
			field:    "client_id",
			contains: "is required",
		},
		{
			name:     "ErrResourceRequired",
			err:      ErrResourceRequired,
			field:    "resource",
			contains: "is required",
		},
		{
			name:     "ErrResourceAttributesRequired",
			err:      ErrResourceAttributesRequired,
			field:    "resource_attributes",
			contains: "are required",
		},
		{
			name:     "ErrActionRequired",
			err:      ErrActionRequired,
			field:    "action",
			contains: "is required",
		},
		{
			name:     "ErrSubjectAttributesRequired",
			err:      ErrSubjectAttributesRequired,
			field:    "subject_attributes",
			contains: "are required",
		},
		{
			name:     "ErrRequestNil",
			err:      ErrRequestNil,
			field:    "request",
			contains: "cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatalf("%s is nil", tt.name)
			}

			errStr := tt.err.Error()
			if !strings.Contains(errStr, tt.field) {
				t.Errorf("%s error message should contain field '%s', got: %s", tt.name, tt.field, errStr)
			}

			if !strings.Contains(errStr, tt.contains) {
				t.Errorf("%s error message should contain '%s', got: %s", tt.name, tt.contains, errStr)
			}

			// Check that it's a ValidationError
			if _, ok := tt.err.(*ValidationError); !ok {
				t.Errorf("%s should be *ValidationError, got %T", tt.name, tt.err)
			}
		})
	}
}

// TestErrorWrapping tests that errors can be properly wrapped with errors.Is and errors.As
func TestErrorWrapping(t *testing.T) {
	baseErr := errors.New("base error")

	authErr := NewAuthenticationError("auth failed", baseErr)
	if !errors.Is(authErr, baseErr) {
		t.Error("AuthenticationError should wrap base error with errors.Is")
	}

	apiErr := NewAPIError(500, "api failed", baseErr)
	if !errors.Is(apiErr, baseErr) {
		t.Error("APIError should wrap base error with errors.Is")
	}

	encErr := NewEncryptionError("encrypt", "encryption failed", baseErr)
	if !errors.Is(encErr, baseErr) {
		t.Error("EncryptionError should wrap base error with errors.Is")
	}
}

// TestErrorTypes tests type assertions and conversions
func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantType string
	}{
		{
			name:     "ValidationError type",
			err:      NewValidationError("field", "message"),
			wantType: "*stratium.ValidationError",
		},
		{
			name:     "AuthenticationError type",
			err:      NewAuthenticationError("message", nil),
			wantType: "*stratium.AuthenticationError",
		},
		{
			name:     "APIError type",
			err:      NewAPIError(404, "not found", nil),
			wantType: "*stratium.APIError",
		},
		{
			name:     "EncryptionError type",
			err:      NewEncryptionError("encrypt", "failed", nil),
			wantType: "*stratium.EncryptionError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.wantType {
			case "*stratium.ValidationError":
				var validationErr *ValidationError
				if !errors.As(tt.err, &validationErr) {
					t.Errorf("Error should be convertible to %s", tt.wantType)
				}
			case "*stratium.AuthenticationError":
				var authErr *AuthenticationError
				if !errors.As(tt.err, &authErr) {
					t.Errorf("Error should be convertible to %s", tt.wantType)
				}
			case "*stratium.APIError":
				var apiErr *APIError
				if !errors.As(tt.err, &apiErr) {
					t.Errorf("Error should be convertible to %s", tt.wantType)
				}
			case "*stratium.EncryptionError":
				var encErr *EncryptionError
				if !errors.As(tt.err, &encErr) {
					t.Errorf("Error should be convertible to %s", tt.wantType)
				}
			}
		})
	}
}