package stratium

import "fmt"

// Error types for the Stratium SDK

// ValidationError represents a validation error (e.g., missing required fields)
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error: %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{Field: field, Message: message}
}

// AuthenticationError represents an authentication error
type AuthenticationError struct {
	Message string
	Err     error
}

func (e *AuthenticationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("authentication error: %s: %v", e.Message, e.Err)
	}
	return fmt.Sprintf("authentication error: %s", e.Message)
}

func (e *AuthenticationError) Unwrap() error {
	return e.Err
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(message string, err error) *AuthenticationError {
	return &AuthenticationError{Message: message, Err: err}
}

// APIError represents an API error with HTTP status code
type APIError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *APIError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("API error (status %d): %s: %v", e.StatusCode, e.Message, e.Err)
	}
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

func (e *APIError) Unwrap() error {
	return e.Err
}

// NewAPIError creates a new API error
func NewAPIError(statusCode int, message string, err error) *APIError {
	return &APIError{StatusCode: statusCode, Message: message, Err: err}
}

// EncryptionError represents an encryption/decryption error
type EncryptionError struct {
	Operation string // "encrypt" or "decrypt"
	Message   string
	Err       error
}

func (e *EncryptionError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s error: %s: %v", e.Operation, e.Message, e.Err)
	}
	return fmt.Sprintf("%s error: %s", e.Operation, e.Message)
}

func (e *EncryptionError) Unwrap() error {
	return e.Err
}

// NewEncryptionError creates a new encryption error
func NewEncryptionError(operation, message string, err error) *EncryptionError {
	return &EncryptionError{Operation: operation, Message: message, Err: err}
}

// Common validation errors
var (
	ErrClientIDRequired           = NewValidationError("client_id", "is required")
	ErrResourceRequired           = NewValidationError("resource", "is required")
	ErrResourceAttributesRequired = NewValidationError("resource_attributes", "are required")
	ErrActionRequired             = NewValidationError("action", "is required")
	ErrSubjectAttributesRequired  = NewValidationError("subject_attributes", "are required")
	ErrRequestNil                 = NewValidationError("request", "cannot be nil")
)
