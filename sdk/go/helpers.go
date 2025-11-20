package stratium

import (
	"context"
	"fmt"
)

// tokenProvider is an interface for types that can provide authentication tokens
type tokenProvider interface {
	GetToken(ctx context.Context) (string, error)
}

// authHelper encapsulates common authentication patterns used across service clients
type authHelper struct {
	config *Config
	auth   tokenProvider
}

// newAuthHelper creates a new authentication helper
func newAuthHelper(config *Config, auth tokenProvider) *authHelper {
	return &authHelper{
		config: config,
		auth:   auth,
	}
}

// getTokenAndContext retrieves an auth token and returns a context with timeout and auth header.
// This helper reduces code duplication across all service clients.
//
// Usage:
//
//	ctx, cancel, token, err := h.getTokenAndContext(ctx)
//	if err != nil {
//	    return nil, err
//	}
//	defer cancel()
func (h *authHelper) getTokenAndContext(ctx context.Context) (context.Context, context.CancelFunc, string, error) {
	// Get authentication token
	token := ""
	if h.auth != nil {
		var err error
		token, err = h.auth.GetToken(ctx)
		if err != nil {
			return nil, nil, "", fmt.Errorf("%s: %w", ErrMsgFailedToGetAuthToken, err)
		}
	}

	// Add timeout and auth context
	ctx, cancel := h.config.contextWithTimeout(ctx)
	ctx = contextWithAuth(ctx, token)

	return ctx, cancel, token, nil
}

// validateSubjectIdentifier checks if subject attributes contain a valid identifier (sub, user_id, or id)
func validateSubjectIdentifier(subjectAttributes map[string]string) error {
	if _, ok := subjectAttributes[SubjectAttrSub]; !ok {
		if _, ok := subjectAttributes[SubjectAttrUserID]; !ok {
			if _, ok := subjectAttributes[SubjectAttrID]; !ok {
				return NewValidationError("subject_attributes", ErrMsgSubjectIdentifierRequired)
			}
		}
	}
	return nil
}