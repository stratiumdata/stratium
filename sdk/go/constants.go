package stratium

import "time"

// API paths
const (
	// PAP API endpoints
	PAPPoliciesPath     = "/api/v1/policies"
	PAPEntitlementsPath = "/api/v1/entitlements"

	// OIDC paths
	OIDCTokenPath = "/protocol/openid-connect/token"
)

// OAuth grant types
const (
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
)

// HTTP headers and content types
const (
	ContentTypeJSON           = "application/json"
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"
	AuthHeaderPrefix          = "Bearer "
)

// Default values
const (
	DefaultTimeout       = 30 * time.Second
	DefaultRetryAttempts = 3
	DefaultClientID      = "sdk-client"
)

// Subject attribute keys (OIDC standard identifiers)
const (
	SubjectAttrSub    = "sub"
	SubjectAttrUserID = "user_id"
	SubjectAttrID     = "id"
)

// Error messages
const (
	ErrMsgClientIDRequired           = "client_id is required"
	ErrMsgResourceAttributesRequired = "resource_attributes are required"
	ErrMsgActionRequired             = "action is required"
	ErrMsgSubjectAttributesRequired  = "subject_attributes are required"
	ErrMsgSubjectIdentifierRequired  = "subject_attributes must contain 'sub', 'user_id', or 'id'"
	ErrMsgRequestNil                 = "request cannot be nil"
	ErrMsgFailedToGetAuthToken       = "failed to get auth token"
)

// Default OIDC scopes
var DefaultOIDCScopes = []string{"openid", "profile", "email"}