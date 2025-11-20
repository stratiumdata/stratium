package ztdf

import (
	"github.com/stratiumdata/go-sdk/gen/models"
)

// WrapOptions contains options for wrapping data into a ZTDF
type WrapOptions struct {
	// Resource identifier
	Resource string

	// Resource attributes for ABAC policy evaluation
	ResourceAttributes map[string]string

	// Data attributes for policy (optional, defaults will be provided)
	Attributes []Attribute

	// Custom policy (optional, will be generated if not provided)
	Policy *models.ZtdfPolicy

	// Whether to include integrity checking (default: true)
	IntegrityCheck bool

	// Additional context for key access
	Context map[string]string

	// Manifest template for ZTDF
	Manifest *models.Manifest

	// Client key information for DEK wrapping
	ClientKeyID          string
	ClientPrivateKeyPath string
}

// UnwrapOptions contains options for unwrapping a ZTDF
type UnwrapOptions struct {
	// Resource identifier
	Resource string

	// Key ID for the Client
	ClientKeyID string

	// Client private key path
	ClientPrivateKeyPath string

	// Whether to verify payload integrity (default: true)
	VerifyIntegrity bool

	// Whether to verify policy binding (default: true)
	VerifyPolicy bool
}

// Attribute represents a data attribute for ZTDF policy
type Attribute struct {
	// URI of the attribute (e.g., "http://example.com/attr/classification/value/secret")
	URI string

	// Human-readable display name
	DisplayName string

	// Whether this is a default attribute
	IsDefault bool
}

// TrustedDataObject represents a ZTDF object
type TrustedDataObject struct {
	Manifest *models.Manifest
	Payload  *Payload
}

// Payload represents encrypted payload data
type Payload struct {
	Data []byte
}

// PolicyInfo contains parsed policy information
type PolicyInfo struct {
	UUID             string
	DataAttributes   []PolicyAttribute
	TDFSpecVersion   string
	EncryptionMethod string
	IntegrityMethod  string
	KeyAccessURL     string
}

// PolicyAttribute represents a policy attribute
type PolicyAttribute struct {
	Attribute   string
	DisplayName string
	IsDefault   bool
	KasURL      string
}

// FileInfo contains metadata about a ZTDF file
type FileInfo struct {
	PlaintextSize   int64
	EncryptedSize   int64
	EncryptionAlg   string
	KeyAccessURL    string
	Resource        string
	Attributes      []PolicyAttribute
	IntegrityMethod string
}
