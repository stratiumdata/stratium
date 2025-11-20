package ztdf

// ZTDF file structure constants
const (
	// ZIP entry names
	ManifestFileName = "manifest.json"
	PayloadFileName  = "0.payload"

	// File permissions
	DefaultFileMode = 0644
)

// Default values
const (
	DefaultKeyAccessURL = "localhost:50053"
	DefaultResourceName = "ztdf-resource"
)

// Cryptographic constants
const (
	// AES-256 key size in bytes
	AESKeySize = 32

	// Algorithms
	AlgorithmAES256GCM = "AES-256-GCM"
	AlgorithmHS256     = "HS256"
	AlgorithmJWS       = "jws"
	AlgorithmGMAC      = "GMAC"
)

// ZTDF manifest constants
const (
	// Protocols
	ProtocolKAS = "KAS"
	ProtocolZIP = "zip"

	// Types
	TypeSplit     = "SPLIT"
	TypeWrapped   = "WRAPPED"
	TypeReference = "reference"

	// MIME types
	MIMETypeOctetStream = "application/octet-stream"

	// TDF spec version
	TDFSpecVersion = "4.0.0"

	// Default classification and handling
	DefaultClassification = "UNCLASSIFIED"
	DefaultHandling       = "CONTROLLED"

	// Placeholders
	PlaceholderSignature = "placeholder-signature"
)

// Policy URI templates
const (
	AttributeURITemplate          = "http://example.com/attr/%s/value/%s"
	ClassificationURITemplate     = "http://example.com/attr/classification/value/%s"
	DefaultClassificationURI      = "http://example.com/attr/classification/value/confidential"
	DefaultClassificationDisplay  = "Classification"
)

// Error messages
const (
	ErrMsgInvalidZTDF             = "invalid ZTDF"
	ErrMsgMissingEncryptionInfo   = "missing encryption information"
	ErrMsgNoKeyAccessObjects      = "no key access objects"
	ErrMsgMissingPayload          = "missing payload"
	ErrMsgFailedToWrapDEK         = "failed to wrap DEK"
	ErrMsgFailedToUnwrapDEK       = "failed to unwrap DEK"
	ErrMsgPolicyVerificationFailed = "policy verification failed"
	ErrMsgIntegrityVerificationFailed = "integrity verification failed"
)