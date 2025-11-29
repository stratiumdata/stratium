package ztdf

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"stratium/pkg/auth"
	"stratium/pkg/models"
	keyAccess "stratium/services/key-access"
	keyManager "stratium/services/key-manager"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

// Client is the main ZTDF SDK client
type Client struct {
	keyAccessAddr string
	kasClient     keyAccess.KeyAccessServiceClient
	kmClient      keyManager.KeyManagerServiceClient
	kasConn       *grpc.ClientConn
	kmConn        *grpc.ClientConn
	keyManager    models.KeyManager
	authProvider  auth.AuthProvider
	authConfig    *auth.AuthConfig
}

// WrapStreamResult contains metadata from a streaming wrap operation.
type WrapStreamResult struct {
	Manifest       *models.Manifest
	PlaintextSize  int64
	CiphertextSize int64
}

type ZtdfClientConfig struct {
	KeyAccessAddr  string
	KeyManagerAddr string
	KeyStorePath   string
	AuthConfig     *auth.AuthConfig
	UseTLS         bool
}

// NewClient creates a new ZTDF SDK client
func NewClient(config *ZtdfClientConfig) (*Client, error) {
	if config == nil {
		return nil, &models.Error{
			Code:    "INVALID_CONFIG",
			Message: "config is required",
		}
	}

	if config.KeyAccessAddr == "" {
		return nil, &models.Error{
			Code:    "INVALID_CONFIG",
			Message: "key access address is required",
		}
	}

	if config.KeyManagerAddr == "" {
		return nil, &models.Error{
			Code:    "INVALID_CONFIG",
			Message: "key manager address is required",
		}
	}

	// Connect to Key Access Service
	kasConn, err := grpc.NewClient(config.KeyAccessAddr, dialCredentials(config.KeyAccessAddr, config.UseTLS))
	if err != nil {
		return nil, &models.Error{
			Code:    "CONNECTION_FAILED",
			Message: "failed to connect to Key Access Service",
			Err:     err,
		}
	}

	// Connect to Key Manager Service
	kmConn, err := grpc.NewClient(config.KeyManagerAddr, dialCredentials(config.KeyManagerAddr, config.UseTLS))
	if err != nil {
		kasConn.Close()
		return nil, &models.Error{
			Code:    "CONNECTION_FAILED",
			Message: "failed to connect to Key Manager Service",
			Err:     err,
		}
	}

	kasClient := keyAccess.NewKeyAccessServiceClient(kasConn)
	kmClient := keyManager.NewKeyManagerServiceClient(kmConn)

	// Create key manager
	localKeyManager, err := NewLocalKeyManager(config.KeyStorePath)
	if err != nil {
		kasConn.Close()
		kmConn.Close()
		return nil, &models.Error{
			Code:    "KEY_MANAGER_INIT_FAILED",
			Message: "failed to create key manager",
			Err:     err,
		}
	}

	// Create auth provider
	authProvider, err := auth.NewKeycloakAuthProvider(config.AuthConfig)
	if err != nil {
		kasConn.Close()
		kmConn.Close()
		return nil, &models.Error{
			Code:    "AUTH_PROVIDER_INIT_FAILED",
			Message: "failed to create auth provider",
			Err:     err,
		}
	}

	return &Client{
		keyAccessAddr: config.KeyAccessAddr,
		kasClient:     kasClient,
		kmClient:      kmClient,
		kasConn:       kasConn,
		kmConn:        kmConn,
		keyManager:    localKeyManager,
		authProvider:  authProvider,
		authConfig:    config.AuthConfig,
	}, nil
}

func dialCredentials(addr string, useTLS bool) grpc.DialOption {
	if useTLS {
		tlsConfig := &tls.Config{}
		if host, _, err := net.SplitHostPort(addr); err == nil {
			tlsConfig.ServerName = host
		} else if addr != "" {
			tlsConfig.ServerName = addr
		}
		return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	}
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// Initialize sets up client keys (first-time setup)
func (c *Client) Initialize(ctx context.Context) error {
	// Load or generate client keys
	if err := c.keyManager.LoadOrGenerate(); err != nil {
		return &models.Error{
			Code:    "INITIALIZATION_FAILED",
			Message: "failed to load or generate client keys",
			Err:     err,
		}
	}

	// Authenticate
	authToken, err := c.authProvider.Authenticate(ctx)
	if err != nil {
		return &models.Error{
			Code:    "INITIALIZATION_FAILED",
			Message: "failed to authenticate",
			Err:     err,
		}
	}

	// Register public key with KAS
	if err := c.keyManager.RegisterPublicKey(ctx, c.kmClient, authToken); err != nil {
		// Check if already registered (not a fatal error)
		log.Printf("Public key registration: %v", err)
		return &models.Error{
			Code:    "REGISTRATION_FAILED",
			Message: "failed to register public key",
			Err:     err,
		}
	}

	log.Printf("Client initialized successfully (key_id: %s)", c.keyManager.GetKeyID())
	return nil
}

// Wrap encrypts plaintext and creates a ZTDF
func (c *Client) Wrap(ctx context.Context, plaintext []byte, opts *models.WrapOptions) (*models.TrustedDataObject, error) {
	return c.wrapStream(ctx, bytes.NewReader(plaintext), opts)
}

func (c *Client) wrapStream(ctx context.Context, reader io.Reader, opts *models.WrapOptions) (*models.TrustedDataObject, error) {
	if opts == nil {
		opts = &models.WrapOptions{}
	}

	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	dek, err := GenerateDEK()
	if err != nil {
		return nil, err
	}

	encryptionResult, err := encryptPayloadBuffered(reader, dek)
	if err != nil {
		return nil, err
	}

	policy := c.createPolicy(opts)
	policyJSON, err := protojson.Marshal(policy)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidPolicy,
			Message: "failed to marshal policy",
			Err:     err,
		}
	}
	policyBase64 := base64.StdEncoding.EncodeToString(policyJSON)
	policyBindingHash := CalculatePolicyBinding(dek, policyBase64)

	wrappedDEK, keyID, err := c.wrapDEK(ctx, dek, opts.Resource, policyBase64)
	if err != nil {
		return nil, err
	}

	manifest := c.createManifest(wrappedDEK, keyID, policyBase64, policyBindingHash, encryptionResult)

	tdo := &models.TrustedDataObject{
		Manifest: manifest,
		Payload: &models.Payload{
			Data: encryptionResult.Ciphertext,
		},
	}

	return tdo, nil
}

// WrapToWriter encrypts data from reader and writes the encrypted payload directly to payloadWriter.
// It returns the manifest and size metadata needed to finalize the ZTDF container.
func (c *Client) WrapToWriter(ctx context.Context, reader io.Reader, opts *models.WrapOptions, payloadWriter io.Writer) (*WrapStreamResult, error) {
	if opts == nil {
		opts = &models.WrapOptions{}
	}

	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	dek, err := GenerateDEK()
	if err != nil {
		return nil, err
	}

	encryptionResult, err := encryptPayloadToWriter(reader, dek, payloadWriter)
	if err != nil {
		return nil, err
	}

	policy := c.createPolicy(opts)
	policyJSON, err := protojson.Marshal(policy)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidPolicy,
			Message: "failed to marshal policy",
			Err:     err,
		}
	}
	policyBase64 := base64.StdEncoding.EncodeToString(policyJSON)
	policyBindingHash := CalculatePolicyBinding(dek, policyBase64)

	wrappedDEK, keyID, err := c.wrapDEK(ctx, dek, opts.Resource, policyBase64)
	if err != nil {
		return nil, err
	}

	manifest := c.createManifest(wrappedDEK, keyID, policyBase64, policyBindingHash, encryptionResult)

	return &WrapStreamResult{
		Manifest:       manifest,
		PlaintextSize:  encryptionResult.PlaintextSize,
		CiphertextSize: encryptionResult.CiphertextSize,
	}, nil
}

// WrapReaderToZip encrypts data from reader and writes a complete ZTDF zip file to outputPath.
func (c *Client) WrapReaderToZip(ctx context.Context, reader io.Reader, opts *models.WrapOptions, outputPath string) (*WrapStreamResult, error) {
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, &models.Error{
			Code:    "FILE_WRITE_FAILED",
			Message: fmt.Sprintf("failed to create zip file: %s", outputPath),
			Err:     err,
		}
	}
	defer file.Close()

	bufferedWriter := bufio.NewWriter(file)
	zipWriter := zip.NewWriter(bufferedWriter)

	payloadHeader := &zip.FileHeader{
		Name:   "0.payload",
		Method: zip.Store,
	}
	payloadWriter, err := zipWriter.CreateHeader(payloadHeader)
	if err != nil {
		zipWriter.Close()
		return nil, &models.Error{
			Code:    "ZIP_CREATE_FAILED",
			Message: "failed to create payload entry",
			Err:     err,
		}
	}

	streamResult, err := c.WrapToWriter(ctx, reader, opts, payloadWriter)
	if err != nil {
		zipWriter.Close()
		return nil, err
	}

	manifestJSON, err := protojson.MarshalOptions{
		Indent: "  ",
	}.Marshal(streamResult.Manifest)
	if err != nil {
		zipWriter.Close()
		return nil, &models.Error{
			Code:    "MARSHAL_FAILED",
			Message: "failed to marshal manifest",
			Err:     err,
		}
	}

	manifestHeader := &zip.FileHeader{
		Name:   "manifest.json",
		Method: zip.Deflate,
	}
	manifestWriter, err := zipWriter.CreateHeader(manifestHeader)
	if err != nil {
		zipWriter.Close()
		return nil, &models.Error{
			Code:    "ZIP_CREATE_FAILED",
			Message: "failed to create manifest entry",
			Err:     err,
		}
	}
	if _, err := manifestWriter.Write(manifestJSON); err != nil {
		zipWriter.Close()
		return nil, &models.Error{
			Code:    "ZIP_WRITE_FAILED",
			Message: "failed to write manifest",
			Err:     err,
		}
	}

	if err := zipWriter.Close(); err != nil {
		return nil, &models.Error{
			Code:    "ZIP_CLOSE_FAILED",
			Message: "failed to close zip writer",
			Err:     err,
		}
	}

	if err := bufferedWriter.Flush(); err != nil {
		return nil, &models.Error{
			Code:    "FILE_WRITE_FAILED",
			Message: "failed to flush zip file",
			Err:     err,
		}
	}

	return streamResult, nil
}

// Unwrap decrypts a ZTDF and returns plaintext
func (c *Client) Unwrap(ctx context.Context, tdo *models.TrustedDataObject, opts *models.UnwrapOptions) ([]byte, error) {
	if opts == nil {
		opts = &models.UnwrapOptions{
			VerifyIntegrity: true,
			VerifyPolicy:    true,
		}
	}

	// Ensure client is initialized
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	// Step 1: Validate manifest
	if tdo.Manifest == nil || tdo.Manifest.EncryptionInformation == nil {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidManifest,
			Message: "invalid ZTDF: missing encryption information",
		}
	}

	encInfo := tdo.Manifest.EncryptionInformation
	if len(encInfo.KeyAccess) == 0 {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidManifest,
			Message: "invalid ZTDF: no key access objects",
		}
	}

	kao := encInfo.KeyAccess[0]

	// Step 2: Decode wrapped key
	wrappedKey, err := base64.StdEncoding.DecodeString(kao.WrappedKey)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidManifest,
			Message: "failed to decode wrapped key",
			Err:     err,
		}
	}

	// Step 3: Unwrap DEK using KAS (returns DEK encrypted with client's public key)
	encryptedDEKForSubject, err := c.unwrapDEK(ctx, wrappedKey, kao.Kid, opts.Resource, encInfo.Policy)
	if err != nil {
		return nil, err
	}

	// Step 4: Decrypt DEK with client's private key
	dek, err := c.keyManager.DecryptDEK(encryptedDEKForSubject)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "failed to decrypt DEK with client private key",
			Err:     err,
		}
	}

	// Step 5: Verify policy binding (if requested)
	if opts.VerifyPolicy && kao.PolicyBinding != nil {
		if err := VerifyPolicyBinding(dek, encInfo.Policy, kao.PolicyBinding.Hash); err != nil {
			return nil, err
		}
	}

	// Step 6: Decrypt payload
	if tdo.Payload == nil {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidManifest,
			Message: "invalid ZTDF: missing payload",
		}
	}

	if encInfo.Method == nil || encInfo.IntegrityInformation == nil {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidManifest,
			Message: "invalid ZTDF: missing method or integrity information",
		}
	}

	if len(encInfo.IntegrityInformation.Segments) == 0 {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidManifest,
			Message: "invalid ZTDF: no integrity segments",
		}
	}

	ivBase64 := encInfo.Method.Iv
	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidManifest,
			Message: "failed to decode IV",
			Err:     err,
		}
	}

	var expectedRoot []byte
	if opts.VerifyIntegrity && encInfo.IntegrityInformation.RootSignature != nil {
		expectedRoot, err = base64.StdEncoding.DecodeString(encInfo.IntegrityInformation.RootSignature.Sig)
		if err != nil {
			return nil, &models.Error{
				Code:    models.ErrCodeInvalidManifest,
				Message: "failed to decode payload root signature",
				Err:     err,
			}
		}
	}

	plaintext, err := decryptPayloadWithSegments(tdo.Payload.Data, dek, iv, encInfo.IntegrityInformation.Segments, expectedRoot)
	if err != nil {
		return nil, err
	}

	// Step 7: (integrity verified during decryption when enabled)

	return plaintext, nil
}

// WrapFile encrypts a file and creates a ZTDF
func (c *Client) WrapFile(ctx context.Context, inputPath, outputPath string, opts *models.WrapOptions) error {
	file, err := os.Open(inputPath)
	if err != nil {
		return &models.Error{
			Code:    "FILE_READ_FAILED",
			Message: fmt.Sprintf("failed to open input file: %s", inputPath),
			Err:     err,
		}
	}
	defer file.Close()

	_, err = c.WrapReaderToZip(ctx, file, opts, outputPath)
	return err
}

// UnwrapFile decrypts a ZTDF file
func (c *Client) UnwrapFile(ctx context.Context, inputPath, outputPath string, opts *models.UnwrapOptions) error {
	tdo, err := LoadFromFile(inputPath)
	if err != nil {
		return err
	}

	plaintext, err := c.Unwrap(ctx, tdo, opts)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
		return &models.Error{
			Code:    "FILE_WRITE_FAILED",
			Message: fmt.Sprintf("failed to write output file: %s", outputPath),
			Err:     err,
		}
	}

	return nil
}

// Close releases resources
func (c *Client) Close() error {
	var err error
	if c.kasConn != nil {
		if closeErr := c.kasConn.Close(); closeErr != nil {
			err = closeErr
		}
	}
	if c.kmConn != nil {
		if closeErr := c.kmConn.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
}

// ensureInitialized ensures the client is initialized
func (c *Client) ensureInitialized(ctx context.Context) error {
	// Check if key manager has keys loaded
	if _, err := c.keyManager.GetPrivateKey(); err != nil {
		// Try to initialize
		return c.Initialize(ctx)
	}
	return nil
}

// wrapDEK wraps a DEK using the Key Access Server
func (c *Client) wrapDEK(ctx context.Context, dek []byte, resource string, policy string) ([]byte, string, error) {
	// Get auth token
	authCtx := context.Background()
	if c.authConfig.AllowInsecureIssuer {
		authCtx = oidc.InsecureIssuerURLContext(authCtx, c.authConfig.IssuerURL)
	}

	authToken, err := c.authProvider.Authenticate(authCtx)
	if err != nil {
		return nil, "", &models.Error{
			Code:    models.ErrCodeAuthFailed,
			Message: "failed to authenticate for DEK wrap",
			Err:     err,
		}
	}

	// Add auth token to context
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", authToken))

	clientWrappedDEK, err := c.keyManager.WrapDEK(dek)
	if err != nil {
		return nil, "", err
	}

	clientKeyID := c.keyManager.GetKeyID()
	if clientKeyID == "" {
		return nil, "", &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "client key ID not available",
		}
	}

	// Call WrapDEK
	resp, err := c.kasClient.WrapDEK(ctx, &keyAccess.WrapDEKRequest{
		Resource:    resource,
		Dek:         clientWrappedDEK,
		Action:      "wrap_dek",
		Policy:      policy,
		ClientKeyId: clientKeyID,
	})
	if err != nil {
		return nil, "", &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to call WrapDEK",
			Err:     err,
		}
	}

	if !resp.AccessGranted {
		return nil, "", &models.Error{
			Code:    models.ErrCodeAccessDenied,
			Message: fmt.Sprintf("access denied: %s", resp.AccessReason),
		}
	}

	return resp.WrappedDek, resp.KeyId, nil
}

// unwrapDEK unwraps a DEK using the Key Access Server
func (c *Client) unwrapDEK(ctx context.Context, wrappedDEK []byte, keyID string, resource string, policy string) ([]byte, error) {
	// Get auth token
	authCtx := ctx
	if c.authConfig.AllowInsecureIssuer {
		authCtx = oidc.InsecureIssuerURLContext(context.Background(), c.authConfig.IssuerURL)
	}

	authToken, err := c.authProvider.Authenticate(authCtx)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeAuthFailed,
			Message: "failed to authenticate for DEK unwrap",
			Err:     err,
		}
	}

	// Add auth token to context
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", authToken))

	// Call UnwrapDEK
	resp, err := c.kasClient.UnwrapDEK(ctx, &keyAccess.UnwrapDEKRequest{
		Resource:    resource,
		WrappedDek:  wrappedDEK,
		ClientKeyId: c.keyManager.GetMetadata().KeyID,
		KeyId:       keyID,
		Action:      "unwrap_dek",
		Policy:      policy,
	})
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "failed to call UnwrapDEK",
			Err:     err,
		}
	}

	if !resp.AccessGranted {
		return nil, &models.Error{
			Code:    models.ErrCodeAccessDenied,
			Message: fmt.Sprintf("access denied: %s", resp.AccessReason),
		}
	}

	// Return the DEK encrypted for the subject (will be decrypted with client's private key)
	return resp.DekForSubject, nil
}

// createPolicy creates a ZTDF policy from options
func (c *Client) createPolicy(opts *models.WrapOptions) *models.ZtdfPolicy {
	if opts.Policy != nil {
		return opts.Policy
	}

	// Create default policy
	attributes := opts.Attributes
	if len(attributes) == 0 {
		attributes = []models.Attribute{
			{
				URI:         "http://example.com/attr/classification/value/confidential",
				DisplayName: "Classification",
				IsDefault:   true,
			},
		}
	}

	dataAttrs := make([]*models.ZtdfPolicy_Body_Attribute, len(attributes))
	for i, attr := range attributes {
		dataAttrs[i] = &models.ZtdfPolicy_Body_Attribute{
			Attribute:   attr.URI,
			DisplayName: attr.DisplayName,
			IsDefault:   attr.IsDefault,
			Kas_URL:     c.keyAccessAddr,
		}
	}

	return &models.ZtdfPolicy{
		Uuid: uuid.New().String(),
		Body: &models.ZtdfPolicy_Body{
			DataAttributes: dataAttrs,
		},
		TdfSpecVersion: "4.0.0",
	}
}

// createManifest creates a ZTDF manifest
func (c *Client) createManifest(wrappedDEK []byte, keyID, policyBase64, policyBindingHash string, encResult *payloadEncryptionResult) *models.Manifest {
	ivBase64 := base64.StdEncoding.EncodeToString(encResult.BaseNonce)

	var segmentSizeDefault int32
	var encryptedSegmentSizeDefault int32
	if len(encResult.Segments) > 0 {
		segmentSizeDefault = encResult.Segments[0].GetSegmentSize()
		encryptedSegmentSizeDefault = encResult.Segments[0].GetEncryptedSegmentSize()
	}

	rootSignature := &models.EncryptionInformation_IntegrityInformation_RootSignature{
		Alg: defaultSegmentHashAlg,
		Sig: base64.StdEncoding.EncodeToString(encResult.PayloadHash),
	}

	return &models.Manifest{
		Assertions: []*models.Assertion{
			{
				Id:             uuid.New().String(),
				Type:           models.Assertion_HANDLING,
				Scope:          models.Assertion_TDO,
				AppliesToState: models.AppliesTo_CIPHERTEXT,
				Statement: &models.Assertion_Statement{
					Format: models.Assertion_Statement_JSON_STRUCTURED,
					JsonValue: `{
						"classification": "UNCLASSIFIED",
						"handling": "CONTROLLED"
					}`,
				},
				Binding: &models.Assertion_AssertionBinding{
					Method:    "jws",
					Signature: "placeholder-signature",
				},
			},
		},
		EncryptionInformation: &models.EncryptionInformation{
			Type: models.EncryptionInformation_SPLIT,
			KeyAccess: []*models.EncryptionInformation_KeyAccessObject{
				{
					Type:       models.EncryptionInformation_KeyAccessObject_WRAPPED,
					Url:        c.keyAccessAddr,
					Protocol:   models.EncryptionInformation_KeyAccessObject_KAS,
					WrappedKey: base64.StdEncoding.EncodeToString(wrappedDEK),
					Sid:        uuid.New().String(),
					Kid:        keyID,
					PolicyBinding: &models.EncryptionInformation_KeyAccessObject_PolicyBinding{
						Alg:  "HS256",
						Hash: policyBindingHash,
					},
					TdfSpecVersion: "4.0.0",
				},
			},
			Method: &models.EncryptionInformation_Method{
				Algorithm:    "AES-256-GCM",
				IsStreamable: true,
				Iv:           ivBase64,
			},
			IntegrityInformation: &models.EncryptionInformation_IntegrityInformation{
				RootSignature:               rootSignature,
				SegmentHashAlg:              defaultSegmentHashAlg,
				SegmentSizeDefault:          segmentSizeDefault,
				EncryptedSegmentSizeDefault: encryptedSegmentSizeDefault,
				Segments:                    encResult.Segments,
			},
			Policy: policyBase64,
		},
		Payload: &models.PayloadReference{
			Type:           "reference",
			Url:            "0.payload",
			Protocol:       "zip",
			IsEncrypted:    true,
			MimeType:       "application/octet-stream",
			TdfSpecVersion: "4.0.0",
		},
	}
}

// SaveToFile saves a ZTDF to a ZIP file
func SaveToFile(tdo *models.TrustedDataObject, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return &models.Error{
			Code:    "FILE_WRITE_FAILED",
			Message: fmt.Sprintf("failed to create zip file: %s", outputPath),
			Err:     err,
		}
	}
	defer file.Close()

	bufferedWriter := bufio.NewWriter(file)
	if err := writeTDOToZip(tdo, bufferedWriter); err != nil {
		return err
	}

	if err := bufferedWriter.Flush(); err != nil {
		return &models.Error{
			Code:    "FILE_WRITE_FAILED",
			Message: "failed to flush zip file",
			Err:     err,
		}
	}

	return nil
}

// writeTDOToZip writes the manifest and payload to a zip writer.
func writeTDOToZip(tdo *models.TrustedDataObject, w io.Writer) error {
	zipWriter := zip.NewWriter(w)

	manifestJSON, err := protojson.MarshalOptions{
		Indent: "  ",
	}.Marshal(tdo.Manifest)
	if err != nil {
		zipWriter.Close()
		return &models.Error{
			Code:    "MARSHAL_FAILED",
			Message: "failed to marshal manifest",
			Err:     err,
		}
	}

	manifestHeader := &zip.FileHeader{
		Name:   "manifest.json",
		Method: zip.Deflate,
	}
	manifestWriter, err := zipWriter.CreateHeader(manifestHeader)
	if err != nil {
		zipWriter.Close()
		return &models.Error{
			Code:    "ZIP_CREATE_FAILED",
			Message: "failed to create manifest entry",
			Err:     err,
		}
	}
	if _, err := manifestWriter.Write(manifestJSON); err != nil {
		zipWriter.Close()
		return &models.Error{
			Code:    "ZIP_WRITE_FAILED",
			Message: "failed to write manifest",
			Err:     err,
		}
	}

	payloadHeader := &zip.FileHeader{
		Name:   "0.payload",
		Method: zip.Store,
	}

	payloadWriter, err := zipWriter.CreateHeader(payloadHeader)
	if err != nil {
		zipWriter.Close()
		return &models.Error{
			Code:    "ZIP_CREATE_FAILED",
			Message: "failed to create payload entry",
			Err:     err,
		}
	}
	if _, err := payloadWriter.Write(tdo.Payload.Data); err != nil {
		zipWriter.Close()
		return &models.Error{
			Code:    "ZIP_WRITE_FAILED",
			Message: "failed to write payload",
			Err:     err,
		}
	}

	if err := zipWriter.Close(); err != nil {
		return &models.Error{
			Code:    "ZIP_CLOSE_FAILED",
			Message: "failed to close zip writer",
			Err:     err,
		}
	}

	return nil
}

// LoadFromFile loads a ZTDF from a ZIP file
func LoadFromFile(zipPath string) (*models.TrustedDataObject, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, &models.Error{
			Code:    "ZIP_OPEN_FAILED",
			Message: "failed to open zip",
			Err:     err,
		}
	}
	defer reader.Close()

	tdo := &models.TrustedDataObject{}

	for _, file := range reader.File {
		if file.Name == "manifest.json" {
			rc, err := file.Open()
			if err != nil {
				return nil, &models.Error{
					Code:    "ZIP_READ_FAILED",
					Message: "failed to open manifest",
					Err:     err,
				}
			}
			manifestData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, &models.Error{
					Code:    "ZIP_READ_FAILED",
					Message: "failed to read manifest",
					Err:     err,
				}
			}

			manifest := &models.Manifest{}
			if err := protojson.Unmarshal(manifestData, manifest); err != nil {
				return nil, &models.Error{
					Code:    models.ErrCodeInvalidManifest,
					Message: "failed to unmarshal manifest",
					Err:     err,
				}
			}
			tdo.Manifest = manifest
		} else if file.Name == "0.payload" {
			rc, err := file.Open()
			if err != nil {
				return nil, &models.Error{
					Code:    "ZIP_READ_FAILED",
					Message: "failed to open payload",
					Err:     err,
				}
			}
			payloadData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, &models.Error{
					Code:    "ZIP_READ_FAILED",
					Message: "failed to read payload",
					Err:     err,
				}
			}
			tdo.Payload = &models.Payload{Data: payloadData}
		}
	}

	if tdo.Manifest == nil || tdo.Payload == nil {
		return nil, &models.Error{
			Code:    models.ErrCodeInvalidManifest,
			Message: "incomplete ZTDF: missing manifest or payload",
		}
	}

	return tdo, nil
}
