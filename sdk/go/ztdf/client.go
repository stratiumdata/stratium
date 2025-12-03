// Package ztdf provides utilities for working with Zero Trust Data Format (ZTDF) files.
//
// ZTDF is a secure file format that combines encryption, policy-based access control,
// and integrity verification. This package provides tools to:
//   - Encrypt data into ZTDF format with attribute-based access control
//   - Decrypt ZTDF files with policy enforcement
//   - Work with ZTDF policies and attributes
//   - Validate and inspect ZTDF files
//
// Example usage:
//
//	// Create ZTDF client
//	client := ztdf.NewClient(stratiumClient)
//
//	// Wrap (encrypt) data
//	tdo, err := client.Wrap(ctx, plaintext, &ztdf.WrapOptions{
//	    Resource: "my-document",
//	    Attributes: []ztdf.Attribute{
//	        {
//	            URI:         "http://example.com/attr/classification/value/secret",
//	            DisplayName: "Classification: Secret",
//	            IsDefault:   true,
//	        },
//	    },
//	})
//
//	// Save to file
//	ztdf.SaveToFile(tdo, "encrypted.ztdf")
//
//	// Load from file
//	tdo, err := ztdf.LoadFromFile("encrypted.ztdf")
//
//	// Unwrap (decrypt) data
//	plaintext, err := client.Unwrap(ctx, tdo, &ztdf.UnwrapOptions{
//	    Resource: "my-document",
//	})
package ztdf

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/uuid"
	stratium "github.com/stratiumdata/go-sdk"
	"github.com/stratiumdata/go-sdk/gen/models"
)

// keyAccessProvider defines the interface for key access operations needed by the ZTDF client.
// This interface allows for dependency injection and testing.
type keyAccessProvider interface {
	RequestDEK(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error)
	UnwrapDEK(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error)
}

// Client provides high-level methods for working with ZTDF files.
// It integrates with the Stratium SDK to handle key management and access control.
type Client struct {
	stratiumClient *stratium.Client
	keyAccessURL   string
	keyAccess      keyAccessProvider // for dependency injection in tests
}

// NewClient creates a new ZTDF client using a Stratium SDK client.
//
// Example:
//
//	stratiumClient, _ := stratium.NewClient(config)
//	ztdfClient := ztdf.NewClient(stratiumClient)
func NewClient(stratiumClient *stratium.Client) *Client {
	keyAccessURL := stratiumClient.Config().KeyAccessAddress
	if keyAccessURL == "" {
		keyAccessURL = DefaultKeyAccessURL
	}

	return &Client{
		stratiumClient: stratiumClient,
		keyAccessURL:   keyAccessURL,
	}
}

// Wrap encrypts plaintext data and creates a ZTDF.
//
// The wrap process:
//  1. Generates a random Data Encryption Key (DEK)
//  2. Encrypts the payload with the DEK using AES-256-GCM
//  3. Creates a policy from the provided attributes
//  4. Wraps the DEK using the Key Access Server (policy enforcement)
//  5. Creates a manifest with all metadata
//  6. Returns a complete ZTDF structure
//
// Example:
//
//	tdo, err := client.Wrap(ctx, plaintext, &ztdf.WrapOptions{
//	    Resource: "document-123",
//	    Attributes: []ztdf.Attribute{
//	        {
//	            URI:         "http://example.com/attr/classification/value/secret",
//	            DisplayName: "Classification: Secret",
//	            IsDefault:   true,
//	        },
//	    },
//	    IntegrityCheck: true,
//	})
func (c *Client) Wrap(ctx context.Context, plaintext []byte, opts *WrapOptions) (*TrustedDataObject, error) {
	return c.wrapStream(ctx, bytes.NewReader(plaintext), opts)
}

func (c *Client) wrapStream(ctx context.Context, reader io.Reader, opts *WrapOptions) (*TrustedDataObject, error) {
	if opts == nil {
		opts = &WrapOptions{}
	}

	if len(opts.ResourceAttributes) == 0 {
		opts.ResourceAttributes = map[string]string{"name": DefaultResourceName}
	}

	dek, err := GenerateDEK()
	if err != nil {
		return nil, err
	}

	encryptionResult, err := encryptPayloadStream(reader, dek)
	if err != nil {
		return nil, err
	}

	policy := opts.Policy
	if policy == nil {
		policy = CreatePolicy(c.keyAccessURL, opts.Attributes)
	}

	policyBase64, err := EncodePolicyToBase64(policy)
	if err != nil {
		return nil, err
	}

	policyBindingHash := CalculatePolicyBinding(dek, policyBase64)

	if opts.ClientKeyID == "" {
		return nil, fmt.Errorf("%s: %s", ErrMsgFailedToWrapDEK, "client key ID is required")
	}
	if opts.ClientPrivateKeyPath == "" {
		return nil, fmt.Errorf("%s: %s", ErrMsgFailedToWrapDEK, "client private key path is required")
	}

	privateKey, err := GetRSAPrivateKeyFromFile(opts.ClientPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrMsgFailedToWrapDEK, err)
	}

	clientWrappedDEK, err := WrapDEKWithRSAPrivateKey(privateKey, dek)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrMsgFailedToWrapDEK, err)
	}

	wrappedDEK, keyID, err := c.wrapDEK(ctx, opts.Resource, opts.ClientKeyID, clientWrappedDEK, dek, opts.ResourceAttributes, policyBase64, opts.Context)
	if err != nil {
		return nil, err
	}

	manifest := c.createManifest(
		opts.Manifest,
		wrappedDEK,
		keyID,
		policyBase64,
		policyBindingHash,
		encryptionResult,
	)

	tdo := &TrustedDataObject{
		Manifest: manifest,
		Payload: &Payload{
			Data: encryptionResult.Ciphertext,
		},
	}

	return tdo, nil
}

// Unwrap decrypts a ZTDF and returns the plaintext.
//
// The unwrap process:
//  1. Validates the manifest structure
//  2. Unwraps the DEK using the Key Access Server (policy enforcement)
//  3. Verifies the policy binding (if enabled)
//  4. Decrypts the payload with the DEK
//  5. Verifies payload integrity (if enabled)
//  6. Returns the plaintext
//
// Example:
//
//		plaintext, err := client.Unwrap(ctx, tdo, &ztdf.UnwrapOptions{
//		    Resource:        "document-123",
//	     ClientKeyID:     key.KeyID,
//		    VerifyIntegrity: true,
//		    VerifyPolicy:    true,
//		})
func (c *Client) Unwrap(ctx context.Context, tdo *TrustedDataObject, opts *UnwrapOptions) ([]byte, error) {
	// Step 1: Validate manifest
	if tdo.Manifest == nil || tdo.Manifest.EncryptionInformation == nil {
		return nil, fmt.Errorf("%s: %s", ErrMsgInvalidZTDF, ErrMsgMissingEncryptionInfo)
	}

	encInfo := tdo.Manifest.EncryptionInformation
	if len(encInfo.KeyAccess) == 0 {
		return nil, fmt.Errorf("%s: %s", ErrMsgInvalidZTDF, ErrMsgNoKeyAccessObjects)
	}

	kao := encInfo.KeyAccess[0]

	// Step 2: Decode wrapped key
	wrappedKey, err := base64.StdEncoding.DecodeString(kao.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode wrapped key: %w", err)
	}

	// Step 3: Unwrap DEK using Key Access Server
	encryptedDEK, err := c.unwrapDEK(ctx, opts, kao.Kid, wrappedKey, encInfo.Policy)
	if err != nil {
		return nil, err
	}

	// Step 4: Decrypt DEK with private key
	privateKey, err := GetRSAPrivateKeyFromFile(opts.ClientPrivateKeyPath)
	if err != nil {
		return nil, err
	}

	dek, err := DecryptDEKWithRSAPrivateKey(privateKey, encryptedDEK)
	if err != nil {
		log.Fatal(err)
	}

	// Step 4: Verify policy binding (if requested)
	if opts.VerifyPolicy && kao.PolicyBinding != nil {
		if err := VerifyPolicyBinding(dek, encInfo.Policy, kao.PolicyBinding.Hash); err != nil {
			return nil, fmt.Errorf("%s: %w", ErrMsgPolicyVerificationFailed, err)
		}
	}

	if tdo.Payload == nil {
		return nil, fmt.Errorf("%s: %s", ErrMsgInvalidZTDF, ErrMsgMissingPayload)
	}
	if encInfo.Method == nil {
		return nil, fmt.Errorf("%s: %s", ErrMsgInvalidZTDF, "missing encryption method")
	}

	ivBase64 := encInfo.Method.Iv
	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	hasIntegrity := encInfo.IntegrityInformation != nil && len(encInfo.IntegrityInformation.Segments) > 0
	isSegmented := encInfo.Method.GetIsStreamable() && hasIntegrity

	var plaintext []byte
	if isSegmented {
		var expectedRoot []byte
		if opts.VerifyIntegrity && encInfo.IntegrityInformation.RootSignature != nil {
			expectedRoot, err = base64.StdEncoding.DecodeString(encInfo.IntegrityInformation.RootSignature.Sig)
			if err != nil {
				return nil, fmt.Errorf("failed to decode payload root signature: %w", err)
			}
		}
		plaintext, err = decryptPayloadWithSegments(tdo.Payload.Data, dek, iv, encInfo.IntegrityInformation.Segments, expectedRoot)
		if err != nil {
			return nil, err
		}
	} else {
		plaintext, err = decryptSinglePayload(tdo.Payload.Data, dek, iv)
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

// WrapFile encrypts a file and saves it as a ZTDF.
//
// Example:
//
//	err := client.WrapFile(ctx, "plaintext.txt", "encrypted.ztdf", &ztdf.WrapOptions{
//	    Resource: "my-document",
//	})
func (c *Client) WrapFile(ctx context.Context, inputPath, outputPath string, opts *WrapOptions) error {
	file, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	tdo, err := c.wrapStream(ctx, file, opts)
	if err != nil {
		return err
	}

	return SaveToFile(tdo, outputPath)
}

// UnwrapFile decrypts a ZTDF file and saves the plaintext.
//
// Example:
//
//	err := client.UnwrapFile(ctx, "encrypted.ztdf", "plaintext.txt", &ztdf.UnwrapOptions{
//	    Resource: "my-document",
//	})
func (c *Client) UnwrapFile(ctx context.Context, inputPath, outputPath string, opts *UnwrapOptions) error {
	tdo, err := LoadFromFile(inputPath)
	if err != nil {
		return err
	}

	plaintext, err := c.Unwrap(ctx, tdo, opts)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, plaintext, DefaultFileMode); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// wrapDEK wraps a DEK using the Key Access Server
func (c *Client) wrapDEK(ctx context.Context, resource, clientKeyID string, clientWrappedDEK, dek []byte, resourceAttributes map[string]string, policy string, contextMap map[string]string) ([]byte, string, error) {
	if resource == "" {
		return nil, "", fmt.Errorf("%s: %s", ErrMsgFailedToWrapDEK, "resource identifier cannot be empty")
	}
	if clientKeyID == "" {
		return nil, "", fmt.Errorf("%s: %s", ErrMsgFailedToWrapDEK, "client key ID cannot be empty")
	}
	if len(clientWrappedDEK) == 0 {
		return nil, "", fmt.Errorf("%s: %s", ErrMsgFailedToWrapDEK, "client wrapped DEK cannot be empty")
	}

	// Use injected keyAccess for testing, or stratiumClient.KeyAccess for production
	keyAccess := c.keyAccess
	if keyAccess == nil {
		keyAccess = c.stratiumClient.KeyAccess
	}

	resp, err := keyAccess.RequestDEK(ctx, &stratium.DEKRequest{
		Resource:           resource,
		ResourceAttributes: resourceAttributes,
		Purpose:            "encryption",
		Context:            contextMap,
		DEK:                dek,
		Policy:             policy,
		ClientKeyID:        clientKeyID,
		ClientWrappedDEK:   clientWrappedDEK,
	})
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", ErrMsgFailedToWrapDEK, err)
	}

	return resp.WrappedDEK, resp.KeyID, nil
}

// unwrapDEK unwraps a DEK using the Key Access Server
func (c *Client) unwrapDEK(ctx context.Context, cfg *UnwrapOptions, kid string, wrappedDEK []byte, policy string) ([]byte, error) {
	if cfg.Resource == "" {
		return nil, fmt.Errorf("%s: %s", ErrMsgFailedToUnwrapDEK, "resource identifier cannot be empty")
	}

	// Use injected keyAccess for testing, or stratiumClient.KeyAccess for production
	keyAccess := c.keyAccess
	if keyAccess == nil {
		keyAccess = c.stratiumClient.KeyAccess
	}

	dek, err := keyAccess.UnwrapDEK(ctx, cfg.Resource, cfg.ClientKeyID, kid, wrappedDEK, policy)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrMsgFailedToUnwrapDEK, err)
	}

	return dek, nil
}

// createManifest creates a ZTDF manifest
func (c *Client) createManifest(baseline *models.Manifest, wrappedDEK []byte, keyID, policyBase64, policyBindingHash string, encResult *payloadEncryptionResult) *models.Manifest {
	if baseline == nil {
		baseline = &models.Manifest{
			Assertions: []*models.Assertion{
				{
					Id:             uuid.New().String(),
					Type:           models.Assertion_HANDLING,
					Scope:          models.Assertion_TDO,
					AppliesToState: models.AppliesTo_CIPHERTEXT,
					Statement: &models.Assertion_Statement{
						Format: models.Assertion_Statement_JSON_STRUCTURED,
						JsonValue: fmt.Sprintf(`{
						"classification": %s,
						"handling": %s
					}`, DefaultClassification, DefaultHandling),
					},
					Binding: &models.Assertion_AssertionBinding{
						Method:    AlgorithmJWS,
						Signature: PlaceholderSignature,
					},
				},
			},
			EncryptionInformation: &models.EncryptionInformation{
				Type: models.EncryptionInformation_SPLIT,
				KeyAccess: []*models.EncryptionInformation_KeyAccessObject{
					{
						Type:       models.EncryptionInformation_KeyAccessObject_WRAPPED,
						Url:        c.keyAccessURL,
						Protocol:   models.EncryptionInformation_KeyAccessObject_KAS,
						WrappedKey: base64.StdEncoding.EncodeToString(wrappedDEK),
						Sid:        uuid.New().String(),
						Kid:        keyID,
						PolicyBinding: &models.EncryptionInformation_KeyAccessObject_PolicyBinding{
							Alg:  AlgorithmHS256,
							Hash: policyBindingHash,
						},
						TdfSpecVersion: TDFSpecVersion,
					},
				},
				Method: &models.EncryptionInformation_Method{
					Algorithm:    AlgorithmAES256GCM,
					IsStreamable: true,
					Iv:           base64.StdEncoding.EncodeToString(encResult.BaseNonce),
				},
				IntegrityInformation: &models.EncryptionInformation_IntegrityInformation{
					RootSignature: &models.EncryptionInformation_IntegrityInformation_RootSignature{
						Alg: AlgorithmHS256,
						Sig: base64.StdEncoding.EncodeToString(encResult.PayloadHash),
					},
					SegmentHashAlg:              defaultSegmentHashAlg,
					SegmentSizeDefault:          0,
					EncryptedSegmentSizeDefault: 0,
					Segments:                    encResult.Segments,
				},
				Policy: policyBase64,
			},
			Payload: &models.PayloadReference{
				Type:           TypeReference,
				Url:            PayloadFileName,
				Protocol:       ProtocolZIP,
				IsEncrypted:    true,
				MimeType:       MIMETypeOctetStream,
				TdfSpecVersion: TDFSpecVersion,
			},
		}
	}
	for _, keyAccess := range baseline.EncryptionInformation.KeyAccess {
		keyAccess.WrappedKey = base64.StdEncoding.EncodeToString(wrappedDEK)
		keyAccess.Kid = keyID
		keyAccess.PolicyBinding.Hash = policyBindingHash
	}

	if len(encResult.Segments) > 0 {
		baseline.EncryptionInformation.IntegrityInformation.SegmentSizeDefault = encResult.Segments[0].GetSegmentSize()
		baseline.EncryptionInformation.IntegrityInformation.EncryptedSegmentSizeDefault = encResult.Segments[0].GetEncryptedSegmentSize()
	}

	baseline.EncryptionInformation.Method.Iv = base64.StdEncoding.EncodeToString(encResult.BaseNonce)
	baseline.EncryptionInformation.IntegrityInformation.RootSignature.Sig = base64.StdEncoding.EncodeToString(encResult.PayloadHash)
	baseline.EncryptionInformation.IntegrityInformation.SegmentHashAlg = defaultSegmentHashAlg
	baseline.EncryptionInformation.IntegrityInformation.Segments = encResult.Segments

	return baseline
}
