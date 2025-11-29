package cmd

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"stratium/pkg/auth"

	"stratium/pkg/models"
	"stratium/pkg/ztdf"

	"google.golang.org/protobuf/encoding/protojson"
)

// ZTDFCreator handles ZTDF creation and encryption using the SDK
type ZTDFCreator struct {
	client *ztdf.Client
}

// NewZTDFCreator creates a new ZTDF creator
func NewZTDFCreator(keyManagerAddr, keyAccessAddr, keycloakURL, clientID, username, password string, useTLS bool) (*ZTDFCreator, error) {
	// Configure the SDK client
	config := &ztdf.ZtdfClientConfig{
		KeyManagerAddr: keyManagerAddr,
		KeyAccessAddr:  keyAccessAddr,
		AuthConfig: &auth.AuthConfig{
			IssuerURL: keycloakURL,
			ClientID:  clientID,
			Username:  username,
			Password:  password,
		},
		UseTLS: useTLS,
	}

	// Create SDK client
	client, err := ztdf.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ZTDF client: %w", err)
	}

	// Initialize client (authenticates, loads/generates keys, registers public key)
	ctx := context.Background()
	if err := client.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize ZTDF client: %w", err)
	}

	return &ZTDFCreator{
		client: client,
	}, nil
}

// Close closes the ZTDF creator
func (z *ZTDFCreator) Close() error {
	if z.client != nil {
		return z.client.Close()
	}
	return nil
}

// CreateZTDF creates a ZTDF from plaintext data
func (z *ZTDFCreator) CreateZTDF(ctx context.Context, plaintext []byte, resource string) (*models.TrustedDataObject, error) {
	// Configure wrap options
	opts := &models.WrapOptions{
		Resource: resource,
		Attributes: []models.Attribute{
			{
				URI:         "http://example.com/attr/classification/value/confidential",
				DisplayName: "Classification",
				IsDefault:   true,
			},
		},
		IntegrityCheck: true,
		Context: map[string]string{
			"action": "wrap_dek",
		},
	}

	// Use SDK to wrap the data
	tdo, err := z.client.Wrap(ctx, plaintext, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap data: %w", err)
	}

	return tdo, nil
}

// CreateZTDFStream encrypts data from reader and writes the streamed ZTDF to outputPath.
func (z *ZTDFCreator) CreateZTDFStream(ctx context.Context, reader io.Reader, resource, outputPath string) (*ztdf.WrapStreamResult, error) {
	opts := &models.WrapOptions{
		Resource: resource,
		Attributes: []models.Attribute{
			{
				URI:         "http://example.com/attr/classification/value/confidential",
				DisplayName: "Classification",
				IsDefault:   true,
			},
		},
		IntegrityCheck: true,
		Context: map[string]string{
			"action": "wrap_dek",
		},
	}

	result, err := z.client.WrapReaderToZip(ctx, reader, opts, outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stream ZTDF: %w", err)
	}

	return result, nil
}

// UnwrapZTDF decrypts a ZTDF and returns the plaintext
func (z *ZTDFCreator) UnwrapZTDF(ctx context.Context, tdo *models.TrustedDataObject, resource string) ([]byte, error) {
	// Configure unwrap options
	opts := &models.UnwrapOptions{
		Resource:        resource,
		VerifyIntegrity: true,
		VerifyPolicy:    true,
		Context: map[string]string{
			"action": "unwrap_dek",
		},
	}

	// Use SDK to unwrap the data
	plaintext, err := z.client.Unwrap(ctx, tdo, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap data: %w", err)
	}

	return plaintext, nil
}

// SaveProgressCallback allows callers to observe progress when a ZTDF is written to disk.
type SaveProgressCallback func(written, total int64)

// SaveZTDFToZip saves a ZTDF to a zip file
func SaveZTDFToZip(tdo *models.TrustedDataObject, outputPath string, progress SaveProgressCallback) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	manifestJSON, err := protojson.MarshalOptions{
		Indent: "  ",
	}.Marshal(tdo.Manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	total := int64(len(manifestJSON) + len(tdo.Payload.Data))

	buffered := bufio.NewWriter(file)
	var writer io.Writer = buffered
	if progress != nil && total > 0 {
		writer = &progressCountingWriter{
			writer:   writer,
			total:    total,
			progress: progress,
		}
	}

	zipWriter := zip.NewWriter(writer)

	manifestHeader := &zip.FileHeader{
		Name:   "manifest.json",
		Method: zip.Deflate,
	}
	manifestWriter, err := zipWriter.CreateHeader(manifestHeader)
	if err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to create manifest entry: %w", err)
	}
	if _, err := manifestWriter.Write(manifestJSON); err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	payloadHeader := &zip.FileHeader{
		Name:   "0.payload",
		Method: zip.Store,
	}

	payloadWriter, err := zipWriter.CreateHeader(payloadHeader)
	if err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to create payload entry: %w", err)
	}
	if _, err := payloadWriter.Write(tdo.Payload.Data); err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to write payload: %w", err)
	}

	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close zip writer: %w", err)
	}
	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("failed to flush zip file: %w", err)
	}

	if progress != nil && total > 0 {
		progress(total, total)
	}

	return nil
}

// LoadZTDFFromZip loads a ZTDF from a zip file
func LoadZTDFFromZip(zipPath string) (*models.TrustedDataObject, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}
	defer reader.Close()

	tdo := &models.TrustedDataObject{}

	for _, file := range reader.File {
		if file.Name == "manifest.json" {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open manifest: %w", err)
			}
			manifestData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read manifest: %w", err)
			}

			manifest := &models.Manifest{}
			if err := protojson.Unmarshal(manifestData, manifest); err != nil {
				return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
			}
			tdo.Manifest = manifest
		} else if file.Name == "0.payload" {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open payload: %w", err)
			}
			payloadData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read payload: %w", err)
			}
			tdo.Payload = &models.Payload{Data: payloadData}
		}
	}

	if tdo.Manifest == nil || tdo.Payload == nil {
		return nil, fmt.Errorf("incomplete ZTDF: missing manifest or payload")
	}

	return tdo, nil
}

type progressCountingWriter struct {
	writer   io.Writer
	written  int64
	total    int64
	progress SaveProgressCallback
}

func (w *progressCountingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n > 0 {
		w.written += int64(n)
		if w.progress != nil && w.total > 0 {
			if w.written > w.total {
				w.progress(w.total, w.total)
			} else {
				w.progress(w.written, w.total)
			}
		}
	}
	return n, err
}

// Helper function to get policy from manifest for display purposes
func GetPolicyFromManifest(tdo *models.TrustedDataObject) (*models.ZtdfPolicy, error) {
	if tdo.Manifest == nil || tdo.Manifest.EncryptionInformation == nil {
		return nil, fmt.Errorf("invalid ZTDF: missing encryption information")
	}

	policyBase64 := tdo.Manifest.EncryptionInformation.Policy
	policyJSON, err := base64.StdEncoding.DecodeString(policyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode policy: %w", err)
	}

	policy := &models.ZtdfPolicy{}
	if err := protojson.Unmarshal(policyJSON, policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return policy, nil
}
