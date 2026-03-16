package ztdf

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"stratium/logging"
	"stratium/pkg/models"
	keyManager "stratium/services/key-manager"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
)

const yubiKeySignedDEKEnvelopeVersion = "yubikey-signed-dek-v1"
const yubiKeyPlainDEKEnvelopeVersion = "yubikey-plain-dek-v1"

type yubiKeySignedDEKEnvelope struct {
	Version   string `json:"version"`
	DEK       string `json:"dek"`
	Signature string `json:"signature"`
}

type yubiKeyPlainDEKEnvelope struct {
	Version string `json:"version"`
	DEK     string `json:"dek"`
}

// YubiKeyKeyManagerOptions configures the client-side YubiKey key manager.
type YubiKeyKeyManagerOptions struct {
	Slot         string
	PIN          string
	RequireTouch bool
	PIVToolPath  string
	YKManPath    string
	FIPSEnabled  bool
}

// YubiKeyKeyManager implements KeyManager for client keys stored on a YubiKey.
type YubiKeyKeyManager struct {
	keyStorePath string
	slot         string
	pin          string
	requireTouch bool
	pivToolPath  string
	ykmanPath    string
	fipsEnabled  bool

	cardReader keyManager.CardReader
	publicKey  *rsa.PublicKey
	keyID      string
	metadata   *models.KeyMetadata
}

// NewYubiKeyKeyManager creates a key manager backed by a YubiKey PIV slot.
func NewYubiKeyKeyManager(keyStorePath string, options *YubiKeyKeyManagerOptions) (models.KeyManager, error) {
	if keyStorePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		keyStorePath = filepath.Join(home, ".ztdf", "yubikey-client-key")
	}

	slot := "9d"
	pin := strings.TrimSpace(os.Getenv("STRATIUM_YUBIKEY_PIN"))
	requireTouch, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv("STRATIUM_YUBIKEY_REQUIRE_TOUCH")))
	pivToolPath := ""
	ykmanPath := ""
	fipsEnabled := false
	if options != nil {
		if strings.TrimSpace(options.Slot) != "" {
			slot = strings.TrimSpace(options.Slot)
		}
		if strings.TrimSpace(options.PIN) != "" {
			pin = strings.TrimSpace(options.PIN)
		}
		requireTouch = options.RequireTouch
		pivToolPath = strings.TrimSpace(options.PIVToolPath)
		ykmanPath = strings.TrimSpace(options.YKManPath)
		fipsEnabled = options.FIPSEnabled
	}

	return &YubiKeyKeyManager{
		keyStorePath: keyStorePath,
		slot:         slot,
		pin:          pin,
		requireTouch: requireTouch,
		pivToolPath:  pivToolPath,
		ykmanPath:    ykmanPath,
		fipsEnabled:  fipsEnabled,
		cardReader:   keyManager.NewYubiKeyPIVCardReader(),
	}, nil
}

// LoadOrGenerate connects to the YubiKey and loads public key metadata from the configured slot.
// This manager expects the private key to already exist on the YubiKey.
func (km *YubiKeyKeyManager) LoadOrGenerate() error {
	if err := km.ensureAuthenticatedReader(); err != nil {
		return err
	}

	publicKey, err := km.cardReader.GetPublicKey(km.slot)
	if err != nil {
		return &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: fmt.Sprintf("failed to read public key from YubiKey slot %s", km.slot),
			Err:     err,
		}
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return &models.Error{
			Code:    "KEY_TYPE_UNSUPPORTED",
			Message: fmt.Sprintf("YubiKey slot %s public key must be RSA for current client flow", km.slot),
		}
	}
	km.publicKey = rsaPublicKey

	metadataPath := filepath.Join(km.keyStorePath, "key_metadata.json")
	metadataJSON, err := os.ReadFile(metadataPath)
	if err == nil {
		metadata, parseErr := parseMetadataFile(metadataJSON)
		if parseErr != nil {
			return &models.Error{
				Code:    "INVALID_METADATA",
				Message: "failed to parse key metadata",
				Err:     parseErr,
			}
		}
		km.metadata = metadata
		km.keyID = metadata.KeyID
		return nil
	}

	if !os.IsNotExist(err) {
		return &models.Error{
			Code:    "METADATA_LOAD_FAILED",
			Message: "failed to read key metadata",
			Err:     err,
		}
	}

	keyType, err := keyTypeFromRSAPublicKey(rsaPublicKey)
	if err != nil {
		return err
	}

	km.keyID = fmt.Sprintf("yubikey-%s", km.slot)
	km.metadata = &models.KeyMetadata{
		KeyID:     km.keyID,
		CreatedAt: time.Now(),
		KeyType:   keyType,
		Status:    "active",
		KeySize:   rsaPublicKey.N.BitLen(),
		Client:    "yubikey",
	}

	if err := km.saveMetadata(); err != nil {
		return err
	}

	logging.Info("Loaded YubiKey client key from slot %s", km.slot)
	return nil
}

func (km *YubiKeyKeyManager) ensureAuthenticatedReader() error {
	if strings.TrimSpace(km.pin) == "" {
		return &models.Error{
			Code:    models.ErrCodeAuthFailed,
			Message: "YubiKey PIN is required (set --yk-pin or STRATIUM_YUBIKEY_PIN)",
		}
	}

	config := map[string]string{
		"reader_backend": "yubikey",
		"slot":           km.slot,
		"key_id":         km.slot,
		"pin":            km.pin,
		"require_touch":  strconv.FormatBool(km.requireTouch),
	}
	if km.pivToolPath != "" {
		config["piv_tool_path"] = km.pivToolPath
	}
	if km.ykmanPath != "" {
		config["ykman_path"] = km.ykmanPath
	}

	if err := km.cardReader.Connect(config); err != nil {
		return &models.Error{
			Code:    "KEY_MANAGER_INIT_FAILED",
			Message: "failed to connect to YubiKey",
			Err:     err,
		}
	}
	if err := km.cardReader.Authenticate(km.pin); err != nil {
		return &models.Error{
			Code:    models.ErrCodeAuthFailed,
			Message: "failed to authenticate with YubiKey PIN",
			Err:     err,
		}
	}
	return nil
}

// GetPublicKey returns the loaded public key.
func (km *YubiKeyKeyManager) GetPublicKey() (*rsa.PublicKey, error) {
	if km.publicKey == nil {
		return nil, &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "public key not loaded",
		}
	}
	return km.publicKey, nil
}

// GetPrivateKey is unsupported for hardware-backed keys.
func (km *YubiKeyKeyManager) GetPrivateKey() (*rsa.PrivateKey, error) {
	return nil, &models.Error{
		Code:    models.ErrCodeKeyNotFound,
		Message: "private key is hardware-backed and not exportable",
	}
}

// RegisterPublicKey registers the YubiKey public key with Key Manager.
func (km *YubiKeyKeyManager) RegisterPublicKey(ctx context.Context, kmClient models.KeyManagerClient, authToken string) error {
	if km.publicKey == nil {
		return &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "public key not loaded",
		}
	}

	keyType, err := keyTypeFromRSAPublicKey(km.publicKey)
	if err != nil {
		return err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(km.publicKey)
	if err != nil {
		return &models.Error{
			Code:    "KEY_MARSHAL_FAILED",
			Message: "failed to marshal public key",
			Err:     err,
		}
	}
	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", authToken))
	resp, err := kmClient.RegisterClientKey(ctx, &keyManager.RegisterClientKeyRequest{
		ClientId:     "stratium-key-manager",
		PublicKeyPem: publicKeyPEM,
		KeyType:      keyType,
		Metadata: map[string]string{
			"key_id":                 km.keyID,
			"key_size":               fmt.Sprintf("%d", km.publicKey.N.BitLen()),
			"client_key_provider":    "yubikey",
			"slot":                   km.slot,
			"yubikey_touch_required": strconv.FormatBool(km.requireTouch),
		},
	})
	if err != nil {
		return &models.Error{
			Code:    "REGISTRATION_FAILED",
			Message: "failed to register public key with key manager",
			Err:     err,
		}
	}
	if !resp.Success {
		return &models.Error{
			Code:    "REGISTRATION_FAILED",
			Message: fmt.Sprintf("key registration failed: %s", resp.ErrorMessage),
		}
	}

	if km.metadata == nil {
		km.metadata = &models.KeyMetadata{
			CreatedAt: time.Now(),
			KeyType:   keyType,
			Status:    "active",
			KeySize:   km.publicKey.N.BitLen(),
			Client:    "yubikey",
		}
	}
	km.metadata.RegisteredAt = time.Now()
	km.metadata.Client = resp.Key.ClientId
	km.metadata.KeyID = resp.Key.KeyId
	km.keyID = resp.Key.KeyId

	if err := km.saveMetadata(); err != nil {
		logging.Warn("failed to save metadata after YubiKey registration: %v", err)
	}

	return nil
}

// DecryptDEK decrypts a DEK using the YubiKey private key in the configured slot.
func (km *YubiKeyKeyManager) DecryptDEK(encryptedDEK []byte) ([]byte, error) {
	if dek, ok, err := parseYubiKeyPlainDEKEnvelope(encryptedDEK); err != nil {
		return nil, err
	} else if ok {
		if km.requireTouch {
			if err := km.ensureAuthenticatedReader(); err != nil {
				return nil, err
			}
			// Force a hardware private-key operation so unwrap requires touch.
			if _, err := km.cardReader.Sign(km.slot, dek); err != nil {
				return nil, &models.Error{
					Code:    models.ErrCodeDecryptionFailed,
					Message: "failed YubiKey touch verification during DEK unwrap",
					Err:     err,
				}
			}
		}
		return dek, nil
	}

	if err := km.ensureAuthenticatedReader(); err != nil {
		return nil, err
	}

	plaintext, err := km.cardReader.Decrypt(km.slot, encryptedDEK)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "failed to decrypt DEK with YubiKey private key",
			Err:     err,
		}
	}
	return plaintext, nil
}

// WrapDEK wraps a DEK for the client->KM rewrap flow.
// In FIPS mode this remains a passthrough to match existing FIPS server behavior.
// In non-FIPS mode, the YubiKey signs the DEK and returns a signed envelope.
func (km *YubiKeyKeyManager) WrapDEK(dek []byte) ([]byte, error) {
	if km.fipsEnabled {
		out := make([]byte, len(dek))
		copy(out, dek)
		return out, nil
	}

	if err := km.ensureAuthenticatedReader(); err != nil {
		return nil, err
	}

	signature, err := km.cardReader.Sign(km.slot, dek)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to sign DEK with YubiKey private key",
			Err:     err,
		}
	}

	envelope := yubiKeySignedDEKEnvelope{
		Version:   yubiKeySignedDEKEnvelopeVersion,
		DEK:       base64.StdEncoding.EncodeToString(dek),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, &models.Error{
			Code:    models.ErrCodeEncryptionFailed,
			Message: "failed to encode YubiKey DEK envelope",
			Err:     err,
		}
	}

	return encoded, nil
}

// GetKeyID returns the current key identifier used for KAS/KM calls.
func (km *YubiKeyKeyManager) GetKeyID() string {
	return km.keyID
}

// GetMetadata returns current key metadata.
func (km *YubiKeyKeyManager) GetMetadata() *models.KeyMetadata {
	return km.metadata
}

// Rotate re-registers the current YubiKey slot public key.
func (km *YubiKeyKeyManager) Rotate(ctx context.Context, kmClient models.KeyManagerClient, authToken string) error {
	if err := km.LoadOrGenerate(); err != nil {
		return err
	}
	return km.RegisterPublicKey(ctx, kmClient, authToken)
}

func (km *YubiKeyKeyManager) saveMetadata() error {
	if err := os.MkdirAll(km.keyStorePath, 0700); err != nil {
		return &models.Error{
			Code:    "METADATA_SAVE_FAILED",
			Message: "failed to create metadata directory",
			Err:     err,
		}
	}

	metadataPath := filepath.Join(km.keyStorePath, "key_metadata.json")
	metadataJSON, err := json.MarshalIndent(km.metadata, "", "  ")
	if err != nil {
		return &models.Error{
			Code:    "METADATA_SAVE_FAILED",
			Message: "failed to marshal metadata",
			Err:     err,
		}
	}

	if err := os.WriteFile(metadataPath, metadataJSON, 0600); err != nil {
		return &models.Error{
			Code:    "METADATA_SAVE_FAILED",
			Message: "failed to save metadata",
			Err:     err,
		}
	}
	return nil
}

func keyTypeFromRSAPublicKey(key *rsa.PublicKey) (keyManager.KeyType, error) {
	switch key.N.BitLen() {
	case 2048:
		return keyManager.KeyType_KEY_TYPE_RSA_2048, nil
	case 3072:
		return keyManager.KeyType_KEY_TYPE_RSA_3072, nil
	case 4096:
		return keyManager.KeyType_KEY_TYPE_RSA_4096, nil
	default:
		return keyManager.KeyType_KEY_TYPE_UNSPECIFIED, &models.Error{
			Code:    "KEY_TYPE_UNSUPPORTED",
			Message: fmt.Sprintf("unsupported RSA key size: %d", key.N.BitLen()),
		}
	}
}

func parseYubiKeyPlainDEKEnvelope(data []byte) ([]byte, bool, error) {
	var envelope yubiKeyPlainDEKEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, false, nil
	}
	if envelope.Version != yubiKeyPlainDEKEnvelopeVersion {
		return nil, false, nil
	}
	dek, err := base64.StdEncoding.DecodeString(envelope.DEK)
	if err != nil {
		return nil, true, &models.Error{
			Code:    models.ErrCodeDecryptionFailed,
			Message: "failed to decode YubiKey DEK envelope",
			Err:     err,
		}
	}
	return dek, true, nil
}
