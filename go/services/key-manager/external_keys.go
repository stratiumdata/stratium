package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"stratium/config"

	"google.golang.org/protobuf/types/known/timestamppb"
)

type secretFetcher interface {
	FetchSecret(ctx context.Context, region, endpoint, secretID, versionID, versionStage string) (string, error)
}

// ExternalKeyLoader loads external key manifests into the key store
type ExternalKeyLoader struct {
	cfg            config.ExternalKeysConfig
	keyStore       KeyStore
	secretsFetcher secretFetcher
	now            func() time.Time
}

type ExternalKeyLoadReport struct {
	SourcesConfigured int
	SourcesProcessed  int
	KeysDiscovered    int
	KeysImported      int
	KeysFailed        int
	SourceReports     []ExternalKeySourceReport
}

type ExternalKeySourceReport struct {
	Name           string
	Type           string
	Location       string
	KeysDiscovered int
	KeysImported   int
	KeysFailed     int
	Errors         []string
}

type ExternalKeyManifest struct {
	KeyID                string                   `json:"key_id"`
	Name                 string                   `json:"name"`
	ClientID             string                   `json:"client_id"`
	Description          string                   `json:"description"`
	KeyType              string                   `json:"key_type"`
	ProviderType         string                   `json:"provider_type"`
	Status               string                   `json:"status"`
	RotationPolicy       string                   `json:"rotation_policy"`
	RotationIntervalDays int32                    `json:"rotation_interval_days"`
	MaxUsageCount        int64                    `json:"max_usage_count"`
	UsageCount           int64                    `json:"usage_count"`
	PublicKeyFile        string                   `json:"public_key_file"`
	PrivateKeyFile       string                   `json:"private_key_file"`
	Metadata             map[string]string        `json:"metadata"`
	ExpiresAt            string                   `json:"expires_at"`
	CreatedAt            string                   `json:"created_at"`
	LastRotated          string                   `json:"last_rotated"`
	PrivateKeySecretRef  *ManifestSecretReference `json:"private_key_secret_ref"`
	AdditionalProviders  []string                 `json:"additional_providers"`
	Tags                 map[string]string        `json:"tags"`
	ManifestMetadata     map[string]string        `json:"manifest_metadata"`
}

type ManifestSecretReference struct {
	Name         string `json:"name"`
	Region       string `json:"region"`
	VersionID    string `json:"version_id"`
	VersionStage string `json:"version_stage"`
	KeyField     string `json:"key_field"`
}

type fileDefaults struct {
	manifest string
	public   string
	private  string
}

func NewExternalKeyLoader(cfg config.ExternalKeysConfig, keyStore KeyStore) *ExternalKeyLoader {
	return &ExternalKeyLoader{
		cfg:      cfg,
		keyStore: keyStore,
		now:      time.Now,
	}
}

func (l *ExternalKeyLoader) Load(ctx context.Context) *ExternalKeyLoadReport {
	if !l.cfg.Enabled {
		return nil
	}
	if l.cfg.EmergencyDisable {
		logger.Info("External key loading skipped: emergency disable flag is set")
		return nil
	}
	if len(l.cfg.Sources) == 0 {
		logger.Info("External key loading enabled but no sources configured")
		return nil
	}

	report := &ExternalKeyLoadReport{
		SourcesConfigured: len(l.cfg.Sources),
		SourceReports:     make([]ExternalKeySourceReport, 0, len(l.cfg.Sources)),
	}

	for _, source := range l.cfg.Sources {
		select {
		case <-ctx.Done():
			report.SourceReports = append(report.SourceReports, ExternalKeySourceReport{
				Name:   source.Name,
				Type:   source.Type,
				Errors: []string{"context cancelled"},
			})
			return report
		default:
		}

		sourceReport := l.loadSource(ctx, source)
		report.SourceReports = append(report.SourceReports, sourceReport)
		report.SourcesProcessed++
		report.KeysDiscovered += sourceReport.KeysDiscovered
		report.KeysImported += sourceReport.KeysImported
		report.KeysFailed += sourceReport.KeysFailed
	}

	return report
}

func (l *ExternalKeyLoader) loadSource(ctx context.Context, source config.ExternalKeySourceConfig) ExternalKeySourceReport {
	logger.Info("Loading external key source %s", source.Name)

	sourceType := strings.ToLower(strings.TrimSpace(source.Type))
	if sourceType == "" {
		sourceType = "volume"
	}

	report := ExternalKeySourceReport{
		Name: source.Name,
		Type: sourceType,
	}

	switch sourceType {
	case "volume":
		report = l.loadVolumeSource(ctx, source)
	default:
		report.Errors = append(report.Errors, fmt.Sprintf("unsupported source type %q", sourceType))
		report.KeysFailed++
	}

	return report
}

func (l *ExternalKeyLoader) loadVolumeSource(ctx context.Context, source config.ExternalKeySourceConfig) ExternalKeySourceReport {
	report := ExternalKeySourceReport{
		Name: source.Name,
		Type: "volume",
	}
	if source.Volume == nil {
		report.Errors = append(report.Errors, "volume configuration missing")
		report.KeysFailed++
		return report
	}

	basePath := filepath.Clean(source.Volume.BasePath)
	report.Location = basePath
	logger.Info("Scanning external key source %s at %s (recursive=%t)", source.Name, basePath, source.Volume.Recursive)

	defs := fileDefaults{
		manifest: defaultOr(source.Volume.ManifestFile, "manifest.json"),
		public:   defaultOr(source.Volume.PublicKeyFile, "public.pem"),
		private:  defaultOr(source.Volume.PrivateKeyFile, "private.pem"),
	}

	dirs, err := l.discoverManifestDirs(basePath, defs.manifest, source.Volume.Recursive)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		report.KeysFailed++
		return report
	}

	if len(dirs) == 0 {
		logger.Info("External key source %s: no manifest directories found under %s", source.Name, basePath)
	}

	for _, dir := range dirs {
		logger.Info("External key source %s: processing manifest directory %s", source.Name, dir)
		select {
		case <-ctx.Done():
			report.Errors = append(report.Errors, "context cancelled while loading manifests")
			return report
		default:
		}

		manifestPath := filepath.Join(dir, defs.manifest)
		report.KeysDiscovered++
		if err := l.processManifestDirectory(ctx, source, dir, manifestPath, defs); err != nil {
			report.KeysFailed++
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", dir, err))
			continue
		}
		report.KeysImported++
	}

	return report
}

func (l *ExternalKeyLoader) processManifestDirectory(ctx context.Context, source config.ExternalKeySourceConfig, dirPath, manifestPath string, defs fileDefaults) error {
	logger.Info("External key source %s: reading manifest %s", source.Name, manifestPath)
	bytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest ExternalKeyManifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		return fmt.Errorf("invalid manifest JSON: %w", err)
	}

	applyManifestDefaults(&manifest, defs)

	if err := validateManifest(manifest); err != nil {
		logger.Info("External key source %s: manifest validation failed for %s: %v", source.Name, manifest.KeyID, err)
		return err
	}

	keyType, err := parseKeyTypeString(manifest.KeyType)
	if err != nil {
		logger.Info("External key source %s: unsupported key type for %s: %v", source.Name, manifest.KeyID, err)
		return err
	}

	providerType, err := parseProviderTypeString(manifest.ProviderType)
	if err != nil {
		logger.Info("External key source %s: unsupported provider type for %s: %v", source.Name, manifest.KeyID, err)
		return err
	}

	status, err := parseKeyStatusString(manifest.Status)
	if err != nil {
		logger.Info("External key source %s: invalid status for %s: %v", source.Name, manifest.KeyID, err)
		return err
	}

	rotationPolicy, err := parseRotationPolicyString(manifest.RotationPolicy)
	if err != nil {
		logger.Info("External key source %s: invalid rotation policy for %s: %v", source.Name, manifest.KeyID, err)
		return err
	}

	publicPath := filepath.Join(dirPath, manifest.PublicKeyFile)
	publicPEM, err := os.ReadFile(publicPath)
	if err != nil {
		logger.Info("External key source %s: failed to read public key for %s: %v", source.Name, manifest.KeyID, err)
		return fmt.Errorf("failed to read public key %s: %w", publicPath, err)
	}

	privatePEM, privateSource, err := l.resolvePrivateKey(ctx, manifest, dirPath, source)
	if err != nil {
		logger.Info("External key source %s: failed to resolve private key for %s: %v", source.Name, manifest.KeyID, err)
		return err
	}

	privateKey, err := parsePrivateKeyPEM(privatePEM, keyType)
	if err != nil {
		logger.Info("External key source %s: failed to parse private key for %s: %v", source.Name, manifest.KeyID, err)
		return err
	}

	createdAt := l.now().UTC()
	if manifest.CreatedAt != "" {
		if ts, err := time.Parse(time.RFC3339, manifest.CreatedAt); err == nil {
			createdAt = ts
		} else {
			return fmt.Errorf("invalid created_at timestamp: %w", err)
		}
	}

	var expiresAt *time.Time
	if manifest.ExpiresAt != "" {
		ts, err := time.Parse(time.RFC3339, manifest.ExpiresAt)
		if err != nil {
			return fmt.Errorf("invalid expires_at timestamp: %w", err)
		}
		expiresAt = &ts
	}

	var lastRotated *time.Time
	if manifest.LastRotated != "" {
		ts, err := time.Parse(time.RFC3339, manifest.LastRotated)
		if err != nil {
			return fmt.Errorf("invalid last_rotated timestamp: %w", err)
		}
		lastRotated = &ts
	}

	metadata := copyMetadata(manifest.Metadata)
	if manifest.Description != "" {
		metadata["description"] = manifest.Description
	}
	for k, v := range manifest.Tags {
		metadata["tag."+k] = v
	}
	for k, v := range manifest.ManifestMetadata {
		metadata["manifest."+k] = v
	}

	externalInfo := externalMetadataDescriptor{
		SourceName:       source.Name,
		ManifestPath:     manifestPath,
		LoaderType:       strings.ToLower(defaultOr(source.Type, "volume")),
		PrivateKeySource: privateSource,
		LoadedAt:         l.now().UTC(),
	}

	keyMetadata := applyExternalMetadata(copyMetadata(metadata), externalInfo)

	key := &Key{
		KeyId:                manifest.KeyID,
		Name:                 manifest.Name,
		ClientId:             manifest.ClientID,
		KeyType:              keyType,
		ProviderType:         providerType,
		Status:               status,
		PublicKeyPem:         string(publicPEM),
		CreatedAt:            timestamppb.New(createdAt),
		RotationPolicy:       rotationPolicy,
		RotationIntervalDays: manifest.RotationIntervalDays,
		UsageCount:           manifest.UsageCount,
		MaxUsageCount:        manifest.MaxUsageCount,
		Metadata:             keyMetadata,
		ExternallyManaged:    true,
		ExternalSource:       source.Name,
		ExternalManifestPath: manifestPath,
		PrivateKeySource:     privateSource,
		ExternalLoadedAt:     timestamppb.New(externalInfo.LoadedAt),
	}

	if expiresAt != nil {
		key.ExpiresAt = timestamppb.New(*expiresAt)
	}
	if lastRotated != nil {
		key.LastRotated = timestamppb.New(*lastRotated)
	}

	keyPair := &KeyPair{
		KeyID:                manifest.KeyID,
		KeyType:              keyType,
		ProviderType:         providerType,
		PublicKey:            nil,
		PrivateKey:           privateKey,
		PublicKeyPEM:         string(publicPEM),
		CreatedAt:            createdAt,
		ExpiresAt:            expiresAt,
		LastRotated:          lastRotated,
		UsageCount:           manifest.UsageCount,
		MaxUsageCount:        manifest.MaxUsageCount,
		Metadata:             applyExternalMetadata(copyMetadata(metadata), externalInfo),
		ExternallyManaged:    true,
		ExternalSource:       source.Name,
		ExternalManifestPath: manifestPath,
		PrivateKeySource:     privateSource,
		ExternalLoaderType:   externalInfo.LoaderType,
		ExternalLoadedAt:     &externalInfo.LoadedAt,
	}

	if err := l.keyStore.StoreKey(ctx, key); err != nil {
		logger.Info("External key source %s: failed to store key metadata for %s: %v", source.Name, manifest.KeyID, err)
		return fmt.Errorf("store key metadata: %w", err)
	}

	if err := l.keyStore.StoreKeyPair(ctx, keyPair); err != nil {
		logger.Info("External key source %s: failed to store key pair for %s: %v", source.Name, manifest.KeyID, err)
		return fmt.Errorf("store key pair: %w", err)
	}

	logger.Info("External key source %s: successfully imported key %s", source.Name, manifest.KeyID)
	return nil
}

func (l *ExternalKeyLoader) resolvePrivateKey(ctx context.Context, manifest ExternalKeyManifest, dirPath string, source config.ExternalKeySourceConfig) (string, string, error) {
	privatePath := filepath.Join(dirPath, manifest.PrivateKeyFile)
	if data, err := os.ReadFile(privatePath); err == nil {
		return string(data), fmt.Sprintf("file:%s", privatePath), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("failed to read private key file: %w", err)
	}

	if manifest.PrivateKeySecretRef == nil {
		return "", "", fmt.Errorf("private key not found for manifest %s", manifest.KeyID)
	}

	ref := manifest.PrivateKeySecretRef
	region := strings.TrimSpace(ref.Region)
	endpoint := ""
	keyField := strings.TrimSpace(ref.KeyField)

	if source.AWSSecretsManager != nil {
		if region == "" {
			region = strings.TrimSpace(source.AWSSecretsManager.Region)
		}
		if endpoint == "" {
			endpoint = strings.TrimSpace(source.AWSSecretsManager.Endpoint)
		}
		if keyField == "" {
			keyField = strings.TrimSpace(source.AWSSecretsManager.SecretKeyField)
		}
	}

	if ref.Name == "" {
		return "", "", errors.New("private key secret reference requires name")
	}

	fetcher := l.getSecretFetcher()
	payload, err := fetcher.FetchSecret(ctx, region, endpoint, ref.Name, ref.VersionID, ref.VersionStage)
	if err != nil {
		return "", "", err
	}

	payload, err = extractFieldFromJSON(payload, keyField)
	if err != nil {
		return "", "", err
	}

	if strings.TrimSpace(payload) == "" {
		return "", "", fmt.Errorf("secret %s returned empty payload", ref.Name)
	}

	return payload, fmt.Sprintf("aws-secrets-manager:%s", ref.Name), nil
}

func (l *ExternalKeyLoader) getSecretFetcher() secretFetcher {
	if l.secretsFetcher == nil {
		l.secretsFetcher = NewAWSSecretsManagerFetcher()
	}
	return l.secretsFetcher
}

func (l *ExternalKeyLoader) discoverManifestDirs(basePath, manifestFile string, recursive bool) ([]string, error) {
	info, err := os.Stat(basePath)
	if err != nil {
		return nil, fmt.Errorf("invalid base path %s: %w", basePath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("base path %s is not a directory", basePath)
	}

	var dirs []string
	if recursive {
		err = filepath.WalkDir(basePath, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if strings.EqualFold(d.Name(), manifestFile) {
				dirs = append(dirs, filepath.Dir(path))
			}
			return nil
		})
		return dirs, err
	}

	baseManifest := filepath.Join(basePath, manifestFile)
	if _, err := os.Stat(baseManifest); err == nil {
		dirs = append(dirs, basePath)
	}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		dir := filepath.Join(basePath, entry.Name())
		info, err := os.Stat(dir)
		if err != nil {
			logger.Info("External key loader: failed to stat %s: %v", dir, err)
			continue
		}
		logger.Info("External key loader: candidate entry %s (dir=%t)", dir, info.IsDir())
		if !info.IsDir() {
			continue
		}
		manifestPath := filepath.Join(dir, manifestFile)
		if _, err := os.Stat(manifestPath); err == nil {
			logger.Info("External key loader: found manifest at %s", manifestPath)
			dirs = append(dirs, dir)
		} else {
			logger.Info("External key loader: missing manifest %s: %v", manifestPath, err)
		}
	}

	return dirs, nil
}

func validateManifest(manifest ExternalKeyManifest) error {
	if strings.TrimSpace(manifest.KeyID) == "" {
		return errors.New("manifest key_id is required")
	}
	if strings.TrimSpace(manifest.Name) == "" {
		return errors.New("manifest name is required")
	}
	if strings.TrimSpace(manifest.KeyType) == "" {
		return errors.New("manifest key_type is required")
	}
	if strings.TrimSpace(manifest.ProviderType) == "" {
		return errors.New("manifest provider_type is required")
	}
	if manifest.PrivateKeyFile == "" && manifest.PrivateKeySecretRef == nil {
		return errors.New("either private_key_file or private_key_secret_ref must be provided")
	}
	return nil
}

func parseKeyTypeString(value string) (KeyType, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	switch normalized {
	case "KEY_TYPE_RSA_2048", "RSA2048":
		return KeyType_KEY_TYPE_RSA_2048, nil
	case "KEY_TYPE_RSA_3072", "RSA3072":
		return KeyType_KEY_TYPE_RSA_3072, nil
	case "KEY_TYPE_RSA_4096", "RSA4096":
		return KeyType_KEY_TYPE_RSA_4096, nil
	case "KEY_TYPE_ECC_P256", "ECC256", "P256":
		return KeyType_KEY_TYPE_ECC_P256, nil
	case "KEY_TYPE_ECC_P384", "ECC384", "P384":
		return KeyType_KEY_TYPE_ECC_P384, nil
	case "KEY_TYPE_ECC_P521", "ECC521", "P521":
		return KeyType_KEY_TYPE_ECC_P521, nil
	case "KEY_TYPE_KYBER_512", "KYBER512":
		return KeyType_KEY_TYPE_KYBER_512, nil
	case "KEY_TYPE_KYBER_768", "KYBER768":
		return KeyType_KEY_TYPE_KYBER_768, nil
	case "KEY_TYPE_KYBER_1024", "KYBER1024":
		return KeyType_KEY_TYPE_KYBER_1024, nil
	default:
		return KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported key_type %q", value)
	}
}

func parseProviderTypeString(value string) (KeyProviderType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "software":
		return KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE, nil
	case "hsm":
		return KeyProviderType_KEY_PROVIDER_TYPE_HSM, nil
	case "smart_card", "smartcard":
		return KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD, nil
	case "usb_token", "usb":
		return KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN, nil
	default:
		return KeyProviderType_KEY_PROVIDER_TYPE_UNSPECIFIED, fmt.Errorf("unsupported provider_type %q", value)
	}
}

func parseKeyStatusString(value string) (KeyStatus, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "active":
		return KeyStatus_KEY_STATUS_ACTIVE, nil
	case "inactive":
		return KeyStatus_KEY_STATUS_INACTIVE, nil
	case "pending_rotation":
		return KeyStatus_KEY_STATUS_PENDING_ROTATION, nil
	case "deprecated":
		return KeyStatus_KEY_STATUS_DEPRECATED, nil
	case "compromised":
		return KeyStatus_KEY_STATUS_COMPROMISED, nil
	case "revoked":
		return KeyStatus_KEY_STATUS_REVOKED, nil
	default:
		return KeyStatus_KEY_STATUS_UNSPECIFIED, fmt.Errorf("unsupported key status %q", value)
	}
}

func parseRotationPolicyString(value string) (RotationPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "manual":
		return RotationPolicy_ROTATION_POLICY_MANUAL, nil
	case "time_based", "time-based":
		return RotationPolicy_ROTATION_POLICY_TIME_BASED, nil
	case "usage_based", "usage-based":
		return RotationPolicy_ROTATION_POLICY_USAGE_BASED, nil
	case "combined":
		return RotationPolicy_ROTATION_POLICY_COMBINED, nil
	default:
		return RotationPolicy_ROTATION_POLICY_UNSPECIFIED, fmt.Errorf("unsupported rotation policy %q", value)
	}
}

func parsePrivateKeyPEM(pemData string, keyType KeyType) (any, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}

	switch keyType {
	case KeyType_KEY_TYPE_RSA_2048, KeyType_KEY_TYPE_RSA_3072, KeyType_KEY_TYPE_RSA_4096:
		if block.Type == "PRIVATE KEY" {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				if rsaKey, ok := key.(*rsa.PrivateKey); ok {
					return rsaKey, nil
				}
			}
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				return rsaKey, nil
			}
		}
		return nil, errors.New("failed to parse RSA private key")
	case KeyType_KEY_TYPE_ECC_P256, KeyType_KEY_TYPE_ECC_P384, KeyType_KEY_TYPE_ECC_P521:
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
				return ecKey, nil
			}
		}
		return nil, errors.New("failed to parse ECC private key")
	default:
		return nil, fmt.Errorf("external loader does not support key type %v yet", keyType)
	}
}

func copyMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return make(map[string]string)
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func applyManifestDefaults(manifest *ExternalKeyManifest, defs fileDefaults) {
	if manifest.PublicKeyFile == "" {
		manifest.PublicKeyFile = defs.public
	}
	if manifest.PrivateKeyFile == "" {
		manifest.PrivateKeyFile = defs.private
	}
	if manifest.Status == "" {
		manifest.Status = "active"
	}
	if manifest.RotationPolicy == "" {
		manifest.RotationPolicy = "manual"
	}
}

func defaultOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
