package key_manager

import (
	"context"
	"fmt"
	"os"
	"strings"

	"stratium/config"

	"sigs.k8s.io/yaml"
)

type KeyManagerSeedData struct {
	Keys []KeySeed `json:"keys" yaml:"keys"`
}

type KeySeed struct {
	Name                 string            `json:"name" yaml:"name"`
	KeyType              string            `json:"key_type" yaml:"key_type"`
	ProviderType         string            `json:"provider_type" yaml:"provider_type"`
	RotationPolicy       string            `json:"rotation_policy" yaml:"rotation_policy"`
	RotationIntervalDays int32             `json:"rotation_interval_days" yaml:"rotation_interval_days"`
	MaxUsageCount        int64             `json:"max_usage_count" yaml:"max_usage_count"`
	AuthorizedSubjects   []string          `json:"authorized_subjects" yaml:"authorized_subjects"`
	AuthorizedResources  []string          `json:"authorized_resources" yaml:"authorized_resources"`
	Metadata             map[string]string `json:"metadata" yaml:"metadata"`
}

func (s *Server) initializeSeedData(cfg *config.Config, defaultKeyType KeyType) {
	if cfg != nil && !cfg.KeyManager.SeedSampleData {
		logger.Info("Key Manager sample data seeding disabled via configuration")
		return
	}

	var seedData *KeyManagerSeedData
	if cfg != nil && cfg.KeyManager.SeedDataPath != "" {
		data, err := loadKeyManagerSeedData(cfg.KeyManager.SeedDataPath)
		if err != nil {
			logger.Error("Failed to load key manager seed data from %s: %v", cfg.KeyManager.SeedDataPath, err)
		} else {
			logger.Info("Loaded key manager seed data from %s", cfg.KeyManager.SeedDataPath)
			seedData = data
		}
	}

	if seedData == nil {
		seedData = defaultKeyManagerSeedData(defaultKeyType)
		logger.Info("Using built-in key manager sample data")
	}

	if err := s.applyKeyManagerSeedData(seedData, defaultKeyType); err != nil {
		logger.Error("Failed to apply key manager seed data: %v", err)
	}
}

func loadKeyManagerSeedData(path string) (*KeyManagerSeedData, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read seed data file: %w", err)
	}

	var seed KeyManagerSeedData
	if err := yaml.Unmarshal(payload, &seed); err != nil {
		return nil, fmt.Errorf("failed to parse seed data: %w", err)
	}
	return &seed, nil
}

func (s *Server) applyKeyManagerSeedData(seed *KeyManagerSeedData, defaultKeyType KeyType) error {
	if seed == nil || len(seed.Keys) == 0 {
		return nil
	}

	ctx := context.Background()
	defaultProvider := KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE
	defaultRotationPolicy := RotationPolicy_ROTATION_POLICY_TIME_BASED
	defaultRotationInterval := int32(90)

	for _, keySeed := range seed.Keys {
		if keySeed.Name == "" {
			logger.Warn("Skipping key seed entry without a name")
			continue
		}

		keyType, err := parseKeyTypeFromSeed(keySeed.KeyType, defaultKeyType)
		if err != nil {
			logger.Warn("Seed key %s has invalid key_type '%s': %v. Using default %s", keySeed.Name, keySeed.KeyType, err, defaultKeyType)
		}

		providerType, err := parseProviderTypeFromSeed(keySeed.ProviderType, defaultProvider)
		if err != nil {
			logger.Warn("Seed key %s has invalid provider_type '%s': %v. Using default %s", keySeed.Name, keySeed.ProviderType, err, defaultProvider)
		}

		rotationPolicy, err := parseRotationPolicyFromSeed(keySeed.RotationPolicy, defaultRotationPolicy)
		if err != nil {
			logger.Warn("Seed key %s has invalid rotation_policy '%s': %v. Using default %s", keySeed.Name, keySeed.RotationPolicy, err, defaultRotationPolicy)
		}

		rotationInterval := keySeed.RotationIntervalDays
		if rotationInterval == 0 {
			rotationInterval = defaultRotationInterval
		}

		req := &CreateKeyRequest{
			Name:                 keySeed.Name,
			KeyType:              keyType,
			ProviderType:         providerType,
			RotationPolicy:       rotationPolicy,
			RotationIntervalDays: rotationInterval,
			MaxUsageCount:        keySeed.MaxUsageCount,
			AuthorizedSubjects:   keySeed.AuthorizedSubjects,
			AuthorizedResources:  keySeed.AuthorizedResources,
			Metadata:             map[string]string{},
		}
		for k, v := range keySeed.Metadata {
			req.Metadata[k] = v
		}

		if _, err := s.CreateKey(ctx, req); err != nil {
			logger.Error("failed to create seed key %s: %v", keySeed.Name, err)
		} else {
			logger.Info("created seed key: %s", keySeed.Name)
		}
	}

	return nil
}

func parseKeyTypeFromSeed(value string, defaultType KeyType) (KeyType, error) {
	if value == "" {
		return defaultType, nil
	}
	enumValue, err := parseEnumValue(value, "KEY_TYPE_", KeyType_value)
	if err != nil {
		return defaultType, err
	}
	return KeyType(enumValue), nil
}

func parseProviderTypeFromSeed(value string, defaultType KeyProviderType) (KeyProviderType, error) {
	if value == "" {
		return defaultType, nil
	}
	enumValue, err := parseEnumValue(value, "KEY_PROVIDER_TYPE_", KeyProviderType_value)
	if err != nil {
		return defaultType, err
	}
	return KeyProviderType(enumValue), nil
}

func parseRotationPolicyFromSeed(value string, defaultPolicy RotationPolicy) (RotationPolicy, error) {
	if value == "" {
		return defaultPolicy, nil
	}
	enumValue, err := parseEnumValue(value, "ROTATION_POLICY_", RotationPolicy_value)
	if err != nil {
		return defaultPolicy, err
	}
	return RotationPolicy(enumValue), nil
}

func parseEnumValue(value, prefix string, lookup map[string]int32) (int32, error) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if normalized == "" {
		return 0, fmt.Errorf("empty value")
	}
	if !strings.HasPrefix(normalized, prefix) {
		normalized = prefix + normalized
	}
	if v, ok := lookup[normalized]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("unknown value %s", value)
}

func defaultKeyManagerSeedData(defaultKeyType KeyType) *KeyManagerSeedData {
	keyTypeName := defaultKeyType.String()
	return &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:                 "service-encryption-key",
				KeyType:              keyTypeName,
				ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE.String(),
				RotationPolicy:       RotationPolicy_ROTATION_POLICY_TIME_BASED.String(),
				RotationIntervalDays: 90,
				AuthorizedSubjects:   []string{"user123", "service-account-1"},
				AuthorizedResources:  []string{"document-service", "user-service"},
				Metadata: map[string]string{
					"environment": "development",
					"created_by":  "seed_data_init",
				},
			},
			{
				Name:                 "backup-encryption-key",
				KeyType:              keyTypeName,
				ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE.String(),
				RotationPolicy:       RotationPolicy_ROTATION_POLICY_TIME_BASED.String(),
				RotationIntervalDays: 90,
				AuthorizedSubjects:   []string{"admin456", "backup-service"},
				AuthorizedResources:  []string{"backup-storage", "archive-service"},
				Metadata: map[string]string{
					"environment": "development",
					"created_by":  "seed_data_init",
				},
			},
		},
	}
}
