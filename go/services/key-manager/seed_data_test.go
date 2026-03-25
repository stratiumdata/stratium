package key_manager

import (
	"os"
	"testing"

	"stratium/config"
	"stratium/pkg/security/encryption"
)

func TestLoadKeyManagerSeedData_FileNotFound(t *testing.T) {
	_, err := loadKeyManagerSeedData("/nonexistent/path/seed.yaml")
	if err == nil {
		t.Fatal("loadKeyManagerSeedData() should fail for nonexistent file")
	}
}

func TestLoadKeyManagerSeedData_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "seed_invalid_*.yaml")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString("{invalid yaml: [unclosed"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	f.Close()

	_, err = loadKeyManagerSeedData(f.Name())
	if err == nil {
		t.Fatal("loadKeyManagerSeedData() should fail for invalid YAML")
	}
}

func TestLoadKeyManagerSeedData_ValidYAML(t *testing.T) {
	yaml := `keys:
  - name: test-key-1
    key_type: RSA_2048
    provider_type: SOFTWARE
    rotation_policy: TIME_BASED
    rotation_interval_days: 30
    max_usage_count: 1000
    authorized_subjects:
      - user1
      - user2
    authorized_resources:
      - resource1
    metadata:
      env: test
  - name: test-key-2
    key_type: ECC_P256
    provider_type: SOFTWARE
`
	f, err := os.CreateTemp("", "seed_valid_*.yaml")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(yaml); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	f.Close()

	seed, err := loadKeyManagerSeedData(f.Name())
	if err != nil {
		t.Fatalf("loadKeyManagerSeedData() error = %v", err)
	}
	if seed == nil {
		t.Fatal("loadKeyManagerSeedData() returned nil seed")
	}
	if len(seed.Keys) != 2 {
		t.Errorf("loadKeyManagerSeedData() got %d keys, want 2", len(seed.Keys))
	}
	if seed.Keys[0].Name != "test-key-1" {
		t.Errorf("loadKeyManagerSeedData() Keys[0].Name = %q, want %q", seed.Keys[0].Name, "test-key-1")
	}
	if seed.Keys[0].RotationIntervalDays != 30 {
		t.Errorf("loadKeyManagerSeedData() Keys[0].RotationIntervalDays = %d, want 30", seed.Keys[0].RotationIntervalDays)
	}
}

func TestDefaultKeyManagerSeedData_RSA(t *testing.T) {
	seed := defaultKeyManagerSeedData(KeyType_KEY_TYPE_RSA_2048)
	if seed == nil {
		t.Fatal("defaultKeyManagerSeedData() returned nil")
	}
	if len(seed.Keys) == 0 {
		t.Error("defaultKeyManagerSeedData() returned empty keys list")
	}
	for _, k := range seed.Keys {
		if k.Name == "" {
			t.Error("defaultKeyManagerSeedData() key has empty name")
		}
	}
}

func TestDefaultKeyManagerSeedData_ECC(t *testing.T) {
	seed := defaultKeyManagerSeedData(KeyType_KEY_TYPE_ECC_P256)
	if seed == nil {
		t.Fatal("defaultKeyManagerSeedData() returned nil")
	}
	if len(seed.Keys) == 0 {
		t.Error("defaultKeyManagerSeedData() returned empty keys list for ECC")
	}
}

func TestParseKeyTypeFromSeed_Empty(t *testing.T) {
	got, err := parseKeyTypeFromSeed("", KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("parseKeyTypeFromSeed() empty error = %v", err)
	}
	if got != KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("parseKeyTypeFromSeed() empty = %v, want RSA_2048", got)
	}
}

func TestParseKeyTypeFromSeed_Valid(t *testing.T) {
	got, err := parseKeyTypeFromSeed("RSA_2048", KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Errorf("parseKeyTypeFromSeed() RSA_2048 error = %v", err)
	}
	if got != KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("parseKeyTypeFromSeed() RSA_2048 = %v, want RSA_2048", got)
	}
}

func TestParseKeyTypeFromSeed_Invalid(t *testing.T) {
	got, err := parseKeyTypeFromSeed("INVALID_TYPE", KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Error("parseKeyTypeFromSeed() INVALID_TYPE should return error")
	}
	// Returns default on error
	if got != KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("parseKeyTypeFromSeed() INVALID_TYPE = %v, want default RSA_2048", got)
	}
}

func TestParseProviderTypeFromSeed_Empty(t *testing.T) {
	got, err := parseProviderTypeFromSeed("", KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Errorf("parseProviderTypeFromSeed() empty error = %v", err)
	}
	if got != KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE {
		t.Errorf("parseProviderTypeFromSeed() empty = %v, want SOFTWARE", got)
	}
}

func TestParseProviderTypeFromSeed_Valid(t *testing.T) {
	got, err := parseProviderTypeFromSeed("SOFTWARE", KeyProviderType_KEY_PROVIDER_TYPE_HSM)
	if err != nil {
		t.Errorf("parseProviderTypeFromSeed() SOFTWARE error = %v", err)
	}
	if got != KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE {
		t.Errorf("parseProviderTypeFromSeed() SOFTWARE = %v, want SOFTWARE", got)
	}
}

func TestParseProviderTypeFromSeed_Invalid(t *testing.T) {
	got, err := parseProviderTypeFromSeed("INVALID_PROVIDER", KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err == nil {
		t.Error("parseProviderTypeFromSeed() INVALID_PROVIDER should return error")
	}
	if got != KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE {
		t.Errorf("parseProviderTypeFromSeed() INVALID_PROVIDER = %v, want default", got)
	}
}

func TestParseRotationPolicyFromSeed_Empty(t *testing.T) {
	got, err := parseRotationPolicyFromSeed("", RotationPolicy_ROTATION_POLICY_TIME_BASED)
	if err != nil {
		t.Errorf("parseRotationPolicyFromSeed() empty error = %v", err)
	}
	if got != RotationPolicy_ROTATION_POLICY_TIME_BASED {
		t.Errorf("parseRotationPolicyFromSeed() empty = %v, want TIME_BASED", got)
	}
}

func TestParseRotationPolicyFromSeed_Valid(t *testing.T) {
	got, err := parseRotationPolicyFromSeed("TIME_BASED", RotationPolicy_ROTATION_POLICY_MANUAL)
	if err != nil {
		t.Errorf("parseRotationPolicyFromSeed() TIME_BASED error = %v", err)
	}
	if got != RotationPolicy_ROTATION_POLICY_TIME_BASED {
		t.Errorf("parseRotationPolicyFromSeed() TIME_BASED = %v, want TIME_BASED", got)
	}
}

func TestParseRotationPolicyFromSeed_Invalid(t *testing.T) {
	got, err := parseRotationPolicyFromSeed("INVALID_POLICY", RotationPolicy_ROTATION_POLICY_TIME_BASED)
	if err == nil {
		t.Error("parseRotationPolicyFromSeed() INVALID_POLICY should return error")
	}
	if got != RotationPolicy_ROTATION_POLICY_TIME_BASED {
		t.Errorf("parseRotationPolicyFromSeed() INVALID_POLICY = %v, want default", got)
	}
}

func TestParseEnumValue_WithPrefix(t *testing.T) {
	// Passes an already-prefixed value
	v, err := parseEnumValue("KEY_TYPE_RSA_2048", "KEY_TYPE_", KeyType_value)
	if err != nil {
		t.Errorf("parseEnumValue() with prefix error = %v", err)
	}
	if KeyType(v) != KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("parseEnumValue() with prefix = %v, want RSA_2048", v)
	}
}

func TestParseEnumValue_WithoutPrefix(t *testing.T) {
	// Passes a value without the prefix - should be added
	v, err := parseEnumValue("RSA_2048", "KEY_TYPE_", KeyType_value)
	if err != nil {
		t.Errorf("parseEnumValue() without prefix error = %v", err)
	}
	if KeyType(v) != KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("parseEnumValue() without prefix = %v, want RSA_2048", v)
	}
}

func TestParseEnumValue_Empty(t *testing.T) {
	_, err := parseEnumValue("", "KEY_TYPE_", KeyType_value)
	if err == nil {
		t.Error("parseEnumValue() empty should return error")
	}
}

func TestParseEnumValue_Unknown(t *testing.T) {
	_, err := parseEnumValue("TOTALLY_UNKNOWN_VALUE", "KEY_TYPE_", KeyType_value)
	if err == nil {
		t.Error("parseEnumValue() unknown should return error")
	}
}

func TestApplyKeyManagerSeedData_NilSeed(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	err := server.applyKeyManagerSeedData(nil, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("applyKeyManagerSeedData() nil seed error = %v", err)
	}
}

func TestApplyKeyManagerSeedData_EmptyKeys(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	seed := &KeyManagerSeedData{Keys: []KeySeed{}}
	err := server.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("applyKeyManagerSeedData() empty keys error = %v", err)
	}
}

func TestApplyKeyManagerSeedData_ValidKeys(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:                 "seed-rsa-key",
				KeyType:              "RSA_2048",
				ProviderType:         "SOFTWARE",
				RotationPolicy:       "TIME_BASED",
				RotationIntervalDays: 90,
				MaxUsageCount:        0,
				AuthorizedSubjects:   []string{"user1"},
				AuthorizedResources:  []string{"resource1"},
				Metadata:             map[string]string{"env": "test"},
			},
		},
	}

	err := server.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("applyKeyManagerSeedData() valid keys error = %v", err)
	}
}

func TestApplyKeyManagerSeedData_SkipsEmptyName(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:     "", // Should be skipped
				KeyType:  "RSA_2048",
			},
			{
				Name:    "valid-key",
				KeyType: "RSA_2048",
			},
		},
	}

	err := server.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("applyKeyManagerSeedData() error = %v", err)
	}
}

func TestApplyKeyManagerSeedData_InvalidKeyType(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	// Invalid key type should use the default, not fail
	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:    "fallback-key",
				KeyType: "INVALID_KEY_TYPE",
			},
		},
	}

	err := server.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("applyKeyManagerSeedData() with invalid key type error = %v (should use default)", err)
	}
}

func TestApplyKeyManagerSeedData_ZeroRotationInterval(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	// Zero rotation interval should use default (90)
	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:                 "zero-interval-key",
				KeyType:              "RSA_2048",
				RotationIntervalDays: 0, // Should use default 90
			},
		},
	}

	err := server.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("applyKeyManagerSeedData() zero rotation interval error = %v", err)
	}
}

func TestInitializeSeedData_NilConfig(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	// initializeSeedData with nil config should use built-in defaults
	server.initializeSeedData(nil, KeyType_KEY_TYPE_RSA_2048)
}

func TestInitializeSeedData_SeedDisabled(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	cfg := &config.Config{
		KeyManager: config.KeyManagerConfig{
			SeedSampleData: false,
		},
	}
	// Should return early without seeding
	server.initializeSeedData(cfg, KeyType_KEY_TYPE_RSA_2048)
}

func TestInitializeSeedData_SeedEnabled_NoPath(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	cfg := &config.Config{
		KeyManager: config.KeyManagerConfig{
			SeedSampleData: true,
			SeedDataPath:   "", // No path, uses defaults
		},
	}
	server.initializeSeedData(cfg, KeyType_KEY_TYPE_RSA_2048)
}

func TestInitializeSeedData_SeedEnabled_WithPath(t *testing.T) {
	yaml := `keys:
  - name: init-test-key
    key_type: RSA_2048
    provider_type: SOFTWARE
`
	f, err := os.CreateTemp("", "init_seed_*.yaml")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(yaml); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	f.Close()

	server := newTestKeyManagerServer(t, encryption.RSA2048)
	cfg := &config.Config{
		KeyManager: config.KeyManagerConfig{
			SeedSampleData: true,
			SeedDataPath:   f.Name(),
		},
	}
	server.initializeSeedData(cfg, KeyType_KEY_TYPE_RSA_2048)
}

func TestInitializeSeedData_SeedEnabled_InvalidPath(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	cfg := &config.Config{
		KeyManager: config.KeyManagerConfig{
			SeedSampleData: true,
			SeedDataPath:   "/nonexistent/path.yaml",
		},
	}
	// Should log error and fall back to defaults
	server.initializeSeedData(cfg, KeyType_KEY_TYPE_RSA_2048)
}
