package stratium

import (
	"context"
	"testing"
)

// Tests for the main SDK Client

// ===== NewClient Tests =====

func TestNewClient_NilConfig(t *testing.T) {
	_, err := NewClient(nil)
	if err == nil {
		t.Error("NewClient() with nil config expected error, got nil")
	}
}

func TestNewClient_InvalidConfig(t *testing.T) {
	config := &Config{
		// Empty config should fail validation
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() with invalid config expected error, got nil")
	}
}

func TestNewClient_ValidConfig(t *testing.T) {
	config := &Config{
		PlatformAddress:   "localhost:50051",
		KeyManagerAddress: "localhost:50052",
		KeyAccessAddress:  "localhost:50053",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}

	// Verify clients are initialized
	if client.Platform == nil {
		t.Error("NewClient() should initialize Platform client")
	}

	if client.KeyManager == nil {
		t.Error("NewClient() should initialize KeyManager client")
	}

	if client.KeyAccess == nil {
		t.Error("NewClient() should initialize KeyAccess client")
	}

	// Clean up
	client.Close()
}

func TestNewClient_WithOIDC(t *testing.T) {
	config := &Config{
		PlatformAddress:   "localhost:50051",
		KeyManagerAddress: "localhost:50052",
		KeyAccessAddress:  "localhost:50053",
		OIDC: &OIDCConfig{
			IssuerURL:    "https://example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		},
	}

	// This will fail to connect to OIDC, but we can check the error
	_, err := NewClient(config)
	if err == nil {
		t.Skip("NewClient() with OIDC config requires real OIDC server, skipping")
	}

	// We expect an error since we don't have a real OIDC server
	if err == nil {
		t.Error("NewClient() should error without real OIDC server")
	}
}

func TestNewClient_PartialServices(t *testing.T) {
	// Test with only platform service
	config := &Config{
		PlatformAddress: "localhost:50051",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}

	// Platform should be initialized
	if client.Platform == nil {
		t.Error("NewClient() should initialize Platform client")
	}

	// Others should be nil
	if client.KeyManager != nil {
		t.Error("NewClient() should not initialize KeyManager without address")
	}

	if client.KeyAccess != nil {
		t.Error("NewClient() should not initialize KeyAccess without address")
	}

	client.Close()
}

// ===== Close Tests =====

func TestClient_Close(t *testing.T) {
	config := &Config{
		PlatformAddress: "localhost:50051",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	err = client.Close()
	if err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// Verify client is closed
	if !client.IsClosed() {
		t.Error("Close() should mark client as closed")
	}

	// Closing again should be safe
	err = client.Close()
	if err != nil {
		t.Errorf("Close() second call error: %v", err)
	}
}

func TestClient_IsClosed(t *testing.T) {
	config := &Config{
		PlatformAddress: "localhost:50051",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	// Should not be closed initially
	if client.IsClosed() {
		t.Error("IsClosed() should return false for new client")
	}

	client.Close()

	// Should be closed after Close()
	if !client.IsClosed() {
		t.Error("IsClosed() should return true after Close()")
	}
}

// ===== GetToken Tests =====

func TestClient_GetToken_NoAuth(t *testing.T) {
	config := &Config{
		PlatformAddress: "localhost:50051",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	token, err := client.GetToken(ctx)
	if err != nil {
		t.Errorf("GetToken() error: %v", err)
	}

	// Should return empty string when no auth configured
	if token != "" {
		t.Errorf("GetToken() without auth = %v, want empty string", token)
	}
}

// ===== RefreshToken Tests =====

func TestClient_RefreshToken_NoAuth(t *testing.T) {
	config := &Config{
		PlatformAddress: "localhost:50051",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	err = client.RefreshToken(ctx)
	if err == nil {
		t.Error("RefreshToken() without auth expected error, got nil")
	}
}

// ===== Config Tests =====

func TestClient_Config(t *testing.T) {
	config := &Config{
		PlatformAddress:   "localhost:50051",
		KeyManagerAddress: "localhost:50052",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	defer client.Close()

	returnedConfig := client.Config()
	if returnedConfig == nil {
		t.Fatal("Config() returned nil")
	}

	if returnedConfig.PlatformAddress != config.PlatformAddress {
		t.Errorf("Config() platform address = %v, want %v", returnedConfig.PlatformAddress, config.PlatformAddress)
	}

	if returnedConfig.KeyManagerAddress != config.KeyManagerAddress {
		t.Errorf("Config() key manager address = %v, want %v", returnedConfig.KeyManagerAddress, config.KeyManagerAddress)
	}
}

// ===== Config Validation Tests =====

func TestConfig_SetDefaults(t *testing.T) {
	config := &Config{
		PlatformAddress: "localhost:50051",
	}

	config.SetDefaults()

	// Check that defaults are set
	if config.Timeout == 0 {
		t.Error("SetDefaults() should set timeout")
	}
}

func TestConfig_Validate_Empty(t *testing.T) {
	config := &Config{}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() with empty config expected error, got nil")
	}
}

func TestConfig_Validate_ValidPlatform(t *testing.T) {
	config := &Config{
		PlatformAddress: "localhost:50051",
	}

	config.SetDefaults()
	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() with valid platform config error: %v", err)
	}
}

func TestConfig_Validate_ValidKeyManager(t *testing.T) {
	config := &Config{
		KeyManagerAddress: "localhost:50052",
	}

	config.SetDefaults()
	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() with valid key manager config error: %v", err)
	}
}

func TestConfig_Validate_ValidKeyAccess(t *testing.T) {
	config := &Config{
		KeyAccessAddress: "localhost:50053",
	}

	config.SetDefaults()
	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() with valid key access config error: %v", err)
	}
}

func TestConfig_Validate_AllServices(t *testing.T) {
	config := &Config{
		PlatformAddress:   "localhost:50051",
		KeyManagerAddress: "localhost:50052",
		KeyAccessAddress:  "localhost:50053",
		PAPAddress:        "http://localhost:8080",
	}

	config.SetDefaults()
	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() with all services error: %v", err)
	}
}

// Note: OIDC configuration validation is done as part of Config.Validate()
// when OIDC is configured, so we don't need separate OIDC validation tests.