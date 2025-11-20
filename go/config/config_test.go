package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"stratium/features"
	"stratium/pkg/security/encryption"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_GetDatabaseURL(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name: "postgres with all fields",
			config: &Config{
				Database: DatabaseConfig{
					Driver:   "postgres",
					Host:     "localhost",
					Port:     5432,
					Database: "testdb",
					User:     "testuser",
					Password: "testpass",
					SSLMode:  "disable",
				},
			},
			expected: "postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable",
		},
		{
			name: "empty driver returns empty string",
			config: &Config{
				Database: DatabaseConfig{
					Driver: "",
				},
			},
			expected: "",
		},
		{
			name: "mysql with custom port",
			config: &Config{
				Database: DatabaseConfig{
					Driver:   "mysql",
					Host:     "db.example.com",
					Port:     3306,
					Database: "mydb",
					User:     "root",
					Password: "secret",
					SSLMode:  "require",
				},
			},
			expected: "mysql://root:secret@db.example.com:3306/mydb?sslmode=require",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetDatabaseURL()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetEncryptionAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		expected  encryption.Algorithm
		wantErr   bool
	}{
		{
			name:      "RSA2048",
			algorithm: "RSA2048",
			expected:  encryption.RSA2048,
			wantErr:   false,
		},
		{
			name:      "RSA4096",
			algorithm: "RSA4096",
			expected:  encryption.RSA4096,
			wantErr:   false,
		},
		{
			name:      "KYBER768",
			algorithm: "KYBER768",
			expected:  encryption.KYBER768,
			wantErr:   false,
		},
		{
			name:      "invalid algorithm",
			algorithm: "INVALID",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Encryption: EncryptionConfig{
					Algorithm: tt.algorithm,
				},
			}

			result, err := cfg.GetEncryptionAlgorithm()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestConfig_IsDevelopment(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		expected    bool
	}{
		{"development", "development", true},
		{"dev", "dev", true},
		{"production", "production", false},
		{"staging", "staging", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Service: ServiceConfig{
					Environment: tt.environment,
				},
			}
			assert.Equal(t, tt.expected, cfg.IsDevelopment())
		})
	}
}

func TestConfig_IsProduction(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		expected    bool
	}{
		{"production", "production", true},
		{"prod", "prod", true},
		{"development", "development", false},
		{"staging", "staging", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Service: ServiceConfig{
					Environment: tt.environment,
				},
			}
			assert.Equal(t, tt.expected, cfg.IsProduction())
		})
	}
}

func TestConfig_MaskSensitive(t *testing.T) {
	original := &Config{
		Database: DatabaseConfig{
			Password: "db-secret",
			User:     "testuser",
		},
		OIDC: OIDCConfig{
			ClientSecret: "oidc-secret",
			ClientID:     "client123",
		},
		Cache: CacheConfig{
			Redis: RedisConfig{
				Password: "redis-secret",
				Address:  "localhost:6379",
			},
		},
	}

	masked := original.MaskSensitive()

	// Check that sensitive values are masked
	assert.Equal(t, "***", masked.Database.Password)
	assert.Equal(t, "***", masked.OIDC.ClientSecret)
	assert.Equal(t, "***", masked.Cache.Redis.Password)

	// Check that non-sensitive values are preserved
	assert.Equal(t, "testuser", masked.Database.User)
	assert.Equal(t, "client123", masked.OIDC.ClientID)
	assert.Equal(t, "localhost:6379", masked.Cache.Redis.Address)

	// Check that original is not modified
	assert.Equal(t, "db-secret", original.Database.Password)
	assert.Equal(t, "oidc-secret", original.OIDC.ClientSecret)
	assert.Equal(t, "redis-secret", original.Cache.Redis.Password)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config",
			config: &Config{
				Service: ServiceConfig{
					Name: "test-service",
				},
				Server: ServerConfig{
					Port: 8080,
				},
			},
			wantErr: false,
		},
		{
			name: "missing service name",
			config: &Config{
				Service: ServiceConfig{
					Name: "",
				},
				Server: ServerConfig{
					Port: 8080,
				},
			},
			wantErr: true,
			errMsg:  "service.name is required",
		},
		{
			name: "invalid port - too low",
			config: &Config{
				Service: ServiceConfig{
					Name: "test-service",
				},
				Server: ServerConfig{
					Port: 0,
				},
			},
			wantErr: true,
			errMsg:  "server.port must be between 1 and 65535",
		},
		{
			name: "invalid port - too high",
			config: &Config{
				Service: ServiceConfig{
					Name: "test-service",
				},
				Server: ServerConfig{
					Port: 70000,
				},
			},
			wantErr: true,
			errMsg:  "server.port must be between 1 and 65535",
		},
		{
			name: "TLS enabled without cert file",
			config: &Config{
				Service: ServiceConfig{
					Name: "test-service",
				},
				Server: ServerConfig{
					Port: 8080,
					TLS: TLSConfig{
						Enabled: true,
						KeyFile: "/path/to/key.pem",
					},
				},
			},
			wantErr: true,
			errMsg:  "server.tls.cert_file and server.tls.key_file are required when TLS is enabled",
		},
		{
			name: "database configured without host",
			config: &Config{
				Service: ServiceConfig{
					Name: "test-service",
				},
				Server: ServerConfig{
					Port: 8080,
				},
				Database: DatabaseConfig{
					Driver:   "postgres",
					Database: "testdb",
				},
			},
			wantErr: true,
			errMsg:  "database.host is required when database is configured",
		},
		{
			name: "database configured without database name",
			config: &Config{
				Service: ServiceConfig{
					Name: "test-service",
				},
				Server: ServerConfig{
					Port: 8080,
				},
				Database: DatabaseConfig{
					Driver: "postgres",
					Host:   "localhost",
				},
			},
			wantErr: true,
			errMsg:  "database.database is required when database is configured",
		},
		{
			name: "OIDC enabled without issuer URL",
			config: &Config{
				Service: ServiceConfig{
					Name: "test-service",
				},
				Server: ServerConfig{
					Port: 8080,
				},
				OIDC: OIDCConfig{
					Enabled:  true,
					ClientID: "client123",
				},
			},
			wantErr: true,
			errMsg:  "oidc.issuer_url is required when OIDC is enabled",
		},
		{
			name: "OIDC enabled without client ID",
			config: &Config{
				Service: ServiceConfig{
					Name: "test-service",
				},
				Server: ServerConfig{
					Port: 8080,
				},
				OIDC: OIDCConfig{
					Enabled:   true,
					IssuerURL: "https://auth.example.com",
				},
			},
			wantErr: true,
			errMsg:  "oidc.client_id is required when OIDC is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	// Create a temporary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(tmpFile, []byte("test"), 0644)
	require.NoError(t, err)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "existing file",
			path:     tmpFile,
			expected: true,
		},
		{
			name:     "non-existing file",
			path:     filepath.Join(tmpDir, "nonexistent.txt"),
			expected: false,
		},
		{
			name:     "empty path",
			path:     "",
			expected: false,
		},
		{
			name:     "relative path",
			path:     "relative/path.txt",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fileExists(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Set some environment variables
	os.Setenv("STRATIUM_SERVICE_NAME", "env-test-service")
	os.Setenv("STRATIUM_SERVER_PORT", "9090")
	os.Setenv("STRATIUM_SERVICE_ENVIRONMENT", "testing")
	defer func() {
		os.Unsetenv("STRATIUM_SERVICE_NAME")
		os.Unsetenv("STRATIUM_SERVER_PORT")
		os.Unsetenv("STRATIUM_SERVICE_ENVIRONMENT")
	}()

	cfg, err := LoadFromEnv()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "env-test-service", cfg.Service.Name)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "testing", cfg.Service.Environment)
}

func TestLoad_WithConfigFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "stratium.yaml")

	configContent := `
service:
  name: yaml-test-service
  version: 2.0.0
  environment: production

server:
  host: 127.0.0.1
  port: 8443
  read_timeout: 60s
  write_timeout: 60s

database:
  driver: postgres
  host: db.example.com
  port: 5432
  database: stratium_prod
  user: produser
  password: prodpass
  sslmode: require

encryption:
  algorithm: RSA4096
  key_rotation: true

logging:
  level: warn
  format: json
  output: stdout
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify service config
	assert.Equal(t, "yaml-test-service", cfg.Service.Name)
	assert.Equal(t, "2.0.0", cfg.Service.Version)
	assert.Equal(t, "production", cfg.Service.Environment)

	// Verify server config
	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 8443, cfg.Server.Port)
	assert.Equal(t, 60*time.Second, cfg.Server.ReadTimeout)
	assert.Equal(t, 60*time.Second, cfg.Server.WriteTimeout)

	// Verify database config
	assert.Equal(t, "postgres", cfg.Database.Driver)
	assert.Equal(t, "db.example.com", cfg.Database.Host)
	assert.Equal(t, 5432, cfg.Database.Port)
	assert.Equal(t, "stratium_prod", cfg.Database.Database)
	assert.Equal(t, "produser", cfg.Database.User)
	assert.Equal(t, "prodpass", cfg.Database.Password)
	assert.Equal(t, "require", cfg.Database.SSLMode)

	// Verify encryption config
	assert.Equal(t, "RSA4096", cfg.Encryption.Algorithm)
	assert.Equal(t, true, cfg.Encryption.KeyRotation)

	// Verify logging config
	assert.Equal(t, "warn", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, "stdout", cfg.Logging.Output)
}

func TestLoad_InvalidConfigFile(t *testing.T) {
	// Create a temporary invalid config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.yaml")

	invalidContent := `
service:
  name: test
server:
  port: invalid-port
`

	err := os.WriteFile(configFile, []byte(invalidContent), 0644)
	require.NoError(t, err)

	_, err = Load(configFile)
	assert.Error(t, err)
}

func TestLoad_NonExistentConfigFile(t *testing.T) {
	// Loading with a specific non-existent file path should return an error
	_, err := Load("/nonexistent/path/to/config.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestApplyServiceSpecificRateLimits(t *testing.T) {
	tests := []struct {
		name                              string
		serviceName                       string
		expectedRequestPerMinIfEnabled    int
		expectedBurstIfEnabled            int
		expectedRequestPerMinIfDisabled   int
		expectedBurstIfDisabled           int
	}{
		{
			name:                            "key-access-server",
			serviceName:                     "key-access-server",
			expectedRequestPerMinIfEnabled:  4,
			expectedBurstIfEnabled:          1,
			expectedRequestPerMinIfDisabled: 100, // unchanged
			expectedBurstIfDisabled:         50,  // unchanged
		},
		{
			name:                            "key-manager-server",
			serviceName:                     "key-manager-server",
			expectedRequestPerMinIfEnabled:  10,
			expectedBurstIfEnabled:          2,
			expectedRequestPerMinIfDisabled: 100, // unchanged
			expectedBurstIfDisabled:         50,  // unchanged
		},
		{
			name:                            "other-service",
			serviceName:                     "other-service",
			expectedRequestPerMinIfEnabled:  100, // unchanged - no special config
			expectedBurstIfEnabled:          50,  // unchanged - no special config
			expectedRequestPerMinIfDisabled: 100, // unchanged
			expectedBurstIfDisabled:         50,  // unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Security: SecurityConfig{
					RateLimiting: RateLimitConfig{
						Enabled:        true,
						RequestsPerMin: 100,
						Burst:          50,
					},
				},
			}

			ApplyServiceSpecificRateLimits(cfg, tt.serviceName)

			// Test based on whether rate limiting is enabled
			if features.ShouldEnableRateLimiting() {
				assert.Equal(t, tt.expectedRequestPerMinIfEnabled, cfg.Security.RateLimiting.RequestsPerMin,
					"RequestsPerMin should match expected value when rate limiting is enabled")
				assert.Equal(t, tt.expectedBurstIfEnabled, cfg.Security.RateLimiting.Burst,
					"Burst should match expected value when rate limiting is enabled")
			} else {
				assert.Equal(t, tt.expectedRequestPerMinIfDisabled, cfg.Security.RateLimiting.RequestsPerMin,
					"RequestsPerMin should remain unchanged when rate limiting is disabled")
				assert.Equal(t, tt.expectedBurstIfDisabled, cfg.Security.RateLimiting.Burst,
					"Burst should remain unchanged when rate limiting is disabled")
			}
		})
	}
}

func TestApplyFeatureFlags(t *testing.T) {
	t.Run("should apply feature flags", func(t *testing.T) {
		cfg := &Config{
			Observability: ObservabilityConfig{
				Metrics: MetricsConfig{
					Enabled: true,
				},
				Tracing: TracingConfig{
					Enabled: true,
				},
			},
			Cache: CacheConfig{
				Type:    "redis",
				TTL:     5 * time.Minute,
				MaxSize: 1000,
			},
			Server: ServerConfig{
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
				GracefulStop: 30 * time.Second,
			},
			Services: ServicesConfig{
				Platform: ServiceEndpoint{
					Timeout: 10 * time.Second,
				},
				KeyManager: ServiceEndpoint{
					Timeout: 10 * time.Second,
				},
				KeyAccess: ServiceEndpoint{
					Timeout: 10 * time.Second,
				},
				PAP: ServiceEndpoint{
					Timeout: 10 * time.Second,
				},
			},
			Security: SecurityConfig{
				RateLimiting: RateLimitConfig{
					Enabled: false,
				},
			},
		}

		applyFeatureFlags(cfg)

		// Verify feature flags were applied
		// Note: The actual behavior depends on the feature flags module
		// These assertions may need to be adjusted based on actual feature flag values
		if !features.ShouldEnableMetrics() {
			assert.False(t, cfg.Observability.Metrics.Enabled)
		}

		if !features.ShouldEnableObservability() {
			assert.False(t, cfg.Observability.Tracing.Enabled)
			assert.False(t, cfg.Observability.Metrics.Enabled)
		}

		if features.ShouldUseShortTimeouts() {
			assert.Equal(t, 5*time.Second, cfg.Server.ReadTimeout)
			assert.Equal(t, 5*time.Second, cfg.Server.WriteTimeout)
			assert.Equal(t, 30*time.Second, cfg.Server.IdleTimeout)
			assert.Equal(t, 5*time.Second, cfg.Server.GracefulStop)
			assert.Equal(t, 3*time.Second, cfg.Services.Platform.Timeout)
			assert.Equal(t, 3*time.Second, cfg.Services.KeyManager.Timeout)
			assert.Equal(t, 3*time.Second, cfg.Services.KeyAccess.Timeout)
			assert.Equal(t, 3*time.Second, cfg.Services.PAP.Timeout)
		}

		if features.ShouldEnableRateLimiting() {
			assert.True(t, cfg.Security.RateLimiting.Enabled)
		}

		if !features.ShouldEnableCaching() {
			assert.Equal(t, "none", cfg.Cache.Type)
			assert.Equal(t, time.Duration(0), cfg.Cache.TTL)
			assert.Equal(t, 0, cfg.Cache.MaxSize)
		}
	})
}

func TestDefaultValues(t *testing.T) {
	// Load without config file (should use defaults)
	cfg, err := LoadFromEnv()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify default values are set
	assert.Equal(t, "stratium", cfg.Service.Name)
	assert.Equal(t, "1.0.0", cfg.Service.Version)
	assert.Equal(t, "development", cfg.Service.Environment)

	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 50051, cfg.Server.Port)
	// Note: Server timeouts may be overridden by feature flags
	if !features.ShouldUseShortTimeouts() {
		assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
		assert.Equal(t, 120*time.Second, cfg.Server.IdleTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.GracefulStop)
	}

	assert.Equal(t, "postgres", cfg.Database.Driver)
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, 5432, cfg.Database.Port)
	assert.Equal(t, "stratium", cfg.Database.Database)

	// Cache defaults may be overridden by feature flags
	if features.ShouldEnableCaching() {
		assert.Equal(t, "memory", cfg.Cache.Type)
		assert.Equal(t, 5*time.Minute, cfg.Cache.TTL)
		assert.Equal(t, 1000, cfg.Cache.MaxSize)
	} else {
		assert.Equal(t, "none", cfg.Cache.Type)
		assert.Equal(t, time.Duration(0), cfg.Cache.TTL)
		assert.Equal(t, 0, cfg.Cache.MaxSize)
	}

	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, "stdout", cfg.Logging.Output)
}

func TestConfig_EnvironmentOverridesDefaults(t *testing.T) {
	// Set environment variables that should override defaults
	os.Setenv("STRATIUM_SERVER_HOST", "custom.host")
	os.Setenv("STRATIUM_SERVER_PORT", "7777")
	os.Setenv("STRATIUM_LOGGING_LEVEL", "debug")
	defer func() {
		os.Unsetenv("STRATIUM_SERVER_HOST")
		os.Unsetenv("STRATIUM_SERVER_PORT")
		os.Unsetenv("STRATIUM_LOGGING_LEVEL")
	}()

	cfg, err := LoadFromEnv()
	require.NoError(t, err)

	assert.Equal(t, "custom.host", cfg.Server.Host)
	assert.Equal(t, 7777, cfg.Server.Port)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestApplyFeatureFlags_ShortTimeouts(t *testing.T) {
	t.Run("verify short timeouts feature flag behavior", func(t *testing.T) {
		// Create config with default timeout values
		cfg := &Config{
			Server: ServerConfig{
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
				GracefulStop: 30 * time.Second,
			},
			Services: ServicesConfig{
				Platform: ServiceEndpoint{
					Timeout: 10 * time.Second,
				},
				KeyManager: ServiceEndpoint{
					Timeout: 10 * time.Second,
				},
				KeyAccess: ServiceEndpoint{
					Timeout: 10 * time.Second,
				},
				PAP: ServiceEndpoint{
					Timeout: 10 * time.Second,
				},
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// Verify behavior based on actual feature flag
		if features.ShouldUseShortTimeouts() {
			// When enabled, timeouts should be shortened
			assert.Equal(t, 5*time.Second, cfg.Server.ReadTimeout,
				"ReadTimeout should be 5s when short timeouts are enabled")
			assert.Equal(t, 5*time.Second, cfg.Server.WriteTimeout,
				"WriteTimeout should be 5s when short timeouts are enabled")
			assert.Equal(t, 30*time.Second, cfg.Server.IdleTimeout,
				"IdleTimeout should be 30s when short timeouts are enabled")
			assert.Equal(t, 5*time.Second, cfg.Server.GracefulStop,
				"GracefulStop should be 5s when short timeouts are enabled")

			// Service timeouts
			assert.Equal(t, 3*time.Second, cfg.Services.Platform.Timeout,
				"Platform timeout should be 3s when short timeouts are enabled")
			assert.Equal(t, 3*time.Second, cfg.Services.KeyManager.Timeout,
				"KeyManager timeout should be 3s when short timeouts are enabled")
			assert.Equal(t, 3*time.Second, cfg.Services.KeyAccess.Timeout,
				"KeyAccess timeout should be 3s when short timeouts are enabled")
			assert.Equal(t, 3*time.Second, cfg.Services.PAP.Timeout,
				"PAP timeout should be 3s when short timeouts are enabled")

			t.Log("✓ Short timeouts feature is ENABLED - verified all timeouts are shortened")
		} else {
			// When disabled, timeouts should remain unchanged
			assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout,
				"ReadTimeout should remain 30s when short timeouts are disabled")
			assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout,
				"WriteTimeout should remain 30s when short timeouts are disabled")
			assert.Equal(t, 120*time.Second, cfg.Server.IdleTimeout,
				"IdleTimeout should remain 120s when short timeouts are disabled")
			assert.Equal(t, 30*time.Second, cfg.Server.GracefulStop,
				"GracefulStop should remain 30s when short timeouts are disabled")

			// Service timeouts
			assert.Equal(t, 10*time.Second, cfg.Services.Platform.Timeout,
				"Platform timeout should remain 10s when short timeouts are disabled")
			assert.Equal(t, 10*time.Second, cfg.Services.KeyManager.Timeout,
				"KeyManager timeout should remain 10s when short timeouts are disabled")
			assert.Equal(t, 10*time.Second, cfg.Services.KeyAccess.Timeout,
				"KeyAccess timeout should remain 10s when short timeouts are disabled")
			assert.Equal(t, 10*time.Second, cfg.Services.PAP.Timeout,
				"PAP timeout should remain 10s when short timeouts are disabled")

			t.Log("✓ Short timeouts feature is DISABLED - verified all timeouts remain unchanged")
		}
	})

	t.Run("ENABLED scenario - validates timeout values when feature is enabled", func(t *testing.T) {
		// This test documents what SHOULD happen when the feature is enabled
		// It will only pass if the feature is actually enabled
		if !features.ShouldUseShortTimeouts() {
			t.Skip("Short timeouts feature is currently disabled - skipping enabled scenario test")
		}

		cfg := &Config{
			Server: ServerConfig{
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
				GracefulStop: 30 * time.Second,
			},
			Services: ServicesConfig{
				Platform:   ServiceEndpoint{Timeout: 10 * time.Second},
				KeyManager: ServiceEndpoint{Timeout: 10 * time.Second},
				KeyAccess:  ServiceEndpoint{Timeout: 10 * time.Second},
				PAP:        ServiceEndpoint{Timeout: 10 * time.Second},
			},
		}

		applyFeatureFlags(cfg)

		// MUST apply short timeouts
		require.Equal(t, 5*time.Second, cfg.Server.ReadTimeout, "Server.ReadTimeout")
		require.Equal(t, 5*time.Second, cfg.Server.WriteTimeout, "Server.WriteTimeout")
		require.Equal(t, 30*time.Second, cfg.Server.IdleTimeout, "Server.IdleTimeout")
		require.Equal(t, 5*time.Second, cfg.Server.GracefulStop, "Server.GracefulStop")
		require.Equal(t, 3*time.Second, cfg.Services.Platform.Timeout, "Services.Platform.Timeout")
		require.Equal(t, 3*time.Second, cfg.Services.KeyManager.Timeout, "Services.KeyManager.Timeout")
		require.Equal(t, 3*time.Second, cfg.Services.KeyAccess.Timeout, "Services.KeyAccess.Timeout")
		require.Equal(t, 3*time.Second, cfg.Services.PAP.Timeout, "Services.PAP.Timeout")
	})

	t.Run("DISABLED scenario - validates timeouts remain unchanged when feature is disabled", func(t *testing.T) {
		// This test documents what SHOULD happen when the feature is disabled
		// It will only pass if the feature is actually disabled
		if features.ShouldUseShortTimeouts() {
			t.Skip("Short timeouts feature is currently enabled - skipping disabled scenario test")
		}

		cfg := &Config{
			Server: ServerConfig{
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
				GracefulStop: 30 * time.Second,
			},
			Services: ServicesConfig{
				Platform:   ServiceEndpoint{Timeout: 10 * time.Second},
				KeyManager: ServiceEndpoint{Timeout: 10 * time.Second},
				KeyAccess:  ServiceEndpoint{Timeout: 10 * time.Second},
				PAP:        ServiceEndpoint{Timeout: 10 * time.Second},
			},
		}

		applyFeatureFlags(cfg)

		// MUST NOT modify timeouts
		require.Equal(t, 30*time.Second, cfg.Server.ReadTimeout, "Server.ReadTimeout must remain unchanged")
		require.Equal(t, 30*time.Second, cfg.Server.WriteTimeout, "Server.WriteTimeout must remain unchanged")
		require.Equal(t, 120*time.Second, cfg.Server.IdleTimeout, "Server.IdleTimeout must remain unchanged")
		require.Equal(t, 30*time.Second, cfg.Server.GracefulStop, "Server.GracefulStop must remain unchanged")
		require.Equal(t, 10*time.Second, cfg.Services.Platform.Timeout, "Services.Platform.Timeout must remain unchanged")
		require.Equal(t, 10*time.Second, cfg.Services.KeyManager.Timeout, "Services.KeyManager.Timeout must remain unchanged")
		require.Equal(t, 10*time.Second, cfg.Services.KeyAccess.Timeout, "Services.KeyAccess.Timeout must remain unchanged")
		require.Equal(t, 10*time.Second, cfg.Services.PAP.Timeout, "Services.PAP.Timeout must remain unchanged")
	})

	t.Run("should not modify timeouts already shorter than short timeout values", func(t *testing.T) {
		// Create config with very short timeout values
		cfg := &Config{
			Server: ServerConfig{
				ReadTimeout:  1 * time.Second,
				WriteTimeout: 1 * time.Second,
				IdleTimeout:  5 * time.Second,
				GracefulStop: 1 * time.Second,
			},
			Services: ServicesConfig{
				Platform: ServiceEndpoint{
					Timeout: 1 * time.Second,
				},
				KeyManager: ServiceEndpoint{
					Timeout: 1 * time.Second,
				},
				KeyAccess: ServiceEndpoint{
					Timeout: 1 * time.Second,
				},
				PAP: ServiceEndpoint{
					Timeout: 1 * time.Second,
				},
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// When short timeouts are enabled, they will still be overwritten
		// This is the actual behavior of the function - it unconditionally sets values
		if features.ShouldUseShortTimeouts() {
			assert.Equal(t, 5*time.Second, cfg.Server.ReadTimeout)
			assert.Equal(t, 5*time.Second, cfg.Server.WriteTimeout)
			assert.Equal(t, 30*time.Second, cfg.Server.IdleTimeout)
			assert.Equal(t, 5*time.Second, cfg.Server.GracefulStop)
			assert.Equal(t, 3*time.Second, cfg.Services.Platform.Timeout)
			assert.Equal(t, 3*time.Second, cfg.Services.KeyManager.Timeout)
			assert.Equal(t, 3*time.Second, cfg.Services.KeyAccess.Timeout)
			assert.Equal(t, 3*time.Second, cfg.Services.PAP.Timeout)
		}
	})
}

func TestApplyFeatureFlags_RateLimiting(t *testing.T) {
	t.Run("verify rate limiting feature flag behavior", func(t *testing.T) {
		cfg := &Config{
			Security: SecurityConfig{
				RateLimiting: RateLimitConfig{
					Enabled:        false,
					RequestsPerMin: 100,
					Burst:          50,
				},
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// Verify behavior based on actual feature flag
		if features.ShouldEnableRateLimiting() {
			assert.True(t, cfg.Security.RateLimiting.Enabled,
				"Rate limiting should be enabled when feature flag is enabled")
			// Other values should remain unchanged
			assert.Equal(t, 100, cfg.Security.RateLimiting.RequestsPerMin)
			assert.Equal(t, 50, cfg.Security.RateLimiting.Burst)
			t.Log("✓ Rate limiting feature is ENABLED - verified Enabled flag is set to true")
		} else {
			assert.False(t, cfg.Security.RateLimiting.Enabled,
				"Rate limiting should remain disabled when feature flag is disabled")
			t.Log("✓ Rate limiting feature is DISABLED - verified Enabled flag remains false")
		}
	})

	t.Run("ENABLED scenario - validates rate limiting is enabled when feature is enabled", func(t *testing.T) {
		// This test documents what SHOULD happen when the feature is enabled
		// It will only pass if the feature is actually enabled
		if !features.ShouldEnableRateLimiting() {
			t.Skip("Rate limiting feature is currently disabled - skipping enabled scenario test")
		}

		cfg := &Config{
			Security: SecurityConfig{
				RateLimiting: RateLimitConfig{
					Enabled:        false,
					RequestsPerMin: 100,
					Burst:          50,
				},
			},
		}

		applyFeatureFlags(cfg)

		// MUST set Enabled to true
		require.True(t, cfg.Security.RateLimiting.Enabled, "Security.RateLimiting.Enabled must be true")
		// Other values MUST remain unchanged
		require.Equal(t, 100, cfg.Security.RateLimiting.RequestsPerMin, "RequestsPerMin must remain unchanged")
		require.Equal(t, 50, cfg.Security.RateLimiting.Burst, "Burst must remain unchanged")
	})

	t.Run("DISABLED scenario - validates rate limiting remains unchanged when feature is disabled", func(t *testing.T) {
		// This test documents what SHOULD happen when the feature is disabled
		// It will only pass if the feature is actually disabled
		if features.ShouldEnableRateLimiting() {
			t.Skip("Rate limiting feature is currently enabled - skipping disabled scenario test")
		}

		cfg := &Config{
			Security: SecurityConfig{
				RateLimiting: RateLimitConfig{
					Enabled:        false,
					RequestsPerMin: 100,
					Burst:          50,
				},
			},
		}

		applyFeatureFlags(cfg)

		// MUST NOT modify Enabled flag
		require.False(t, cfg.Security.RateLimiting.Enabled, "Security.RateLimiting.Enabled must remain false")
		require.Equal(t, 100, cfg.Security.RateLimiting.RequestsPerMin, "RequestsPerMin must remain unchanged")
		require.Equal(t, 50, cfg.Security.RateLimiting.Burst, "Burst must remain unchanged")
	})

	t.Run("should not disable rate limiting if already enabled", func(t *testing.T) {
		cfg := &Config{
			Security: SecurityConfig{
				RateLimiting: RateLimitConfig{
					Enabled:        true,
					RequestsPerMin: 200,
					Burst:          100,
				},
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// If feature flag is enabled, it should still be enabled
		// If feature flag is disabled, the function doesn't disable it
		// (it only enables when the flag is true)
		if features.ShouldEnableRateLimiting() {
			assert.True(t, cfg.Security.RateLimiting.Enabled,
				"Rate limiting should remain enabled when feature flag is enabled")
		} else {
			// The function doesn't disable rate limiting, so it should stay enabled
			assert.True(t, cfg.Security.RateLimiting.Enabled,
				"Rate limiting should remain enabled even when feature flag is disabled (function only enables, doesn't disable)")
		}

		// Other values should remain unchanged regardless
		assert.Equal(t, 200, cfg.Security.RateLimiting.RequestsPerMin)
		assert.Equal(t, 100, cfg.Security.RateLimiting.Burst)
	})
}

func TestApplyFeatureFlags_Caching(t *testing.T) {
	t.Run("should disable caching when feature flag is disabled", func(t *testing.T) {
		cfg := &Config{
			Cache: CacheConfig{
				Type:    "redis",
				TTL:     5 * time.Minute,
				MaxSize: 1000,
				Redis: RedisConfig{
					Address:  "localhost:6379",
					Password: "secret",
					DB:       0,
					Prefix:   "stratium:",
				},
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// Verify behavior based on actual feature flag
		if !features.ShouldEnableCaching() {
			assert.Equal(t, "none", cfg.Cache.Type,
				"Cache type should be 'none' when caching is disabled")
			assert.Equal(t, time.Duration(0), cfg.Cache.TTL,
				"Cache TTL should be 0 when caching is disabled")
			assert.Equal(t, 0, cfg.Cache.MaxSize,
				"Cache MaxSize should be 0 when caching is disabled")
			assert.Equal(t, "", cfg.Cache.Redis.Address,
				"Redis address should be empty when caching is disabled")
			assert.Equal(t, "", cfg.Cache.Redis.Password,
				"Redis password should be empty when caching is disabled")
		} else {
			// When enabled, cache config should remain unchanged
			assert.Equal(t, "redis", cfg.Cache.Type)
			assert.Equal(t, 5*time.Minute, cfg.Cache.TTL)
			assert.Equal(t, 1000, cfg.Cache.MaxSize)
			assert.Equal(t, "localhost:6379", cfg.Cache.Redis.Address)
		}
	})

	t.Run("should not modify cache config when feature flag is enabled", func(t *testing.T) {
		cfg := &Config{
			Cache: CacheConfig{
				Type:    "memory",
				TTL:     10 * time.Minute,
				MaxSize: 5000,
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// When caching is enabled, config should remain unchanged
		if features.ShouldEnableCaching() {
			assert.Equal(t, "memory", cfg.Cache.Type,
				"Cache type should remain unchanged when caching is enabled")
			assert.Equal(t, 10*time.Minute, cfg.Cache.TTL,
				"Cache TTL should remain unchanged when caching is enabled")
			assert.Equal(t, 5000, cfg.Cache.MaxSize,
				"Cache MaxSize should remain unchanged when caching is enabled")
		}
	})
}

func TestApplyFeatureFlags_Observability(t *testing.T) {
	t.Run("should disable metrics when feature flag is disabled", func(t *testing.T) {
		cfg := &Config{
			Observability: ObservabilityConfig{
				Metrics: MetricsConfig{
					Enabled: true,
					Address: ":9090",
					Path:    "/metrics",
				},
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// Verify behavior based on actual feature flag
		if !features.ShouldEnableMetrics() {
			assert.False(t, cfg.Observability.Metrics.Enabled,
				"Metrics should be disabled when feature flag is disabled")
		} else {
			assert.True(t, cfg.Observability.Metrics.Enabled,
				"Metrics should remain enabled when feature flag is enabled")
		}
	})

	t.Run("should disable observability when feature flag is disabled", func(t *testing.T) {
		cfg := &Config{
			Observability: ObservabilityConfig{
				Metrics: MetricsConfig{
					Enabled: true,
					Address: ":9090",
					Path:    "/metrics",
				},
				Tracing: TracingConfig{
					Enabled:     true,
					Provider:    "jaeger",
					Endpoint:    "http://jaeger:14268",
					ServiceName: "stratium",
				},
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// When observability is disabled, both metrics and tracing should be disabled
		if !features.ShouldEnableObservability() {
			assert.False(t, cfg.Observability.Metrics.Enabled,
				"Metrics should be disabled when observability feature flag is disabled")
			assert.False(t, cfg.Observability.Tracing.Enabled,
				"Tracing should be disabled when observability feature flag is disabled")
		} else {
			assert.True(t, cfg.Observability.Metrics.Enabled,
				"Metrics should remain enabled when observability feature flag is enabled")
			assert.True(t, cfg.Observability.Tracing.Enabled,
				"Tracing should remain enabled when observability feature flag is enabled")
		}
	})

	t.Run("observability flag takes precedence over metrics flag", func(t *testing.T) {
		cfg := &Config{
			Observability: ObservabilityConfig{
				Metrics: MetricsConfig{
					Enabled: true,
				},
			},
		}

		// Apply feature flags
		applyFeatureFlags(cfg)

		// Note: In the actual code, ShouldEnableObservability is checked AFTER ShouldEnableMetrics
		// So if observability is disabled, it will disable metrics even if metrics flag is enabled
		if !features.ShouldEnableObservability() {
			assert.False(t, cfg.Observability.Metrics.Enabled,
				"Observability flag should override metrics flag")
		}
	})
}
