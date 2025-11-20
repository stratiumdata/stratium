package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"stratium/features"
	"stratium/pkg/security/encryption"

	"github.com/spf13/viper"
)

// Config holds application configuration for all Stratium services
type Config struct {
	// Service identification
	Service ServiceConfig `mapstructure:"service"`

	// Server configuration
	Server ServerConfig `mapstructure:"server"`

	// Database configuration
	Database DatabaseConfig `mapstructure:"database"`

	// Cache configuration
	Cache CacheConfig `mapstructure:"cache"`

	// Encryption configuration
	Encryption EncryptionConfig `mapstructure:"encryption"`

	// OIDC/OAuth2 configuration
	OIDC OIDCConfig `mapstructure:"oidc"`

	// Service discovery/connections
	Services ServicesConfig `mapstructure:"services"`

	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging"`

	// Security configuration
	Security SecurityConfig `mapstructure:"security"`

	// Observability configuration
	Observability ObservabilityConfig `mapstructure:"observability"`

	// External key loading configuration
	ExternalKeys ExternalKeysConfig `mapstructure:"externalKeys"`

	// Platform-specific configuration
	Platform PlatformConfig `mapstructure:"platform"`

	// Key Manager-specific configuration
	KeyManager KeyManagerConfig `mapstructure:"key_manager"`
}

// ServiceConfig identifies the service
type ServiceConfig struct {
	Name                      string `mapstructure:"name"`
	Version                   string `mapstructure:"version"`
	Environment               string `mapstructure:"environment"` // dev, staging, production
	ServiceKeyCacheTTLSeconds int    `mapstructure:"service_key_cache_ttl_seconds"`
	PolicyCacheTTLSeconds     int    `mapstructure:"policy_cache_ttl_seconds"`
}

// ServerConfig holds server-specific settings
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	GracefulStop time.Duration `mapstructure:"graceful_stop"`
	TLS          TLSConfig     `mapstructure:"tls"`
}

// TLSConfig holds TLS/SSL settings
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	CAFile   string `mapstructure:"ca_file"`
}

// DatabaseConfig holds database connection settings
type DatabaseConfig struct {
	Driver          string        `mapstructure:"driver"` // postgres, mysql, etc.
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Database        string        `mapstructure:"database"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
}

// CacheConfig holds cache settings
type CacheConfig struct {
	Type    string        `mapstructure:"type"` // memory, redis
	TTL     time.Duration `mapstructure:"ttl"`
	MaxSize int           `mapstructure:"max_size"`
	Redis   RedisConfig   `mapstructure:"redis"`
}

// RedisConfig holds Redis-specific settings
type RedisConfig struct {
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	Prefix   string `mapstructure:"prefix"`
}

// EncryptionConfig holds encryption settings
type EncryptionConfig struct {
	Algorithm        string   `mapstructure:"algorithm"` // RSA2048, RSA4096, AES256, etc.
	KeyRotation      bool     `mapstructure:"key_rotation"`
	AdminKeyProvider string   `mapstructure:"admin_key_provider"` // env, file, composite
	AdminKeyConfig   string   `mapstructure:"admin_key_config"`
	AdminKeys        []string `mapstructure:"admin_keys"`
}

// OIDCConfig holds OIDC/OAuth2 settings
type OIDCConfig struct {
	Enabled             bool     `mapstructure:"enabled"`
	IssuerURL           string   `mapstructure:"issuer_url"`
	ClientID            string   `mapstructure:"client_id"`
	ClientSecret        string   `mapstructure:"client_secret"`
	RedirectURL         string   `mapstructure:"redirect_url"`
	Scopes              []string `mapstructure:"scopes"`
	AllowInsecureIssuer bool     `mapstructure:"allow_insecure_issuer"`
	SkipClientIDCheck   bool     `mapstructure:"skip_client_id_check"`
}

// ServicesConfig holds connection information for other services
type ServicesConfig struct {
	Platform   ServiceEndpoint `mapstructure:"platform"`
	KeyManager ServiceEndpoint `mapstructure:"key_manager"`
	KeyAccess  ServiceEndpoint `mapstructure:"key_access"`
	PAP        ServiceEndpoint `mapstructure:"pap"`
}

// ServiceEndpoint defines how to connect to a service
type ServiceEndpoint struct {
	Address string        `mapstructure:"address"`
	TLS     TLSConfig     `mapstructure:"tls"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level  string `mapstructure:"level"`  // debug, info, warn, error
	Format string `mapstructure:"format"` // json, text
	Output string `mapstructure:"output"` // stdout, stderr, file path
}

// SecurityConfig holds security-related settings
type SecurityConfig struct {
	RateLimiting RateLimitConfig `mapstructure:"rate_limiting"`
	CORS         CORSConfig      `mapstructure:"cors"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	RequestsPerMin int  `mapstructure:"requests_per_min"`
	Burst          int  `mapstructure:"burst"`
}

// CORSConfig holds CORS settings
type CORSConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	AllowedOrigins   []string      `mapstructure:"allowed_origins"`
	AllowedMethods   []string      `mapstructure:"allowed_methods"`
	AllowedHeaders   []string      `mapstructure:"allowed_headers"`
	ExposeHeaders    []string      `mapstructure:"expose_headers"`
	AllowCredentials bool          `mapstructure:"allow_credentials"`
	MaxAge           time.Duration `mapstructure:"max_age"`
}

// ObservabilityConfig holds metrics and tracing settings
type ObservabilityConfig struct {
	Metrics MetricsConfig `mapstructure:"metrics"`
	Tracing TracingConfig `mapstructure:"tracing"`
}

// PlatformConfig holds platform-service specific settings
type PlatformConfig struct {
	SeedSampleData bool   `mapstructure:"seed_sample_data"`
	SeedDataPath   string `mapstructure:"seed_data_path"`
}

// KeyManagerConfig holds key-manager specific settings
type KeyManagerConfig struct {
	SeedSampleData bool   `mapstructure:"seed_sample_data"`
	SeedDataPath   string `mapstructure:"seed_data_path"`
}

// ExternalKeysConfig controls how externally managed key pairs are loaded
type ExternalKeysConfig struct {
	Enabled          bool                      `mapstructure:"enabled"`
	EmergencyDisable bool                      `mapstructure:"emergencyDisable"`
	Sources          []ExternalKeySourceConfig `mapstructure:"sources"`
}

// ExternalKeySourceConfig defines a source of external key manifests
type ExternalKeySourceConfig struct {
	Name              string                         `mapstructure:"name"`
	Type              string                         `mapstructure:"type"`
	Volume            *ExternalVolumeSourceConfig    `mapstructure:"volume"`
	AWSSecretsManager *AWSSecretsManagerSourceConfig `mapstructure:"awsSecretsManager"`
}

// ExternalVolumeSourceConfig describes a mounted directory of manifests and PEM blobs
type ExternalVolumeSourceConfig struct {
	BasePath       string `mapstructure:"basePath"`
	ManifestFile   string `mapstructure:"manifestFile"`
	PublicKeyFile  string `mapstructure:"publicKeyFile"`
	PrivateKeyFile string `mapstructure:"privateKeyFile"`
	Recursive      bool   `mapstructure:"recursive"`
}

// AWSSecretsManagerSourceConfig configures AWS secrets lookups for private key blobs
type AWSSecretsManagerSourceConfig struct {
	Region         string `mapstructure:"region"`
	Endpoint       string `mapstructure:"endpoint"`
	SecretKeyField string `mapstructure:"secretKeyField"`
}

// MetricsConfig holds metrics export settings
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Address string `mapstructure:"address"` // Prometheus endpoint
	Path    string `mapstructure:"path"`
}

// TracingConfig holds distributed tracing settings
type TracingConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	Provider    string `mapstructure:"provider"` // jaeger, zipkin, otlp
	Endpoint    string `mapstructure:"endpoint"`
	ServiceName string `mapstructure:"service_name"`
}

// Load loads configuration from multiple sources with precedence:
// 1. Command line flags (highest priority)
// 2. Environment variables
// 3. Config file
// 4. Default values (lowest priority)
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set configuration file details
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Search for config in multiple locations
		v.SetConfigName("stratium")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/stratium/")
		v.AddConfigPath("$HOME/.stratium")
		v.AddConfigPath("./config")
		v.AddConfigPath(".")
	}

	// Enable environment variable reading
	v.SetEnvPrefix("STRATIUM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Set default values
	setDefaults(v)

	// Read config file if it exists
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found; using environment variables and defaults
	}

	// Unmarshal into config struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Apply feature flag overrides
	applyFeatureFlags(&cfg)

	return &cfg, nil
}

// LoadFromEnv loads configuration from environment variables (legacy compatibility)
func LoadFromEnv() (*Config, error) {
	return Load("")
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Service defaults
	v.SetDefault("service.name", "stratium")
	v.SetDefault("service.version", "1.0.0")
	v.SetDefault("service.environment", "development")
	v.SetDefault("service.service_key_cache_ttl_seconds", 300)
	v.SetDefault("service.policy_cache_ttl_seconds", 5)
	v.SetDefault("platform.seed_sample_data", true)
	v.SetDefault("platform.seed_data_path", "")
	v.SetDefault("key_manager.seed_sample_data", true)
	v.SetDefault("key_manager.seed_data_path", "")

	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 50051)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "120s")
	v.SetDefault("server.graceful_stop", "30s")
	v.SetDefault("server.tls.enabled", false)

	// Database defaults
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.database", "stratium")
	v.SetDefault("database.user", "stratium")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", "5m")
	v.SetDefault("database.conn_max_idle_time", "5m")

	// Cache defaults
	v.SetDefault("cache.type", "memory")
	v.SetDefault("cache.ttl", "5m")
	v.SetDefault("cache.max_size", 1000)
	v.SetDefault("cache.redis.address", "localhost:6379")
	v.SetDefault("cache.redis.db", 0)
	v.SetDefault("cache.redis.prefix", "stratium:policy:")

	// Encryption defaults
	v.SetDefault("encryption.algorithm", "RSA2048")
	v.SetDefault("encryption.key_rotation", false)
	v.SetDefault("encryption.admin_key_provider", "composite")
	v.SetDefault("encryption.admin_key_config", "/var/run/secrets/stratium/admin-key")

	// OIDC defaults
	v.SetDefault("oidc.enabled", false)
	v.SetDefault("oidc.scopes", []string{"openid", "profile", "email"})

	// Service discovery defaults
	v.SetDefault("services.platform.address", "localhost:50051")
	v.SetDefault("services.platform.timeout", "10s")
	v.SetDefault("services.key_manager.address", "localhost:50052")
	v.SetDefault("services.key_manager.timeout", "10s")
	v.SetDefault("services.key_access.address", "localhost:50053")
	v.SetDefault("services.key_access.timeout", "10s")
	v.SetDefault("services.pap.address", "localhost:8090")
	v.SetDefault("services.pap.timeout", "10s")

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")

	// Security defaults
	v.SetDefault("security.rate_limiting.enabled", true)
	v.SetDefault("security.rate_limiting.requests_per_min", 100)
	v.SetDefault("security.rate_limiting.burst", 50)
	v.SetDefault("security.cors.enabled", true)
	v.SetDefault("security.cors.allowed_origins", []string{"*"})
	v.SetDefault("security.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	v.SetDefault("security.cors.allowed_headers", []string{"Authorization", "Content-Type"})

	// Observability defaults
	v.SetDefault("observability.metrics.enabled", false)
	v.SetDefault("observability.metrics.address", ":9090")
	v.SetDefault("observability.metrics.path", "/metrics")
	v.SetDefault("observability.tracing.enabled", false)

	// External key loading defaults
	v.SetDefault("externalKeys.enabled", false)
	v.SetDefault("externalKeys.emergencyDisable", false)
	v.SetDefault("externalKeys.sources", []map[string]interface{}{})
}

// validateConfig validates the configuration
func validateConfig(cfg *Config) error {
	// Validate service name
	if cfg.Service.Name == "" {
		return fmt.Errorf("service.name is required")
	}

	// Validate server port
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535")
	}

	// Validate TLS configuration
	if cfg.Server.TLS.Enabled {
		if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
			return fmt.Errorf("server.tls.cert_file and server.tls.key_file are required when TLS is enabled")
		}
		if !fileExists(cfg.Server.TLS.CertFile) {
			return fmt.Errorf("TLS certificate file not found: %s", cfg.Server.TLS.CertFile)
		}
		if !fileExists(cfg.Server.TLS.KeyFile) {
			return fmt.Errorf("TLS key file not found: %s", cfg.Server.TLS.KeyFile)
		}
	}

	// Validate database configuration
	if cfg.Database.Driver != "" {
		if cfg.Database.Host == "" {
			return fmt.Errorf("database.host is required when database is configured")
		}
		if cfg.Database.Database == "" {
			return fmt.Errorf("database.database is required when database is configured")
		}
	}

	// Validate OIDC configuration
	if cfg.OIDC.Enabled {
		if cfg.OIDC.IssuerURL == "" {
			return fmt.Errorf("oidc.issuer_url is required when OIDC is enabled")
		}
		if cfg.OIDC.ClientID == "" {
			return fmt.Errorf("oidc.client_id is required when OIDC is enabled")
		}
	}

	// Validate external key sources when enabled
	if cfg.ExternalKeys.Enabled {
		if len(cfg.ExternalKeys.Sources) == 0 {
			return fmt.Errorf("externalKeys.sources must be configured when external key loading is enabled")
		}
		for _, source := range cfg.ExternalKeys.Sources {
			if source.Name == "" {
				return fmt.Errorf("externalKeys.sources[].name is required")
			}
			sourceType := strings.ToLower(source.Type)
			if sourceType == "" {
				sourceType = "volume"
			}
			switch sourceType {
			case "volume":
				if source.Volume == nil {
					return fmt.Errorf("external key source %q requires volume configuration", source.Name)
				}
				if strings.TrimSpace(source.Volume.BasePath) == "" {
					return fmt.Errorf("external key source %q volume.basePath is required", source.Name)
				}
			default:
				return fmt.Errorf("external key source %q has unsupported type %q", source.Name, source.Type)
			}
		}
	}

	return nil
}

// GetDatabaseURL constructs a database connection URL from the config
func (c *Config) GetDatabaseURL() string {
	if c.Database.Driver == "" {
		return ""
	}

	return fmt.Sprintf("%s://%s:%s@%s:%d/%s?sslmode=%s",
		c.Database.Driver,
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Database,
		c.Database.SSLMode,
	)
}

// GetEncryptionAlgorithm returns the parsed encryption algorithm
func (c *Config) GetEncryptionAlgorithm() (encryption.Algorithm, error) {
	return encryption.ParseAlgorithm(c.Encryption.Algorithm)
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Service.Environment == "development" || c.Service.Environment == "dev"
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Service.Environment == "production" || c.Service.Environment == "prod"
}

// MaskSensitive returns a copy of the config with sensitive values masked
func (c *Config) MaskSensitive() *Config {
	masked := *c
	masked.Database.Password = "***"
	masked.OIDC.ClientSecret = "***"
	masked.Cache.Redis.Password = "***"
	return &masked
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	expandedPath := os.ExpandEnv(path)
	if !filepath.IsAbs(expandedPath) {
		return false
	}
	_, err := os.Stat(expandedPath)
	return err == nil
}

// applyFeatureFlags applies build-time feature flags to override configuration
func applyFeatureFlags(cfg *Config) {
	// Disable metrics if not enabled via feature flag
	if !features.ShouldEnableMetrics() {
		cfg.Observability.Metrics.Enabled = false
	}

	// Disable observability/tracing if not enabled via feature flag
	if !features.ShouldEnableObservability() {
		cfg.Observability.Tracing.Enabled = false
		cfg.Observability.Metrics.Enabled = false
	}

	// Apply short timeouts for demo/dev builds
	if features.ShouldUseShortTimeouts() {
		cfg.Server.ReadTimeout = 5 * time.Second
		cfg.Server.WriteTimeout = 5 * time.Second
		cfg.Server.IdleTimeout = 30 * time.Second
		cfg.Server.GracefulStop = 5 * time.Second

		// Shorter service timeouts
		cfg.Services.Platform.Timeout = 3 * time.Second
		cfg.Services.KeyManager.Timeout = 3 * time.Second
		cfg.Services.KeyAccess.Timeout = 3 * time.Second
		cfg.Services.PAP.Timeout = 3 * time.Second
	}

	// Apply rate limiting if enabled
	if features.ShouldEnableRateLimiting() {
		cfg.Security.RateLimiting.Enabled = true
	}

	// Disable caching unless feature flag is enabled
	if !features.ShouldEnableCaching() {
		cfg.Cache.Type = "none" // Disable caching entirely
		cfg.Cache.TTL = 0
		cfg.Cache.MaxSize = 0
		cfg.Cache.Redis.Address = ""
		cfg.Cache.Redis.Password = ""
	}
}

// ApplyServiceSpecificRateLimits applies service-specific rate limit overrides
// This should be called by each service with its service name
func ApplyServiceSpecificRateLimits(cfg *Config, serviceName string) {
	if !features.ShouldEnableRateLimiting() {
		return
	}

	// Apply service-specific rate limits for demo builds
	switch serviceName {
	case "key-access-server":
		cfg.Security.RateLimiting.RequestsPerMin = 4
		cfg.Security.RateLimiting.Burst = 1
	case "key-manager-server":
		cfg.Security.RateLimiting.RequestsPerMin = 10
		cfg.Security.RateLimiting.Burst = 2
	}
}
