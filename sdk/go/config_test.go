package stratium

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TestConfigValidate tests the Config.Validate method
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with platform address only",
			config: &Config{
				PlatformAddress: "localhost:50051",
			},
			wantErr: false,
		},
		{
			name: "valid config with key manager address only",
			config: &Config{
				KeyManagerAddress: "localhost:50052",
			},
			wantErr: false,
		},
		{
			name: "valid config with key access address only",
			config: &Config{
				KeyAccessAddress: "localhost:50053",
			},
			wantErr: false,
		},
		{
			name: "valid config with PAP address only",
			config: &Config{
				PAPAddress: "http://localhost:8090",
			},
			wantErr: false,
		},
		{
			name: "valid config with all addresses",
			config: &Config{
				PlatformAddress:   "localhost:50051",
				KeyManagerAddress: "localhost:50052",
				KeyAccessAddress:  "localhost:50053",
				PAPAddress:        "http://localhost:8090",
			},
			wantErr: false,
		},
		{
			name:    "invalid config with no addresses",
			config:  &Config{},
			wantErr: true,
			errMsg:  "at least one service address must be configured",
		},
		{
			name: "valid config with OIDC",
			config: &Config{
				PlatformAddress: "localhost:50051",
				OIDC: &OIDCConfig{
					IssuerURL:    "https://keycloak.example.com/realms/stratium",
					ClientID:     "my-client",
					ClientSecret: "my-secret",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid config - OIDC missing issuer URL",
			config: &Config{
				PlatformAddress: "localhost:50051",
				OIDC: &OIDCConfig{
					ClientID:     "my-client",
					ClientSecret: "my-secret",
				},
			},
			wantErr: true,
			errMsg:  "OIDC issuer URL is required",
		},
		{
			name: "invalid config - OIDC missing client ID",
			config: &Config{
				PlatformAddress: "localhost:50051",
				OIDC: &OIDCConfig{
					IssuerURL:    "https://keycloak.example.com/realms/stratium",
					ClientSecret: "my-secret",
				},
			},
			wantErr: true,
			errMsg:  "OIDC client ID is required",
		},
		{
			name: "invalid config - OIDC missing client secret",
			config: &Config{
				PlatformAddress: "localhost:50051",
				OIDC: &OIDCConfig{
					IssuerURL: "https://keycloak.example.com/realms/stratium",
					ClientID:  "my-client",
				},
			},
			wantErr: true,
			errMsg:  "OIDC client secret is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("Config.Validate() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestConfigSetDefaults tests the Config.SetDefaults method
func TestConfigSetDefaults(t *testing.T) {
	tests := []struct {
		name            string
		config          *Config
		expectedTimeout time.Duration
		expectedRetries int
		expectedScopes  []string
	}{
		{
			name:            "sets default timeout when zero",
			config:          &Config{},
			expectedTimeout: DefaultTimeout,
			expectedRetries: DefaultRetryAttempts,
			expectedScopes:  nil,
		},
		{
			name: "preserves custom timeout",
			config: &Config{
				Timeout: 60 * time.Second,
			},
			expectedTimeout: 60 * time.Second,
			expectedRetries: DefaultRetryAttempts,
			expectedScopes:  nil,
		},
		{
			name: "sets default retry attempts when zero",
			config: &Config{
				Timeout: 30 * time.Second,
			},
			expectedTimeout: 30 * time.Second,
			expectedRetries: DefaultRetryAttempts,
			expectedScopes:  nil,
		},
		{
			name: "preserves custom retry attempts",
			config: &Config{
				RetryAttempts: 5,
			},
			expectedTimeout: DefaultTimeout,
			expectedRetries: 5,
			expectedScopes:  nil,
		},
		{
			name: "sets default OIDC scopes when empty",
			config: &Config{
				OIDC: &OIDCConfig{
					IssuerURL:    "https://keycloak.example.com/realms/stratium",
					ClientID:     "my-client",
					ClientSecret: "my-secret",
				},
			},
			expectedTimeout: DefaultTimeout,
			expectedRetries: DefaultRetryAttempts,
			expectedScopes:  DefaultOIDCScopes,
		},
		{
			name: "preserves custom OIDC scopes",
			config: &Config{
				OIDC: &OIDCConfig{
					IssuerURL:    "https://keycloak.example.com/realms/stratium",
					ClientID:     "my-client",
					ClientSecret: "my-secret",
					Scopes:       []string{"openid", "custom"},
				},
			},
			expectedTimeout: DefaultTimeout,
			expectedRetries: DefaultRetryAttempts,
			expectedScopes:  []string{"openid", "custom"},
		},
		{
			name: "does not set OIDC scopes when OIDC is nil",
			config: &Config{
				OIDC: nil,
			},
			expectedTimeout: DefaultTimeout,
			expectedRetries: DefaultRetryAttempts,
			expectedScopes:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.SetDefaults()

			if tt.config.Timeout != tt.expectedTimeout {
				t.Errorf("Config.SetDefaults() timeout = %v, want %v", tt.config.Timeout, tt.expectedTimeout)
			}

			if tt.config.RetryAttempts != tt.expectedRetries {
				t.Errorf("Config.SetDefaults() retryAttempts = %v, want %v", tt.config.RetryAttempts, tt.expectedRetries)
			}

			if tt.config.OIDC != nil {
				if tt.expectedScopes == nil && tt.config.OIDC.Scopes != nil {
					t.Errorf("Config.SetDefaults() OIDC scopes should be nil, got %v", tt.config.OIDC.Scopes)
				}
				if tt.expectedScopes != nil {
					if len(tt.config.OIDC.Scopes) != len(tt.expectedScopes) {
						t.Errorf("Config.SetDefaults() OIDC scopes length = %v, want %v", len(tt.config.OIDC.Scopes), len(tt.expectedScopes))
					}
					for i, scope := range tt.expectedScopes {
						if tt.config.OIDC.Scopes[i] != scope {
							t.Errorf("Config.SetDefaults() OIDC scope[%d] = %v, want %v", i, tt.config.OIDC.Scopes[i], scope)
						}
					}
				}
			}
		})
	}
}

// TestConfigDialOptions tests the Config.dialOptions method
func TestConfigDialOptions(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		wantOptions int // minimum expected number of dial options
	}{
		{
			name: "default options without TLS",
			config: &Config{
				UseTLS: false,
			},
			wantOptions: 1, // at least insecure credentials
		},
		{
			name: "options with TLS (currently returns insecure)",
			config: &Config{
				UseTLS: true,
			},
			wantOptions: 1, // at least credentials option (even though it's insecure for now)
		},
		{
			name: "options with custom dial options",
			config: &Config{
				UseTLS: false,
				DialOptions: []grpc.DialOption{
					grpc.WithBlock(),
					grpc.WithDefaultCallOptions(),
				},
			},
			wantOptions: 3, // credentials + 2 custom options
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.config.dialOptions()
			if len(opts) < tt.wantOptions {
				t.Errorf("Config.dialOptions() returned %d options, want at least %d", len(opts), tt.wantOptions)
			}
		})
	}
}

// TestConfigContextWithTimeout tests the Config.contextWithTimeout method
func TestConfigContextWithTimeout(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		hasDeadline bool
	}{
		{
			name: "creates context with timeout",
			config: &Config{
				Timeout: 5 * time.Second,
			},
			hasDeadline: true,
		},
		{
			name: "returns context without timeout when timeout is zero",
			config: &Config{
				Timeout: 0,
			},
			hasDeadline: false,
		},
		{
			name: "returns context without timeout when timeout is negative",
			config: &Config{
				Timeout: -1 * time.Second,
			},
			hasDeadline: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			newCtx, cancel := tt.config.contextWithTimeout(ctx)
			defer cancel()

			_, hasDeadline := newCtx.Deadline()
			if hasDeadline != tt.hasDeadline {
				t.Errorf("Config.contextWithTimeout() hasDeadline = %v, want %v", hasDeadline, tt.hasDeadline)
			}
		})
	}
}

// TestContextWithAuth tests the contextWithAuth function
func TestContextWithAuth(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		expectHeader  bool
		expectedValue string
	}{
		{
			name:          "adds auth header with token",
			token:         "my-token-123",
			expectHeader:  true,
			expectedValue: AuthHeaderPrefix + "my-token-123",
		},
		{
			name:         "does not add header with empty token",
			token:        "",
			expectHeader: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			newCtx := contextWithAuth(ctx, tt.token)

			md, ok := metadata.FromOutgoingContext(newCtx)
			if tt.expectHeader {
				if !ok {
					t.Error("contextWithAuth() did not add metadata to context")
					return
				}
				authValues := md.Get("authorization")
				if len(authValues) == 0 {
					t.Error("contextWithAuth() did not add authorization header")
					return
				}
				if authValues[0] != tt.expectedValue {
					t.Errorf("contextWithAuth() authorization header = %v, want %v", authValues[0], tt.expectedValue)
				}
			} else {
				if ok {
					authValues := md.Get("authorization")
					if len(authValues) > 0 {
						t.Error("contextWithAuth() should not add authorization header for empty token")
					}
				}
			}
		})
	}
}

// TestOIDCConfigComplete tests various OIDC configuration scenarios
func TestOIDCConfigComplete(t *testing.T) {
	tests := []struct {
		name       string
		oidcConfig *OIDCConfig
		complete   bool
	}{
		{
			name: "complete OIDC config with client credentials",
			oidcConfig: &OIDCConfig{
				IssuerURL:    "https://keycloak.example.com/realms/stratium",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Scopes:       []string{"openid", "profile"},
			},
			complete: true,
		},
		{
			name: "complete OIDC config with password grant",
			oidcConfig: &OIDCConfig{
				IssuerURL:    "https://keycloak.example.com/realms/stratium",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Username:     "user@example.com",
				Password:     "password123",
				Scopes:       []string{"openid"},
			},
			complete: true,
		},
		{
			name: "OIDC config with redirect URL",
			oidcConfig: &OIDCConfig{
				IssuerURL:    "https://keycloak.example.com/realms/stratium",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				RedirectURL:  "https://localhost:8080/callback",
			},
			complete: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				PlatformAddress: "localhost:50051",
				OIDC:            tt.oidcConfig,
			}

			err := config.Validate()
			if tt.complete && err != nil {
				t.Errorf("Complete OIDC config should be valid, got error: %v", err)
			}
		})
	}
}

// TestConfigIntegration tests a complete configuration scenario
func TestConfigIntegration(t *testing.T) {
	config := &Config{
		PlatformAddress:   "platform.example.com:50051",
		KeyManagerAddress: "key-manager.example.com:50052",
		KeyAccessAddress:  "key-access.example.com:50053",
		PAPAddress:        "http://pap.example.com:8090",
		OIDC: &OIDCConfig{
			IssuerURL:    "https://keycloak.example.com/realms/stratium",
			ClientID:     "my-app",
			ClientSecret: "secret",
		},
		UseTLS: false,
	}

	// Test validation
	if err := config.Validate(); err != nil {
		t.Fatalf("Valid config failed validation: %v", err)
	}

	// Test setting defaults
	config.SetDefaults()

	if config.Timeout != DefaultTimeout {
		t.Errorf("SetDefaults() did not set timeout correctly, got %v want %v", config.Timeout, DefaultTimeout)
	}

	if config.RetryAttempts != DefaultRetryAttempts {
		t.Errorf("SetDefaults() did not set retry attempts correctly, got %v want %v", config.RetryAttempts, DefaultRetryAttempts)
	}

	if len(config.OIDC.Scopes) != len(DefaultOIDCScopes) {
		t.Errorf("SetDefaults() did not set OIDC scopes correctly, got %v want %v", config.OIDC.Scopes, DefaultOIDCScopes)
	}

	// Test dial options
	opts := config.dialOptions()
	if len(opts) < 1 {
		t.Error("dialOptions() should return at least one option")
	}

	// Test context with timeout
	ctx := context.Background()
	timeoutCtx, cancel := config.contextWithTimeout(ctx)
	defer cancel()

	_, hasDeadline := timeoutCtx.Deadline()
	if !hasDeadline {
		t.Error("contextWithTimeout() should create context with deadline")
	}

	// Test context with auth
	authCtx := contextWithAuth(ctx, "test-token")
	md, ok := metadata.FromOutgoingContext(authCtx)
	if !ok {
		t.Error("contextWithAuth() should add metadata to context")
	}
	authValues := md.Get("authorization")
	if len(authValues) == 0 || authValues[0] != "Bearer test-token" {
		t.Errorf("contextWithAuth() authorization header = %v, want 'Bearer test-token'", authValues)
	}
}