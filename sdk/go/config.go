// Package stratium provides a Golang SDK for integrating with the Stratium platform.
//
// The SDK provides easy-to-use clients for:
//   - Key Manager: Register keys, encrypt/decrypt data
//   - Platform: Make authorization decisions
//   - PAP: Manage policies and entitlements
//   - Key Access: Request data encryption keys
//
// Example usage:
//
//	config := &stratium.Config{
//	    PlatformAddress:   "platform.example.com:50051",
//	    KeyManagerAddress: "key-manager.example.com:50052",
//	    KeyAccessAddress:  "key-access.example.com:50053",
//	    PAPAddress:        "pap.example.com:8090",
//	    OIDC: &stratium.OIDCConfig{
//	        IssuerURL:    "https://keycloak.example.com/realms/stratium",
//	        ClientID:     "my-app",
//	        ClientSecret: "secret",
//	    },
//	}
//
//	client, err := stratium.NewClient(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
package stratium

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Config holds the configuration for the Stratium SDK client.
type Config struct {
	// Service Addresses
	PlatformAddress   string // Platform service gRPC address (e.g., "platform.example.com:50051")
	KeyManagerAddress string // Key Manager service gRPC address (e.g., "key-manager.example.com:50052")
	KeyAccessAddress  string // Key Access service gRPC address (e.g., "key-access.example.com:50053")
	PAPAddress        string // PAP service HTTP address (e.g., "http://pap.example.com:8090")

	// Authentication
	OIDC *OIDCConfig // OIDC configuration for authentication

	// Connection options
	Timeout       time.Duration // Default timeout for requests (default: 30s)
	RetryAttempts int           // Number of retry attempts on failure (default: 3)
	UseTLS        bool          // Use TLS for gRPC connections (default: false)

	// Advanced options
	DialOptions []grpc.DialOption // Additional gRPC dial options
}

// OIDCConfig holds OIDC authentication configuration.
type OIDCConfig struct {
	IssuerURL    string   // OIDC issuer URL (e.g., "https://keycloak.example.com/realms/stratium")
	ClientID     string   // OIDC client ID
	ClientSecret string   // OIDC client secret
	Username     string   // Username to use with password grant
	Password     string   // Password to use with password grant
	Scopes       []string // OIDC scopes (default: ["openid", "profile", "email"])
	RedirectURL  string   // OIDC redirect url (e.g., https://localhost:8080/callback)
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.PlatformAddress == "" && c.KeyManagerAddress == "" && c.KeyAccessAddress == "" && c.PAPAddress == "" {
		return fmt.Errorf("at least one service address must be configured")
	}

	if c.OIDC != nil {
		if c.OIDC.IssuerURL == "" {
			return fmt.Errorf("OIDC issuer URL is required")
		}
		if c.OIDC.ClientID == "" {
			return fmt.Errorf("OIDC client ID is required")
		}
		if c.OIDC.ClientSecret == "" {
			return fmt.Errorf("OIDC client secret is required")
		}
	}

	return nil
}

// SetDefaults sets default values for unspecified configuration options.
func (c *Config) SetDefaults() {
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.RetryAttempts == 0 {
		c.RetryAttempts = DefaultRetryAttempts
	}
	if c.OIDC != nil && len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = DefaultOIDCScopes
	}
}

// dialOptions returns the gRPC dial options based on configuration.
func (c *Config) dialOptions() []grpc.DialOption {
	opts := []grpc.DialOption{}

	// Add TLS or insecure credentials
	if c.UseTLS {
		// TODO: Add TLS credentials support
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Add custom dial options
	opts = append(opts, c.DialOptions...)

	return opts
}

// contextWithTimeout creates a context with the configured timeout.
func (c *Config) contextWithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.Timeout > 0 {
		return context.WithTimeout(ctx, c.Timeout)
	}
	return ctx, func() {}
}

// contextWithAuth adds authentication metadata to the context.
func contextWithAuth(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", AuthHeaderPrefix+token)
}
