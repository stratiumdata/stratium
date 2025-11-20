package stratium

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"
)

// Client is the main Stratium SDK client that provides access to all services.
type Client struct {
	config *Config

	// Service clients
	Platform   *PlatformClient
	KeyManager *KeyManagerClient
	KeyAccess  *KeyAccessClient
	//PAP        *PAPClient

	// Authentication
	auth *authManager

	// Internal connections
	platformConn   *grpc.ClientConn
	keyManagerConn *grpc.ClientConn
	keyAccessConn  *grpc.ClientConn

	mu     sync.RWMutex
	closed bool
}

// NewClient creates a new Stratium SDK client with the given configuration.
//
// The client will establish connections to all configured services and
// handle authentication automatically.
//
// Example:
//
//	config := &stratium.Config{
//	    PlatformAddress:   "localhost:50051",
//	    KeyManagerAddress: "localhost:50052",
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
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Set defaults and validate
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	client := &Client{
		config: config,
	}

	// Initialize authentication if OIDC is configured
	if config.OIDC != nil {
		auth, err := newAuthManager(config.OIDC)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize authentication: %w", err)
		}
		client.auth = auth
	}

	// Connect to services
	if err := client.connect(); err != nil {
		client.Close() // Clean up any partial connections
		return nil, fmt.Errorf("failed to connect to services: %w", err)
	}

	return client, nil
}

// connect establishes connections to all configured services.
func (c *Client) connect() error {
	var err error

	// Connect to Platform service
	if c.config.PlatformAddress != "" {
		c.platformConn, err = grpc.NewClient(c.config.PlatformAddress, c.config.dialOptions()...)
		if err != nil {
			return fmt.Errorf("failed to connect to Platform service: %w", err)
		}
		c.Platform = newPlatformClient(c.platformConn, c.config, c.auth)
	}

	// Connect to Key Manager service
	if c.config.KeyManagerAddress != "" {
		c.keyManagerConn, err = grpc.NewClient(c.config.KeyManagerAddress, c.config.dialOptions()...)
		if err != nil {
			return fmt.Errorf("failed to connect to Key Manager service: %w", err)
		}
		c.KeyManager = newKeyManagerClient(c.keyManagerConn, c.config, c.auth)
	}

	// Connect to Key Access service
	if c.config.KeyAccessAddress != "" {
		c.keyAccessConn, err = grpc.NewClient(c.config.KeyAccessAddress, c.config.dialOptions()...)
		if err != nil {
			return fmt.Errorf("failed to connect to Key Access service: %w", err)
		}
		c.KeyAccess = newKeyAccessClient(c.keyAccessConn, c.config, c.auth)
	}

	// Connect to PAP service (HTTP-based)
	//if c.config.PAPAddress != "" {
	//	c.PAP = newPAPClient(c.config, c.auth)
	//}

	return nil
}

// Close closes all connections to Stratium services.
// It is safe to call Close multiple times.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	var errs []error

	if c.platformConn != nil {
		if err := c.platformConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close Platform connection: %w", err))
		}
	}

	if c.keyManagerConn != nil {
		if err := c.keyManagerConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close Key Manager connection: %w", err))
		}
	}

	if c.keyAccessConn != nil {
		if err := c.keyAccessConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close Key Access connection: %w", err))
		}
	}

	c.closed = true

	if len(errs) > 0 {
		return fmt.Errorf("errors closing connections: %v", errs)
	}

	return nil
}

// IsClosed returns true if the client has been closed.
func (c *Client) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// GetToken returns the current authentication token.
// Returns an empty string if authentication is not configured.
func (c *Client) GetToken(ctx context.Context) (string, error) {
	if c.auth == nil {
		return "", nil
	}
	return c.auth.GetToken(ctx)
}

// RefreshToken forces a token refresh.
// Returns an error if authentication is not configured.
func (c *Client) RefreshToken(ctx context.Context) error {
	if c.auth == nil {
		return fmt.Errorf("authentication not configured")
	}
	return c.auth.RefreshToken(ctx)
}

// Config returns the client's configuration.
// This is useful for accessing service addresses and other configuration details.
func (c *Client) Config() *Config {
	return c.config
}
