package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"stratium/config"
	"stratium/logging"
	"stratium/pkg/cache"
	"stratium/pkg/repository/postgres"
	"stratium/services/pap"
)

var (
	// Command-line flags
	configFile = flag.String("config", "", "Path to configuration file")
	version    = flag.Bool("version", false, "Print version information")
)

const (
	ServiceName    = "pap-server"
	ServiceVersion = "1.0.0"
)

func main() {
	flag.Parse()

	// Initialize logger
	logger := logging.GetLogger()

	// Print version and exit if requested
	if *version {
		fmt.Printf("%s version %s\n", ServiceName, ServiceVersion)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		logger.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	// Override service name and version
	cfg.Service.Name = ServiceName
	cfg.Service.Version = ServiceVersion

	// Apply service-specific rate limits
	config.ApplyServiceSpecificRateLimits(cfg, ServiceName)

	// Print build and feature flag information
	logger.PrintBuildInfo(ServiceName, ServiceVersion)

	// Log configuration (with sensitive data masked)
	logConfiguration(cfg, logger)

	// Create PostgreSQL repository
	logger.Startup("Connecting to database: %s", maskDBPassword(cfg.GetDatabaseURL()))
	repo, err := postgres.NewRepository(cfg.GetDatabaseURL())
	if err != nil {
		logger.Error("Failed to create repository: %v", err)
		os.Exit(1)
	}
	defer repo.Close()

	// Verify database connection
	if err := repo.Ping(context.Background()); err != nil {
		logger.Error("Failed to ping database: %v", err)
		os.Exit(1)
	}
	logger.Startup("Database connection successful")

	// Create auth service
	var authService *pap.AuthService
	if cfg.OIDC.Enabled {
		logger.Startup("Initializing OIDC authentication with issuer: %s", cfg.OIDC.IssuerURL)
		oidcConfig := &pap.OIDCConfig{
			IssuerURL:    cfg.OIDC.IssuerURL,
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			RedirectURL:  cfg.OIDC.RedirectURL,
			Scopes:       cfg.OIDC.Scopes,
		}
		authService, err = pap.NewAuthService(oidcConfig)
		if err != nil {
			logger.Error("Failed to create auth service: %v", err)
			os.Exit(1)
		}
		logger.Startup("OIDC authentication initialized successfully")
	} else {
		if cfg.IsProduction() {
			logger.Warn("OIDC authentication is disabled in production environment!")
			logger.Warn("This is not recommended for production use.")
		}
		logger.Startup("Using mock authentication for development")
		authService = pap.NewMockAuthService()
	}

	// Create cache invalidator for distributed cache invalidation
	var cacheInvalidator cache.CacheInvalidator

	if cfg.Cache.Type == "redis" {
		logger.Startup("Initializing Redis cache invalidator at %s", cfg.Cache.Redis.Address)
		cacheInvalidator, err = cache.NewRedisCacheInvalidator(cache.RedisCacheConfig{
			Addr:     cfg.Cache.Redis.Address,
			Password: cfg.Cache.Redis.Password,
			DB:       cfg.Cache.Redis.DB,
			Prefix:   cfg.Cache.Redis.Prefix,
		})
		if err != nil {
			logger.Warn("Failed to initialize Redis cache invalidator: %v", err)
			logger.Warn("Cache invalidation will be disabled")
			cacheInvalidator = cache.NewNoOpCacheInvalidator()
		} else {
			logger.Startup("Redis cache invalidator initialized successfully")
		}
	} else {
		logger.Startup("Using no-op cache invalidator (in-memory cache or cache disabled)")
		cacheInvalidator = cache.NewNoOpCacheInvalidator()
	}

	// Create PAP server with cache invalidator
	server := pap.NewServerWithCacheInvalidator(repo, authService, cacheInvalidator, cfg.Security.CORS)

	// Determine server address
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	// Start server in a goroutine
	go func() {
		logger.Startup("Starting %s version %s", ServiceName, ServiceVersion)
		logger.Startup("Environment: %s", cfg.Service.Environment)
		logger.Startup("PAP API server listening on %s", serverAddr)
		logger.Info("Configuration:")
		logger.Info("  - Database: %s", cfg.Database.Host)
		logger.Info("  - Cache: %s", cfg.Cache.Type)
		logger.Info("  - OIDC: %v", cfg.OIDC.Enabled)
		logger.Info("  - Rate Limiting: %v", cfg.Security.RateLimiting.Enabled)
		logger.Info("  - CORS: %v", cfg.Security.CORS.Enabled)
		logger.Info("  - Metrics: %v", cfg.Observability.Metrics.Enabled)
		logger.Info("  - Tracing: %v", cfg.Observability.Tracing.Enabled)

		if err := server.Start(serverAddr); err != nil {
			logger.Error("Failed to start server: %v", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Startup("Shutting down %s gracefully...", ServiceName)
	// TODO: Implement graceful shutdown with cfg.Server.GracefulStop timeout
}

// logConfiguration logs the configuration with sensitive data masked
func logConfiguration(cfg *config.Config, logger *logging.Logger) {
	logger.Startup("Configuration loaded successfully")
	logger.Info("Service: %s v%s (%s)", cfg.Service.Name, cfg.Service.Version, cfg.Service.Environment)
	logger.Info("Server: %s:%d (timeouts: read=%v write=%v idle=%v)",
		cfg.Server.Host, cfg.Server.Port,
		cfg.Server.ReadTimeout, cfg.Server.WriteTimeout, cfg.Server.IdleTimeout)
	logger.Info("Database: %s@%s:%d/%s", cfg.Database.User, cfg.Database.Host, cfg.Database.Port, cfg.Database.Database)
	logger.Info("Cache: %s", cfg.Cache.Type)
	if cfg.Cache.Type == "redis" {
		logger.Info("Redis: %s (DB: %d)", cfg.Cache.Redis.Address, cfg.Cache.Redis.DB)
	}
	logger.Info("Logging mode: %s", logging.LoggingMode())

	if cfg.IsDevelopment() {
		logger.Info("Running in DEVELOPMENT mode")
		logger.Info("  - TLS: disabled")
		logger.Info("  - Permissive CORS: enabled")
	} else if cfg.IsProduction() {
		logger.Info("Running in PRODUCTION mode")
		logger.Info("  - TLS: %v", cfg.Server.TLS.Enabled)
		logger.Info("  - Rate limiting: %v", cfg.Security.RateLimiting.Enabled)
		logger.Info("  - Metrics: %v", cfg.Observability.Metrics.Enabled)
		logger.Info("  - Tracing: %v", cfg.Observability.Tracing.Enabled)
	}
}

// maskDBPassword masks the password in the database connection string for logging
func maskDBPassword(connStr string) string {
	// Simple masking - extract host and database name for logging
	// Format: postgres://user:password@host:port/database?params
	return "postgres://***:***@.../stratium_pap"
}
