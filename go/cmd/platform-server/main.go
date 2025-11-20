package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"stratium/config"
	"stratium/logging"
	"stratium/middleware"
	"stratium/pkg/repository/postgres"
	"stratium/services/platform"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	// Command-line flags
	configFile = flag.String("config", "", "Path to configuration file")
	version    = flag.Bool("version", false, "Print version information")
	pprofAddr  = flag.String("pprof-addr", "", "Address to expose pprof (e.g., :6060)")
)

const (
	ServiceName    = "platform-server"
	ServiceVersion = "1.0.0"
)

func main() {
	flag.Parse()

	// Initialize logger
	logger := logging.GetLogger()
	startPprofServer(*pprofAddr, logger)

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

	// Create cache based on configuration
	policyTTL := time.Duration(cfg.Service.PolicyCacheTTLSeconds) * time.Second
	var cache platform.PolicyCache
	if cfg.Cache.Type == "redis" {
		logger.Startup("Initializing Redis cache at %s", cfg.Cache.Redis.Address)
		cache, err = platform.NewRedisPolicyCache(platform.RedisCacheConfig{
			Addr:     cfg.Cache.Redis.Address,
			Password: cfg.Cache.Redis.Password,
			DB:       cfg.Cache.Redis.DB,
			Prefix:   cfg.Cache.Redis.Prefix,
			TTL:      policyTTL,
		})
		if err != nil {
			logger.Warn("Failed to initialize Redis cache: %v", err)
			logger.Warn("Falling back to in-memory cache")
			cache = platform.NewInMemoryPolicyCache()
		} else {
			logger.Startup("Redis cache initialized successfully")
		}
	} else {
		logger.Startup("Using in-memory policy cache")
		cache = platform.NewInMemoryPolicyCache()
	}

	// Create PDP and platform server
	logger.Startup("Initializing Policy Decision Point")
	var pdp *platform.PolicyDecisionPoint
	pdp = platform.NewPolicyDecisionPoint(repo, cache, policyTTL)
	platformServer := platform.NewServerWithPDP(pdp, cfg)
	logger.Startup("Policy Decision Point initialized successfully")

	// Determine server address
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	// Create TCP listener
	lis, err := net.Listen("tcp", serverAddr)
	if err != nil {
		logger.Error("Failed to listen: %v", err)
		os.Exit(1)
	}

	// Create rate limiter
	rateLimiter := middleware.NewRateLimiter(cfg)
	rateLimiter.PrintRateLimitInfo(ServiceName)

	// Create gRPC server with rate limiting interceptors
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			rateLimiter.UnaryServerInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			rateLimiter.StreamServerInterceptor(),
		),
	)

	// Register the platform service
	platform.RegisterPlatformServiceServer(grpcServer, platformServer)

	// Register reflection service on gRPC server for easier debugging
	reflection.Register(grpcServer)

	// Start server in a goroutine
	go func() {
		logger.Startup("Starting %s version %s", ServiceName, ServiceVersion)
		logger.Startup("Environment: %s", cfg.Service.Environment)
		logger.Startup("Platform gRPC server listening on %s", serverAddr)
		logger.Info("Configuration:")
		logger.Info("  - Database: %s", cfg.Database.Host)
		logger.Info("  - Cache: %s", cfg.Cache.Type)
		logger.Info("  - Metrics: %v", cfg.Observability.Metrics.Enabled)
		logger.Info("  - Tracing: %v", cfg.Observability.Tracing.Enabled)
		logger.Info("Available endpoints:")
		logger.Info("  - GetDecision")
		logger.Info("  - GetEntitlements")
		logger.Info("PDP Mode: Enabled (using PostgreSQL policy repository)")

		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("Failed to serve: %v", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Startup("Shutting down %s gracefully...", ServiceName)
	grpcServer.GracefulStop()
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
	} else if cfg.IsProduction() {
		logger.Info("Running in PRODUCTION mode")
		logger.Info("  - TLS: %v", cfg.Server.TLS.Enabled)
		logger.Info("  - Metrics: %v", cfg.Observability.Metrics.Enabled)
		logger.Info("  - Tracing: %v", cfg.Observability.Tracing.Enabled)
	}
}

func startPprofServer(addr string, logger *logging.Logger) {
	if addr == "" {
		return
	}
	go func() {
		logger.Startup("pprof server listening on %s", addr)
		if err := http.ListenAndServe(addr, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("pprof server exited: %v", err)
		}
	}()
}

// maskDBPassword masks the password in the database connection string for logging
func maskDBPassword(connStr string) string {
	// Simple masking - extract host and database name for logging
	// Format: postgres://user:password@host:port/database?params
	return "postgres://***:***@.../stratium_pap"
}
