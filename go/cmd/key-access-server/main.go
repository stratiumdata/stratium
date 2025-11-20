package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"stratium/config"
	"stratium/logging"
	"stratium/middleware"
	keyAccess "stratium/services/key-access"

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
	ServiceName    = "key-access-server"
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

	// Apply service-specific rate limits for key-access-server (4 calls/min)
	config.ApplyServiceSpecificRateLimits(cfg, ServiceName)

	// Print build and feature flag information
	logger.PrintBuildInfo(ServiceName, ServiceVersion)

	// Log configuration
	logConfiguration(cfg, logger)

	// Get key manager address from configuration
	keyManagerAddr := cfg.Services.KeyManager.Address
	if keyManagerAddr == "" {
		keyManagerAddr = "localhost:50052"
	}

	// Create auth config from OIDC settings
	if cfg.OIDC.Enabled {
		logger.Startup("Initializing OIDC authentication with issuer: %s", cfg.OIDC.IssuerURL)
		logger.Startup("OIDC authentication initialized successfully")
	} else {
		logger.Error("OIDC authentication is disabled!")
		os.Exit(1)
	}

	// Create key access server
	logger.Startup("Connecting to Key Manager at: %s", keyManagerAddr)
	keyAccessServer, err := keyAccess.NewServer(keyManagerAddr, cfg)
	if err != nil {
		logger.Error("Failed to create key access server: %v", err)
		os.Exit(1)
	}
	logger.Startup("Key Access server initialized successfully")

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

	// Create gRPC server with auth and rate limiting interceptors
	var unaryInterceptors []grpc.UnaryServerInterceptor
	unaryInterceptors = append(unaryInterceptors, rateLimiter.UnaryServerInterceptor())

	// Only add auth interceptor if auth service is configured
	if keyAccessServer.GetAuthService() != nil {
		unaryInterceptors = append(unaryInterceptors, keyAccessServer.GetAuthService().AuthInterceptor())
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(
			rateLimiter.StreamServerInterceptor(),
		),
	)

	// Register the key access service
	keyAccess.RegisterKeyAccessServiceServer(grpcServer, keyAccessServer)

	// Register reflection service for easier debugging
	reflection.Register(grpcServer)

	// Start server in a goroutine
	go func() {
		logger.Startup("Starting %s version %s", ServiceName, ServiceVersion)
		logger.Startup("Environment: %s", cfg.Service.Environment)
		logger.Startup("Key Access gRPC server listening on %s", serverAddr)
		logger.Info("Configuration:")
		logger.Info("  - Key Manager: %s", keyManagerAddr)
		logger.Info("  - OIDC: %v", cfg.OIDC.Enabled)
		logger.Info("  - Metrics: %v", cfg.Observability.Metrics.Enabled)
		logger.Info("  - Tracing: %v", cfg.Observability.Tracing.Enabled)
		logger.Info("Available endpoints:")
		logger.Info("  - WrapDEK")
		logger.Info("  - UnwrapDEK")

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
	keyAccessServer.Close()
	grpcServer.GracefulStop()
}

// logConfiguration logs the configuration with sensitive data masked
func logConfiguration(cfg *config.Config, logger *logging.Logger) {
	logger.Startup("Configuration loaded successfully")
	logger.Info("Service: %s v%s (%s)", cfg.Service.Name, cfg.Service.Version, cfg.Service.Environment)
	logger.Info("Server: %s:%d (timeouts: read=%v write=%v idle=%v)",
		cfg.Server.Host, cfg.Server.Port,
		cfg.Server.ReadTimeout, cfg.Server.WriteTimeout, cfg.Server.IdleTimeout)
	logger.Info("Logging mode: %s", logging.LoggingMode())

	if cfg.IsDevelopment() {
		logger.Info("Running in DEVELOPMENT mode")
		logger.Info("  - TLS: disabled")
	} else if cfg.IsProduction() {
		logger.Info("Running in PRODUCTION mode")
		logger.Info("  - TLS: %v", cfg.Server.TLS.Enabled)
		logger.Info("  - OIDC: %v", cfg.OIDC.Enabled)
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
