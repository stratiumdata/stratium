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
	"stratium/pkg/security/encryption"
	keyManager "stratium/services/key-manager"

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
	ServiceName    = "key-manager-server"
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

	// Get encryption algorithm from configuration
	algorithmStr := cfg.Encryption.Algorithm
	if algorithmStr == "" {
		algorithmStr = "RSA2048"
	}

	logger.Startup("Initializing Key Manager with encryption algorithm: %s", algorithmStr)

	// Parse the algorithm string to encryption.Algorithm type
	encryptionAlgorithm, err := encryption.ParseAlgorithm(algorithmStr)
	if err != nil {
		logger.Error("Invalid encryption algorithm '%s': %v", algorithmStr, err)
		os.Exit(1)
	}

	// Register the key manager service with config
	keyManagerServer, err := keyManager.NewServer(encryptionAlgorithm, cfg)
	if err != nil {
		logger.Error("Failed to create key manager server: %v", err)
		os.Exit(1)
	}
	logger.Startup("Key Manager server initialized successfully")

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
	if keyManagerServer.GetAuthService() != nil {
		unaryInterceptors = append(unaryInterceptors, keyManagerServer.GetAuthService().AuthInterceptor())
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(
			rateLimiter.StreamServerInterceptor(),
		),
	)

	keyManager.RegisterKeyManagerServiceServer(grpcServer, keyManagerServer)

	// Register reflection service for easier debugging
	reflection.Register(grpcServer)

	// Start server in a goroutine
	go func() {
		logger.Startup("Starting %s version %s", ServiceName, ServiceVersion)
		logger.Startup("Environment: %s", cfg.Service.Environment)
		logger.Startup("Key Manager gRPC server listening on %s", serverAddr)
		logger.Info("Configuration:")
		logger.Info("  - Encryption Algorithm: %s", encryptionAlgorithm)
		logger.Info("  - Key Rotation: %v", cfg.Encryption.KeyRotation)
		logger.Info("  - Metrics: %v", cfg.Observability.Metrics.Enabled)
		logger.Info("  - Tracing: %v", cfg.Observability.Tracing.Enabled)
		logger.Info("Available endpoints:")
		logger.Info("  Service Key Management:")
		logger.Info("    - CreateKey")
		logger.Info("    - GetKey")
		logger.Info("    - ListKeys")
		logger.Info("    - DeleteKey")
		logger.Info("    - RotateKey")
		logger.Info("  DEK Operations:")
		logger.Info("    - UnwrapDEK")
		logger.Info("  Provider Management:")
		logger.Info("    - ListProviders")
		logger.Info("    - GetProviderInfo")
		logger.Info("  Client Key Management:")
		logger.Info("    - RegisterClientKey")
		logger.Info("    - GetUserKey")
		logger.Info("    - ListUserKeys")
		logger.Info("    - RevokeUserKey")
		logger.Info("    - ListSubjects")

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
	logger.Info("Encryption: algorithm=%s, key_rotation=%v", cfg.Encryption.Algorithm, cfg.Encryption.KeyRotation)
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
