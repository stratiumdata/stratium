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

	"stratium/config"
	"stratium/features"
	"stratium/logging"
	"stratium/middleware"
	"stratium/observability"
	"stratium/pkg/repository/postgres"
	"stratium/pkg/security/tlspolicy"
	agent_gateway "stratium/services/agent-gateway"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var (
	configFile = flag.String("config", "", "Path to configuration file")
	version    = flag.Bool("version", false, "Print version information")
	pprofAddr  = flag.String("pprof-addr", "", "Address to expose pprof (e.g., :6060)")
)

const (
	ServiceName    = "agent-gateway-server"
	ServiceVersion = "1.0.0"
)

func main() {
	flag.Parse()

	logger := logging.GetLogger()
	ctx := context.Background()
	startPprofServer(*pprofAddr, logger)

	if *version {
		fmt.Printf("%s version %s\n", ServiceName, ServiceVersion)
		os.Exit(0)
	}

	// Verify agent-auth feature is enabled
	cfg, err := config.Load(*configFile)
	if err != nil {
		logger.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	if !features.ShouldEnableAgentAuth() {
		logger.Error("Agent Gateway requires the 'agent-auth' feature flag to be enabled")
		logger.Error("Build with: -ldflags \"-X stratium/features.BuildFeatures=agent-auth\"")
		logger.Error("Or set environment: AGENT_AUTH_ENABLED=true")
		os.Exit(1)
	}

	cfg.Service.Name = ServiceName
	cfg.Service.Version = ServiceVersion

	config.ApplyServiceSpecificRateLimits(cfg, ServiceName)

	licenseEnforcer, err := middleware.NewLicenseEnforcer(cfg, ServiceName)
	if err != nil {
		logger.Error("Failed to initialize license enforcement: %v", err)
		os.Exit(1)
	}
	if err := licenseEnforcer.Check(); err != nil {
		logger.Error("License validation failed: %v", err)
		os.Exit(1)
	}
	licenseEnforcer.LogStatus()

	logger.PrintBuildInfo(ServiceName, ServiceVersion)

	// Initialize observability
	telemetryProvider, err := observability.Init(ctx, cfg, logger, ServiceName, ServiceVersion)
	if err != nil {
		logger.Warn("Observability initialization had warnings: %v", err)
	}
	if telemetryProvider != nil {
		defer telemetryProvider.Shutdown(context.Background())
	}

	// Create PostgreSQL repository
	logger.Startup("Connecting to database...")
	repo, err := postgres.NewRepository(cfg.GetDatabaseURL())
	if err != nil {
		logger.Error("Failed to create repository: %v", err)
		os.Exit(1)
	}
	defer repo.Close()

	if err := repo.Ping(context.Background()); err != nil {
		logger.Error("Failed to ping database: %v", err)
		os.Exit(1)
	}
	logger.Startup("Database connection successful")

	// Create Agent Gateway server
	gatewayServer, err := agent_gateway.NewServer(cfg, repo)
	if err != nil {
		logger.Error("Failed to create Agent Gateway server: %v", err)
		os.Exit(1)
	}

	// Determine server address
	port := cfg.AgentGateway.GRPCPort
	if port == 0 {
		port = 50054
	}
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, port)

	// Create TCP listener
	lis, err := net.Listen("tcp", serverAddr)
	if err != nil {
		logger.Error("Failed to listen: %v", err)
		os.Exit(1)
	}

	// Create rate limiter
	rateLimiter := middleware.NewRateLimiter(cfg)
	rateLimiter.PrintRateLimitInfo(ServiceName)

	// Create gRPC server with interceptors
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		licenseEnforcer.UnaryServerInterceptor(),
		rateLimiter.UnaryServerInterceptor(),
	}
	streamInterceptors := []grpc.StreamServerInterceptor{
		licenseEnforcer.StreamServerInterceptor(),
		rateLimiter.StreamServerInterceptor(),
	}

	grpcServerOpts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}
	if cfg.Server.TLS.Enabled {
		tlsConfig, err := tlspolicy.LoadServerConfig(
			cfg.Server.TLS.CertFile,
			cfg.Server.TLS.KeyFile,
			cfg.Server.TLS.CAFile,
			cfg.Server.TLS.ClientCAFile,
			cfg.Server.TLS.RequireClientCert,
		)
		if err != nil {
			logger.Error("Failed to configure TLS: %v", err)
			os.Exit(1)
		}
		grpcServerOpts = append(grpcServerOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcServer := grpc.NewServer(grpcServerOpts...)

	// Register the Agent Gateway gRPC service
	grpcAdapter := agent_gateway.NewGRPCServer(gatewayServer)
	agent_gateway.RegisterAgentGatewayServiceServer(grpcServer, grpcAdapter)

	reflection.Register(grpcServer)

	// Start server
	go func() {
		logger.Startup("Starting %s version %s", ServiceName, ServiceVersion)
		logger.Startup("Environment: %s", cfg.Service.Environment)
		logger.Startup("Agent Gateway gRPC server listening on %s", serverAddr)
		logger.Info("Configuration:")
		logger.Info("  - Delegation TTL: %v", cfg.AgentGateway.DelegationTokenTTL)
		logger.Info("  - Delegation Max TTL: %v", cfg.AgentGateway.DelegationMaxTTL)
		logger.Info("  - Delegation Max Depth: %d", cfg.AgentGateway.DelegationMaxDepth)
		logger.Info("  - Cascade Revoke: %v", cfg.AgentGateway.CascadeRevoke)
		logger.Info("Available RPCs:")
		logger.Info("  - CreateDelegation")
		logger.Info("  - RevokeDelegation")
		logger.Info("  - ExecuteAction")
		logger.Info("  - ValidateActionPlan")
		logger.Info("  - GetDelegationChain")
		logger.Info("  - RegisterAgent / GetAgent / ListAgents / UpdateAgent / SuspendAgent")

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
