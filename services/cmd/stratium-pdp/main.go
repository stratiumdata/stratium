// Command stratium-pdp is the Policy Decision Point: it loads configuration,
// optionally applies migrations on a dedicated connection, then opens the
// serving database connection and serves the Decide RPC over gRPC until it
// receives a shutdown signal.
//
// Migrations and serving are deliberately different connections, opened
// from different (optionally different) database URLs. Running both on one
// connection would force the login role serving requests to also hold
// whatever privileges migrations need — for migration 000004 specifically,
// standing membership in stratium_audit_owner, which carries DDL rights
// (DROP TRIGGER, DROP RULE) over audit_chain. checkNotAuditOwner is the
// enforcement half of that split: it refuses to serve on an identity that
// holds that membership, rather than trusting deployment configuration to
// keep the two apart.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq" // registers the "postgres" database/sql driver
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"stratium/internal/config"
	"stratium/internal/pdpgrpc"
	"stratium/internal/policy"
	"stratium/internal/policy/cedar"
	"stratium/internal/store"
	"stratium/migrations"
)

// shutdownTimeout bounds GracefulStop. A connection that never finishes must
// not prevent the process from exiting once a shutdown signal arrives.
const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("stratium-pdp exited with error", "error", err)
		os.Exit(1)
	}
}

// run does the real work and returns an error instead of calling os.Exit
// itself, so main's deferred db.Close still runs on every exit path.
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.MigrationDatabaseURL != "" {
		if err := runMigrations(logger, cfg); err != nil {
			return err
		}
	} else {
		logger.Info("STRATIUM_MIGRATION_DATABASE_URL not set: skipping migrations, " +
			"assuming an already-migrated schema")
	}

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			logger.Error("closing database", "error", cerr)
		}
	}()

	pingCtx, cancel := context.WithTimeout(context.Background(), cfg.DBTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("connect to database within %s: %w", cfg.DBTimeout, err)
	}

	// Refuse to serve on an identity that can DROP TRIGGER (or DROP RULE) on
	// audit_chain — migration 000004 exists specifically to keep that DDL
	// power away from whatever role serves requests. This turns that
	// ownership split from a convention (remember not to grant this) into
	// something the PDP itself checks and enforces on every startup.
	checkCtx, checkCancel := context.WithTimeout(context.Background(), cfg.DBTimeout)
	defer checkCancel()
	if err := checkNotAuditOwner(checkCtx, db); err != nil {
		return fmt.Errorf("serving identity startup check: %w", err)
	}

	repo := store.New(db, cfg.TenantID)

	// policy.Multi, not Unconfigured: a real engine is wired in. Registry
	// currently holds only Cedar — Rego, JSON, and XACML are later tasks —
	// but Multi is what closes spec defect D10 even with a registry of one:
	// a tenant whose policies.language is anything other than "cedar" now
	// gets an honest deny naming that language (see Multi's own doc comment
	// in internal/policy/multi.go), where the single-engine policy.Configured
	// this replaced would have silently never loaded or evaluated it at all.
	// Multi loads and prepares this tenant's policies fresh on every Decide
	// call (no cache — see the Phase 2c plan's "caching is deliberately out
	// of scope" and Task 5's measurement of why). A tenant with no policies
	// stored still denies at the principal leg, just as Unconfigured always
	// did; Unconfigured itself remains for a deployment that wants no policy
	// engine at all. repo satisfies both Store (pdpgrpc's own dependency
	// interface) and policy.AllPolicySource structurally, so it needs no
	// adapter to serve both — and Multi itself now supplies pdpgrpc's
	// CreateDelegation gate with a compiled set via PrepareAll, so repo and
	// an engine no longer need to be passed to NewServer a second time raw.
	registry := policy.Registry{"cedar": cedar.New()}
	srv := pdpgrpc.NewServer(repo, policy.NewMulti(repo, registry), cfg)

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}

	grpcServer := grpc.NewServer()
	pdpgrpc.RegisterPDPServiceServer(grpcServer, srv)

	// The standard health service, nothing else registered alongside it: no
	// reflection. The predecessor enabled reflection unconditionally and it
	// was flagged CRITICAL — it lets any client enumerate every RPC and
	// message type. Local-development reflection is a Phase 2 conversation
	// behind an explicit config value, not a default in this binary.
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthSrv)

	logger.Info("stratium-pdp starting", "tenant_id", cfg.TenantID, "listen_addr", cfg.ListenAddr)
	logger.Info("principal policy: multi-engine (registered: cedar), policies loaded fresh from the store " +
		"on every decision (no cache); a tenant with none stored still denies at the principal leg, and a " +
		"policy authored in an unregistered language denies naming that language rather than being skipped")

	return serve(logger, grpcServer, lis)
}

// runMigrations opens a connection to cfg.MigrationDatabaseURL, applies
// pending migrations, and closes it before returning — deliberately scoped
// to this function rather than deferred at run's level, so the migration
// connection is always closed before run goes on to open the serving
// connection and, eventually, start accepting RPCs. See the package doc for
// why that separation matters.
func runMigrations(logger *slog.Logger, cfg config.Config) error {
	db, err := sql.Open("postgres", cfg.MigrationDatabaseURL)
	if err != nil {
		return fmt.Errorf("open migration database: %w", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			logger.Error("closing migration database", "error", cerr)
		}
	}()

	pingCtx, cancel := context.WithTimeout(context.Background(), cfg.DBTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("connect to migration database within %s: %w", cfg.DBTimeout, err)
	}

	if err := migrations.Up(db); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	logger.Info("migrations applied on STRATIUM_MIGRATION_DATABASE_URL, closing that connection")
	return nil
}

// serve runs grpcServer until it errors or a SIGINT/SIGTERM arrives, then
// stops it gracefully, forcing a stop if shutdownTimeout elapses first.
func serve(logger *slog.Logger, grpcServer *grpc.Server, lis net.Listener) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(lis) }()

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	logger.Info("shutdown signal received, stopping gracefully", "timeout", shutdownTimeout)
	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()
	select {
	case <-stopped:
		logger.Info("shutdown complete")
	case <-timer.C:
		logger.Warn("graceful shutdown timed out, forcing stop")
		grpcServer.Stop()
	}
	return nil
}
