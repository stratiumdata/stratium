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
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq" // registers the "postgres" database/sql driver
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/stratiumdata/stratium/internal/config"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/internal/token"
	"github.com/stratiumdata/stratium/migrations"
)

// shutdownTimeout bounds GracefulStop. A connection that never finishes must
// not prevent the process from exiting once a shutdown signal arrives.
const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	// SetDefault as well as passing logger explicitly. Everything in this
	// file threads the logger through, which stays the house style, but
	// internal/pdpgrpc has one thing to say that nothing asked it for — a
	// tier override dropped for lowering the tier beneath it
	// (honoredOverrides, server.go) — and pdpgrpc.NewServer has no logger
	// parameter to reach it through. Giving it one would mean touching every
	// one of its ~79 construction sites to carry a dependency exactly one
	// line uses. slog.Default() is Go's own answer for a library with no
	// injected logger; this line is what makes it the same handler, format,
	// and stream (stdout) as every other line this binary emits, instead of
	// slog's built-in default, which writes plain text to stderr.
	slog.SetDefault(logger)
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

	// Checked before anything stateful (migrations, the serving DB
	// connection): buildRegistry only needs cfg.PolicyLanguages, so a
	// misconfigured language name is caught for free, before this process
	// has opened a single network connection — the cheapest possible fail
	// fast, and the same principle DatabaseURL/TenantID's own presence
	// checks already apply above.
	registry, err := buildRegistry(cfg.PolicyLanguages)
	if err != nil {
		return fmt.Errorf("build policy registry: %w", err)
	}

	// Loaded here for the same reason buildRegistry is checked first: pure
	// filesystem and crypto, no network connection open yet, so a missing or
	// malformed signing key fails before this process has touched the
	// database at all — the cheapest possible fail fast, and the one K1
	// itself calls for ("a PDP that starts without a signing key and fails
	// every decision looks like a policy problem, not a deployment one").
	// The private key never leaves this process from here on: signer is
	// passed to pdpgrpc.NewServer below and nowhere else, so the PDP stays
	// the sole signing-key holder (spec A4).
	signer, err := token.Load(cfg.TokenSigningKeyPath, cfg.TokenPreviousKeyPath)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
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

	// The schedule K8 requires for spent_proofs (reaper.go). Started here,
	// after the connection is proven and before the server accepts anything,
	// so the very first decision that spends a jti already has a sweeper
	// behind it. Cancelled by this defer when run returns — which is after
	// serve() below has finished shutting the gRPC server down — so the last
	// thing to stop is the thing with nothing left to do.
	//
	// Nothing waits for the goroutine to observe the cancellation. A sweep in
	// flight at shutdown is a DELETE of rows that are already expired: losing
	// it costs one interval of table growth, and the next process to start
	// deletes them. Blocking exit on it would be paying a shutdown-latency
	// risk for nothing.
	reaperCtx, stopReaper := context.WithCancel(context.Background())
	defer stopReaper()
	go reapSpentProofs(reaperCtx, logger, repo.ReapSpentProofs, cfg.SpentProofReapInterval, cfg.DBTimeout)

	// policy.Multi is wired in with a real, non-empty registry (built above,
	// from cfg.PolicyLanguages, before this process opened any network
	// connection) holding every language this deployment enabled, default
	// all four. Multi is what closes spec defect D10: a tenant whose
	// policies.language names a language with no registered engine — because
	// this deployment's operator left it out of STRATIUM_POLICY_LANGUAGES, or
	// because a tenant authored in a language this build has never shipped —
	// gets an honest deny naming that language (see Multi's own doc comment
	// in internal/policy/multi.go and orphanVerdicts specifically). Multi
	// loads and prepares this tenant's policies fresh on every Decide call
	// (no cache — see the Phase 2c plan's "caching is deliberately out of
	// scope" and Task 5's and Task 6's own measurements of why). A tenant
	// with no policies stored still denies at the principal leg.
	//
	// A deployment that wants no policy engine at all today needs an
	// explicitly empty Multi (NewMulti(repo, policy.Registry{})) — not
	// reachable through STRATIUM_POLICY_LANGUAGES, since an empty configured
	// value is treated as unset (see config.Load's own envOr-style default),
	// only by code choosing to build one. pdpgrpc.NewServer takes a concrete
	// policy.Multi specifically because it needs PrepareAll for the
	// delegation-creation gate.
	//
	// Unconfigured (a bare, single-engine PrincipalPolicy with no allow-all
	// variant), policy.Configured (which delegated to exactly one
	// PolicyEngine), policy.PolicySource, and store.LoadPolicies are gone —
	// Phase 4a Task 4 deleted all four (see internal/policy/policy.go's own
	// package doc for the full history). A Registry with one entry behaves
	// identically to Configured with that entry's engine, so Configured was
	// redundant with Multi even before considering that it was also worse
	// than merely unused — Configured(source, cedar.New()) loaded exactly
	// one language and silently ignored every policy a tenant wrote in any
	// other, no error, no verdict, no audit trace, which is defect D10
	// itself, the defect this whole phase exists to eliminate. Keeping a
	// redundant path shaped exactly like the bug around, on the theory that
	// it might still "earn its keep," kept that bug wireable.
	//
	// repo satisfies both Store (pdpgrpc's own dependency interface) and
	// policy.AllPolicySource structurally, so it needs no adapter to serve
	// both — and Multi itself now supplies pdpgrpc's CreateDelegation gate
	// with a compiled set via PrepareAll, so repo and an engine no longer
	// need to be passed to NewServer a second time raw.
	srv := pdpgrpc.NewServer(repo, policy.NewMulti(repo, registry), cfg, signer)

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
	// registryLanguages(registry), not cfg.PolicyLanguages: this reports what
	// actually got wired (registry's own keys), not the configured value that
	// produced it — the two agree whenever config is well-formed (the only
	// way run() reaches this line at all, per buildRegistry's own fail-fast
	// check above), but the registry is the ground truth to log.
	logger.Info("principal policy: multi-engine (registered: " + strings.Join(registryLanguages(registry), ", ") +
		"), policies loaded fresh from the store on every decision (no cache); a tenant with none stored still " +
		"denies at the principal leg, and a policy authored in an unregistered language denies naming that " +
		"language rather than being skipped")

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
