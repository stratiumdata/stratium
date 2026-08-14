// Command stratium-pap is the admin plane: the first component in this
// system that authenticates a human, and the only internet-facing one. It
// verifies an OIDC bearer token against the customer's IdP, resolves a role
// from a configured claim, and gates every route on it (Task 1); Task 3
// adds this binary's first database access, the stratium_pap_login
// connection Task 2's migration built the grants for, and the CRUD routes
// (policies.go, agents.go, tier_overrides.go) that use it -- every route is
// reachable only by a verified operator holding a sufficient role, so the
// security foundation Task 1 proved is what everything here depends on.
//
// The tenant (STRATIUM_PAP_TENANT_ID) is read once, here, at startup, and
// nowhere else in this binary -- see server.go's package doc for how the
// HTTP surface keeps that true, and internal/store.New, called once below
// with cfg.TenantID, for how it stays true all the way down to the write
// connection this binary now holds. config.go's own doc comment covers why
// it, like every other required value, has no default to guess.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq" // registers the "postgres" database/sql driver

	"stratium/internal/store"
)

// shutdownTimeout bounds Shutdown -- the http.Server analogue of
// cmd/stratium-pdp/main.go's own shutdownTimeout for GracefulStop: a
// connection that never finishes must not prevent the process from
// exiting once a shutdown signal arrives.
const shutdownTimeout = 10 * time.Second

// readHeaderTimeout bounds how long ListenAndServe waits for a client to
// finish sending request headers -- the standard defense against a
// slow-headers client tying up a connection indefinitely, worth stating
// explicitly (net/http's own zero value is "no timeout") specifically
// because this is the one binary in this system reachable from the
// internet.
const readHeaderTimeout = 5 * time.Second

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("stratium-pap exited with error", "error", err)
		os.Exit(1)
	}
}

// run does the real work and returns an error instead of calling os.Exit
// itself, matching cmd/stratium-pdp/main.go's own run -- so main's deferred
// cleanup (db.Close, added this task) has a single, testable place to live.
func run(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// OIDC discovery is deliberately a separate, later step from
	// loadConfig above, not folded into it -- see config.go's own doc
	// comment: loadConfig checks presence and syntax only (pure, no
	// network), while discovery is real I/O against the configured
	// issuer and fails for a different reason (an unreachable or
	// non-conformant IdP, not a missing environment variable). The same
	// layering cmd/stratium-pdp/main.go uses for token.Load, called
	// separately after its own config.Load.
	oidcCtx, oidcCancel := context.WithTimeout(context.Background(), cfg.OIDCTimeout)
	defer oidcCancel()
	verifier, err := NewVerifier(oidcCtx, cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCTimeout)
	if err != nil {
		return fmt.Errorf("initialize OIDC verifier: %w", err)
	}

	// The database connection, opened here for the first time in this
	// binary's history (Task 1/2 had none -- see the package doc). This
	// process authenticates as stratium_pap_login (deploy/docker/
	// init-db.sql; migrations/000016_stratium_pap_role), the write role
	// Task 2 built, never stratium_app: STRATIUM_PAP_DATABASE_URL names
	// which identity connects, and CreatePolicy/CreateAgent/
	// CreateTierOverride succeeding at all depends on it naming the right
	// one -- a URL misconfigured to stratium_app would fail every write
	// closed with a permission-denied error, not silently reuse a
	// read-only grant, since stratium_app has no INSERT/UPDATE/DELETE on
	// any of these tables (N3).
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			logger.Error("closing database", "error", cerr)
		}
	}()

	pingCtx, pingCancel := context.WithTimeout(context.Background(), cfg.DBTimeout)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("connect to database within %s: %w", cfg.DBTimeout, err)
	}

	repo := store.New(db, cfg.TenantID)
	registry := newPolicyRegistry()

	srv := NewServer(verifier, cfg.RoleClaim, cfg.Roles, repo, registry)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	logger.Info("stratium-pap starting", "tenant_id", cfg.TenantID, "listen_addr", cfg.ListenAddr,
		"oidc_issuer", cfg.OIDCIssuer)
	return serve(logger, httpServer)
}

// serve runs httpServer until it errors or a SIGINT/SIGTERM arrives, then
// shuts it down gracefully, forcing a close if shutdownTimeout elapses
// first. The http.Server analogue of cmd/stratium-pdp/main.go's own serve
// for a grpc.Server.
func serve(logger *slog.Logger, httpServer *http.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.ListenAndServe() }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	logger.Info("shutdown signal received, stopping gracefully", "timeout", shutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown did not complete cleanly", "error", err)
	}
	return nil
}
