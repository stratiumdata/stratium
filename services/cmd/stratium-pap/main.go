// Command stratium-pap is the admin plane: the first component in this
// system that authenticates a human, and the only internet-facing one. It
// verifies an OIDC bearer token against the customer's IdP, resolves a
// role from a configured claim, and gates every route on it -- Task 1's
// whole scope. No writes exist yet (Task 3); every route reachable today
// returns "not implemented," but only to a verified operator holding a
// sufficient role, so the security foundation this binary's later write
// credentials depend on is proven before anything can use it.
//
// The tenant (STRATIUM_PAP_TENANT_ID) is read once, here, at startup, and
// nowhere else in this binary -- see server.go's package doc for how the
// HTTP surface keeps that true once routes exist, and config.go's for why
// it, like every other required value, has no default to guess.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
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
// cleanup (none needed here yet; Task 3 opens a database connection this
// will need to close) has a single, testable place to live.
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
	ctx, cancel := context.WithTimeout(context.Background(), cfg.OIDCTimeout)
	defer cancel()
	verifier, err := NewVerifier(ctx, cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCTimeout)
	if err != nil {
		return fmt.Errorf("initialize OIDC verifier: %w", err)
	}

	srv := NewServer(verifier, cfg.RoleClaim, cfg.Roles)
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
