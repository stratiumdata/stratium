package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/stratiumdata/stratium/internal/config"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/internal/principal"
)

// configurePrincipalAuth gives srv the means to learn who a new session is
// for: an OIDC verifier, unless the operator set
// STRATIUM_PRINCIPAL_AUTH_INSECURE=true (config.Load refuses a Config with
// neither). The opt-out is logged as a warning on every start.
//
// Discovery runs here, before the listener opens: a PDP pointed at a wrong
// or unreachable issuer stops at startup instead of refusing every session.
func configurePrincipalAuth(logger *slog.Logger, cfg config.Config, srv *pdpgrpc.Server) error {
	if cfg.PrincipalAuthInsecure {
		logger.Warn("principal authentication is OFF (STRATIUM_PRINCIPAL_AUTH_INSECURE=true): any caller can " +
			"start a session for any subject; use only for local development")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.PrincipalOIDCTimeout)
	defer cancel()
	v, err := principal.NewVerifier(ctx, cfg.PrincipalOIDCIssuer, cfg.PrincipalOIDCAudience,
		cfg.PrincipalClaim, cfg.PrincipalOIDCTimeout)
	if err != nil {
		return fmt.Errorf("principal authentication (STRATIUM_PRINCIPAL_OIDC_ISSUER): %w", err)
	}
	srv.WithPrincipalVerifier(v)
	if principal.ChangeableClaim(cfg.PrincipalClaim) {
		logger.Warn("STRATIUM_PRINCIPAL_CLAIM names a claim that a person or their administrator can change; "+
			"use one the identity provider never reassigns, such as sub or oid", "claim", cfg.PrincipalClaim)
	}
	logger.Info("principal authentication: root delegations require an OIDC token",
		"issuer", cfg.PrincipalOIDCIssuer, "audience", cfg.PrincipalOIDCAudience, "claim", cfg.PrincipalClaim)
	return nil
}
