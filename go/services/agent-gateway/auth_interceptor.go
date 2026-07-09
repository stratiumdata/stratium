package agent_gateway

import (
	"context"
	"fmt"
	"strings"

	"stratium/config"
	"stratium/pkg/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenVerifier verifies a raw OIDC bearer token and returns the caller's
// identity (preferred_username, falling back to sub) from VERIFIED claims.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (string, error)
}

// identityCtxKey is the private context key for the verified caller identity.
type identityCtxKey struct{}

func withIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, identity)
}

// identityFromContext returns the verified identity set by the interceptor.
// An empty identity is treated as absent.
func identityFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(identityCtxKey{}).(string)
	return id, ok && id != ""
}

// oidcVerifier is the production TokenVerifier backed by the shared
// JWKS-verifying AuthService. It uses ValidateToken (real signature check) only —
// NOT AuthService.AuthInterceptor/MockValidateToken, which fall back to unverified
// parsing.
type oidcVerifier struct {
	svc *auth.AuthService
}

// NewOIDCVerifier builds a JWKS-backed verifier from the shared OIDC config.
// It performs OIDC discovery (a network call to the issuer); an unreachable issuer
// returns an error, which callers MUST treat as fatal (fail-closed).
func NewOIDCVerifier(oidcCfg *config.OIDCConfig) (TokenVerifier, error) {
	svc, err := auth.NewAuthService(oidcCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC verifier: %w", err)
	}
	return &oidcVerifier{svc: svc}, nil
}

func (v *oidcVerifier) Verify(ctx context.Context, rawToken string) (string, error) {
	claims, err := v.svc.ValidateToken(ctx, rawToken)
	if err != nil {
		return "", err
	}
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername, nil
	}
	return claims.Sub, nil
}

// IdentityVerificationInterceptor verifies a present bearer token and stores the
// verified identity in the context. A present-but-invalid token is rejected on
// every RPC; an absent token passes through with no identity (handlers that
// require identity reject via extractUserID).
func IdentityVerificationInterceptor(v TokenVerifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if authz := md.Get("authorization"); len(authz) > 0 {
				if raw := stripBearer(authz[0]); raw != "" {
					identity, err := v.Verify(ctx, raw)
					if err != nil {
						return nil, status.Error(codes.Unauthenticated, "token verification failed")
					}
					ctx = withIdentity(ctx, identity)
				}
			}
		}
		return handler(ctx, req)
	}
}

func stripBearer(header string) string {
	// Trim only leading whitespace before the prefix check so trailing spaces
	// in "Bearer    " don't collapse the value to "Bearer" (no space → no match).
	h := strings.TrimLeft(header, " \t\r\n")
	const prefix = "bearer "
	if len(h) >= len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return strings.TrimSpace(h)
}
