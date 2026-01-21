package middleware

import (
	"context"
	"net/http"
	"time"

	"stratium/config"
	"stratium/logging"
	"stratium/pkg/licensing"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LicenseEnforcer blocks requests when offline license checks fail.
type LicenseEnforcer struct {
	manager     *licensing.Manager
	serviceName string
	logger      *logging.Logger
}

// NewLicenseEnforcer creates a license enforcer from config.
func NewLicenseEnforcer(cfg *config.Config, serviceName string) (*LicenseEnforcer, error) {
	manager, err := licensing.NewManager(cfg.License)
	if err != nil {
		return nil, err
	}

	return &LicenseEnforcer{
		manager:     manager,
		serviceName: serviceName,
		logger:      logging.GetLogger(),
	}, nil
}

// Enabled returns true when license enforcement is configured.
func (l *LicenseEnforcer) Enabled() bool {
	if l == nil || l.manager == nil {
		return false
	}
	return l.manager.Enabled()
}

// Check validates the license for the configured service.
func (l *LicenseEnforcer) Check() error {
	if !l.Enabled() {
		return nil
	}
	return l.manager.ValidateService(l.serviceName)
}

// LogStatus emits a one-line summary of license enforcement.
func (l *LicenseEnforcer) LogStatus() {
	if l == nil {
		return
	}
	if !l.Enabled() {
		l.logger.Startup("License enforcement: DISABLED")
		return
	}

	state := l.manager.State()
	if state.Valid && state.Claims != nil {
		expires := "never"
		if state.Claims.ExpiresAt != nil {
			expires = state.Claims.ExpiresAt.Time.Format(time.RFC3339)
		}
		customer := state.Claims.CustomerName
		if customer == "" {
			customer = state.Claims.CustomerID
		}
		l.logger.Startup(
			"License enforcement: ENABLED (customer=%s, deployment=%s, expires=%s)",
			customer,
			state.Claims.DeploymentID,
			expires,
		)
		return
	}

	l.logger.Warn("License enforcement enabled but license is invalid: %v", state.Err)
}

// UnaryServerInterceptor returns a gRPC unary interceptor for license checks.
func (l *LicenseEnforcer) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if l == nil || !l.Enabled() {
			return handler(ctx, req)
		}
		if err := l.manager.ValidateService(l.serviceName); err != nil {
			l.logger.Warn("license enforcement blocked unary request %s: %v", info.FullMethod, err)
			return nil, status.Errorf(codes.PermissionDenied, "license invalid")
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream interceptor for license checks.
func (l *LicenseEnforcer) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if l == nil || !l.Enabled() {
			return handler(srv, ss)
		}
		if err := l.manager.ValidateService(l.serviceName); err != nil {
			l.logger.Warn("license enforcement blocked stream request %s: %v", info.FullMethod, err)
			return status.Errorf(codes.PermissionDenied, "license invalid")
		}
		return handler(srv, ss)
	}
}

// GinMiddleware enforces license validation for HTTP requests.
func (l *LicenseEnforcer) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if l == nil || !l.Enabled() {
			c.Next()
			return
		}
		if err := l.manager.ValidateService(l.serviceName); err != nil {
			l.logger.Warn("license enforcement blocked http request %s %s: %v", c.Request.Method, c.Request.URL.Path, err)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "license invalid"})
			return
		}
		c.Next()
	}
}
