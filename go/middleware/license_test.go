package middleware

import (
	"context"
	"net/http/httptest"
	"testing"

	"stratium/config"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

// newDisabledEnforcer creates a LicenseEnforcer with licensing disabled.
func newDisabledEnforcer(t *testing.T) *LicenseEnforcer {
	t.Helper()
	cfg := &config.Config{
		License: config.LicenseConfig{
			Enabled: false,
		},
	}
	enforcer, err := NewLicenseEnforcer(cfg, "test-service")
	if err != nil {
		t.Fatalf("NewLicenseEnforcer() error = %v", err)
	}
	return enforcer
}

// TestNewLicenseEnforcer_Disabled verifies constructor succeeds with disabled config.
func TestNewLicenseEnforcer_Disabled(t *testing.T) {
	enforcer := newDisabledEnforcer(t)
	if enforcer == nil {
		t.Fatal("NewLicenseEnforcer() returned nil")
	}
}

// TestLicenseEnforcer_Enabled_WhenDisabled verifies Enabled() returns false when not configured.
func TestLicenseEnforcer_Enabled_WhenDisabled(t *testing.T) {
	enforcer := newDisabledEnforcer(t)
	if enforcer.Enabled() {
		t.Error("Enabled() = true for disabled license config, want false")
	}
}

// TestLicenseEnforcer_Enabled_NilEnforcer verifies nil enforcer returns false.
func TestLicenseEnforcer_Enabled_NilEnforcer(t *testing.T) {
	var enforcer *LicenseEnforcer
	if enforcer.Enabled() {
		t.Error("Enabled() = true for nil LicenseEnforcer, want false")
	}
}

// TestLicenseEnforcer_Check_Disabled verifies Check() returns nil when disabled.
func TestLicenseEnforcer_Check_Disabled(t *testing.T) {
	enforcer := newDisabledEnforcer(t)
	if err := enforcer.Check(); err != nil {
		t.Errorf("Check() error = %v, want nil when disabled", err)
	}
}

// TestLicenseEnforcer_LogStatus_Disabled verifies LogStatus doesn't panic when disabled.
func TestLicenseEnforcer_LogStatus_Disabled(t *testing.T) {
	enforcer := newDisabledEnforcer(t)
	enforcer.LogStatus() // should not panic
}

// TestLicenseEnforcer_LogStatus_Nil verifies nil enforcer doesn't panic.
func TestLicenseEnforcer_LogStatus_Nil(t *testing.T) {
	var enforcer *LicenseEnforcer
	enforcer.LogStatus() // should not panic
}

// TestLicenseEnforcer_UnaryServerInterceptor_Disabled verifies interceptor passes through when disabled.
func TestLicenseEnforcer_UnaryServerInterceptor_Disabled(t *testing.T) {
	enforcer := newDisabledEnforcer(t)
	interceptor := enforcer.UnaryServerInterceptor()
	if interceptor == nil {
		t.Fatal("UnaryServerInterceptor() returned nil")
	}

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}

	resp, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{FullMethod: "/test"}, handler)
	if err != nil {
		t.Errorf("interceptor error = %v, want nil when disabled", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %v, want 'ok'", resp)
	}
	if !called {
		t.Error("handler was not called when license is disabled")
	}
}

// TestLicenseEnforcer_UnaryServerInterceptor_NilEnforcer verifies nil enforcer passes through.
func TestLicenseEnforcer_UnaryServerInterceptor_NilEnforcer(t *testing.T) {
	var enforcer *LicenseEnforcer
	interceptor := enforcer.UnaryServerInterceptor()

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return nil, nil
	}

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Errorf("nil enforcer interceptor error = %v", err)
	}
	if !called {
		t.Error("handler was not called for nil enforcer")
	}
}

// TestLicenseEnforcer_StreamServerInterceptor_Disabled verifies stream interceptor passes through when disabled.
func TestLicenseEnforcer_StreamServerInterceptor_Disabled(t *testing.T) {
	enforcer := newDisabledEnforcer(t)
	interceptor := enforcer.StreamServerInterceptor()
	if interceptor == nil {
		t.Fatal("StreamServerInterceptor() returned nil")
	}

	called := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		called = true
		return nil
	}

	err := interceptor(nil, nil, &grpc.StreamServerInfo{FullMethod: "/test"}, handler)
	if err != nil {
		t.Errorf("stream interceptor error = %v, want nil when disabled", err)
	}
	if !called {
		t.Error("stream handler was not called when license is disabled")
	}
}

// TestLicenseEnforcer_GinMiddleware_Disabled verifies gin middleware calls Next() when disabled.
func TestLicenseEnforcer_GinMiddleware_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	enforcer := newDisabledEnforcer(t)
	mw := enforcer.GinMiddleware()
	if mw == nil {
		t.Fatal("GinMiddleware() returned nil")
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/health", nil)

	mw(c) // should not abort

	if w.Code == 403 {
		t.Error("GinMiddleware() should not block when license is disabled")
	}
}

// TestLicenseEnforcer_GinMiddleware_NilEnforcer verifies nil enforcer calls Next().
func TestLicenseEnforcer_GinMiddleware_NilEnforcer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var enforcer *LicenseEnforcer
	mw := enforcer.GinMiddleware()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	mw(c) // should not panic or abort

	if w.Code == 403 {
		t.Error("nil enforcer GinMiddleware() should not block")
	}
}
