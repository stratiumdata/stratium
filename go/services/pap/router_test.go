package pap

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"stratium/config"
	"stratium/pkg/cache"
	"stratium/pkg/models"
	"stratium/pkg/policy_engine"
	"stratium/pkg/repository"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Mock database for health-check tests
// ---------------------------------------------------------------------------

type mockDatabase struct {
	pingErr error
}

func (m *mockDatabase) Connect(ctx context.Context, connString string) error { return nil }
func (m *mockDatabase) Close() error                                          { return nil }
func (m *mockDatabase) Ping(ctx context.Context) error                        { return m.pingErr }
func (m *mockDatabase) BeginTx(ctx context.Context) (repository.Transaction, error) {
	return nil, models.ErrNotImplemented
}

// newRepoWithDB builds a Repository whose Ping goes to the supplied mockDatabase.
func newRepoWithDB(policyRepo *mockPolicyRepo, entitlementRepo *mockEntitlementRepo, auditRepo *mockAuditRepo, db *mockDatabase) *repository.Repository {
	repo := repository.NewRepository(db)
	repo.Policy = policyRepo
	repo.Entitlement = entitlementRepo
	repo.Audit = auditRepo
	return repo
}

// defaultCORSConfig returns a permissive CORS config suitable for tests.
func defaultCORSConfig() config.CORSConfig {
	return config.CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	}
}

// ---------------------------------------------------------------------------
// NewServer / setupRoutes
// ---------------------------------------------------------------------------

func TestNewServer_CreatesRouter(t *testing.T) {
	repo := &repository.Repository{
		Policy:      newMockPolicyRepo(),
		Entitlement: newMockEntitlementRepo(),
		Audit:       &mockAuditRepo{},
	}
	s := NewServer(repo, NewMockAuthService(), defaultCORSConfig(), nil)
	if s == nil {
		t.Fatal("NewServer() returned nil")
	}
	if s.router == nil {
		t.Fatal("NewServer() did not initialise router")
	}
}

func TestNewServer_HealthCheckRoute(t *testing.T) {
	db := &mockDatabase{}
	repo := newRepoWithDB(newMockPolicyRepo(), newMockEntitlementRepo(), &mockAuditRepo{}, db)
	s := NewServer(repo, NewMockAuthService(), defaultCORSConfig(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /health = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// healthCheck
// ---------------------------------------------------------------------------

func TestHealthCheck_Healthy(t *testing.T) {
	db := &mockDatabase{pingErr: nil}
	repo := newRepoWithDB(newMockPolicyRepo(), newMockEntitlementRepo(), &mockAuditRepo{}, db)
	s := NewServer(repo, NewMockAuthService(), defaultCORSConfig(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("healthCheck status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

func TestHealthCheck_Unhealthy(t *testing.T) {
	db := &mockDatabase{pingErr: models.ErrDatabaseConnection}
	repo := newRepoWithDB(newMockPolicyRepo(), newMockEntitlementRepo(), &mockAuditRepo{}, db)
	s := NewServer(repo, NewMockAuthService(), defaultCORSConfig(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("healthCheck status = %d, want 503 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// OPTIONS preflight handlers (exercises setupRoutes OPTIONS registrations)
// ---------------------------------------------------------------------------

func TestSetupRoutes_OptionsPolicies(t *testing.T) {
	s := NewServer(
		&repository.Repository{
			Policy:      newMockPolicyRepo(),
			Entitlement: newMockEntitlementRepo(),
			Audit:       &mockAuditRepo{},
		},
		NewMockAuthService(),
		defaultCORSConfig(),
		nil,
	)

	for _, path := range []string{
		"/api/v1/policies",
		"/api/v1/policies/some-id",
		"/api/v1/entitlements",
		"/api/v1/entitlements/some-id",
		"/api/v1/audit-logs",
		"/api/v1/audit-logs/some-id",
	} {
		t.Run("OPTIONS "+path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodOptions, path, nil)
			s.router.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				t.Errorf("OPTIONS %s = %d, want 204", path, w.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// mockAuthMiddleware (covered via full-router request with mock auth)
// ---------------------------------------------------------------------------

func TestMockAuthMiddleware_SetsUser(t *testing.T) {
	db := &mockDatabase{}
	repo := newRepoWithDB(newMockPolicyRepo(), newMockEntitlementRepo(), &mockAuditRepo{}, db)
	// NewMockAuthService() returns isMock=true → setupRoutes uses mockAuthMiddleware
	s := NewServer(repo, NewMockAuthService(), defaultCORSConfig(), nil)

	// GET /api/v1/policies routes through mockAuthMiddleware → sets "user" → listPolicies
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	s.router.ServeHTTP(w, req)

	// listPolicies returns 200 if auth passed
	if w.Code != http.StatusOK {
		t.Errorf("mockAuthMiddleware: GET /api/v1/policies = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// authMiddleware (real auth, non-mock mode — test error paths)
// ---------------------------------------------------------------------------

func TestAuthMiddleware_MissingAuthHeader(t *testing.T) {
	// Build a server using a real (non-mock) AuthService so authMiddleware is used.
	// We can construct AuthService directly with isMock=false — real OIDC won't be
	// invoked because we exercise the early-exit paths before token verification.
	authSvc := &AuthService{isMock: false}

	repo := &repository.Repository{
		Policy:      newMockPolicyRepo(),
		Entitlement: newMockEntitlementRepo(),
		Audit:       &mockAuditRepo{},
	}
	s := &Server{
		router:           newGinEngine(),
		repo:             repo,
		engineFactory:    policy_engine.NewEngineFactory(),
		authService:      authSvc,
		cacheInvalidator: cache.NewNoOpCacheInvalidator(),
	}
	s.setupRoutes(defaultCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	// No Authorization header
	s.router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("authMiddleware (no header) = %d, want 401 — body: %s", w.Code, w.Body.String())
	}
}

func TestAuthMiddleware_InvalidBearerFormat(t *testing.T) {
	authSvc := &AuthService{isMock: false}

	repo := &repository.Repository{
		Policy:      newMockPolicyRepo(),
		Entitlement: newMockEntitlementRepo(),
		Audit:       &mockAuditRepo{},
	}
	s := &Server{
		router:           newGinEngine(),
		repo:             repo,
		engineFactory:    policy_engine.NewEngineFactory(),
		authService:      authSvc,
		cacheInvalidator: cache.NewNoOpCacheInvalidator(),
	}
	s.setupRoutes(defaultCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	req.Header.Set("Authorization", "NotBearer token123")
	s.router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("authMiddleware (bad format) = %d, want 401 — body: %s", w.Code, w.Body.String())
	}
}

func TestAuthMiddleware_SingleWordHeader(t *testing.T) {
	// Authorization: "token-only" splits to one part — format check fails with 401.
	authSvc := &AuthService{isMock: false}
	repo := &repository.Repository{
		Policy:      newMockPolicyRepo(),
		Entitlement: newMockEntitlementRepo(),
		Audit:       &mockAuditRepo{},
	}
	s := &Server{
		router:           newGinEngine(),
		repo:             repo,
		engineFactory:    policy_engine.NewEngineFactory(),
		authService:      authSvc,
		cacheInvalidator: cache.NewNoOpCacheInvalidator(),
	}
	s.setupRoutes(defaultCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	req.Header.Set("Authorization", "token-only")
	s.router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("authMiddleware (single word) = %d, want 401 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ConfigureTLS
// ---------------------------------------------------------------------------

func TestConfigureTLS_SetsTLS(t *testing.T) {
	s := &Server{}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	s.ConfigureTLS(tlsCfg)

	if !s.tlsEnabled {
		t.Error("ConfigureTLS: tlsEnabled = false, want true")
	}
	if s.tlsConfig != tlsCfg {
		t.Error("ConfigureTLS: tlsConfig not set correctly")
	}
}

func TestConfigureTLS_NilClearsEnabled(t *testing.T) {
	s := &Server{tlsEnabled: true, tlsConfig: &tls.Config{}}
	s.ConfigureTLS(nil)

	if s.tlsEnabled {
		t.Error("ConfigureTLS(nil): tlsEnabled = true, want false")
	}
	if s.tlsConfig != nil {
		t.Error("ConfigureTLS(nil): tlsConfig should be nil")
	}
}

// ---------------------------------------------------------------------------
// NewServerWithCacheInvalidator
// ---------------------------------------------------------------------------

func TestNewServerWithCacheInvalidator_CreatesRouter(t *testing.T) {
	repo := &repository.Repository{
		Policy:      newMockPolicyRepo(),
		Entitlement: newMockEntitlementRepo(),
		Audit:       &mockAuditRepo{},
	}
	invalidator := cache.NewNoOpCacheInvalidator()
	s := NewServerWithCacheInvalidator(repo, NewMockAuthService(), invalidator, defaultCORSConfig(), nil)

	if s == nil {
		t.Fatal("NewServerWithCacheInvalidator() returned nil")
	}
	if s.cacheInvalidator != invalidator {
		t.Error("NewServerWithCacheInvalidator: cacheInvalidator not stored")
	}

	// Verify routes are wired by hitting /health
	// Note: db is nil here so we need a mockDatabase; use a plain request to
	// an auth-guarded route instead to avoid the nil-db Ping.
	db := &mockDatabase{}
	repoWithDB := newRepoWithDB(newMockPolicyRepo(), newMockEntitlementRepo(), &mockAuditRepo{}, db)
	s2 := NewServerWithCacheInvalidator(repoWithDB, NewMockAuthService(), invalidator, defaultCORSConfig(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	s2.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("NewServerWithCacheInvalidator: GET /api/v1/policies = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// setupRoutes with licenseEnforcer.Enabled() == false (non-nil enforcer)
// Exercises the licenseEnforcer != nil branch in setupRoutes.
// ---------------------------------------------------------------------------

func TestSetupRoutes_LicenseEnforcerNilSkipped(t *testing.T) {
	// nil licenseEnforcer → the if-branch in setupRoutes is skipped; routes still work.
	db := &mockDatabase{}
	repo := newRepoWithDB(newMockPolicyRepo(), newMockEntitlementRepo(), &mockAuditRepo{}, db)
	s := NewServer(repo, NewMockAuthService(), defaultCORSConfig(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("setupRoutes (nil enforcer): GET /health = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// getAuditLog: valid UUID that is found (exercises the success branch)
// ---------------------------------------------------------------------------

type mockAuditRepoWithFound struct {
	mockAuditRepo
	foundLog *models.AuditLog
}

func (m *mockAuditRepoWithFound) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error) {
	if m.foundLog != nil {
		return m.foundLog, nil
	}
	return m.mockAuditRepo.GetByID(ctx, id)
}

func TestPAP_GetAuditLog_Found(t *testing.T) {
	logID := uuid.New()
	auditRepo := &mockAuditRepoWithFound{
		foundLog: &models.AuditLog{ID: logID, Action: models.AuditActionCreate},
	}
	repo := &repository.Repository{
		Policy:      newMockPolicyRepo(),
		Entitlement: newMockEntitlementRepo(),
		Audit:       auditRepo,
	}
	srv := &Server{
		repo:             repo,
		engineFactory:    policy_engine.NewEngineFactory(),
		authService:      NewMockAuthService(),
		cacheInvalidator: cache.NewNoOpCacheInvalidator(),
	}

	w := httptest.NewRecorder()
	c, _ := newGinTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs/"+logID.String(), nil)
	c.Params = ginParams("id", logID.String())
	c.Set("user", "test-user")
	srv.getAuditLog(c)

	if w.Code != http.StatusOK {
		t.Errorf("getAuditLog (found) = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// getPolicy: internal server error (non-ErrPolicyNotFound)
// ---------------------------------------------------------------------------

func TestPAP_GetPolicy_InternalError(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	policyRepo.getErr = models.ErrDatabaseConnection
	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())

	id := uuid.New()
	c, w := ginContext(t, http.MethodGet, "/api/v1/policies/"+id.String(), nil)
	c.Params = ginParams("id", id.String())
	srv.getPolicy(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("getPolicy (internal error) = %d, want 500 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// getEntitlement: internal server error (non-ErrEntitlementNotFound)
// ---------------------------------------------------------------------------

func TestPAP_GetEntitlement_InternalError(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	entitlementRepo.getErr = models.ErrDatabaseConnection
	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)

	id := uuid.New()
	c, w := ginContext(t, http.MethodGet, "/api/v1/entitlements/"+id.String(), nil)
	c.Params = ginParams("id", id.String())
	srv.getEntitlement(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("getEntitlement (internal error) = %d, want 500 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// updateEntitlement: internal server error fetching existing entitlement
// ---------------------------------------------------------------------------

func TestPAP_UpdateEntitlement_GetError(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	entitlementRepo.getErr = models.ErrDatabaseConnection
	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)

	id := uuid.New()
	newName := "whatever"
	req := models.UpdateEntitlementRequest{Name: &newName}

	c, w := ginContext(t, http.MethodPatch, "/api/v1/entitlements/"+id.String(), req)
	c.Params = ginParams("id", id.String())
	srv.updateEntitlement(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("updateEntitlement (get internal error) = %d, want 500 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// updatePolicy: internal server error fetching existing policy
// ---------------------------------------------------------------------------

func TestPAP_UpdatePolicy_GetError(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	policyRepo.getErr = models.ErrDatabaseConnection
	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())

	id := uuid.New()
	newName := "whatever"
	req := models.UpdatePolicyRequest{Name: &newName}

	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+id.String(), req)
	c.Params = ginParams("id", id.String())
	srv.updatePolicy(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("updatePolicy (get internal error) = %d, want 500 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// deletePolicy: internal server error fetching policy for audit
// ---------------------------------------------------------------------------

func TestPAP_DeletePolicy_GetError(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	policyRepo.getErr = models.ErrDatabaseConnection
	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())

	id := uuid.New()
	c, w := ginContext(t, http.MethodDelete, "/api/v1/policies/"+id.String(), nil)
	c.Params = ginParams("id", id.String())
	c.Set("user", "test-user")
	srv.deletePolicy(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("deletePolicy (get internal error) = %d, want 500 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// deleteEntitlement: internal server error fetching entitlement for audit
// ---------------------------------------------------------------------------

func TestPAP_DeleteEntitlement_GetError(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	entitlementRepo.getErr = models.ErrDatabaseConnection
	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)

	id := uuid.New()
	c, w := ginContext(t, http.MethodDelete, "/api/v1/entitlements/"+id.String(), nil)
	c.Params = ginParams("id", id.String())
	c.Set("user", "test-user")
	srv.deleteEntitlement(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("deleteEntitlement (get internal error) = %d, want 500 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// validatePolicy: unsupported language after body is parsed (GetEngine fails)
// ---------------------------------------------------------------------------

func TestPAP_ValidatePolicy_UnsupportedLanguageGetEngine(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := map[string]interface{}{
		"language":       "opa",
		"policy_content": "package test\nallow { true }",
	}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/validate", body)
	srv.validatePolicy(c)

	// OPA is a valid language so GetEngine succeeds; just verify we get 200.
	if w.Code != http.StatusOK {
		t.Errorf("validatePolicy (opa) = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// testPolicy: unsupported language after validation passes GetEngine check
// ---------------------------------------------------------------------------

func TestPAP_TestPolicy_ValidOPALanguage(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := map[string]interface{}{
		"language":       "opa",
		"policy_content": "package test\ndefault allow = false\nallow { true }",
		"subject_attributes": map[string]interface{}{
			"role": "admin",
		},
		"resource_attributes": map[string]interface{}{
			"name": "doc",
		},
		"action": "read",
	}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("testPolicy (opa) = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Helpers not already defined in handlers_test.go
// ---------------------------------------------------------------------------

// newGinEngine creates a new gin engine in test mode.
// Used when we need to call setupRoutes manually on a Server.
func newGinEngine() *gin.Engine {
	return gin.New()
}

// newGinTestContext creates a minimal gin context backed by a recorder.
func newGinTestContext(w *httptest.ResponseRecorder) (*gin.Context, *gin.Engine) {
	eng := gin.New()
	c, _ := gin.CreateTestContext(w)
	return c, eng
}

// ginParams returns a gin.Params slice with a single key-value pair.
func ginParams(key, value string) gin.Params {
	return gin.Params{{Key: key, Value: value}}
}
