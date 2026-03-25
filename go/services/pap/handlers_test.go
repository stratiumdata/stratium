package pap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stratium/pkg/cache"
	"stratium/pkg/models"
	"stratium/pkg/policy_engine"
	"stratium/pkg/repository"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

type mockPolicyRepo struct {
	policies  map[uuid.UUID]*models.Policy
	createErr error
	listErr   error
	countErr  error
	getErr    error
	updateErr error
	deleteErr error
}

func newMockPolicyRepo() *mockPolicyRepo {
	return &mockPolicyRepo{policies: make(map[uuid.UUID]*models.Policy)}
}

func (m *mockPolicyRepo) Create(ctx context.Context, p *models.Policy) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.policies[p.ID] = p
	return nil
}

func (m *mockPolicyRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	p, ok := m.policies[id]
	if !ok {
		return nil, models.ErrPolicyNotFound
	}
	return p, nil
}

func (m *mockPolicyRepo) GetByName(ctx context.Context, name string) (*models.Policy, error) {
	for _, p := range m.policies {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("policy not found")
}

func (m *mockPolicyRepo) List(ctx context.Context, req *models.ListPoliciesRequest) ([]*models.Policy, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	out := make([]*models.Policy, 0, len(m.policies))
	for _, p := range m.policies {
		out = append(out, p)
	}
	return out, nil
}

func (m *mockPolicyRepo) Update(ctx context.Context, p *models.Policy) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.policies[p.ID] = p
	return nil
}

func (m *mockPolicyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.policies, id)
	return nil
}

func (m *mockPolicyRepo) ListEnabled(ctx context.Context) ([]*models.Policy, error) {
	return m.List(ctx, &models.ListPoliciesRequest{})
}

func (m *mockPolicyRepo) Count(ctx context.Context, req *models.ListPoliciesRequest) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	if m.listErr != nil {
		return 0, m.listErr
	}
	return len(m.policies), nil
}

type mockEntitlementRepo struct {
	entitlements    map[uuid.UUID]*models.Entitlement
	createErr       error
	listErr         error
	countErr        error
	getErr          error
	updateErr       error
	deleteErr       error
	findMatchingErr error
}

func newMockEntitlementRepo() *mockEntitlementRepo {
	return &mockEntitlementRepo{entitlements: make(map[uuid.UUID]*models.Entitlement)}
}

func (m *mockEntitlementRepo) Create(ctx context.Context, e *models.Entitlement) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.entitlements[e.ID] = e
	return nil
}

func (m *mockEntitlementRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Entitlement, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	e, ok := m.entitlements[id]
	if !ok {
		return nil, models.ErrEntitlementNotFound
	}
	return e, nil
}

func (m *mockEntitlementRepo) GetByName(ctx context.Context, name string) (*models.Entitlement, error) {
	for _, e := range m.entitlements {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, fmt.Errorf("entitlement not found")
}

func (m *mockEntitlementRepo) List(ctx context.Context, req *models.ListEntitlementsRequest) ([]*models.Entitlement, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	out := make([]*models.Entitlement, 0, len(m.entitlements))
	for _, e := range m.entitlements {
		out = append(out, e)
	}
	return out, nil
}

func (m *mockEntitlementRepo) Update(ctx context.Context, e *models.Entitlement) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.entitlements[e.ID] = e
	return nil
}

func (m *mockEntitlementRepo) Delete(ctx context.Context, id uuid.UUID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.entitlements, id)
	return nil
}

func (m *mockEntitlementRepo) FindMatching(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error) {
	if m.findMatchingErr != nil {
		return nil, m.findMatchingErr
	}
	return m.List(ctx, &models.ListEntitlementsRequest{})
}

func (m *mockEntitlementRepo) ListActive(ctx context.Context) ([]*models.Entitlement, error) {
	return m.List(ctx, &models.ListEntitlementsRequest{})
}

func (m *mockEntitlementRepo) Count(ctx context.Context, req *models.ListEntitlementsRequest) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	if m.listErr != nil {
		return 0, m.listErr
	}
	return len(m.entitlements), nil
}

type mockAuditRepo struct {
	listErr   error
	countErr  error
	createErr error
	logs      []*models.AuditLog
}

func (m *mockAuditRepo) Create(ctx context.Context, a *models.AuditLog) error {
	return m.createErr
}
func (m *mockAuditRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error) {
	return nil, errors.New("not found")
}
func (m *mockAuditRepo) List(ctx context.Context, req *models.ListAuditLogsRequest) ([]*models.AuditLog, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.logs, nil
}
func (m *mockAuditRepo) ListByEntity(ctx context.Context, entityType models.EntityType, entityID uuid.UUID) ([]*models.AuditLog, error) {
	return nil, nil
}
func (m *mockAuditRepo) ListByActor(ctx context.Context, actor string, limit, offset int) ([]*models.AuditLog, error) {
	return nil, nil
}
func (m *mockAuditRepo) Count(ctx context.Context, req *models.ListAuditLogsRequest) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return len(m.logs), nil
}

// ---------------------------------------------------------------------------
// Test server builder
// ---------------------------------------------------------------------------

// newTestPAPServer builds a PAP Server with in-memory mocks.
func newTestPAPServer(policyRepo *mockPolicyRepo, entitlementRepo *mockEntitlementRepo) *Server {
	return newTestPAPServerWithAudit(policyRepo, entitlementRepo, &mockAuditRepo{})
}

// newTestPAPServerWithAudit builds a PAP Server allowing a custom audit repo mock.
func newTestPAPServerWithAudit(policyRepo *mockPolicyRepo, entitlementRepo *mockEntitlementRepo, auditRepo *mockAuditRepo) *Server {
	repo := &repository.Repository{
		Policy:      policyRepo,
		Entitlement: entitlementRepo,
		Audit:       auditRepo,
	}
	return &Server{
		repo:             repo,
		engineFactory:    policy_engine.NewEngineFactory(),
		authService:      NewMockAuthService(),
		cacheInvalidator: cache.NewNoOpCacheInvalidator(),
	}
}

// ginContext builds a gin.Context backed by an httptest.ResponseRecorder and
// an HTTP request with optional JSON body. It also sets "user" in the context.
func ginContext(t *testing.T, method, path string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	var reqBody *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	// Inject authenticated user (bypasses auth middleware for direct handler tests)
	c.Set("user", "test-user")
	return c, w
}

// decodeBody unmarshals the response body into out.
func decodeBody(t *testing.T, w *httptest.ResponseRecorder, out interface{}) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("decodeBody: %v — raw body: %s", err, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Policy handler tests
// ---------------------------------------------------------------------------

func makeValidPolicyRequest() models.CreatePolicyRequest {
	effect := models.PolicyEffectAllow
	return models.CreatePolicyRequest{
		Name:          "test-policy",
		Description:   "unit test policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
		Effect:        effect,
		Priority:      1,
		Enabled:       true,
	}
}

func TestPAP_CreatePolicy_Valid(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())

	c, w := ginContext(t, http.MethodPost, "/api/v1/policies", makeValidPolicyRequest())
	srv.createPolicy(c)

	if w.Code != http.StatusCreated {
		t.Errorf("createPolicy status = %d, want 201 — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_CreatePolicy_InvalidJSON(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBufferString("not-json"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user", "test-user")
	srv.createPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("createPolicy status = %d, want 400 for invalid JSON", w.Code)
	}
}

func TestPAP_CreatePolicy_NoAuth(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	b, _ := json.Marshal(makeValidPolicyRequest())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(b))
	c.Request.Header.Set("Content-Type", "application/json")
	// No "user" key set → getUserFromContext returns error
	srv.createPolicy(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("createPolicy status = %d, want 401 for missing auth", w.Code)
	}
}

func TestPAP_CreatePolicy_RepoError(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	policyRepo.createErr = errors.New("db connection failed")
	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())

	c, w := ginContext(t, http.MethodPost, "/api/v1/policies", makeValidPolicyRequest())
	srv.createPolicy(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("createPolicy status = %d, want 500 for repo error", w.Code)
	}
}

func TestPAP_ListPolicies_Empty(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	c, w := ginContext(t, http.MethodGet, "/api/v1/policies", nil)
	srv.listPolicies(c)

	if w.Code != http.StatusOK {
		t.Errorf("listPolicies status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	policies := resp["policies"].([]interface{})
	if len(policies) != 0 {
		t.Errorf("listPolicies returned %d policies, want 0", len(policies))
	}
}

func TestPAP_ListPolicies_WithData(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name: "p1", Language: models.PolicyLanguageJSON,
		PolicyContent: `{}`, Effect: effect, Priority: 1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodGet, "/api/v1/policies", nil)
	srv.listPolicies(c)

	if w.Code != http.StatusOK {
		t.Errorf("listPolicies status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	total := resp["total"].(float64)
	if int(total) != 1 {
		t.Errorf("listPolicies total = %v, want 1", total)
	}
}

func TestPAP_ListPolicies_RepoError(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	policyRepo.listErr = errors.New("db error")
	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())

	c, w := ginContext(t, http.MethodGet, "/api/v1/policies", nil)
	srv.listPolicies(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("listPolicies status = %d, want 500 for repo error", w.Code)
	}
}

func TestPAP_GetPolicy_Found(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name: "find-me", Language: models.PolicyLanguageJSON,
		PolicyContent: `{}`, Effect: effect, Priority: 1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodGet, "/api/v1/policies/"+p.ID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	srv.getPolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("getPolicy status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_GetPolicy_NotFound(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	id := uuid.New()
	c, w := ginContext(t, http.MethodGet, "/api/v1/policies/"+id.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: id.String()}}
	srv.getPolicy(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("getPolicy status = %d, want 404", w.Code)
	}
}

func TestPAP_GetPolicy_InvalidUUID(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodGet, "/api/v1/policies/not-a-uuid", nil)
	c.Params = gin.Params{{Key: "id", Value: "not-a-uuid"}}
	srv.getPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("getPolicy status = %d, want 400 for invalid UUID", w.Code)
	}
}

func TestPAP_DeletePolicy_Success(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name: "delete-me", Language: models.PolicyLanguageJSON,
		PolicyContent: `{}`, Effect: effect, Priority: 1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodDelete, "/api/v1/policies/"+p.ID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	c.Set("user", "test-user")
	srv.deletePolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("deletePolicy status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	if _, ok := policyRepo.policies[p.ID]; ok {
		t.Error("deletePolicy did not remove policy from store")
	}
}

func TestPAP_DeletePolicy_NotFound(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	id := uuid.New()
	c, w := ginContext(t, http.MethodDelete, "/api/v1/policies/"+id.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: id.String()}}
	c.Set("user", "test-user")
	srv.deletePolicy(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("deletePolicy status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Entitlement handler tests
// ---------------------------------------------------------------------------

func makeValidEntitlementRequest() models.CreateEntitlementRequest {
	exp := time.Now().Add(24 * time.Hour)
	return models.CreateEntitlementRequest{
		Name:    "test-entitlement",
		Actions: []string{"read", "write"},
		SubjectAttributes: map[string]interface{}{
			"sub": "user@example.com",
		},
		ResourceAttributes: map[string]interface{}{
			"name": "document-service",
		},
		Enabled:   true,
		ExpiresAt: &exp,
	}
}

func TestPAP_CreateEntitlement_Valid(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)

	c, w := ginContext(t, http.MethodPost, "/api/v1/entitlements", makeValidEntitlementRequest())
	srv.createEntitlement(c)

	if w.Code != http.StatusCreated {
		t.Errorf("createEntitlement status = %d, want 201 — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_CreateEntitlement_NoAuth(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	b, _ := json.Marshal(makeValidEntitlementRequest())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/entitlements", bytes.NewReader(b))
	c.Request.Header.Set("Content-Type", "application/json")
	// No "user" key
	srv.createEntitlement(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("createEntitlement status = %d, want 401", w.Code)
	}
}

func TestPAP_CreateEntitlement_RepoError(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	entitlementRepo.createErr = errors.New("db error")
	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)

	c, w := ginContext(t, http.MethodPost, "/api/v1/entitlements", makeValidEntitlementRequest())
	srv.createEntitlement(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("createEntitlement status = %d, want 500 for repo error", w.Code)
	}
}

func TestPAP_ListEntitlements_Empty(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	c, w := ginContext(t, http.MethodGet, "/api/v1/entitlements", nil)
	srv.listEntitlements(c)

	if w.Code != http.StatusOK {
		t.Errorf("listEntitlements status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	entitlements := resp["entitlements"].([]interface{})
	if len(entitlements) != 0 {
		t.Errorf("listEntitlements returned %d, want 0", len(entitlements))
	}
}

func TestPAP_ListEntitlements_WithData(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodGet, "/api/v1/entitlements", nil)
	srv.listEntitlements(c)

	if w.Code != http.StatusOK {
		t.Errorf("listEntitlements status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	total := resp["total"].(float64)
	if int(total) != 1 {
		t.Errorf("listEntitlements total = %v, want 1", total)
	}
}

func TestPAP_GetEntitlement_Found(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodGet, "/api/v1/entitlements/"+e.ID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	srv.getEntitlement(c)

	if w.Code != http.StatusOK {
		t.Errorf("getEntitlement status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_GetEntitlement_NotFound(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	id := uuid.New()
	c, w := ginContext(t, http.MethodGet, "/api/v1/entitlements/"+id.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: id.String()}}
	srv.getEntitlement(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("getEntitlement status = %d, want 404", w.Code)
	}
}

func TestPAP_GetEntitlement_InvalidUUID(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodGet, "/api/v1/entitlements/bad-id", nil)
	c.Params = gin.Params{{Key: "id", Value: "bad-id"}}
	srv.getEntitlement(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("getEntitlement status = %d, want 400", w.Code)
	}
}

func TestPAP_DeleteEntitlement_Success(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodDelete, "/api/v1/entitlements/"+e.ID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	c.Set("user", "test-user")
	srv.deleteEntitlement(c)

	if w.Code != http.StatusOK {
		t.Errorf("deleteEntitlement status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	if _, ok := entitlementRepo.entitlements[e.ID]; ok {
		t.Error("deleteEntitlement did not remove entitlement from store")
	}
}

func TestPAP_DeleteEntitlement_NotFound(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	id := uuid.New()
	c, w := ginContext(t, http.MethodDelete, "/api/v1/entitlements/"+id.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: id.String()}}
	c.Set("user", "test-user")
	srv.deleteEntitlement(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("deleteEntitlement status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Additional policy handler tests (updatePolicy, validatePolicy, improvements)
// ---------------------------------------------------------------------------

func TestPAP_UpdatePolicy_Success(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "update-me",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	newName := "updated-name"
	req := models.UpdatePolicyRequest{Name: &newName}

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+p.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	srv.updatePolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("updatePolicy status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_UpdatePolicy_NotFound(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	id := uuid.New()
	newName := "whatever"
	req := models.UpdatePolicyRequest{Name: &newName}

	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+id.String(), req)
	c.Params = gin.Params{{Key: "id", Value: id.String()}}
	srv.updatePolicy(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("updatePolicy status = %d, want 404", w.Code)
	}
}

func TestPAP_UpdatePolicy_InvalidUUID(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	newName := "whatever"
	req := models.UpdatePolicyRequest{Name: &newName}

	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/not-a-uuid", req)
	c.Params = gin.Params{{Key: "id", Value: "not-a-uuid"}}
	srv.updatePolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("updatePolicy status = %d, want 400 for invalid UUID", w.Code)
	}
}

func TestPAP_UpdatePolicy_ValidationError(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "validate-me",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	// An empty string name fails validateUpdatePolicyRequest
	emptyName := ""
	req := models.UpdatePolicyRequest{Name: &emptyName}

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+p.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	srv.updatePolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("updatePolicy status = %d, want 400 for validation error — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_UpdatePolicy_NoAuth(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "auth-check",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	newName := "auth-check-updated"
	req := models.UpdatePolicyRequest{Name: &newName}

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	b, _ := json.Marshal(req)
	c.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/policies/"+p.ID.String(), bytes.NewReader(b))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	// No "user" key set → authentication required
	srv.updatePolicy(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("updatePolicy status = %d, want 401 for missing auth", w.Code)
	}
}

func TestPAP_ValidatePolicy_Valid(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := map[string]interface{}{
		"language":       "json",
		"policy_content": `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
	}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/validate", body)
	srv.validatePolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("validatePolicy status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	if resp["valid"] != true {
		t.Errorf("validatePolicy valid = %v, want true", resp["valid"])
	}
}

func TestPAP_ValidatePolicy_InvalidLanguage(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := map[string]interface{}{
		"language":       "unknown-lang",
		"policy_content": `{}`,
	}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/validate", body)
	srv.validatePolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("validatePolicy status = %d, want 400 for invalid language — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_ValidatePolicy_MissingContent(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := map[string]interface{}{
		"language":       "json",
		"policy_content": "",
	}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/validate", body)
	srv.validatePolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("validatePolicy status = %d, want 400 for missing content — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_DeletePolicy_InvalidUUID(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodDelete, "/api/v1/policies/bad-uuid", nil)
	c.Params = gin.Params{{Key: "id", Value: "bad-uuid"}}
	c.Set("user", "test-user")
	srv.deletePolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("deletePolicy status = %d, want 400 for invalid UUID", w.Code)
	}
}

func TestPAP_ListPolicies_CountError(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	// Put one policy so List succeeds; only Count will fail.
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name: "p1", Language: models.PolicyLanguageJSON,
		PolicyContent: `{}`, Effect: effect, Priority: 1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p
	policyRepo.countErr = errors.New("count db error")

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodGet, "/api/v1/policies", nil)
	srv.listPolicies(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("listPolicies status = %d, want 500 for count error — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Additional entitlement handler tests (updateEntitlement, findMatchingEntitlements, improvements)
// ---------------------------------------------------------------------------

func TestPAP_UpdateEntitlement_Success(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	newName := "updated-entitlement"
	req := models.UpdateEntitlementRequest{Name: &newName}

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodPatch, "/api/v1/entitlements/"+e.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	srv.updateEntitlement(c)

	if w.Code != http.StatusOK {
		t.Errorf("updateEntitlement status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_UpdateEntitlement_NotFound(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	id := uuid.New()
	newName := "whatever"
	req := models.UpdateEntitlementRequest{Name: &newName}

	c, w := ginContext(t, http.MethodPatch, "/api/v1/entitlements/"+id.String(), req)
	c.Params = gin.Params{{Key: "id", Value: id.String()}}
	srv.updateEntitlement(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("updateEntitlement status = %d, want 404", w.Code)
	}
}

func TestPAP_UpdateEntitlement_NoAuth(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	newName := "updated-entitlement"
	req := models.UpdateEntitlementRequest{Name: &newName}

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	b, _ := json.Marshal(req)
	c.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/entitlements/"+e.ID.String(), bytes.NewReader(b))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	// No "user" key set → authentication required
	srv.updateEntitlement(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("updateEntitlement status = %d, want 401 for missing auth", w.Code)
	}
}

func TestPAP_FindMatchingEntitlements_Valid(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	body := models.EntitlementMatchRequest{
		SubjectAttributes: map[string]interface{}{
			"sub": "user@example.com",
		},
		Action: "read",
	}

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodPost, "/api/v1/entitlements/match", body)
	srv.findMatchingEntitlements(c)

	if w.Code != http.StatusOK {
		t.Errorf("findMatchingEntitlements status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_FindMatchingEntitlements_InvalidBody(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	// Missing required subject_attributes and action fields
	body := models.EntitlementMatchRequest{}

	c, w := ginContext(t, http.MethodPost, "/api/v1/entitlements/match", body)
	srv.findMatchingEntitlements(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("findMatchingEntitlements status = %d, want 400 for invalid body — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_DeleteEntitlement_InvalidUUID(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodDelete, "/api/v1/entitlements/bad-uuid", nil)
	c.Params = gin.Params{{Key: "id", Value: "bad-uuid"}}
	c.Set("user", "test-user")
	srv.deleteEntitlement(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("deleteEntitlement status = %d, want 400 for invalid UUID", w.Code)
	}
}

func TestPAP_ListEntitlements_RepoError(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	entitlementRepo.listErr = errors.New("db error")
	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)

	c, w := ginContext(t, http.MethodGet, "/api/v1/entitlements", nil)
	srv.listEntitlements(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("listEntitlements status = %d, want 500 for repo error", w.Code)
	}
}

func TestPAP_ListEntitlements_CountError(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	// Put one entitlement so List succeeds; only Count will fail.
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e
	entitlementRepo.countErr = errors.New("count db error")

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodGet, "/api/v1/entitlements", nil)
	srv.listEntitlements(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("listEntitlements status = %d, want 500 for count error — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Audit handler tests (listAuditLogs, getAuditLog)
// ---------------------------------------------------------------------------

func TestPAP_ListAuditLogs_Empty(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	c, w := ginContext(t, http.MethodGet, "/api/v1/audit-logs", nil)
	srv.listAuditLogs(c)

	if w.Code != http.StatusOK {
		t.Errorf("listAuditLogs status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	// mock returns nil slice; JSON encodes as null but total is 0
	if resp["total"].(float64) != 0 {
		t.Errorf("listAuditLogs total = %v, want 0", resp["total"])
	}
}

func TestPAP_GetAuditLog_NotFound(t *testing.T) {
	// mockAuditRepo.GetByID always returns an error ("not found"), which causes
	// getAuditLog to respond with 404 (no sentinel check — any error → 404).
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	id := uuid.New()

	c, w := ginContext(t, http.MethodGet, "/api/v1/audit-logs/"+id.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: id.String()}}
	srv.getAuditLog(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("getAuditLog status = %d, want 404 — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_GetAuditLog_InvalidUUID(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	c, w := ginContext(t, http.MethodGet, "/api/v1/audit-logs/not-a-uuid", nil)
	c.Params = gin.Params{{Key: "id", Value: "not-a-uuid"}}
	srv.getAuditLog(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("getAuditLog status = %d, want 400 for invalid UUID — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// testPolicy handler tests
// ---------------------------------------------------------------------------

func makeValidTestPolicyRequest() map[string]interface{} {
	return map[string]interface{}{
		"language":       "json",
		"policy_content": `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
		"subject_attributes": map[string]interface{}{
			"sub": "user@example.com",
		},
		"resource_attributes": map[string]interface{}{
			"name": "document-service",
		},
		"action": "read",
	}
}

func TestPAP_TestPolicy_Valid(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", makeValidTestPolicyRequest())
	srv.testPolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("testPolicy status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	if resp["test_result"] == nil {
		t.Error("testPolicy response missing test_result field")
	}
}

func TestPAP_TestPolicy_InvalidJSON(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/policies/test", bytes.NewBufferString("not-json"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user", "test-user")
	srv.testPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("testPolicy status = %d, want 400 for invalid JSON", w.Code)
	}
}

func TestPAP_TestPolicy_EmptyLanguage(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := makeValidTestPolicyRequest()
	body["language"] = ""
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("testPolicy status = %d, want 400 for empty language", w.Code)
	}
}

func TestPAP_TestPolicy_EmptyPolicyContent(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := makeValidTestPolicyRequest()
	body["policy_content"] = ""
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("testPolicy status = %d, want 400 for empty policy_content", w.Code)
	}
}

func TestPAP_TestPolicy_EmptySubjectAttributes(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := makeValidTestPolicyRequest()
	body["subject_attributes"] = map[string]interface{}{}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("testPolicy status = %d, want 400 for empty subject_attributes", w.Code)
	}
}

func TestPAP_TestPolicy_EmptyResourceAttributes(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := makeValidTestPolicyRequest()
	body["resource_attributes"] = map[string]interface{}{}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("testPolicy status = %d, want 400 for empty resource_attributes", w.Code)
	}
}

func TestPAP_TestPolicy_EmptyAction(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := makeValidTestPolicyRequest()
	body["action"] = ""
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("testPolicy status = %d, want 400 for empty action", w.Code)
	}
}

func TestPAP_TestPolicy_UnsupportedLanguage(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := makeValidTestPolicyRequest()
	body["language"] = "graphql"
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("testPolicy status = %d, want 400 for unsupported language", w.Code)
	}
}

// ---------------------------------------------------------------------------
// validatePolicy additional tests
// ---------------------------------------------------------------------------

func TestPAP_ValidatePolicy_InvalidContent(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	// Valid language but invalid/empty JSON content should return 200 with valid=false
	body := map[string]interface{}{
		"language":       "json",
		"policy_content": `{"this":"is-not-a-valid-policy-missing-rules"}`,
	}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/validate", body)
	srv.validatePolicy(c)

	// The engine may return valid=false (200) or 400 depending on validation logic
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("validatePolicy status = %d, want 200 or 400 for invalid content — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_ValidatePolicy_InvalidJSON(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/policies/validate", bytes.NewBufferString("not-json"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user", "test-user")
	srv.validatePolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("validatePolicy status = %d, want 400 for invalid JSON body", w.Code)
	}
}

// ---------------------------------------------------------------------------
// updatePolicy additional tests
// ---------------------------------------------------------------------------

func TestPAP_UpdatePolicy_UpdateErr(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "update-fail",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p
	policyRepo.updateErr = errors.New("db write error")

	newName := "something-new"
	req := models.UpdatePolicyRequest{Name: &newName}

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+p.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	srv.updatePolicy(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("updatePolicy status = %d, want 500 for update error — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_UpdatePolicy_WithContentValidation(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "content-update",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	newContent := `{"version":"1.0","rules":[{"id":"r2","effect":"deny","subjects":["user"],"resources":["doc"],"actions":["delete"]}]}`
	req := models.UpdatePolicyRequest{PolicyContent: &newContent}

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+p.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	srv.updatePolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("updatePolicy status = %d, want 200 for valid content update — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// deletePolicy additional tests
// ---------------------------------------------------------------------------

func TestPAP_DeletePolicy_DeleteErr(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "delete-fail",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p
	policyRepo.deleteErr = errors.New("db delete error")

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodDelete, "/api/v1/policies/"+p.ID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	c.Set("user", "test-user")
	srv.deletePolicy(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("deletePolicy status = %d, want 500 for delete error — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_DeletePolicy_NoAuth(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "no-auth-delete",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/policies/"+p.ID.String(), nil)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	// No "user" key → unauthorized
	srv.deletePolicy(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("deletePolicy status = %d, want 401 for missing auth — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// createEntitlement additional tests
// ---------------------------------------------------------------------------

func TestPAP_CreateEntitlement_InvalidJSON(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/entitlements", bytes.NewBufferString("not-json"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user", "test-user")
	srv.createEntitlement(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("createEntitlement status = %d, want 400 for invalid JSON", w.Code)
	}
}

// ---------------------------------------------------------------------------
// updateEntitlement additional tests
// ---------------------------------------------------------------------------

func TestPAP_UpdateEntitlement_InvalidUUID(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())
	newName := "whatever"
	req := models.UpdateEntitlementRequest{Name: &newName}

	c, w := ginContext(t, http.MethodPatch, "/api/v1/entitlements/bad-uuid", req)
	c.Params = gin.Params{{Key: "id", Value: "bad-uuid"}}
	srv.updateEntitlement(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("updateEntitlement status = %d, want 400 for invalid UUID", w.Code)
	}
}

func TestPAP_UpdateEntitlement_UpdateErr(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e
	entitlementRepo.updateErr = errors.New("db write error")

	newName := "update-fail-entitlement"
	req := models.UpdateEntitlementRequest{Name: &newName}

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodPatch, "/api/v1/entitlements/"+e.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	srv.updateEntitlement(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("updateEntitlement status = %d, want 500 for update error — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// deleteEntitlement additional tests
// ---------------------------------------------------------------------------

func TestPAP_DeleteEntitlement_DeleteErr(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e
	entitlementRepo.deleteErr = errors.New("db delete error")

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodDelete, "/api/v1/entitlements/"+e.ID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	c.Set("user", "test-user")
	srv.deleteEntitlement(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("deleteEntitlement status = %d, want 500 for delete error — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_DeleteEntitlement_NoAuth(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/entitlements/"+e.ID.String(), nil)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	// No "user" key → unauthorized
	srv.deleteEntitlement(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("deleteEntitlement status = %d, want 401 for missing auth — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// findMatchingEntitlements additional tests
// ---------------------------------------------------------------------------

func TestPAP_FindMatchingEntitlements_FindMatchingErr(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	entitlementRepo.findMatchingErr = errors.New("db find error")

	body := models.EntitlementMatchRequest{
		SubjectAttributes: map[string]interface{}{
			"sub": "user@example.com",
		},
		Action: "read",
	}

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodPost, "/api/v1/entitlements/match", body)
	srv.findMatchingEntitlements(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("findMatchingEntitlements status = %d, want 500 for repo error — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_FindMatchingEntitlements_EmptyResults(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := models.EntitlementMatchRequest{
		SubjectAttributes: map[string]interface{}{
			"sub": "nobody@example.com",
		},
		Action: "write",
	}

	c, w := ginContext(t, http.MethodPost, "/api/v1/entitlements/match", body)
	srv.findMatchingEntitlements(c)

	if w.Code != http.StatusOK {
		t.Errorf("findMatchingEntitlements status = %d, want 200 for empty results — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	total := resp["total"].(float64)
	if int(total) != 0 {
		t.Errorf("findMatchingEntitlements total = %v, want 0 for empty repo", total)
	}
}

func TestPAP_FindMatchingEntitlements_InvalidJSONBody(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/entitlements/match", bytes.NewBufferString("not-json"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user", "test-user")
	srv.findMatchingEntitlements(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("findMatchingEntitlements status = %d, want 400 for invalid JSON — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// listAuditLogs additional tests
// ---------------------------------------------------------------------------

func TestPAP_ListAuditLogs_CountErr(t *testing.T) {
	auditRepo := &mockAuditRepo{
		logs:     []*models.AuditLog{{ID: uuid.New()}},
		countErr: errors.New("count db error"),
	}
	srv := newTestPAPServerWithAudit(newMockPolicyRepo(), newMockEntitlementRepo(), auditRepo)

	c, w := ginContext(t, http.MethodGet, "/api/v1/audit-logs", nil)
	srv.listAuditLogs(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("listAuditLogs status = %d, want 500 for count error — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_ListAuditLogs_ListErr(t *testing.T) {
	auditRepo := &mockAuditRepo{
		listErr: errors.New("list db error"),
	}
	srv := newTestPAPServerWithAudit(newMockPolicyRepo(), newMockEntitlementRepo(), auditRepo)

	c, w := ginContext(t, http.MethodGet, "/api/v1/audit-logs", nil)
	srv.listAuditLogs(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("listAuditLogs status = %d, want 500 for list error — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_ListAuditLogs_WithLogs(t *testing.T) {
	auditRepo := &mockAuditRepo{
		logs: []*models.AuditLog{
			{ID: uuid.New(), Action: models.AuditActionCreate},
			{ID: uuid.New(), Action: models.AuditActionUpdate},
		},
	}
	srv := newTestPAPServerWithAudit(newMockPolicyRepo(), newMockEntitlementRepo(), auditRepo)

	c, w := ginContext(t, http.MethodGet, "/api/v1/audit-logs", nil)
	srv.listAuditLogs(c)

	if w.Code != http.StatusOK {
		t.Errorf("listAuditLogs status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	total := resp["total"].(float64)
	if int(total) != 2 {
		t.Errorf("listAuditLogs total = %v, want 2", total)
	}
}

// ---------------------------------------------------------------------------
// createPolicy missing required fields
// ---------------------------------------------------------------------------

func TestPAP_CreatePolicy_MissingName(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	req := makeValidPolicyRequest()
	req.Name = ""
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies", req)
	srv.createPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("createPolicy status = %d, want 400 for missing name", w.Code)
	}
}

func TestPAP_CreatePolicy_UnsupportedLanguage(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	req := makeValidPolicyRequest()
	req.Language = "graphql"
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies", req)
	srv.createPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("createPolicy status = %d, want 400 for unsupported language", w.Code)
	}
}

func TestPAP_CreatePolicy_InvalidPolicyContent(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	req := makeValidPolicyRequest()
	// Invalid JSON that fails engine validation
	req.PolicyContent = `not-valid-json`
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies", req)
	srv.createPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("createPolicy status = %d, want 400 for invalid policy content — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// auth.go MockAuthService tests (NewMockAuthService, IsMock, ValidateToken)
// ---------------------------------------------------------------------------

func TestPAP_MockAuthService_IsMock(t *testing.T) {
	svc := NewMockAuthService()
	if !svc.IsMock() {
		t.Error("NewMockAuthService().IsMock() = false, want true")
	}
}

func TestPAP_MockAuthService_ValidateToken(t *testing.T) {
	svc := NewMockAuthService()
	claims, err := svc.ValidateToken(context.Background(), "any-token")
	if err != nil {
		t.Fatalf("MockAuthService.ValidateToken() unexpected error: %v", err)
	}
	if claims == nil {
		t.Fatal("MockAuthService.ValidateToken() returned nil claims")
	}
	if claims.Sub != "mock-user-123" {
		t.Errorf("claims.Sub = %q, want %q", claims.Sub, "mock-user-123")
	}
	if claims.Email != "mock@example.com" {
		t.Errorf("claims.Email = %q, want %q", claims.Email, "mock@example.com")
	}
}

func TestPAP_RealAuthService_IsMock(t *testing.T) {
	svc := &AuthService{isMock: false}
	if svc.IsMock() {
		t.Error("AuthService{isMock:false}.IsMock() = true, want false")
	}
}

// ---------------------------------------------------------------------------
// createAuditLog with audit.Create error
// ---------------------------------------------------------------------------

func TestPAP_CreateAuditLog_WriteError(t *testing.T) {
	auditRepo := &mockAuditRepo{createErr: errors.New("audit write failed")}
	policyRepo := newMockPolicyRepo()
	srv := newTestPAPServerWithAudit(policyRepo, newMockEntitlementRepo(), auditRepo)

	c, w := ginContext(t, http.MethodPost, "/api/v1/policies", makeValidPolicyRequest())
	srv.createPolicy(c)

	// The policy should still be created (audit error does not fail the request)
	if w.Code != http.StatusCreated {
		t.Errorf("createPolicy status = %d, want 201 even when audit write fails — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// getUserFromContext error path (no "user" key in context)
// ---------------------------------------------------------------------------

func TestPAP_GetUserFromContext_Missing(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	// Deliberately do NOT set "user" in the context
	_, err := srv.getUserFromContext(c)
	if err == nil {
		t.Error("getUserFromContext() expected error for missing user key, got nil")
	}
}

func TestPAP_GetUserFromContext_WrongType(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	// Set "user" to a non-string type
	c.Set("user", 12345)
	_, err := srv.getUserFromContext(c)
	if err == nil {
		t.Error("getUserFromContext() expected error for non-string user, got nil")
	}
}

// ---------------------------------------------------------------------------
// updatePolicy: content update with new language specified
// ---------------------------------------------------------------------------

func TestPAP_UpdatePolicy_ContentWithNewLanguage(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "lang-switch",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	newLang := models.PolicyLanguageJSON
	newContent := `{"version":"2.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`
	req := models.UpdatePolicyRequest{
		Language:      &newLang,
		PolicyContent: &newContent,
	}

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+p.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	srv.updatePolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("updatePolicy status = %d, want 200 when updating content with new language — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_UpdatePolicy_ContentInvalidLanguage(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "bad-lang-switch",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
		Effect:        effect,
		Priority:      1,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	// Use a language value that passes validateUpdatePolicyRequest but fails GetEngine
	// We can't do that since validation and GetEngine are both strict, so test invalid content instead
	newLang := models.PolicyLanguageJSON
	newContent := `not-valid-json`
	req := models.UpdatePolicyRequest{
		Language:      &newLang,
		PolicyContent: &newContent,
	}

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+p.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	srv.updatePolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("updatePolicy status = %d, want 400 for invalid content with language — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// updatePolicy: enabled flag change tracked in audit changes
// ---------------------------------------------------------------------------

func TestPAP_UpdatePolicy_EnabledChange(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	effect := models.PolicyEffectAllow
	p := (&models.CreatePolicyRequest{
		Name:          "enable-toggle",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version":"1.0","rules":[{"id":"r1","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
		Effect:        effect,
		Priority:      1,
		Enabled:       true,
	}).ToPolicy("system")
	policyRepo.policies[p.ID] = p

	disabled := false
	req := models.UpdatePolicyRequest{Enabled: &disabled}

	srv := newTestPAPServer(policyRepo, newMockEntitlementRepo())
	c, w := ginContext(t, http.MethodPatch, "/api/v1/policies/"+p.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: p.ID.String()}}
	srv.updatePolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("updatePolicy status = %d, want 200 for enabled toggle — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// testPolicy: with environment field populated
// ---------------------------------------------------------------------------

func TestPAP_TestPolicy_WithEnvironment(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := makeValidTestPolicyRequest()
	body["environment"] = map[string]interface{}{
		"time_of_day": "business_hours",
		"region":      "us-east-1",
	}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusOK {
		t.Errorf("testPolicy status = %d, want 200 with environment field — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// testPolicy: engine.TestPolicy fails (invalid policy content)
// ---------------------------------------------------------------------------

func TestPAP_TestPolicy_EngineFails(t *testing.T) {
	srv := newTestPAPServer(newMockPolicyRepo(), newMockEntitlementRepo())

	body := map[string]interface{}{
		"language":       "json",
		"policy_content": `not-valid-json`,
		"subject_attributes": map[string]interface{}{
			"sub": "user@example.com",
		},
		"resource_attributes": map[string]interface{}{
			"name": "document-service",
		},
		"action": "read",
	}
	c, w := ginContext(t, http.MethodPost, "/api/v1/policies/test", body)
	srv.testPolicy(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("testPolicy status = %d, want 400 when engine.TestPolicy fails — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// listAuditLogs: query params (page, limit, entity_type, actor)
// ---------------------------------------------------------------------------

func TestPAP_ListAuditLogs_WithQueryParams(t *testing.T) {
	auditRepo := &mockAuditRepo{
		logs: []*models.AuditLog{
			{ID: uuid.New(), Action: models.AuditActionCreate, EntityType: models.EntityTypePolicy},
		},
	}
	srv := newTestPAPServerWithAudit(newMockPolicyRepo(), newMockEntitlementRepo(), auditRepo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?limit=10&offset=0", nil)
	c.Set("user", "test-user")
	srv.listAuditLogs(c)

	if w.Code != http.StatusOK {
		t.Errorf("listAuditLogs status = %d, want 200 with query params — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_ListAuditLogs_LimitCapped(t *testing.T) {
	auditRepo := &mockAuditRepo{logs: []*models.AuditLog{}}
	srv := newTestPAPServerWithAudit(newMockPolicyRepo(), newMockEntitlementRepo(), auditRepo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// limit=200 exceeds max of 100
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?limit=200", nil)
	c.Set("user", "test-user")
	srv.listAuditLogs(c)

	if w.Code != http.StatusOK {
		t.Errorf("listAuditLogs status = %d, want 200 with capped limit — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// updateEntitlement: partial updates (just expiry, just enabled flag)
// ---------------------------------------------------------------------------

func TestPAP_UpdateEntitlement_JustExpiry(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	newExpiry := time.Now().Add(48 * time.Hour)
	req := models.UpdateEntitlementRequest{ExpiresAt: &newExpiry}

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodPatch, "/api/v1/entitlements/"+e.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	srv.updateEntitlement(c)

	if w.Code != http.StatusOK {
		t.Errorf("updateEntitlement status = %d, want 200 for expiry-only update — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_UpdateEntitlement_JustEnabled(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement { r := makeValidEntitlementRequest(); return r.ToEntitlement("system") }()
	entitlementRepo.entitlements[e.ID] = e

	disabled := false
	req := models.UpdateEntitlementRequest{Enabled: &disabled}

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodPatch, "/api/v1/entitlements/"+e.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	srv.updateEntitlement(c)

	if w.Code != http.StatusOK {
		t.Errorf("updateEntitlement status = %d, want 200 for enabled-only update — body: %s", w.Code, w.Body.String())
	}
}

func TestPAP_UpdateEntitlement_EnabledChangedAudit(t *testing.T) {
	entitlementRepo := newMockEntitlementRepo()
	e := func() *models.Entitlement {
		r := makeValidEntitlementRequest()
		ent := r.ToEntitlement("system")
		ent.Enabled = true
		return ent
	}()
	entitlementRepo.entitlements[e.ID] = e

	disabled := false
	newName := "enabled-change-audit"
	req := models.UpdateEntitlementRequest{
		Name:    &newName,
		Enabled: &disabled,
	}

	srv := newTestPAPServer(newMockPolicyRepo(), entitlementRepo)
	c, w := ginContext(t, http.MethodPatch, "/api/v1/entitlements/"+e.ID.String(), req)
	c.Params = gin.Params{{Key: "id", Value: e.ID.String()}}
	srv.updateEntitlement(c)

	if w.Code != http.StatusOK {
		t.Errorf("updateEntitlement status = %d, want 200 for name+enabled change — body: %s", w.Code, w.Body.String())
	}
}

