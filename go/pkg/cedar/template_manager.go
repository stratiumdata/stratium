package cedar

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	cedarlib "github.com/cedar-policy/cedar-go"

	"stratium/pkg/models"

	"github.com/google/uuid"
)

// TemplateStore is the persistence interface for Cedar templates.
type TemplateStore interface {
	CreateTemplate(ctx context.Context, template *models.CedarTemplate) error
	GetTemplateByID(ctx context.Context, id uuid.UUID) (*models.CedarTemplate, error)
	ListTemplates(ctx context.Context, namespace string) ([]*models.CedarTemplate, error)
	UpdateTemplate(ctx context.Context, template *models.CedarTemplate) error
	DeleteTemplate(ctx context.Context, id uuid.UUID) error
	CreateLinkedPolicy(ctx context.Context, link *models.CedarLinkedPolicy) error
	ListLinkedPolicies(ctx context.Context, templateID uuid.UUID) ([]*models.CedarLinkedPolicy, error)
}

// TemplateManager manages Cedar policy templates and template-linked policies.
type TemplateManager struct {
	store TemplateStore
}

// NewTemplateManager creates a new template manager.
func NewTemplateManager(store TemplateStore) *TemplateManager {
	return &TemplateManager{store: store}
}

// CreateTemplate persists a new Cedar policy template.
func (m *TemplateManager) CreateTemplate(ctx context.Context, req *models.CreateCedarTemplateRequest, createdBy string) (*models.CedarTemplate, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid template request: %w", err)
	}

	// Validate template syntax: should parse as valid Cedar (with ?principal/?resource)
	if err := m.validateTemplateContent(req.TemplateContent); err != nil {
		return nil, fmt.Errorf("invalid template content: %w", err)
	}

	template := req.ToTemplate(createdBy)

	if err := m.store.CreateTemplate(ctx, template); err != nil {
		return nil, fmt.Errorf("failed to create template: %w", err)
	}

	return template, nil
}

// GetTemplate retrieves a Cedar template by ID.
func (m *TemplateManager) GetTemplate(ctx context.Context, id uuid.UUID) (*models.CedarTemplate, error) {
	return m.store.GetTemplateByID(ctx, id)
}

// ListTemplates lists all Cedar templates, optionally filtered by namespace.
func (m *TemplateManager) ListTemplates(ctx context.Context, namespace string) ([]*models.CedarTemplate, error) {
	return m.store.ListTemplates(ctx, namespace)
}

// DeleteTemplate removes a Cedar template.
func (m *TemplateManager) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	return m.store.DeleteTemplate(ctx, id)
}

// InstantiateTemplate creates a linked policy from a template by substituting
// the ?principal and ?resource placeholders with concrete entity UIDs.
func (m *TemplateManager) InstantiateTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	req *models.InstantiateTemplateRequest,
	createdBy string,
) (*models.CedarLinkedPolicy, *models.Policy, error) {
	template, err := m.store.GetTemplateByID(ctx, templateID)
	if err != nil {
		return nil, nil, fmt.Errorf("template not found: %w", err)
	}

	// Substitute placeholders
	policyContent := template.TemplateContent
	if req.PrincipalEntity != "" {
		policyContent = strings.ReplaceAll(policyContent, "?principal", req.PrincipalEntity)
	}
	if req.ResourceEntity != "" {
		policyContent = strings.ReplaceAll(policyContent, "?resource", req.ResourceEntity)
	}

	// Validate the instantiated policy
	_, err = cedarlib.NewPolicySetFromBytes("instantiated", []byte(policyContent))
	if err != nil {
		return nil, nil, fmt.Errorf("instantiated policy is invalid: %w", err)
	}

	// Create the policy
	now := time.Now()
	policy := &models.Policy{
		ID:            uuid.New(),
		Name:          fmt.Sprintf("%s-linked-%s", template.Name, uuid.New().String()[:8]),
		Description:   fmt.Sprintf("Instantiated from template %s", template.Name),
		Language:      models.PolicyLanguageCedar,
		PolicyContent: policyContent,
		Effect:        models.PolicyEffectAllow, // Templates are typically permits
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Create the linked policy record
	link := &models.CedarLinkedPolicy{
		ID:              uuid.New(),
		TemplateID:      templateID,
		PolicyID:        policy.ID,
		PrincipalEntity: req.PrincipalEntity,
		ResourceEntity:  req.ResourceEntity,
		CreatedAt:       now,
		CreatedBy:       createdBy,
	}

	if err := m.store.CreateLinkedPolicy(ctx, link); err != nil {
		return nil, nil, fmt.Errorf("failed to create linked policy: %w", err)
	}

	return link, policy, nil
}

// ListLinkedPolicies lists all linked policies for a template.
func (m *TemplateManager) ListLinkedPolicies(ctx context.Context, templateID uuid.UUID) ([]*models.CedarLinkedPolicy, error) {
	return m.store.ListLinkedPolicies(ctx, templateID)
}

// validateTemplateContent checks that template content is syntactically reasonable.
// Templates may contain ?principal and ?resource placeholders which aren't valid Cedar
// syntax, so we do a basic structural check rather than full parsing.
func (m *TemplateManager) validateTemplateContent(content string) error {
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("template content cannot be empty")
	}

	// Check for required structure: must contain permit or forbid
	lower := strings.ToLower(content)
	if !strings.Contains(lower, "permit") && !strings.Contains(lower, "forbid") {
		return fmt.Errorf("template must contain at least one 'permit' or 'forbid' statement")
	}

	// Should contain at least one placeholder or be valid Cedar
	hasPlaceholder := strings.Contains(content, "?principal") || strings.Contains(content, "?resource")
	if !hasPlaceholder {
		// If no placeholders, it should parse as valid Cedar
		_, err := cedarlib.NewPolicySetFromBytes("validate", []byte(content))
		if err != nil {
			return fmt.Errorf("template without placeholders must be valid Cedar: %w", err)
		}
	}

	return nil
}

// MemoryTemplateStore is an in-memory implementation of TemplateStore for testing.
type MemoryTemplateStore struct {
	mu        sync.RWMutex
	templates map[uuid.UUID]*models.CedarTemplate
	links     map[uuid.UUID]*models.CedarLinkedPolicy
}

// NewMemoryTemplateStore creates a new in-memory template store.
func NewMemoryTemplateStore() *MemoryTemplateStore {
	return &MemoryTemplateStore{
		templates: make(map[uuid.UUID]*models.CedarTemplate),
		links:     make(map[uuid.UUID]*models.CedarLinkedPolicy),
	}
}

func (s *MemoryTemplateStore) CreateTemplate(ctx context.Context, template *models.CedarTemplate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.templates[template.ID] = template
	return nil
}

func (s *MemoryTemplateStore) GetTemplateByID(ctx context.Context, id uuid.UUID) (*models.CedarTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.templates[id]
	if !ok {
		return nil, models.ErrCedarTemplateNotFound
	}
	return t, nil
}

func (s *MemoryTemplateStore) ListTemplates(ctx context.Context, namespace string) ([]*models.CedarTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*models.CedarTemplate
	for _, t := range s.templates {
		if namespace == "" || t.Namespace == namespace {
			result = append(result, t)
		}
	}
	return result, nil
}

func (s *MemoryTemplateStore) UpdateTemplate(ctx context.Context, template *models.CedarTemplate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.templates[template.ID]; !ok {
		return models.ErrCedarTemplateNotFound
	}
	s.templates[template.ID] = template
	return nil
}

func (s *MemoryTemplateStore) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.templates[id]; !ok {
		return models.ErrCedarTemplateNotFound
	}
	delete(s.templates, id)
	return nil
}

func (s *MemoryTemplateStore) CreateLinkedPolicy(ctx context.Context, link *models.CedarLinkedPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.links[link.ID] = link
	return nil
}

func (s *MemoryTemplateStore) ListLinkedPolicies(ctx context.Context, templateID uuid.UUID) ([]*models.CedarLinkedPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*models.CedarLinkedPolicy
	for _, link := range s.links {
		if link.TemplateID == templateID {
			result = append(result, link)
		}
	}
	return result, nil
}
