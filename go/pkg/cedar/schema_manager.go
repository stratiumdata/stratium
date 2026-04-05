package cedar

import (
	"context"
	"fmt"
	"sync"

	"stratium/pkg/models"

	"github.com/google/uuid"
)

// SchemaStore is the persistence interface for Cedar schemas.
type SchemaStore interface {
	CreateSchema(ctx context.Context, schema *models.CedarSchema) error
	GetSchemaByID(ctx context.Context, id uuid.UUID) (*models.CedarSchema, error)
	ListSchemas(ctx context.Context, namespace string) ([]*models.CedarSchema, error)
	UpdateSchema(ctx context.Context, schema *models.CedarSchema) error
	DeleteSchema(ctx context.Context, id uuid.UUID) error
	GetActiveSchema(ctx context.Context, namespace string) (*models.CedarSchema, error)
}

// SchemaManager manages Cedar schemas: CRUD, validation, and caching.
type SchemaManager struct {
	store SchemaStore
	mu    sync.RWMutex
	cache map[string]*models.CedarSchema // namespace → active schema
}

// NewSchemaManager creates a new schema manager.
func NewSchemaManager(store SchemaStore) *SchemaManager {
	return &SchemaManager{
		store: store,
		cache: make(map[string]*models.CedarSchema),
	}
}

// CreateSchema persists a new Cedar schema.
func (m *SchemaManager) CreateSchema(ctx context.Context, req *models.CreateCedarSchemaRequest, createdBy string) (*models.CedarSchema, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid schema request: %w", err)
	}

	// Validate that the schema content is parseable
	if err := m.validateSchemaContent(req.SchemaContent, req.SchemaFormat); err != nil {
		return nil, fmt.Errorf("invalid schema content: %w", err)
	}

	schema := req.ToSchema(createdBy)

	if err := m.store.CreateSchema(ctx, schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	// Invalidate cache for this namespace
	m.invalidateCache(schema.Namespace)

	return schema, nil
}

// GetSchema retrieves a Cedar schema by ID.
func (m *SchemaManager) GetSchema(ctx context.Context, id uuid.UUID) (*models.CedarSchema, error) {
	return m.store.GetSchemaByID(ctx, id)
}

// ListSchemas lists all Cedar schemas, optionally filtered by namespace.
func (m *SchemaManager) ListSchemas(ctx context.Context, namespace string) ([]*models.CedarSchema, error) {
	return m.store.ListSchemas(ctx, namespace)
}

// UpdateSchema updates an existing Cedar schema.
func (m *SchemaManager) UpdateSchema(ctx context.Context, id uuid.UUID, req *models.UpdateCedarSchemaRequest, updatedBy string) (*models.CedarSchema, error) {
	schema, err := m.store.GetSchemaByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		schema.Name = *req.Name
	}
	if req.Description != nil {
		schema.Description = *req.Description
	}
	if req.SchemaContent != nil {
		format := schema.SchemaFormat
		if req.SchemaFormat != nil {
			format = *req.SchemaFormat
		}
		if err := m.validateSchemaContent(*req.SchemaContent, format); err != nil {
			return nil, fmt.Errorf("invalid schema content: %w", err)
		}
		schema.SchemaContent = *req.SchemaContent
	}
	if req.SchemaFormat != nil {
		schema.SchemaFormat = *req.SchemaFormat
	}
	if req.Version != nil {
		schema.Version = *req.Version
	}
	if req.IsActive != nil {
		schema.IsActive = *req.IsActive
	}
	schema.UpdatedBy = updatedBy

	if err := m.store.UpdateSchema(ctx, schema); err != nil {
		return nil, fmt.Errorf("failed to update schema: %w", err)
	}

	m.invalidateCache(schema.Namespace)

	return schema, nil
}

// DeleteSchema removes a Cedar schema.
func (m *SchemaManager) DeleteSchema(ctx context.Context, id uuid.UUID) error {
	schema, err := m.store.GetSchemaByID(ctx, id)
	if err != nil {
		return err
	}

	if err := m.store.DeleteSchema(ctx, id); err != nil {
		return fmt.Errorf("failed to delete schema: %w", err)
	}

	m.invalidateCache(schema.Namespace)
	return nil
}

// GetActiveSchema returns the active schema for a namespace (cached).
func (m *SchemaManager) GetActiveSchema(ctx context.Context, namespace string) (*models.CedarSchema, error) {
	m.mu.RLock()
	if cached, ok := m.cache[namespace]; ok {
		m.mu.RUnlock()
		return cached, nil
	}
	m.mu.RUnlock()

	schema, err := m.store.GetActiveSchema(ctx, namespace)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.cache[namespace] = schema
	m.mu.Unlock()

	return schema, nil
}

// validateSchemaContent validates schema content by parsing it.
func (m *SchemaManager) validateSchemaContent(content, format string) error {
	if content == "" {
		return fmt.Errorf("schema content cannot be empty")
	}

	switch format {
	case "json":
		if err := ValidateSchemaJSON(content); err != nil {
			return err
		}
	case "cedar":
		// Cedar-format schemas: validate non-empty and structurally reasonable.
		// Full Cedar schema parsing is available via x/exp/schema when it stabilizes.
		if len(content) < 10 {
			return fmt.Errorf("schema content too short to be a valid Cedar schema")
		}
	default:
		return fmt.Errorf("unsupported schema format: %s (must be 'json' or 'cedar')", format)
	}

	return nil
}

// invalidateCache removes a namespace from the schema cache.
func (m *SchemaManager) invalidateCache(namespace string) {
	m.mu.Lock()
	delete(m.cache, namespace)
	m.mu.Unlock()
}
