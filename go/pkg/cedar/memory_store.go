package cedar

import (
	"context"
	"sync"

	"stratium/pkg/models"

	"github.com/google/uuid"
)

// MemorySchemaStore is an in-memory implementation of SchemaStore for testing.
type MemorySchemaStore struct {
	mu      sync.RWMutex
	schemas map[uuid.UUID]*models.CedarSchema
}

// NewMemorySchemaStore creates a new in-memory schema store.
func NewMemorySchemaStore() *MemorySchemaStore {
	return &MemorySchemaStore{
		schemas: make(map[uuid.UUID]*models.CedarSchema),
	}
}

func (s *MemorySchemaStore) CreateSchema(ctx context.Context, schema *models.CedarSchema) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for uniqueness
	for _, existing := range s.schemas {
		if existing.Namespace == schema.Namespace && existing.Name == schema.Name && existing.Version == schema.Version {
			return models.ErrCedarSchemaAlreadyExists
		}
	}

	s.schemas[schema.ID] = schema
	return nil
}

func (s *MemorySchemaStore) GetSchemaByID(ctx context.Context, id uuid.UUID) (*models.CedarSchema, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	schema, ok := s.schemas[id]
	if !ok {
		return nil, models.ErrCedarSchemaNotFound
	}
	return schema, nil
}

func (s *MemorySchemaStore) ListSchemas(ctx context.Context, namespace string) ([]*models.CedarSchema, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.CedarSchema
	for _, schema := range s.schemas {
		if namespace == "" || schema.Namespace == namespace {
			result = append(result, schema)
		}
	}
	return result, nil
}

func (s *MemorySchemaStore) UpdateSchema(ctx context.Context, schema *models.CedarSchema) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.schemas[schema.ID]; !ok {
		return models.ErrCedarSchemaNotFound
	}
	s.schemas[schema.ID] = schema
	return nil
}

func (s *MemorySchemaStore) DeleteSchema(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.schemas[id]; !ok {
		return models.ErrCedarSchemaNotFound
	}
	delete(s.schemas, id)
	return nil
}

func (s *MemorySchemaStore) GetActiveSchema(ctx context.Context, namespace string) (*models.CedarSchema, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, schema := range s.schemas {
		if schema.Namespace == namespace && schema.IsActive {
			return schema, nil
		}
	}
	return nil, models.ErrCedarSchemaNotFound
}
