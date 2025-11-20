package repository

import (
	"context"
	"testing"

	"stratium/pkg/models"

	"github.com/google/uuid"
)

// MockDatabase is a mock implementation of the Database interface for testing
type MockDatabase struct {
	connectErr error
	closeErr   error
	pingErr    error
}

func (m *MockDatabase) Connect(ctx context.Context, connString string) error {
	return m.connectErr
}

func (m *MockDatabase) Close() error {
	return m.closeErr
}

func (m *MockDatabase) Ping(ctx context.Context) error {
	return m.pingErr
}

func (m *MockDatabase) BeginTx(ctx context.Context) (Transaction, error) {
	return nil, models.ErrNotImplemented
}

func TestNewRepository(t *testing.T) {
	mockDB := &MockDatabase{}
	repo := NewRepository(mockDB)

	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}

	if repo.db != mockDB {
		t.Error("Repository should store the database instance")
	}
}

func TestRepository_Close(t *testing.T) {
	tests := []struct {
		name    string
		db      *MockDatabase
		wantErr bool
	}{
		{
			name:    "Successful close",
			db:      &MockDatabase{closeErr: nil},
			wantErr: false,
		},
		{
			name:    "Close with error",
			db:      &MockDatabase{closeErr: models.ErrDatabaseConnection},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewRepository(tt.db)
			err := repo.Close()

			if (err != nil) != tt.wantErr {
				t.Errorf("Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRepository_Ping(t *testing.T) {
	tests := []struct {
		name    string
		db      *MockDatabase
		wantErr bool
	}{
		{
			name:    "Successful ping",
			db:      &MockDatabase{pingErr: nil},
			wantErr: false,
		},
		{
			name:    "Ping with error",
			db:      &MockDatabase{pingErr: models.ErrDatabaseConnection},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewRepository(tt.db)
			ctx := context.Background()
			err := repo.Ping(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("Ping() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// MockPolicyRepository is a mock implementation of PolicyRepository for testing
type MockPolicyRepository struct {
	policies []*models.Policy
}

func (m *MockPolicyRepository) Create(ctx context.Context, policy *models.Policy) error {
	m.policies = append(m.policies, policy)
	return nil
}

func (m *MockPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	for _, p := range m.policies {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, models.ErrPolicyNotFound
}

func (m *MockPolicyRepository) GetByName(ctx context.Context, name string) (*models.Policy, error) {
	for _, p := range m.policies {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, models.ErrPolicyNotFound
}

func (m *MockPolicyRepository) List(ctx context.Context, req *models.ListPoliciesRequest) ([]*models.Policy, error) {
	return m.policies, nil
}

func (m *MockPolicyRepository) Update(ctx context.Context, policy *models.Policy) error {
	for i, p := range m.policies {
		if p.ID == policy.ID {
			m.policies[i] = policy
			return nil
		}
	}
	return models.ErrPolicyNotFound
}

func (m *MockPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	for i, p := range m.policies {
		if p.ID == id {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return models.ErrPolicyNotFound
}

func (m *MockPolicyRepository) ListEnabled(ctx context.Context) ([]*models.Policy, error) {
	var enabled []*models.Policy
	for _, p := range m.policies {
		if p.Enabled {
			enabled = append(enabled, p)
		}
	}
	return enabled, nil
}

func (m *MockPolicyRepository) Count(ctx context.Context, req *models.ListPoliciesRequest) (int, error) {
	return len(m.policies), nil
}

func TestMockPolicyRepository(t *testing.T) {
	repo := &MockPolicyRepository{}
	ctx := context.Background()

	// Test Create
	policy := &models.Policy{
		ID:            uuid.New(),
		Name:          "test-policy",
		Language:      models.PolicyLanguageOPA,
		PolicyContent: "package test",
		Effect:        models.PolicyEffectAllow,
		Enabled:       true,
	}

	err := repo.Create(ctx, policy)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Test GetByID
	retrieved, err := repo.GetByID(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if retrieved.ID != policy.ID {
		t.Errorf("Expected ID %v, got %v", policy.ID, retrieved.ID)
	}

	// Test GetByName
	retrieved, err = repo.GetByName(ctx, policy.Name)
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}
	if retrieved.Name != policy.Name {
		t.Errorf("Expected name %s, got %s", policy.Name, retrieved.Name)
	}

	// Test List
	policies, err := repo.List(ctx, &models.ListPoliciesRequest{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	// Test ListEnabled
	enabled, err := repo.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled failed: %v", err)
	}
	if len(enabled) != 1 {
		t.Errorf("Expected 1 enabled policy, got %d", len(enabled))
	}

	// Test Update
	policy.Name = "updated-policy"
	err = repo.Update(ctx, policy)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Test Count
	count, err := repo.Count(ctx, &models.ListPoliciesRequest{})
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected count 1, got %d", count)
	}

	// Test Delete
	err = repo.Delete(ctx, policy.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deletion
	_, err = repo.GetByID(ctx, policy.ID)
	if err != models.ErrPolicyNotFound {
		t.Errorf("Expected ErrPolicyNotFound, got %v", err)
	}
}
