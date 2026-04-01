package repository

import (
	"context"

	"stratium/pkg/models"

	"github.com/google/uuid"
)

// Database is the interface that all database implementations must satisfy
// This allows us to easily swap between different database technologies
type Database interface {
	// Connection management
	Connect(ctx context.Context, connString string) error
	Close() error
	Ping(ctx context.Context) error

	// Transaction support
	BeginTx(ctx context.Context) (Transaction, error)
}

// Transaction represents a database transaction
type Transaction interface {
	Commit() error
	Rollback() error
	PolicyRepository() PolicyRepository
	EntitlementRepository() EntitlementRepository
	AuditRepository() AuditRepository
}

// PolicyRepository defines operations for policy data access
type PolicyRepository interface {
	// Create creates a new policy
	Create(ctx context.Context, policy *models.Policy) error

	// GetByID retrieves a policy by ID
	GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error)

	// GetByName retrieves a policy by name
	GetByName(ctx context.Context, name string) (*models.Policy, error)

	// List retrieves policies with optional filtering
	List(ctx context.Context, req *models.ListPoliciesRequest) ([]*models.Policy, error)

	// Update updates an existing policy
	Update(ctx context.Context, policy *models.Policy) error

	// Delete deletes a policy by ID
	Delete(ctx context.Context, id uuid.UUID) error

	// ListEnabled retrieves all enabled policies ordered by priority
	ListEnabled(ctx context.Context) ([]*models.Policy, error)

	// Count returns the total count of policies matching the criteria
	Count(ctx context.Context, req *models.ListPoliciesRequest) (int, error)
}

// EntitlementRepository defines operations for entitlement data access
type EntitlementRepository interface {
	// Create creates a new entitlement
	Create(ctx context.Context, entitlement *models.Entitlement) error

	// GetByID retrieves an entitlement by ID
	GetByID(ctx context.Context, id uuid.UUID) (*models.Entitlement, error)

	// GetByName retrieves an entitlement by name
	GetByName(ctx context.Context, name string) (*models.Entitlement, error)

	// List retrieves entitlements with optional filtering
	List(ctx context.Context, req *models.ListEntitlementsRequest) ([]*models.Entitlement, error)

	// Update updates an existing entitlement
	Update(ctx context.Context, entitlement *models.Entitlement) error

	// Delete deletes an entitlement by ID
	Delete(ctx context.Context, id uuid.UUID) error

	// FindMatching finds entitlements matching the given criteria
	FindMatching(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error)

	// ListActive retrieves all active (enabled and not expired) entitlements
	ListActive(ctx context.Context) ([]*models.Entitlement, error)

	// Count returns the total count of entitlements matching the criteria
	Count(ctx context.Context, req *models.ListEntitlementsRequest) (int, error)
}

// AuditRepository defines operations for audit log data access
type AuditRepository interface {
	// Create creates a new audit log entry
	Create(ctx context.Context, auditLog *models.AuditLog) error

	// GetByID retrieves an audit log entry by ID
	GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error)

	// List retrieves audit logs with optional filtering
	List(ctx context.Context, req *models.ListAuditLogsRequest) ([]*models.AuditLog, error)

	// ListByEntity retrieves audit logs for a specific entity
	ListByEntity(ctx context.Context, entityType models.EntityType, entityID uuid.UUID) ([]*models.AuditLog, error)

	// ListByActor retrieves audit logs for a specific actor
	ListByActor(ctx context.Context, actor string, limit, offset int) ([]*models.AuditLog, error)

	// Count returns the total count of audit logs matching the criteria
	Count(ctx context.Context, req *models.ListAuditLogsRequest) (int, error)
}

// AgentRepository defines operations for agent data access
type AgentRepository interface {
	// Create registers a new agent
	Create(ctx context.Context, agent *models.Agent) error

	// GetByID retrieves an agent by ID
	GetByID(ctx context.Context, id uuid.UUID) (*models.Agent, error)

	// GetByClientID retrieves an agent by client ID (for authentication)
	GetByClientID(ctx context.Context, clientID string) (*models.Agent, error)

	// List retrieves agents with optional filtering
	List(ctx context.Context, req *models.ListAgentsRequest) ([]*models.Agent, error)

	// Update updates an existing agent
	Update(ctx context.Context, agent *models.Agent) error

	// Delete deletes an agent by ID
	Delete(ctx context.Context, id uuid.UUID) error

	// Count returns the total count of agents matching the criteria
	Count(ctx context.Context, req *models.ListAgentsRequest) (int, error)
}

// DelegationRepository defines operations for delegation data access
type DelegationRepository interface {
	// Create creates a new delegation record
	Create(ctx context.Context, delegation *models.Delegation) error

	// GetByID retrieves a delegation by ID
	GetByID(ctx context.Context, id uuid.UUID) (*models.Delegation, error)

	// GetChain retrieves the full delegation chain from root to the given delegation
	GetChain(ctx context.Context, delegationID uuid.UUID) ([]*models.Delegation, error)

	// GetChildren retrieves all direct child delegations
	GetChildren(ctx context.Context, parentID uuid.UUID) ([]*models.Delegation, error)

	// GetDescendants retrieves all descendants (for cascade revocation)
	GetDescendants(ctx context.Context, rootDelegationID uuid.UUID, minDepth int) ([]*models.Delegation, error)

	// Revoke revokes a delegation and returns the number of cascaded revocations
	Revoke(ctx context.Context, id uuid.UUID, reason string) (int, []uuid.UUID, error)

	// ListActive retrieves all active delegations for a user+agent pair
	ListActive(ctx context.Context, userID string, agentID uuid.UUID) ([]*models.Delegation, error)

	// RevokeByAgent revokes all active delegations for an agent (used when suspending)
	RevokeByAgent(ctx context.Context, agentID uuid.UUID) (int, error)

	// CleanExpired removes expired delegations (maintenance)
	CleanExpired(ctx context.Context) (int, error)
}

// Repository provides access to all repository interfaces
type Repository struct {
	Policy      PolicyRepository
	Entitlement EntitlementRepository
	Audit       AuditRepository
	Agent       AgentRepository
	Delegation  DelegationRepository
	db          Database
}

// NewRepository creates a new repository with the given database implementation
func NewRepository(db Database) *Repository {
	return &Repository{
		db: db,
	}
}

// Close closes the database connection
func (r *Repository) Close() error {
	return r.db.Close()
}

// Ping checks the database connection
func (r *Repository) Ping(ctx context.Context) error {
	return r.db.Ping(ctx)
}
