package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"stratium/pkg/repository"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// PostgresDB implements the Database interface for PostgreSQL
type PostgresDB struct {
	db *sqlx.DB
}

// NewPostgresDB creates a new PostgreSQL database instance
func NewPostgresDB() *PostgresDB {
	return &PostgresDB{}
}

// Connect establishes a connection to the PostgreSQL database
func (p *PostgresDB) Connect(ctx context.Context, connString string) error {
	db, err := sqlx.ConnectContext(ctx, "postgres", connString)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	p.db = db
	return nil
}

// Close closes the database connection
func (p *PostgresDB) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

// Ping checks if the database connection is alive
func (p *PostgresDB) Ping(ctx context.Context) error {
	if p.db == nil {
		return fmt.Errorf("database not connected")
	}
	return p.db.PingContext(ctx)
}

// BeginTx starts a new transaction
func (p *PostgresDB) BeginTx(ctx context.Context) (repository.Transaction, error) {
	tx, err := p.db.BeginTxx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &PostgresTx{
		tx:     tx,
		policy: NewPolicyRepository(tx),
		entitlement: NewEntitlementRepository(tx),
		audit:  NewAuditRepository(tx),
	}, nil
}

// DB returns the underlying sqlx.DB instance
func (p *PostgresDB) DB() *sqlx.DB {
	return p.db
}

// PostgresTx implements the Transaction interface for PostgreSQL
type PostgresTx struct {
	tx          *sqlx.Tx
	policy      *PolicyRepository
	entitlement *EntitlementRepository
	audit       *AuditRepository
}

// Commit commits the transaction
func (t *PostgresTx) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction
func (t *PostgresTx) Rollback() error {
	return t.tx.Rollback()
}

// PolicyRepository returns the policy repository for this transaction
func (t *PostgresTx) PolicyRepository() repository.PolicyRepository {
	return t.policy
}

// EntitlementRepository returns the entitlement repository for this transaction
func (t *PostgresTx) EntitlementRepository() repository.EntitlementRepository {
	return t.entitlement
}

// AuditRepository returns the audit repository for this transaction
func (t *PostgresTx) AuditRepository() repository.AuditRepository {
	return t.audit
}

// NewRepository creates a new repository instance with PostgreSQL implementation
func NewRepository(connString string) (*repository.Repository, error) {
	db := NewPostgresDB()

	if err := db.Connect(context.Background(), connString); err != nil {
		return nil, err
	}

	repo := repository.NewRepository(db)
	repo.Policy = NewPolicyRepository(db.DB())
	repo.Entitlement = NewEntitlementRepository(db.DB())
	repo.Audit = NewAuditRepository(db.DB())

	return repo, nil
}