package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

func TestNewPostgresDB(t *testing.T) {
	db := NewPostgresDB()
	assert.NotNil(t, db)
	assert.Nil(t, db.db)
}

func TestPostgresDB_Close(t *testing.T) {
	t.Run("Close with nil db", func(t *testing.T) {
		db := &PostgresDB{db: nil}
		err := db.Close()
		assert.NoError(t, err)
	})

	t.Run("Close with valid db", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")

		db := &PostgresDB{db: sqlxDB}

		mock.ExpectClose()
		err = db.Close()
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPostgresDB_Ping(t *testing.T) {
	t.Run("Ping with nil db", func(t *testing.T) {
		db := &PostgresDB{db: nil}
		err := db.Ping(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database not connected")
	})

	t.Run("Ping with valid db", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db := &PostgresDB{db: sqlxDB}

		mock.ExpectPing().WillReturnError(nil)

		err = db.Ping(context.Background())
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Ping with error", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db := &PostgresDB{db: sqlxDB}

		expectedErr := sql.ErrConnDone
		mock.ExpectPing().WillReturnError(expectedErr)

		err = db.Ping(context.Background())
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPostgresDB_BeginTx(t *testing.T) {
	t.Run("BeginTx success", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db := &PostgresDB{db: sqlxDB}

		mock.ExpectBegin()

		tx, err := db.BeginTx(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, tx)

		// Verify that tx has the correct type
		postgresTx, ok := tx.(*PostgresTx)
		assert.True(t, ok)
		assert.NotNil(t, postgresTx.tx)
		assert.NotNil(t, postgresTx.policy)
		assert.NotNil(t, postgresTx.entitlement)
		assert.NotNil(t, postgresTx.audit)

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("BeginTx error", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db := &PostgresDB{db: sqlxDB}

		expectedErr := sql.ErrConnDone
		mock.ExpectBegin().WillReturnError(expectedErr)

		tx, err := db.BeginTx(context.Background())
		assert.Error(t, err)
		assert.Nil(t, tx)
		assert.Contains(t, err.Error(), "failed to begin transaction")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPostgresDB_DB(t *testing.T) {
	t.Run("DB returns nil before connect", func(t *testing.T) {
		db := NewPostgresDB()
		result := db.DB()
		assert.Nil(t, result)
	})

	t.Run("DB returns valid instance after setting", func(t *testing.T) {
		mockDB, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db := &PostgresDB{db: sqlxDB}

		result := db.DB()
		assert.NotNil(t, result)
		assert.Equal(t, sqlxDB, result)
	})
}

func TestPostgresTx_Commit(t *testing.T) {
	t.Run("Commit success", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")

		mock.ExpectBegin()
		sqlxTx, err := sqlxDB.Beginx()
		assert.NoError(t, err)

		tx := &PostgresTx{tx: sqlxTx}

		mock.ExpectCommit()
		err = tx.Commit()
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Commit error", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")

		mock.ExpectBegin()
		sqlxTx, err := sqlxDB.Beginx()
		assert.NoError(t, err)

		tx := &PostgresTx{tx: sqlxTx}

		expectedErr := sql.ErrTxDone
		mock.ExpectCommit().WillReturnError(expectedErr)
		err = tx.Commit()
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPostgresTx_Rollback(t *testing.T) {
	t.Run("Rollback success", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")

		mock.ExpectBegin()
		sqlxTx, err := sqlxDB.Beginx()
		assert.NoError(t, err)

		tx := &PostgresTx{tx: sqlxTx}

		mock.ExpectRollback()
		err = tx.Rollback()
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Rollback error", func(t *testing.T) {
		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer mockDB.Close()

		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")

		mock.ExpectBegin()
		sqlxTx, err := sqlxDB.Beginx()
		assert.NoError(t, err)

		tx := &PostgresTx{tx: sqlxTx}

		expectedErr := sql.ErrTxDone
		mock.ExpectRollback().WillReturnError(expectedErr)
		err = tx.Rollback()
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPostgresTx_RepositoryGetters(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer mockDB.Close()

	sqlxDB := sqlx.NewDb(mockDB, "sqlmock")

	mock.ExpectBegin()
	sqlxTx, err := sqlxDB.Beginx()
	assert.NoError(t, err)

	policyRepo := NewPolicyRepository(sqlxTx)
	entitlementRepo := NewEntitlementRepository(sqlxTx)
	auditRepo := NewAuditRepository(sqlxTx)

	tx := &PostgresTx{
		tx:          sqlxTx,
		policy:      policyRepo,
		entitlement: entitlementRepo,
		audit:       auditRepo,
	}

	t.Run("PolicyRepository getter", func(t *testing.T) {
		result := tx.PolicyRepository()
		assert.NotNil(t, result)
		assert.Equal(t, policyRepo, result)
	})

	t.Run("EntitlementRepository getter", func(t *testing.T) {
		result := tx.EntitlementRepository()
		assert.NotNil(t, result)
		assert.Equal(t, entitlementRepo, result)
	})

	t.Run("AuditRepository getter", func(t *testing.T) {
		result := tx.AuditRepository()
		assert.NotNil(t, result)
		assert.Equal(t, auditRepo, result)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresTx_Integration(t *testing.T) {
	// This test verifies the full transaction flow
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer mockDB.Close()

	sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
	db := &PostgresDB{db: sqlxDB}

	t.Run("Complete transaction with commit", func(t *testing.T) {
		mock.ExpectBegin()
		tx, err := db.BeginTx(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, tx)

		// Verify repositories are accessible
		assert.NotNil(t, tx.PolicyRepository())
		assert.NotNil(t, tx.EntitlementRepository())
		assert.NotNil(t, tx.AuditRepository())

		mock.ExpectCommit()
		err = tx.Commit()
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Complete transaction with rollback", func(t *testing.T) {
		mock.ExpectBegin()
		tx, err := db.BeginTx(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, tx)

		mock.ExpectRollback()
		err = tx.Rollback()
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// Note: Connect() and NewRepository() tests are not included as they require
// a real PostgreSQL connection. These should be tested with integration tests
// using a test database instance.

func BenchmarkNewPostgresDB(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewPostgresDB()
	}
}

func BenchmarkPostgresTx_Commit(b *testing.B) {
	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()

	sqlxDB := sqlx.NewDb(mockDB, "sqlmock")

	for i := 0; i < b.N; i++ {
		mock.ExpectBegin()
		sqlxTx, _ := sqlxDB.Beginx()
		tx := &PostgresTx{tx: sqlxTx}
		mock.ExpectCommit()
		tx.Commit()
	}
}