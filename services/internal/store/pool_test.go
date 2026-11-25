package store

import (
	"database/sql"
	"testing"

	_ "github.com/lib/pq"
)

func TestLimitPool(t *testing.T) {
	// sql.Open does not connect, so no database is needed.
	db, err := sql.Open("postgres", "postgres://localhost/unused")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if got := db.Stats().MaxOpenConnections; got != 0 {
		t.Fatalf("before LimitPool, MaxOpenConnections = %d, want 0 (database/sql's no-limit default)", got)
	}
	LimitPool(db, 7)
	if got := db.Stats().MaxOpenConnections; got != 7 {
		t.Errorf("MaxOpenConnections = %d, want 7", got)
	}
}
