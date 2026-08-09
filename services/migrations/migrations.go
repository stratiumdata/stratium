// Package migrations embeds the versioned schema and applies it.
//
// Migrations are embedded so a self-hosted operator runs one binary and gets
// the right schema — there is no separate artifact to ship or forget.
package migrations

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed *.sql
var FS embed.FS

// Up applies all pending migrations. Safe on every startup: ErrNoChange is not
// an error condition.
//
// It closes the migrator before returning, success or failure. That is not
// just tidiness: postgres.WithInstance pins a dedicated *sql.Conn off db
// (for advisory-lock session affinity — Lock and Unlock must run on the same
// session) and never returns it to db's pool on its own. A caller that only
// closes db afterward, as cmd/stratium-pdp/main.go's runMigrations also does
// for its own reasons, does not release a connection still checked out from
// that pool — verified against a real postgres:16 instance: without the
// m.Close call below, the migration role's session stayed open and visible
// in pg_stat_activity well after the caller's own db.Close() had returned.
func Up(db *sql.DB) error {
	src, err := iofs.New(FS, ".")
	if err != nil {
		return fmt.Errorf("loading embedded migrations: %w", err)
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("creating postgres migration driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}

	upErr := m.Up()
	if upErr != nil && errors.Is(upErr, migrate.ErrNoChange) {
		upErr = nil
	}

	// sourceErr is always nil here: embed.FS does not implement io.Closer, so
	// iofs.PartialDriver.Close is a no-op for it (see that method). Only the
	// database close error — the one that actually matters, releasing the
	// pinned connection described above — is worth surfacing.
	_, closeErr := m.Close()

	switch {
	case upErr != nil:
		return fmt.Errorf("applying migrations: %w", upErr)
	case closeErr != nil:
		return fmt.Errorf("closing migrator: %w", closeErr)
	default:
		return nil
	}
}
