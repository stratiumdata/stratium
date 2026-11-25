package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrServingRoleBypassesRLS is CheckServingRole's refusal.
var ErrServingRoleBypassesRLS = errors.New(
	"the database role is a superuser or has BYPASSRLS: row-level security does not apply to it, " +
		"so it would read and write every tenant's rows; connect as an ordinary role")

// servingRoleQuery reads the two attributes of the connection's own role that
// exempt it from row-level security. pg_roles is readable by every role.
const servingRoleQuery = `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`

// CheckServingRole refuses a connection whose role PostgreSQL exempts from
// row-level security. Every tenant table relies on RLS to keep one tenant's
// rows from another (migrations/000002), and PostgreSQL applies none of it
// to a superuser or a BYPASSRLS role, FORCE or not. A service connected as
// one would run and answer normally while isolating nothing, so each service
// calls this at start-up and stops.
func CheckServingRole(ctx context.Context, db *sql.DB) error {
	var superuser, bypassRLS bool
	if err := db.QueryRowContext(ctx, servingRoleQuery).Scan(&superuser, &bypassRLS); err != nil {
		return fmt.Errorf("read the database role's attributes: %w", err)
	}
	if superuser || bypassRLS {
		return ErrServingRoleBypassesRLS
	}
	return nil
}
