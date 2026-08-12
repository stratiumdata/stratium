package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
)

// auditOwnerRole is the role migrations/000004_audit_ownership.up.sql
// creates and transfers audit_chain's ownership to. Membership in it —
// direct or inherited — carries DDL rights over the table (DROP TRIGGER,
// DROP RULE, ...), which is exactly what that migration's ownership split
// exists to keep away from whatever role the PDP serves from.
const auditOwnerRole = "stratium_audit_owner"

// sqlStateUndefinedObject is PostgreSQL's SQLSTATE for "undefined_object" —
// what pg_has_role raises when its role argument does not exist.
const sqlStateUndefinedObject = "42704"

// ErrServingIdentityIsAuditOwner indicates the serving connection holds
// membership in stratium_audit_owner. Refusing to start on this converts
// the ownership split from a deployment convention (whoever wires up
// STRATIUM_DATABASE_URL must remember not to grant this) into an enforced
// invariant — the same reasoning that put the tenant check inside
// audit.Verify rather than in a doc comment.
var ErrServingIdentityIsAuditOwner = errors.New(
	"serving identity holds membership in stratium_audit_owner: it must never hold DDL rights over audit_chain")

// ErrAuditOwnerRoleMissing indicates stratium_audit_owner does not exist at
// all. Treated as fatal, the same as holding membership in it: a missing
// role means migration 000004 was never applied, so audit_chain's ownership
// was never separated from whatever ran migrations — the exact condition
// this check exists to catch, just discovered a different way. Starting
// anyway would silently reintroduce the gap this task closes.
var ErrAuditOwnerRoleMissing = errors.New(
	"stratium_audit_owner role does not exist: migration 000004 (audit ownership split) has not been applied")

// checkNotAuditOwner queries whether the serving connection's current_user
// holds membership in stratium_audit_owner and refuses to proceed if it
// does, or if the role cannot be found at all.
//
// pg_has_role errors with SQLSTATE 42704 when its role argument does not
// exist, which reads as an opaque SQL error to anyone who has not memorized
// SQLSTATEs. That case is detected and reported as ErrAuditOwnerRoleMissing
// instead, with the specific fix (run migration 000004) named in the error.
func checkNotAuditOwner(ctx context.Context, db *sql.DB) error {
	var isMember bool
	err := db.QueryRowContext(ctx, `SELECT pg_has_role(current_user, $1, 'member')`, auditOwnerRole).Scan(&isMember)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == sqlStateUndefinedObject {
			return fmt.Errorf("%w: %s", ErrAuditOwnerRoleMissing, pqErr.Message)
		}
		return fmt.Errorf("query %s membership: %w", auditOwnerRole, err)
	}
	if isMember {
		return ErrServingIdentityIsAuditOwner
	}
	return nil
}
