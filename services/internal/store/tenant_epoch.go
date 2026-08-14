package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// defaultTenantEpoch is what LoadTenantEpoch reports for a tenant with no
// tenant_epoch row at all — every tenant until its first governed write
// (migrations/000015_tenant_epoch_trigger creates the row on demand, not on
// some tenant-provisioning step this schema does not have). It is the
// column's own DEFAULT (migrations/000001_baseline), not an arbitrary
// choice: 000015's own comment is explicit that 1 is "the value any reader
// must already treat a genuinely absent row as," which is exactly why the
// trigger's first bump starts at 2 instead of colliding with it. A missing
// row is an ordinary, expected state here, the same "nothing configured yet"
// case LoadAllPolicies and LoadToolCatalog already treat as a normal empty
// result rather than an error — never ErrNotFound, which this package
// reserves for a specific row (by id) that RLS or a real absence hides.
const defaultTenantEpoch int64 = 1

// loadTenantEpochQuery reads the current tenant's epoch. No WHERE tenant_id,
// per the package doc: RLS is the only tenant boundary. Unlike
// loadAllPoliciesQuery/loadToolCatalogQuery, there is also no ORDER BY to
// make deterministic — tenant_epoch's primary key IS tenant_id, so RLS's
// rewrite can return at most one row here, never a set needing an order.
const loadTenantEpochQuery = `SELECT epoch FROM tenant_epoch`

// LoadTenantEpoch reads the tenant's current revocation epoch (spec §4.8.1
// V3; tenant_epoch, migrations/000001_baseline). Read-only: nothing in this
// package writes tenant_epoch, and nothing here should ever be changed to —
// see this file's package doc (store.go) for why that is a permanent
// property (E7, T1), not an oversight this method is a step toward closing.
//
// A missing row reports defaultTenantEpoch (1), not an error — see that
// constant's own doc comment. Any other failure is returned as an error with
// no epoch value alongside it worth trusting: LoadTenantEpoch has no
// fallback of its own to offer, by design (see internal/pdpgrpc.
// loadEpochOrDeny, the caller that turns a non-nil error here into a denial
// rather than ever substituting a value).
func (s *Store) LoadTenantEpoch(ctx context.Context) (int64, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	epoch := defaultTenantEpoch
	if err := tx.QueryRowContext(ctx, loadTenantEpochQuery).Scan(&epoch); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("store: load tenant epoch: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return epoch, nil
}
