// audit.go is this example's whole reason for existing: stratium-pap writes
// a `containment` row to audit_chain (internal/store/containment_audit.go's
// own recordWideningTx) whenever PUT /v1/agents/{id} widens a grant, and
// exposes no route that reads one back. See this package's own doc comment
// ("Step 5 is the point, and it is deliberately awkward") for why the fix
// here is a direct database connection, not a client for an endpoint that
// does not exist.
package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// pgDatabase and pgUser/pgPassword are deploy/docker/docker-compose.yml's
// own postgres service (POSTGRES_USER/POSTGRES_PASSWORD) and
// deploy/docker/init-db.sql's own `CREATE DATABASE stratium` — NOT the
// container's default POSTGRES_DB ("postgres"), which holds nothing:
// init-db.sql creates the "stratium" database and every table this suite
// touches lives there, reached over the postgres service's own superuser
// login. Connecting as that superuser is deliberate, not a shortcut: every
// tenant table (including audit_chain) is FORCE ROW LEVEL SECURITY, scoped
// by a `current_tenant()` session GUC only stratium-pap's own connection
// pool ever sets — and Postgres exempts a superuser from RLS unconditionally
// regardless of FORCE (migrations/000002_rls.up.sql's own doc comment). This
// is exactly what a human operator reaching for `psql` against this compose
// stack would do; there is no lesser-privileged path available for a
// stand-alone reader.
const (
	pgUser     = "postgres"
	pgPassword = "postgres_local_dev_only"
	pgDatabase = "stratium"
)

// containmentRow is the handful of audit_chain columns this example prints
// and asserts against — not every column pkg/audit.Entry hashes, only the
// ones the story in this program's own package doc needs a reader to see.
type containmentRow struct {
	OccurredAt time.Time
	Actor      string
	Decision   string
	Reason     string
}

// readContainmentRow returns the MOST RECENT containment row this agent's
// own PUT /v1/agents/{id} writes appended — ORDER BY seq DESC LIMIT 1, so a
// second run of this example (each of which appends exactly one, per
// resetAgentTools' own idempotent-reset comment in main.go) reads back the
// row its OWN widening PUT just wrote, not a stale one from an earlier run.
func readContainmentRow(pgAddr, agentID string) (containmentRow, error) {
	connStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", pgUser, pgPassword, pgAddr, pgDatabase)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return containmentRow{}, fmt.Errorf("open postgres: %w", err)
	}
	defer func() { _ = db.Close() }()

	var row containmentRow
	err = db.QueryRow(
		`SELECT occurred_at, actor, decision, reason FROM audit_chain `+
			`WHERE tenant_id = $1 AND agent_id = $2::uuid AND event_type = 'containment' `+
			`ORDER BY seq DESC LIMIT 1`,
		tenantID, agentID,
	).Scan(&row.OccurredAt, &row.Actor, &row.Decision, &row.Reason)
	if err != nil {
		if err == sql.ErrNoRows {
			return containmentRow{}, fmt.Errorf(
				"no containment row for agent %s in tenant %s — the widening PUT ran but recorded nothing; "+
					"the example is wrong, or the engine changed", agentID, tenantID)
		}
		return containmentRow{}, fmt.Errorf("query audit_chain: %w", err)
	}
	return row, nil
}

// tenantID is tenant-pap-e2e-integration's own literal — see main.go's
// subject/policyContent doc comments for why this example, like
// example/depth/hook and example/mcp, shares this tenant rather than owning
// one outright.
const tenantID = "tenant-pap-e2e-integration"
