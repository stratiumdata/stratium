package migrations

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestFSContainsBaseline(t *testing.T) {
	if err := fstest.TestFS(FS, "000001_baseline.up.sql", "000001_baseline.down.sql"); err != nil {
		t.Fatalf("embedded FS is missing the baseline: %v", err)
	}
}

// Every up migration needs a down, or a failed deploy cannot be rolled back.
func TestEveryUpHasADown(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("reading embedded FS: %v", err)
	}
	ups, downs := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".up.sql"):
			ups[strings.TrimSuffix(name, ".up.sql")] = true
		case strings.HasSuffix(name, ".down.sql"):
			downs[strings.TrimSuffix(name, ".down.sql")] = true
		}
	}
	if len(ups) == 0 {
		t.Fatal("no up migrations found")
	}
	for v := range ups {
		if !downs[v] {
			t.Errorf("migration %q has an up but no down", v)
		}
	}
}

// createTable is one parsed CREATE TABLE statement.
type createTable struct {
	Name string
	Body string // exactly the parenthesised column list, nothing after it
}

// parseCreateTables extracts each CREATE TABLE's own column list by matching
// parentheses.
//
// Taking the last ")" in the text between one CREATE TABLE and the next does
// NOT work: a trailing `CREATE INDEX ... ON agents(tenant_id);` gets swallowed
// into the body, so a table that has lost its tenant_id column still appears to
// mention one. Five of six tables in the baseline have exactly that layout, so
// the naive version passes on a schema with no tenancy at all.
func parseCreateTables(sql string) []createTable {
	var out []createTable
	const kw = "CREATE TABLE "
	for i := 0; ; {
		j := strings.Index(sql[i:], kw)
		if j < 0 {
			return out
		}
		start := i + j + len(kw)
		open := strings.Index(sql[start:], "(")
		if open < 0 {
			return out
		}
		open += start

		depth, end := 0, -1
		for k := open; k < len(sql); k++ {
			switch sql[k] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = k
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return out
		}

		name := strings.TrimSpace(sql[start:open])
		name = strings.TrimPrefix(name, "IF NOT EXISTS ")
		out = append(out, createTable{Name: strings.TrimSpace(name), Body: sql[open : end+1]})
		i = end + 1
	}
}

// Tenancy is structural: every table must carry tenant_id from creation.
func TestEveryTableHasTenantID(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("reading embedded FS: %v", err)
	}
	total := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		b, err := FS.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		sql := string(b)
		tables := parseCreateTables(sql)

		// Reconcile per file. The depth counter is character-level, so an
		// unbalanced paren inside a string literal or a comment desyncs it and
		// the parser silently returns fewer tables — possibly none — for the
		// rest of the file. A global "did we parse anything at all" check does
		// not catch that, because another file keeps the total nonzero. Compare
		// against a textual count instead: any disagreement means the parser
		// lost track, and an unparsed table is an unchecked table.
		if want, got := strings.Count(sql, "CREATE TABLE"), len(tables); want != got {
			t.Errorf("%s: found %d occurrences of CREATE TABLE but parsed %d — "+
				"the parser lost sync (unbalanced paren in a literal or comment, "+
				"or an unsupported form such as CREATE TABLE ... AS SELECT)",
				e.Name(), want, got)
			continue
		}

		// Equal counts are not sufficient. A stray paren inside one table's body
		// can overrun its true close and swallow a trailing
		// `CREATE INDEX ... ON t(tenant_id);` — no CREATE TABLE is consumed, so
		// the count still matches, but the swallowed text supplies the substring
		// and a table with no tenant_id column passes. That is the exact bug the
		// paren rewrite closed, resurrected. No parsed body may contain a
		// statement terminator or another statement keyword.
		for _, tbl := range tables {
			// A correct body ends at its own ")" and contains no earlier ");".
			// Testing for a bare ";" instead would flag any prose comment that
			// happens to use one, which trains people to reword comments rather
			// than fix parses — a guard nobody trusts is a guard nobody keeps.
			if inner := strings.TrimSuffix(tbl.Body, ")"); strings.Contains(inner, ");") {
				t.Errorf("%s: parsed body for table %q ran past its own closing paren "+
					"and swallowed following statements — the parser lost sync",
					e.Name(), tbl.Name)
			}
		}

		total += len(tables)
		for _, tbl := range tables {
			if !strings.Contains(tbl.Body, "tenant_id") {
				t.Errorf("%s: table %q has no tenant_id column", e.Name(), tbl.Name)
			}
		}
	}
	if total == 0 {
		t.Fatal("parsed no CREATE TABLE statements — the guard is inert")
	}
}

// The reconciliation check must fire when the parser loses sync, rather than
// silently reporting fewer tables.
func TestTenantIDGuardDetectsParserDesync(t *testing.T) {
	desyncing := map[string]string{
		"unbalanced paren in a string literal": `CREATE TABLE a (
    tenant_id TEXT NOT NULL,
    note TEXT DEFAULT 'oops ('
);
CREATE TABLE b (
    id UUID PRIMARY KEY
);`,
		"unbalanced paren in a comment": `CREATE TABLE a (
    tenant_id TEXT NOT NULL, -- see note (
    note TEXT
);
CREATE TABLE b (
    id UUID PRIMARY KEY
);`,
	}
	for name, sql := range desyncing {
		t.Run(name, func(t *testing.T) {
			if want, got := strings.Count(sql, "CREATE TABLE"), len(parseCreateTables(sql)); want == got {
				t.Fatalf("expected the parser to lose sync so the reconciliation "+
					"check can catch it, but it parsed all %d tables", got)
			}
		})
	}
}

// The dangerous desync is the one that keeps the counts equal: a stray paren
// lets a table body swallow a trailing CREATE INDEX naming tenant_id, so a
// table with no such column looks compliant. The body must be rejected for
// containing following statements, not merely counted.
func TestTenantIDGuardCatchesSwallowedStatements(t *testing.T) {
	sql := `CREATE TABLE x (
    id UUID PRIMARY KEY,
    name TEXT DEFAULT 'oops ('
);
CREATE INDEX idx_x_tenant ON x(tenant_id); -- balance )
CREATE TABLE y (
    tenant_id TEXT NOT NULL
);`
	tables := parseCreateTables(sql)
	if strings.Count(sql, "CREATE TABLE") != len(tables) {
		t.Skip("counts already disagree; the count check catches this case")
	}
	swallowed := false
	for _, tbl := range tables {
		if inner := strings.TrimSuffix(tbl.Body, ")"); strings.Contains(inner, ");") {
			swallowed = true
		}
	}
	if !swallowed {
		t.Fatal("a body that ran past its closing paren was not detected — " +
			"a table with no tenant_id column would pass")
	}
}

// The swallow check must not fire on ordinary SQL: prose comments using
// semicolons, and nested parens in CHECK or DEFAULT expressions.
func TestTenantIDGuardDoesNotFalsePositive(t *testing.T) {
	sql := `CREATE TABLE ok (
    tenant_id TEXT NOT NULL,
    -- one thing; then another thing. Semicolons in prose are fine.
    tier SMALLINT NOT NULL CHECK (tier BETWEEN 0 AND 4),
    meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, tier)
);
CREATE INDEX idx_ok_tenant ON ok(tenant_id);`
	tables := parseCreateTables(sql)
	if len(tables) != 1 {
		t.Fatalf("expected 1 table, parsed %d", len(tables))
	}
	if inner := strings.TrimSuffix(tables[0].Body, ")"); strings.Contains(inner, ");") {
		t.Fatalf("swallow check false-positived on ordinary SQL: %q", tables[0].Body)
	}
}

// The guard must actually catch a table that lost its tenant_id, including when
// a trailing CREATE INDEX still names the column. This is the case the previous
// substring-based version missed.
func TestTenantIDGuardCatchesMissingColumn(t *testing.T) {
	cases := map[string]string{
		"plain": `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL
);`,
		"trailing index names the column": `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE INDEX idx_thing_tenant ON thing(tenant_id);`,
		"nested parens in a CHECK": `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    tier SMALLINT NOT NULL CHECK (tier BETWEEN 0 AND 4)
);
CREATE INDEX idx_thing_tenant ON thing(tenant_id);`,
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			tables := parseCreateTables(sql)
			if len(tables) != 1 {
				t.Fatalf("expected 1 table, parsed %d", len(tables))
			}
			if strings.Contains(tables[0].Body, "tenant_id") {
				t.Fatalf("parser leaked text outside the column list: %q", tables[0].Body)
			}
		})
	}
}

// A table that legitimately has the column must still be recognised.
func TestTenantIDGuardAcceptsPresentColumn(t *testing.T) {
	sql := `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    tier SMALLINT NOT NULL CHECK (tier BETWEEN 0 AND 4),
    UNIQUE (tenant_id, id)
);
CREATE INDEX idx_thing_tenant ON thing(tenant_id);`
	tables := parseCreateTables(sql)
	if len(tables) != 1 || !strings.Contains(tables[0].Body, "tenant_id") {
		t.Fatalf("parser failed to find a present tenant_id: %+v", tables)
	}
}
