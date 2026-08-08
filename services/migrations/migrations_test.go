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
	seen := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		b, err := FS.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		for _, tbl := range parseCreateTables(string(b)) {
			seen++
			if !strings.Contains(tbl.Body, "tenant_id") {
				t.Errorf("%s: table %q has no tenant_id column", e.Name(), tbl.Name)
			}
		}
	}
	if seen == 0 {
		t.Fatal("parsed no CREATE TABLE statements — the guard is inert")
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
