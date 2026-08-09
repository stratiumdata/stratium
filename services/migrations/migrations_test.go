package migrations

import (
	"fmt"
	"regexp"
	"sort"
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

// reconcileTableCount reports whether the number of parsed tables matches
// the textual count of "CREATE TABLE" occurrences. A mismatch means
// parseCreateTables lost sync: an unbalanced paren inside a string literal
// or a comment desyncs the character-level depth counter and it silently
// returns fewer tables — possibly none — for the rest of the file. A
// global "did we parse anything at all" check does not catch that, because
// another file keeps the total nonzero; comparing against a textual count
// does, because any disagreement means the parser lost track.
//
// Extracted so TestTenantIDGuardDetectsParserDesync can pin this check's
// behavior directly against a manufactured mismatch, rather than depend on
// today's parser actually losing sync on some particular fixture — that
// would make the test start failing the day the parser becomes
// quote-aware and stops losing sync, punishing a strict improvement.
func reconcileTableCount(sql string, tables []createTable) error {
	if want, got := strings.Count(sql, "CREATE TABLE"), len(tables); want != got {
		return fmt.Errorf("found %d occurrences of CREATE TABLE but parsed %d — "+
			"the parser lost sync (unbalanced paren in a literal or comment, "+
			"or an unsupported form such as CREATE TABLE ... AS SELECT)", want, got)
	}
	return nil
}

// swallowedStatement reports whether tbl's body ran past its own closing
// paren and absorbed a following statement. Equal counts from
// reconcileTableCount are not sufficient: a stray paren inside one table's
// body can overrun its true close and swallow a trailing
// `CREATE INDEX ... ON t(tenant_id);` — no CREATE TABLE is consumed, so the
// count still matches, but the swallowed text supplies the substring and a
// table with no tenant_id column passes.
//
// A correct body ends at its own ")" and contains no earlier ");". Testing
// for a bare ";" instead would flag any prose comment that happens to use
// one, which trains people to reword comments rather than fix parses — a
// guard nobody trusts is a guard nobody keeps.
func swallowedStatement(tbl createTable) bool {
	inner := strings.TrimSuffix(tbl.Body, ")")
	return strings.Contains(inner, ");")
}

// tablesMissingTenantID returns the names of tables in tables that have no
// tenant_id column. Both TestEveryTableHasTenantID (the real migrations)
// and TestTenantIDGuardStillGuards (a fixture known to be missing the
// column) call this, so weakening or deleting the check breaks a
// clearly-named test rather than leaving a silent gap in migration
// coverage.
func tablesMissingTenantID(tables []createTable) []string {
	var missing []string
	for _, tbl := range tables {
		if !strings.Contains(tbl.Body, "tenant_id") {
			missing = append(missing, tbl.Name)
		}
	}
	return missing
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

		if err := reconcileTableCount(sql, tables); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}

		for _, tbl := range tables {
			if swallowedStatement(tbl) {
				t.Errorf("%s: parsed body for table %q ran past its own closing paren "+
					"and swallowed following statements — the parser lost sync",
					e.Name(), tbl.Name)
			}
		}

		total += len(tables)
		for _, name := range tablesMissingTenantID(tables) {
			t.Errorf("%s: table %q has no tenant_id column", e.Name(), name)
		}
	}
	if total == 0 {
		t.Fatal("parsed no CREATE TABLE statements — the guard is inert")
	}
}

// TestTenantIDGuardStillGuards pins that tablesMissingTenantID actually
// flags a table with no tenant_id column, against a fixture wholly
// independent of the real migrations. Without this, the check inside
// TestEveryTableHasTenantID could be weakened or deleted — e.g. changed to
// do nothing — and the suite would stay green on every future migration,
// tenant_id column or not.
func TestTenantIDGuardStillGuards(t *testing.T) {
	sql := `CREATE TABLE thing (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL
);`
	missing := tablesMissingTenantID(parseCreateTables(sql))
	if len(missing) != 1 || missing[0] != "thing" {
		t.Fatalf("expected the guard to flag table %q as missing tenant_id, got %v", "thing", missing)
	}
}

// The reconciliation check must fire on a want/got mismatch, independent of
// what causes one. This deliberately does not derive the mismatch from
// today's parser actually losing sync on some fixture: asserting that the
// parser itself is broken would make this test start failing the day
// parseCreateTables becomes quote-aware and stops losing sync on exactly
// that fixture — punishing a strict improvement. Instead it manufactures
// the mismatch reconcileTableCount exists to catch and checks that it does.
func TestTenantIDGuardDetectsParserDesync(t *testing.T) {
	sql := "CREATE TABLE a (id UUID PRIMARY KEY); CREATE TABLE b (id UUID PRIMARY KEY);"
	// Two CREATE TABLE occurrences, one parsed table: a manufactured
	// desync, not one derived from parseCreateTables' current behavior.
	short := []createTable{{Name: "a", Body: "(id UUID PRIMARY KEY)"}}
	if err := reconcileTableCount(sql, short); err == nil {
		t.Fatal("expected the reconciliation check to catch a want/got mismatch")
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

	// This fixture must trip one guard or the other: the count check, if
	// parseCreateTables' table count disagrees with the textual count, or
	// the swallow check, if counts agree but a body ran past its own close
	// paren. Assert whichever applies — never skip, or a fixture that stops
	// tripping either check would silently pass this test.
	if err := reconcileTableCount(sql, tables); err != nil {
		return // the count check caught it — that is success for this test
	}

	swallowed := false
	for _, tbl := range tables {
		if swallowedStatement(tbl) {
			swallowed = true
		}
	}
	if !swallowed {
		t.Fatal("neither the count check nor the swallow check caught a body " +
			"that ran past its closing paren — a table with no tenant_id " +
			"column would pass")
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

// reEnableRLSDirect matches a literal "ALTER TABLE <name> ENABLE ROW LEVEL
// SECURITY", the form 000003_audit_chain.up.sql uses for audit_chain.
var reEnableRLSDirect = regexp.MustCompile(`(?i)ALTER TABLE\s+(\w+)\s+ENABLE ROW LEVEL SECURITY`)

// reArrayLiteral matches an ARRAY[...] literal; reQuotedIdent pulls the
// quoted identifiers out of one. Together they read the FOREACH-over-ARRAY
// form 000002_rls.up.sql uses to loop ALTER TABLE ... ENABLE ROW LEVEL
// SECURITY over a list of table names inside one DO block.
var (
	reArrayLiteral = regexp.MustCompile(`ARRAY\s*\[([^\]]*)\]`)
	reQuotedIdent  = regexp.MustCompile(`'(\w+)'`)
)

// rlsEnabledTables returns every table name that gets row-level security
// enabled somewhere in an .up.sql file's contents, recognising both forms
// above.
//
// ponytail: scoped to "this file mentions ENABLE ROW LEVEL SECURITY at
// all, so every ARRAY[...] literal and every direct ALTER TABLE in it
// counts" — file-level, not statement-level. Correct for today's four
// migrations, where each RLS-enabling file has exactly one such array or
// statement set. If a future migration mixes an RLS loop with an unrelated
// ARRAY[...], tighten this to scope by DO $$ ... END $$ block instead.
func rlsEnabledTables(sql string) map[string]bool {
	out := map[string]bool{}
	if !strings.Contains(strings.ToUpper(sql), "ENABLE ROW LEVEL SECURITY") {
		return out
	}
	for _, m := range reEnableRLSDirect.FindAllStringSubmatch(sql, -1) {
		out[m[1]] = true
	}
	for _, arr := range reArrayLiteral.FindAllStringSubmatch(sql, -1) {
		for _, name := range reQuotedIdent.FindAllStringSubmatch(arr[1], -1) {
			out[name[1]] = true
		}
	}
	return out
}

// TestRLSCoversEveryTable pins that every table created by any migration
// gets row-level security enabled somewhere — the shared array in
// 000002_rls.up.sql, or an individual block like audit_chain's in
// 000003_audit_chain.up.sql. Without this, a table added by a later
// migration and added to neither passes every other test in this file: RLS
// coverage is invisible to the tenant_id guard above.
func TestRLSCoversEveryTable(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("reading embedded FS: %v", err)
	}

	allTables := map[string]bool{}
	rlsTables := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		b, err := FS.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		sql := string(b)
		for _, tbl := range parseCreateTables(sql) {
			allTables[tbl.Name] = true
		}
		for name := range rlsEnabledTables(sql) {
			rlsTables[name] = true
		}
	}

	if len(allTables) == 0 {
		t.Fatal("parsed no CREATE TABLE statements — the guard is inert")
	}
	var missing []string
	for name := range allTables {
		if !rlsTables[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("table(s) with no row-level security anywhere in the migrations: %v", missing)
	}
}

// TestRLSCoverageGuardStillGuards pins that rlsEnabledTables actually
// leaves an uncovered table out, against fixtures independent of the real
// migrations — the same belt-and-suspenders reasoning as
// TestTenantIDGuardStillGuards above.
func TestRLSCoverageGuardStillGuards(t *testing.T) {
	sql := `CREATE TABLE covered (id UUID PRIMARY KEY);
CREATE TABLE uncovered (id UUID PRIMARY KEY);
ALTER TABLE covered ENABLE ROW LEVEL SECURITY;`
	rls := rlsEnabledTables(sql)
	if !rls["covered"] {
		t.Error(`expected "covered" to be recognised as RLS-enabled`)
	}
	if rls["uncovered"] {
		t.Error(`expected "uncovered" to NOT be recognised as RLS-enabled`)
	}
}
