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

// Tenancy is structural: every table must carry tenant_id from creation.
func TestEveryTableHasTenantID(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("reading embedded FS: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		b, err := FS.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		for _, stmt := range strings.Split(string(b), "CREATE TABLE") {
			if !strings.Contains(stmt, "(") || strings.HasPrefix(strings.TrimSpace(stmt), "--") {
				continue
			}
			body := stmt[strings.Index(stmt, "(") : strings.LastIndex(stmt, ")")+1]
			if !strings.Contains(body, "tenant_id") {
				name := strings.TrimSpace(strings.Split(stmt, "(")[0])
				t.Errorf("%s: table %q has no tenant_id column", e.Name(), name)
			}
		}
	}
}
