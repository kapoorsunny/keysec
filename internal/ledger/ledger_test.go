package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempLedger(t *testing.T) *Ledger {
	t.Helper()
	return NewAt(filepath.Join(t.TempDir(), "keys.json"))
}

func TestLoadMissingIsEmpty(t *testing.T) {
	l := tempLedger(t)
	entries, err := l.Load()
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Load = %d entries, want 0", len(entries))
	}
}

func TestUpsertRemoveRoundTrip(t *testing.T) {
	l := tempLedger(t)
	for _, name := range []string{"gitlab.repo_flay", "db.password", "mytoken"} {
		if err := l.Upsert(name); err != nil {
			t.Fatalf("Upsert(%q): %v", name, err)
		}
	}
	entries, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Load = %d entries, want 3", len(entries))
	}
	// Sorted by name.
	if entries[0].Name != "db.password" || entries[2].Name != "mytoken" {
		t.Errorf("order: %v", entries)
	}
	// Every entry carries a date.
	for _, e := range entries {
		if e.Updated.IsZero() || e.Created.IsZero() {
			t.Errorf("entry %q missing dates: %+v", e.Name, e)
		}
	}

	if err := l.Remove("db.password"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	entries, _ = l.Load()
	if len(entries) != 2 {
		t.Fatalf("after Remove = %d entries, want 2", len(entries))
	}
	for _, e := range entries {
		if e.Name == "db.password" {
			t.Errorf("db.password still present after Remove")
		}
	}
}

func TestUpsertExistingKeepsCreated(t *testing.T) {
	l := tempLedger(t)
	if err := l.Upsert("a.b"); err != nil {
		t.Fatal(err)
	}
	first, _ := l.Load()
	created := first[0].Created
	// Upsert again; created must be stable, updated must move forward.
	l.Upsert("a.b")
	second, _ := l.Load()
	if !second[0].Created.Equal(created) {
		t.Errorf("created changed on upsert: %v -> %v", created, second[0].Created)
	}
	if len(second) != 1 {
		t.Errorf("upsert duplicated the entry: %d", len(second))
	}
}

func TestRemoveUnknownIsNoOp(t *testing.T) {
	l := tempLedger(t)
	l.Upsert("a.b")
	if err := l.Remove("no.such"); err != nil {
		t.Fatalf("Remove unknown: %v", err)
	}
	if _, err := l.Load(); err != nil {
		t.Fatalf("Load after no-op remove: %v", err)
	}
}

func TestFileHasStrictPermissions(t *testing.T) {
	l := tempLedger(t)
	if err := l.Upsert("a.b"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode = %o, want 600", got)
	}
}

func TestValuesNeverOnDisk(t *testing.T) {
	l := tempLedger(t)
	if err := l.Upsert("some.key"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret", "value", "password"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("ledger file contains %q — it must only hold names and dates", secret)
		}
	}
}
