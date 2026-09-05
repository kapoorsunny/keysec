package migrate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"repo.flay.ai/root/keysec/internal/keychain"
)

// fakeStore is a minimal keychain store for migration tests, keyed by
// "service\x00account".
type fakeStore struct {
	mu      sync.Mutex
	m       map[string]string
	deletes []string
}

func newFakeStore(initial map[string]string) *fakeStore {
	return &fakeStore{m: initial}
}

func kv(svc, acct string) string { return svc + "\x00" + acct }

func (f *fakeStore) Put(_ context.Context, svc, acct, val string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[kv(svc, acct)] = val
	return nil
}

func (f *fakeStore) Get(_ context.Context, svc, acct string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.m[kv(svc, acct)]; ok {
		return v, nil
	}
	return "", keychain.ErrNotFound
}

func (f *fakeStore) Delete(_ context.Context, svc, acct string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[kv(svc, acct)]; !ok {
		return keychain.ErrNotFound
	}
	delete(f.m, kv(svc, acct))
	f.deletes = append(f.deletes, svc+"/"+acct)
	return nil
}

func (f *fakeStore) Has(_ context.Context, svc, acct string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.m[kv(svc, acct)]
	return ok, nil
}

func writeLegacy(t *testing.T, entries string) {
	t.Helper()
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), dirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"version":1,"keys":`+entries+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func withHome(t *testing.T) {
	t.Helper()
	t.Setenv("KEYSEC_HOME", t.TempDir())
}

func TestRunMovesDottedSkipsDotlessAndRotator(t *testing.T) {
	withHome(t)
	store := newFakeStore(map[string]string{
		kv("git", "repo.flay.ai.root.keysec"): "tokenvalue",
		kv("keysec", "plain"):                 "p",
		kv("svc", "thing.rotator"):            "x",
	})
	writeLegacy(t, `[
		{"name":"git.repo.flay.ai.root.keysec"},
		{"name":"plain"},
		{"name":"thing.rotator"}
	]`)

	sum, err := Run(context.Background(), store, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(sum.Moved, "git.repo.flay.ai.root.keysec") {
		t.Errorf("moved = %v, want the dotted key", sum.Moved)
	}
	if len(sum.Skipped) != 2 {
		t.Fatalf("skipped = %v, want 2 (dotless + reserved)", sum.Skipped)
	}
	if v, _ := store.m[kv("keysec", "git.repo.flay.ai.root.keysec")]; v != "tokenvalue" {
		t.Errorf("new location = %q, want the moved value", v)
	}
	if _, ok := store.m[kv("git", "repo.flay.ai.root.keysec")]; ok {
		t.Error("old location should have been deleted")
	}
	if !sum.FileRemoved {
		t.Error("keys.json should be removed after a clean migration")
	}
}

func TestRunResolverForDotless(t *testing.T) {
	withHome(t)
	store := newFakeStore(map[string]string{kv("keysec", "plain"): "p"})
	writeLegacy(t, `[{"name":"plain"}]`)
	sum, err := Run(context.Background(), store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Moved) != 0 {
		t.Errorf("dotless key must not move (already at its v0.2 location), moved = %v", sum.Moved)
	}
}

func TestRunAbortsOnPutFailureKeepsFile(t *testing.T) {
	withHome(t)
	// Seed the legacy location so the move reaches Put (where it fails)
	// instead of being skipped as a missing secret.
	store := &putErrStore{newFakeStore(map[string]string{
		kv("a", "b"): "v",
	})}
	writeLegacy(t, `[{"name":"a.b"}]`)
	_, err := Run(context.Background(), store, nil)
	if err == nil {
		t.Fatal("expected failure")
	}
	if !strings.Contains(err.Error(), "write failed") {
		t.Errorf("err = %v, want the put failure", err)
	}
	p, _ := Path()
	if _, statErr := os.Stat(p); statErr != nil {
		t.Errorf("keys.json must survive a failed migration: %v", statErr)
	}
}

func TestRunSkipsEntryWhoseSecretIsMissing(t *testing.T) {
	withHome(t)
	store := newFakeStore(nil)
	writeLegacy(t, `[{"name":"gone.away"}]`)
	sum, err := Run(context.Background(), store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Skipped) != 1 || !strings.Contains(sum.Skipped[0].Reason, "missing") {
		t.Errorf("skipped = %+v, want the missing-secret skip", sum.Skipped)
	}
	if len(sum.Moved) != 0 {
		t.Errorf("moved = %v, want none", sum.Moved)
	}
	if !sum.FileRemoved {
		t.Error("a run whose entries all skipped should still remove the index")
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	withHome(t)
	entries, err := Load()
	if err != nil || len(entries) != 0 {
		t.Errorf("Load on missing file = %v, %v; want empty, nil", entries, err)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

type putErrStore struct {
	*fakeStore
}

func (s *putErrStore) Put(_ context.Context, _, _, _ string) error {
	return errors.New("write failed")
}
