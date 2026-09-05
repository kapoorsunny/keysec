package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/ledger"
	"repo.flay.ai/root/keysec/internal/ui"
)

type fakeStore struct {
	m      map[string]string
	getErr error
	putErr error
	delErr error
	hasErr error
}

func (f *fakeStore) sk(service, account string) string { return service + "\x00" + account }
func (f *fakeStore) Put(ctx context.Context, s, a, v string) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.m[f.sk(s, a)] = v
	return nil
}
func (f *fakeStore) Get(ctx context.Context, s, a string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.m[f.sk(s, a)]
	if !ok {
		return "", keychain.ErrNotFound
	}
	return v, nil
}
func (f *fakeStore) Delete(ctx context.Context, s, a string) error {
	if f.delErr != nil {
		return f.delErr
	}
	delete(f.m, f.sk(s, a))
	return nil
}
func (f *fakeStore) Has(ctx context.Context, s, a string) (bool, error) {
	if f.hasErr != nil {
		return false, f.hasErr
	}
	_, ok := f.m[f.sk(s, a)]
	return ok, nil
}

// testApp wires an App with a fake store, a temp ledger, and captured
// stdout/stderr so tests can assert on exact output.
type testApp struct {
	app    *App
	store  *fakeStore
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	store := &fakeStore{m: map[string]string{}}
	led := ledger.NewAt(filepath.Join(t.TempDir(), "keys.json"))
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	app := New(store, led, ui.New(stdout, stderr), ui.NewPrompts(strings.NewReader(""), stderr), strings.NewReader(""))
	return &testApp{app: app, store: store, stdout: stdout, stderr: stderr}
}

func (ta *testApp) run(t *testing.T, args ...string) int {
	t.Helper()
	return ta.app.Execute(context.Background(), args)
}

func decode(t *testing.T, b *bytes.Buffer, v any) {
	t.Helper()
	if err := json.Unmarshal(b.Bytes(), v); err != nil {
		t.Fatalf("cannot decode %q as JSON: %v", b.String(), err)
	}
}

func TestGetJSON(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["gitlab\x00repo_flay"] = "glpat-abc"
	ta.app.ledger.Upsert("gitlab.repo_flay")

	rc := ta.run(t, "get", "--json", "gitlab.repo_flay")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var v struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	decode(t, ta.stdout, &v)
	if v.Name != "gitlab.repo_flay" || v.Value != "glpat-abc" {
		t.Errorf("get --json = %+v", v)
	}
}

func TestGetJSONHumanModeUnchanged(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["k\x00v"] = "raw-value"
	ta.app.ledger.Upsert("k.v")

	ta.run(t, "get", "k.v")
	if got := ta.stdout.String(); got != "raw-value\n" {
		t.Errorf("human get = %q, want raw value + newline", got)
	}
}

func TestGetJSONNotFound(t *testing.T) {
	ta := newTestApp(t)
	ta.app.ledger.Upsert("gitlab.repo_flay")

	rc := ta.run(t, "get", "--json", "gitlab.tken")
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if ta.stdout.Len() != 0 {
		t.Errorf("stdout should be empty on error, got %q", ta.stdout.String())
	}
	var e struct {
		Error string `json:"error"`
		Key   string `json:"key"`
		Hint  string `json:"hint"`
	}
	decode(t, ta.stderr, &e)
	if e.Error != "not_found" || e.Key != "gitlab.tken" {
		t.Errorf("error = %+v", e)
	}
	if e.Hint == "" {
		t.Error("expected a did-you-mean hint")
	}
}

func TestListJSONEmpty(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "list", "--json")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	var l struct {
		Count int   `json:"count"`
		Keys  []any `json:"keys"`
	}
	decode(t, ta.stdout, &l)
	if l.Count != 0 || len(l.Keys) != 0 {
		t.Errorf("list --json = %+v", l)
	}
}

func TestListJSONPresent(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["gitlab\x00repo_flay"] = "tok"
	ta.app.ledger.Upsert("gitlab.repo_flay")

	ta.run(t, "list", "--json")
	var l struct {
		Count int `json:"count"`
		Keys  []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"keys"`
	}
	decode(t, ta.stdout, &l)
	if l.Count != 1 || l.Keys[0].Name != "gitlab.repo_flay" || l.Keys[0].State != "present" {
		t.Errorf("list --json = %+v", l)
	}
}

func TestSetJSON(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "set", "--json", "gitlab.repo_flay", "tok-1")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var a struct {
		OK     bool   `json:"ok"`
		Action string `json:"action"`
		Key    string `json:"key"`
	}
	decode(t, ta.stdout, &a)
	if !a.OK || a.Action != "saved" || a.Key != "gitlab.repo_flay" {
		t.Errorf("set --json ack = %+v", a)
	}
	if ta.store.m["gitlab\x00repo_flay"] != "tok-1" {
		t.Error("value not stored")
	}
}

func TestRmJSONYes(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["k\x00v"] = "x"
	ta.app.ledger.Upsert("k.v")

	rc := ta.run(t, "rm", "--json", "--yes", "k.v")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var a struct {
		OK     bool   `json:"ok"`
		Action string `json:"action"`
	}
	decode(t, ta.stdout, &a)
	if !a.OK || a.Action != "removed" {
		t.Errorf("rm --json ack = %+v", a)
	}
	if _, still := ta.store.m["k\x00v"]; still {
		t.Error("value still present after rm")
	}
}

func TestUsageJSONExitCode(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "get", "--json") // missing <key>
	if rc != 2 {
		t.Fatalf("exit = %d, want 2 for usage", rc)
	}
	var e struct {
		Error string `json:"error"`
	}
	decode(t, ta.stderr, &e)
	if e.Error != "usage" {
		t.Errorf("error = %+v", e)
	}
}

func TestGitCredentialUnaffectedByJSON(t *testing.T) {
	ta := newTestApp(t)
	// --json must be stripped and must not leak into the protocol stream.
	in := "protocol=https\nhost=example.com\nusername=u\npassword=p%20q\n"
	ta.app.stdin = strings.NewReader(in)
	rc := ta.app.Execute(context.Background(), []string{"git-credential", "--json", "approve"})
	if rc != 0 {
		t.Fatalf("git-credential approve exit = %d, want 0", rc)
	}
	// The stored key is derived from host; value round-trips.
	if got, _ := ta.store.Get(context.Background(), "git", "example.com"); got != "p q" {
		t.Errorf("git approve stored %q, want 'p q'", got)
	}
}
