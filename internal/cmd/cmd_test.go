package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kapoorsunny/keysec/internal/keychain"
	"github.com/kapoorsunny/keysec/internal/ui"
)

type fakeStore struct {
	m       map[string]string
	getErr  error
	putErr  error
	delErr  error
	hasErr  error
	listErr error
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
func (f *fakeStore) List(ctx context.Context) ([]keychain.Entry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []keychain.Entry
	for k := range f.m {
		s, a, _ := strings.Cut(k, "\x00")
		out = append(out, keychain.Entry{Service: s, Account: a})
	}
	return out, nil
}

// testApp wires an App with a fake store (which also enumerates) and
// captured stdout/stderr so tests can assert on exact output.
type testApp struct {
	app    *App
	store  *fakeStore
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	store := &fakeStore{m: map[string]string{}}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	app := New(store, store, ui.New(stdout, stderr), ui.NewPrompts(strings.NewReader(""), stderr), strings.NewReader(""))
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
	ta.store.m["keysec\x00gitlab.api_token"] = "glpat-abc"

	rc := ta.run(t, "get", "--json", "gitlab.api_token")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var v struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	decode(t, ta.stdout, &v)
	if v.Name != "gitlab.api_token" || v.Value != "glpat-abc" {
		t.Errorf("get --json = %+v", v)
	}
}

func TestGetJSONHumanModeUnchanged(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00k.v"] = "raw-value"

	ta.run(t, "get", "k.v")
	if got := ta.stdout.String(); got != "raw-value\n" {
		t.Errorf("human get = %q, want raw value + newline", got)
	}
}

func TestGetJSONNotFound(t *testing.T) {
	ta := newTestApp(t)
	// Seed a close name so the suggestion machinery has something to find.
	ta.store.m["keysec\x00gitlab.api_tokenx"] = "v"

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
	ta.store.m["keysec\x00gitlab.api_token"] = "tok"

	ta.run(t, "list", "--json")
	var l struct {
		Count int `json:"count"`
		Keys  []struct {
			Name    string `json:"name"`
			Rotates string `json:"rotates"`
		} `json:"keys"`
	}
	decode(t, ta.stdout, &l)
	if l.Count != 1 || l.Keys[0].Name != "gitlab.api_token" || l.Keys[0].Rotates != "" {
		t.Errorf("list --json = %+v", l)
	}
}

func TestSetJSON(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "set", "--json", "gitlab.api_token", "tok-1")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var a struct {
		OK     bool   `json:"ok"`
		Action string `json:"action"`
		Key    string `json:"key"`
	}
	decode(t, ta.stdout, &a)
	if !a.OK || a.Action != "saved" || a.Key != "gitlab.api_token" {
		t.Errorf("set --json ack = %+v", a)
	}
	if ta.store.m["keysec\x00gitlab.api_token"] != "tok-1" {
		t.Error("value not stored")
	}
}

func TestRmJSONYes(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00k.v"] = "x"

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
	if _, still := ta.store.m["keysec\x00k.v"]; still {
		t.Error("value still present after rm")
	}
}

func TestRmCascadesToRotator(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00k.v"] = "x"
	ta.store.m["keysec\x00k.v.rotator"] = `{"kind":"generate","length":32}`

	rc := ta.run(t, "rm", "--json", "--yes", "k.v")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if _, still := ta.store.m["keysec\x00k.v.rotator"]; still {
		t.Error("rotator companion still present after rm")
	}
}

// rmFailSpecStore fails deletes of rotator companions while letting secret
// deletes through, to exercise M1: a leftover-spec failure must not turn an
// otherwise-successful rm into a reported error.
type rmFailSpecStore struct {
	m map[string]string
}

func (f *rmFailSpecStore) sk(service, account string) string { return service + "\x00" + account }
func (f *rmFailSpecStore) Put(ctx context.Context, s, a, v string) error {
	f.m[f.sk(s, a)] = v
	return nil
}
func (f *rmFailSpecStore) Get(ctx context.Context, s, a string) (string, error) {
	v, ok := f.m[f.sk(s, a)]
	if !ok {
		return "", keychain.ErrNotFound
	}
	return v, nil
}
func (f *rmFailSpecStore) Delete(ctx context.Context, s, a string) error {
	if strings.HasSuffix(a, ".rotator") {
		return errors.New("boom")
	}
	delete(f.m, f.sk(s, a))
	return nil
}
func (f *rmFailSpecStore) Has(ctx context.Context, s, a string) (bool, error) {
	_, ok := f.m[f.sk(s, a)]
	return ok, nil
}
func (f *rmFailSpecStore) List(ctx context.Context) ([]keychain.Entry, error) { return nil, nil }

func TestRmSurvivesCompanionDeleteFailure(t *testing.T) {
	store := &rmFailSpecStore{m: map[string]string{
		"keysec\x00k.v":         "x",
		"keysec\x00k.v.rotator": `{"kind":"generate","length":32}`,
	}}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	app := New(store, store, ui.New(stdout, stderr), ui.NewPrompts(strings.NewReader(""), stderr), strings.NewReader(""))

	rc := app.Execute(context.Background(), []string{"rm", "--json", "--yes", "k.v"})
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (companion cleanup failure must not fail rm); stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
	}
	if _, still := store.m["keysec\x00k.v"]; still {
		t.Error("secret should have been deleted")
	}
}

func TestRotateAllSurfacesUnreadableSpec(t *testing.T) {
	ta := newTestApp(t)
	// A key whose rotator companion holds a valid secret but corrupt JSON.
	ta.store.m["keysec\x00k.good"] = "old"
	ta.store.m["keysec\x00k.good.rotator"] = `{"kind":"generate","length":32}`
	ta.store.m["keysec\x00k.bad"] = "old2"
	ta.store.m["keysec\x00k.bad.rotator"] = `not-json`

	rc := ta.run(t, "rotate", "--all", "--json")
	if rc != 1 {
		t.Fatalf("exit = %d, want 1 (corrupt spec must fail the sweep)", rc)
	}
	var b struct {
		OK     bool `json:"ok"`
		Failed []struct {
			Key string `json:"key"`
		} `json:"failed"`
	}
	decode(t, ta.stdout, &b)
	if b.OK {
		t.Error("sweep should not report ok with a corrupt spec")
	}
	foundBad := false
	for _, f := range b.Failed {
		if strings.Contains(f.Key, "k.bad") {
			foundBad = true
		}
	}
	if !foundBad {
		t.Errorf("expected k.bad in failed list; got %+v", b.Failed)
	}
}

func TestRotatorSetJSON(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00k.v"] = "x"

	rc := ta.run(t, "rotator", "set", "--json", "k.v", "--kind", "generate", "--length", "48")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var a struct {
		OK     bool   `json:"ok"`
		Action string `json:"action"`
	}
	decode(t, ta.stdout, &a)
	if !a.OK || a.Action != "rotator.set" {
		t.Errorf("rotator set --json ack = %+v", a)
	}
	var s struct {
		Kind   string `json:"kind"`
		Length int    `json:"length"`
	}
	decodeFromStr := json.Unmarshal([]byte(ta.store.m["keysec\x00k.v.rotator"]), &s)
	if decodeFromStr != nil {
		t.Fatalf("spec not stored as JSON: %v", decodeFromStr)
	}
	if s.Kind != "generate" || s.Length != 48 {
		t.Errorf("stored spec = %+v", s)
	}
}

func TestRotatorSetSpecSwitchesKind(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00k.v"] = "x"
	ta.store.m["keysec\x00k.v.rotator"] = `{"kind":"generate","length":48}`

	rc := ta.run(t, "rotator", "set", "--json", "k.v",
		"--spec", `{"kind":"http","url":"https://id.example/new-token","new_expires":"data.expires_at"}`)
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var s struct {
		Kind       string `json:"kind"`
		URL        string `json:"url"`
		NewExpires string `json:"new_expires"`
		Length     int    `json:"length"`
	}
	if err := json.Unmarshal([]byte(ta.store.m["keysec\x00k.v.rotator"]), &s); err != nil {
		t.Fatalf("stored spec is not JSON: %v", err)
	}
	if s.Kind != "http" || s.URL != "https://id.example/new-token" || s.NewExpires != "data.expires_at" {
		t.Errorf("stored spec = %+v; --spec fields must survive a kind switch", s)
	}
	if s.Length != 0 {
		t.Errorf("generate length leaked into the http spec: %+v", s)
	}
}

func TestRotateJSON(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00k.v"] = "old"
	ta.store.m["keysec\x00k.v.rotator"] = `{"kind":"generate","length":32}`

	rc := ta.run(t, "rotate", "--json", "k.v")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var a struct {
		OK     bool   `json:"ok"`
		Action string `json:"action"`
		Key    string `json:"key"`
	}
	decode(t, ta.stdout, &a)
	if !a.OK || a.Action != "rotated" || a.Key != "k.v" {
		t.Errorf("rotate --json ack = %+v", a)
	}
	got := ta.store.m["keysec\x00k.v"]
	if got == "old" || len(got) != 32 {
		t.Errorf("new value = %q, want a fresh 32-char secret", got)
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
	// The stored key is derived from host; value round-trips under keysec.
	if got, _ := ta.store.Get(context.Background(), "keysec", "git.example.com"); got != "p q" {
		t.Errorf("git approve stored %q, want 'p q'", got)
	}
}

// seedRotatable stores a key with a generate rotator, optionally with a
// recorded expiry, so sweep filtering can be exercised.
func (ta *testApp) seedRotatable(t *testing.T, name, expiresAt string) {
	t.Helper()
	ta.store.m[ta.store.sk("keysec", name)] = "current-value"
	spec := `{"kind":"generate","length":8`
	if expiresAt != "" {
		spec += `,"expires_at":"` + expiresAt + `"`
	}
	spec += `}`
	ta.store.m[ta.store.sk("keysec", name+".rotator")] = spec
}

// TestRotateAllDueFiltersByExpiry is the documented sweep. The gate used
// to be "if !all", so passing --all disabled --due entirely and every
// key with a rotator was rotated — mass-replacing healthy credentials.
func TestRotateAllDueFiltersByExpiry(t *testing.T) {
	ta := newTestApp(t)
	ta.seedRotatable(t, "past", "2000-01-01T00:00:00Z")
	ta.seedRotatable(t, "future", "2100-01-01T00:00:00Z")
	ta.seedRotatable(t, "noexpiry", "")

	before := map[string]string{}
	for _, n := range []string{"past", "future", "noexpiry"} {
		before[n] = ta.store.m[ta.store.sk("keysec", n)]
	}
	if err := ta.app.Rotate(context.Background(), []string{"--all", "--due"}); err != nil {
		t.Fatalf("rotate --all --due: %v", err)
	}
	if got := ta.store.m[ta.store.sk("keysec", "past")]; got == before["past"] {
		t.Error("the expired key should have been rotated")
	}
	for _, n := range []string{"future", "noexpiry"} {
		if got := ta.store.m[ta.store.sk("keysec", n)]; got != before[n] {
			t.Errorf("%q is not due and must not be rotated", n)
		}
	}
}

// TestRotateAllWithoutDueTakesEverything keeps the other half honest.
func TestRotateAllWithoutDueTakesEverything(t *testing.T) {
	ta := newTestApp(t)
	ta.seedRotatable(t, "future", "2100-01-01T00:00:00Z")
	before := ta.store.m[ta.store.sk("keysec", "future")]
	if err := ta.app.Rotate(context.Background(), []string{"--all"}); err != nil {
		t.Fatalf("rotate --all: %v", err)
	}
	if ta.store.m[ta.store.sk("keysec", "future")] == before {
		t.Error("--all on its own should rotate every key with a rotator")
	}
}

// TestLeadingJSONBeforeRun: "--json" is documented as accepted anywhere,
// but run is dispatched before flag stripping, so a leading --json used
// to fall through to the switch and die with "unknown command 'run'".
func TestLeadingJSONBeforeRun(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m[ta.store.sk("keysec", "tok")] = "s3cret"
	code := ta.app.Execute(context.Background(), []string{"--json", "run", "--env", "T=tok", "true"})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, ta.stderr.String())
	}
	if strings.Contains(ta.stderr.String(), "unknown command") {
		t.Errorf("run was not recognised: %s", ta.stderr.String())
	}
}

// TestRotatorFlagEmptyValue: "--flag=" is an explicit empty value and
// the only way to clear a field. Treating it as "value missing" ate the
// next argument and silently misparsed the rest of the line.
func TestRotatorFlagEmptyValue(t *testing.T) {
	flags, positional, _, err := parseRotatorFlags([]string{"mykey", "--auth-key=", "--kind", "generate"})
	if err != nil {
		t.Fatalf("parseRotatorFlags: %v", err)
	}
	if got, ok := flags["--auth-key"]; !ok || got != "" {
		t.Errorf("--auth-key = %q (present=%v), want an empty value", got, ok)
	}
	if flags["--kind"] != "generate" {
		t.Errorf("--kind = %q, want generate", flags["--kind"])
	}
	if len(positional) != 1 || positional[0] != "mykey" {
		t.Errorf("positional = %v, want [mykey]", positional)
	}
}
