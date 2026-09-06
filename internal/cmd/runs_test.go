package cmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kapoorsunny/keysec/internal/keychain"
	"github.com/kapoorsunny/keysec/internal/runlog"
)

func seedRun(ctx context.Context, t *testing.T, ta *testApp, cmd string, keys ...string) {
	t.Helper()
	if _, err := runlog.Append(ctx, ta.store, cmd, keys); err != nil {
		t.Fatalf("seeding run log: %v", err)
	}
}

func TestRunsEmpty(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "runs")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if ta.stdout.Len() != 0 {
		t.Errorf("stdout should be empty, got %q", ta.stdout.String())
	}
	if !strings.Contains(ta.stderr.String(), "no runs recorded yet") {
		t.Errorf("stderr = %q, want a hint", ta.stderr.String())
	}
}

func TestRunsJSONEmpty(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "runs", "--json")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	var r struct {
		Count    int              `json:"count"`
		Entries  []map[string]any `json:"entries"`
		Tampered bool             `json:"tampered"`
	}
	decode(t, ta.stdout, &r)
	if r.Count != 0 || len(r.Entries) != 0 || r.Tampered {
		t.Errorf("runs --json = %+v", r)
	}
}

func TestRunsHumanShowsRows(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedRun(ctx, t, ta, "bash -c deploy", "mytoken", "other")

	rc := ta.run(t, "runs")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	out := ta.stdout.String()
	if !strings.Contains(out, "bash -c deploy") {
		t.Errorf("stdout should contain the command, got %q", out)
	}
	if !strings.Contains(out, "mytoken,other") {
		t.Errorf("stdout should contain the sorted secret names, got %q", out)
	}
}

func TestRunsJSONPresent(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedRun(ctx, t, ta, "bash -c deploy", "mytoken", "other")
	seedRun(ctx, t, ta, "echo again", "other")

	rc := ta.run(t, "runs", "--json")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	var r struct {
		Count   int `json:"count"`
		Entries []struct {
			Seq int      `json:"seq"`
			Cmd string   `json:"command"`
			Env []string `json:"secret_keys"`
			Sha string   `json:"sha"`
		} `json:"entries"`
		Tampered bool `json:"tampered"`
	}
	decode(t, ta.stdout, &r)
	if r.Count != 2 || len(r.Entries) != 2 {
		t.Fatalf("runs --json = %+v", r)
	}
	first := r.Entries[0]
	if first.Cmd != "bash -c deploy" || len(first.Env) != 2 || first.Sha == "" {
		t.Errorf("first entry = %+v", first)
	}
	if second := r.Entries[1]; second.Seq != 2 || second.Sha == "" {
		t.Errorf("second entry = %+v", second)
	}
}

func TestRunsDetectsTampering(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedRun(ctx, t, ta, "echo hi", "tok")
	seedRun(ctx, t, ta, "echo bye", "tok")

	raw := ta.store.m["keysec\x00.runlog"]
	tampered := strings.Replace(raw, "echo hi", "echo HI", 1)
	if tampered == raw {
		t.Fatal("test setup: could not mutate the stored log")
	}
	ta.store.m["keysec\x00.runlog"] = tampered

	rc := ta.run(t, "runs")
	if rc != 1 {
		t.Fatalf("exit = %d, want 1 on tampered log; stderr=%q", rc, ta.stderr.String())
	}
	if !strings.Contains(ta.stderr.String(), "integrity") {
		t.Errorf("stderr = %q, want an integrity failure notice", ta.stderr.String())
	}
	if !strings.Contains(ta.stderr.String(), "runs --yes") {
		t.Errorf("stderr = %q, want the reset path hinted", ta.stderr.String())
	}
}

func TestRunsJSONReportsTampered(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedRun(ctx, t, ta, "echo hi", "tok")
	raw := ta.store.m["keysec\x00.runlog"]
	ta.store.m["keysec\x00.runlog"] = strings.Replace(raw, "echo hi", "echo HI", 1)

	rc := ta.run(t, "runs", "--json")
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	var r struct {
		Count    int  `json:"count"`
		Tampered bool `json:"tampered"`
	}
	decode(t, ta.stdout, &r)
	if !r.Tampered || r.Count != 1 {
		t.Errorf("runs --json on tampered log = %+v (want Count=1, Tampered=true)", r)
	}
	var e struct {
		Error string `json:"error"`
	}
	decode(t, ta.stderr, &e)
	if e.Error != "io" {
		t.Errorf("stderr error = %+v, want io kind", e)
	}
}

func TestRunsUsage(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "runs", "extra")
	if rc != 2 {
		t.Fatalf("exit = %d, want 2 (usage)", rc)
	}
}

func TestRunLogHiddenFromList(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedRun(ctx, t, ta, "echo hi", "tok")
	ta.store.m["keysec\x00gitlab.api_token"] = "glpat-x"

	rc := ta.run(t, "list", "--json")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	var l struct {
		Count int `json:"count"`
		Keys  []struct {
			Name string `json:"name"`
		} `json:"keys"`
	}
	decode(t, ta.stdout, &l)
	if l.Count != 1 || l.Keys[0].Name != "gitlab.api_token" {
		t.Errorf("list = %+v; the .runlog overlay must not be enumerated as a key", l)
	}
	if _, ok := ta.store.m["keysec\x00.runlog"]; !ok {
		t.Fatal("test setup: runlog missing")
	}
}

// --- --yes reset tests ---

func seedTampered(ctx context.Context, t *testing.T, ta *testApp) {
	t.Helper()
	seedRun(ctx, t, ta, "echo hi", "tok")
	raw := ta.store.m["keysec\x00.runlog"]
	ta.store.m["keysec\x00.runlog"] = strings.Replace(raw, "echo hi", "echo HI", 1)
}

func TestRunsResetHuman(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedTampered(ctx, t, ta)

	rc := ta.run(t, "runs", "--yes")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if _, ok := ta.store.m["keysec\x00.runlog"]; ok {
		t.Error("the .runlog entry should have been deleted")
	}
	if !strings.Contains(ta.stderr.String(), "cleared") {
		t.Errorf("stderr = %q, want a cleared confirmation", ta.stderr.String())
	}
}

func TestRunsResetJSON(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedTampered(ctx, t, ta)

	rc := ta.run(t, "runs", "--yes", "--json")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	var r struct {
		OK      bool   `json:"ok"`
		Action  string `json:"action"`
		Cleared int    `json:"cleared"`
	}
	decode(t, ta.stdout, &r)
	if !r.OK || r.Action != "runs.reset" || r.Cleared != 1 {
		t.Errorf("runs --yes --json = %+v", r)
	}
	if _, ok := ta.store.m["keysec\x00.runlog"]; ok {
		t.Error("the .runlog entry should have been deleted")
	}
}

func TestRunsResetEmptyLog(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "runs", "--yes")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	if !strings.Contains(ta.stderr.String(), "nothing to clear") {
		t.Errorf("stderr = %q", ta.stderr.String())
	}
}

func TestRunsResetClearsHealthyLog(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedRun(ctx, t, ta, "first", "a")
	seedRun(ctx, t, ta, "second", "b")

	rc := ta.run(t, "runs", "--yes")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if _, ok := ta.store.m["keysec\x00.runlog"]; ok {
		t.Error("log should be gone")
	}
	if !strings.Contains(ta.stderr.String(), "2 entr") {
		t.Errorf("stderr = %q, want '2 entr' (count of cleared entries)", ta.stderr.String())
	}
}

func TestRunsResetLocked(t *testing.T) {
	ta := newTestApp(t)
	ta.store.delErr = keychain.ErrLocked

	rc := ta.run(t, "runs", "--yes")
	if rc != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q", rc, ta.stderr.String())
	}
	if !strings.Contains(strings.ToLower(ta.stderr.String()), "lock") {
		t.Errorf("stderr = %q, want locked hint", ta.stderr.String())
	}
}

func TestRunsResetUsage(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "runs", "--yes", "extra")
	if rc != 2 {
		t.Fatalf("exit = %d, want 2 (usage)", rc)
	}
}

func TestRunHealsAfterReset(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t)
	seedTampered(ctx, t, ta)

	rc := ta.run(t, "runs", "--yes")
	if rc != 0 {
		t.Fatalf("reset exit = %d", rc)
	}
	ta.store.m["keysec\x00mytoken"] = "new-tok"
	rc = ta.run(t, "run", "--env", "TOKEN=mytoken", "--", "echo", "ok")
	if rc != 0 {
		t.Fatalf("run after reset exit = %d; stderr=%q", rc, ta.stderr.String())
	}
	var log runlog.Log
	if err := decodeUnmarshal(ta.store.m["keysec\x00.runlog"], &log); err != nil {
		t.Fatalf("no fresh log after reset + run: %v", err)
	}
	if len(log.Entries) != 1 || log.Entries[0].Seq != 1 {
		t.Errorf("fresh log = %+v, want exactly one entry with Seq=1", log)
	}
}

func decodeUnmarshal(raw string, v any) error {
	return json.Unmarshal([]byte(raw), v)
}
