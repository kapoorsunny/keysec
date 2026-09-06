package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kapoorsunny/keysec/internal/keychain"
	"github.com/kapoorsunny/keysec/internal/runlog"
)

// --- parseEnvArg unit tests ---

func TestParseEnvArgValid(t *testing.T) {
	tests := []struct {
		input string
		name  string
		key   string
	}{
		{"TOKEN=mytoken", "TOKEN", "mytoken"},
		{"AWS_ACCESS_KEY_ID=aws.key", "AWS_ACCESS_KEY_ID", "aws.key"},
		{"lower=value", "lower", "value"},
		{"_UNDER=x", "_UNDER", "x"},
		{"A1=b", "A1", "b"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			f, err := parseEnvArg(tt.input)
			if err != nil {
				t.Fatalf("parseEnvArg(%q) unexpected error: %v", tt.input, err)
			}
			if f.name != tt.name || f.key != tt.key {
				t.Errorf("parseEnvArg(%q) = %+v, want name=%q key=%q", tt.input, f, tt.name, tt.key)
			}
		})
	}
}

func TestParseEnvArgInvalid(t *testing.T) {
	tests := []struct {
		input string
		desc  string
	}{
		{"TOKENMYTOKEN", "no equals sign"},
		{"=mytoken", "empty name"},
		{"TOKEN=", "empty key"},
		{"1BAD=x", "name starts with digit"},
		{"MY-TOKEN=x", "name contains dash"},
		{"MY TOKEN=x", "name contains space"},
		{"", "empty string"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			_, err := parseEnvArg(tt.input)
			if err == nil {
				t.Errorf("parseEnvArg(%q) should fail (%s), got no error", tt.input, tt.desc)
			}
		})
	}
}

// --- normalizeChildCode unit tests ---

func TestNormalizeChildCode(t *testing.T) {
	tests := []struct {
		code int
		want int
	}{
		{0, 0},
		{1, 1},
		{42, 42},
		{127, 127},
		{255, 255},
		{256, 1},  // out of range → signal death → 1
		{-1, 1},   // negative → signal death → 1
		{-128, 1}, // large negative → signal death → 1
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := normalizeChildCode(tt.code)
			if got != tt.want {
				t.Errorf("normalizeChildCode(%d) = %d, want %d", tt.code, got, tt.want)
			}
		})
	}
}

// --- runStartError unit tests ---

func TestRunStartError(t *testing.T) {
	e := runStartError("mycmd", &testExecError{msg: "not found"})
	if e == nil {
		t.Fatal("expected non-nil error")
	}
	if e.Kind != "io" {
		t.Errorf("kind = %q, want io", e.Kind)
	}
	if !strings.Contains(e.Message, "mycmd") {
		t.Errorf("message should mention program name: %q", e.Message)
	}
}

// testExecError satisfies the error interface and mimics exec.Error for testing.
type testExecError struct {
	msg string
}

func (e *testExecError) Error() string { return e.msg }

// --- Run integration tests (fork real child processes) ---

func TestRunSuccessNoEnv(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00tok"] = "secret"

	rc := ta.run(t, "run", "--", "echo", "hello")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "hello" {
		t.Errorf("stdout = %q, want 'hello'", got)
	}
}

func TestRunEnvInjection(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00mytoken"] = "s3cret"

	rc := ta.run(t, "run", "--env", "TOKEN=mytoken", "--", "bash", "-c", "echo $TOKEN")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "s3cret" {
		t.Errorf("stdout = %q, want 's3cret'", got)
	}
}

func TestRunEnvInjectionEqualsForm(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00mytoken"] = "eq-val"

	rc := ta.run(t, "run", "--env=TOKEN=mytoken", "--", "bash", "-c", "echo $TOKEN")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "eq-val" {
		t.Errorf("stdout = %q, want 'eq-val'", got)
	}
}

func TestRunMultipleEnv(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00a"] = "alpha"
	ta.store.m["keysec\x00b"] = "beta"

	rc := ta.run(t, "run", "--env", "VAR_A=a", "--env", "VAR_B=b", "--", "bash", "-c", "echo $VAR_A $VAR_B")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "alpha beta" {
		t.Errorf("stdout = %q, want 'alpha beta'", got)
	}
}

func TestRunFirstNonFlagEndsParsing(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00tok"] = "val"

	// No -- separator; "echo" is the first non-flag arg and starts the child command.
	rc := ta.run(t, "run", "--env", "TOKEN=tok", "echo", "world")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "world" {
		t.Errorf("stdout = %q, want 'world'", got)
	}
}

func TestRunChildExitsNonZero(t *testing.T) {
	ta := newTestApp(t)

	rc := ta.run(t, "run", "--", "bash", "-c", "exit 42")
	if rc != 42 {
		t.Errorf("exit = %d, want 42; stderr=%q", rc, ta.stderr.String())
	}
}

func TestRunChildExitsOne(t *testing.T) {
	ta := newTestApp(t)

	rc := ta.run(t, "run", "--", "bash", "-c", "exit 1")
	if rc != 1 {
		t.Errorf("exit = %d, want 1; stderr=%q", rc, ta.stderr.String())
	}
}

func TestRunChildExits255(t *testing.T) {
	ta := newTestApp(t)

	rc := ta.run(t, "run", "--", "bash", "-c", "exit 255")
	if rc != 255 {
		t.Errorf("exit = %d, want 255; stderr=%q", rc, ta.stderr.String())
	}
}

func TestRunNoCommandUsage(t *testing.T) {
	ta := newTestApp(t)

	// --env provided but no command after it.
	rc := ta.run(t, "run", "--env", "TOKEN=tok")
	if rc != 2 {
		t.Fatalf("exit = %d, want 2 (usage); stderr=%q", rc, ta.stderr.String())
	}
	if ta.stdout.Len() != 0 {
		t.Errorf("stdout should be empty on usage error, got %q", ta.stdout.String())
	}
}

func TestRunMissingEnvValue(t *testing.T) {
	ta := newTestApp(t)

	// --env with no value following it.
	rc := ta.run(t, "run", "--env", "--", "echo", "hi")
	if rc != 2 {
		t.Fatalf("exit = %d, want 2 (usage); stderr=%q", rc, ta.stderr.String())
	}
}

func TestRunInvalidEnvName(t *testing.T) {
	ta := newTestApp(t)

	rc := ta.run(t, "run", "--env", "1BAD=x", "--", "echo", "hi")
	if rc != 2 {
		t.Fatalf("exit = %d, want 2 (usage); stderr=%q", rc, ta.stderr.String())
	}
}

func TestRunKeyNotFound(t *testing.T) {
	ta := newTestApp(t)
	// Seed a close name so the suggestion machinery has something to find.
	ta.store.m["keysec\x00token"] = "v"

	rc := ta.run(t, "run", "--env", "TOKEN=tokn", "--", "echo", "hi")
	if rc != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q", rc, ta.stderr.String())
	}
	if ta.stdout.Len() != 0 {
		t.Errorf("stdout should be empty on error, got %q", ta.stdout.String())
	}
}

func TestRunCommandNotFound(t *testing.T) {
	ta := newTestApp(t)

	rc := ta.run(t, "run", "--", "/nonexistent/binary/path", "arg")
	if rc != 1 {
		t.Errorf("exit = %d, want 1 (io error for missing command)", rc)
	}
}

func TestRunInheritsParentEnv(t *testing.T) {
	ta := newTestApp(t)
	t.Setenv("KEYSEC_TEST_INHERIT", "from_parent")

	rc := ta.run(t, "run", "--", "bash", "-c", "echo $KEYSEC_TEST_INHERIT")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "from_parent" {
		t.Errorf("stdout = %q, want 'from_parent' (child should inherit parent env)", got)
	}
}

func TestRunInjectedOverridesParent(t *testing.T) {
	ta := newTestApp(t)
	t.Setenv("KEYSEC_TEST_OVERRIDE", "old")
	ta.store.m["keysec\x00override.key"] = "new"

	rc := ta.run(t, "run", "--env", "KEYSEC_TEST_OVERRIDE=override.key", "--", "bash", "-c", "echo $KEYSEC_TEST_OVERRIDE")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "new" {
		t.Errorf("stdout = %q, want 'new' (injected should override parent env)", got)
	}
}

func TestRunJsonFlagNotIntercepted(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00tok"] = "val"

	// --json after the child command should be passed to the child, not
	// consumed by keysec's splitJSON (run is dispatched before splitJSON).
	rc := ta.run(t, "run", "--env", "TOKEN=tok", "--", "bash", "-c", "echo $TOKEN --json")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "val --json" {
		t.Errorf("stdout = %q, want 'val --json'", got)
	}
}

func TestRunStdinForwarded(t *testing.T) {
	ta := newTestApp(t)
	ta.app.stdin = strings.NewReader("piped-data")

	rc := ta.run(t, "run", "--", "cat")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := ta.stdout.String(); got != "piped-data" {
		t.Errorf("stdout = %q, want 'piped-data'", got)
	}
}

// --- run hardening: wildcards, handoff log, masking ---

func TestRunWildcardRefused(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00tok"] = "v"

	for _, bad := range []string{"*", "TOKEN=*", "TOKEN=prod_*", "TOKEN=?"} {
		rc := ta.run(t, "run", "--env", bad, "--", "echo", "hi")
		if rc != 2 {
			t.Errorf("--env %q exit = %d, want 2 (usage)", bad, rc)
		}
		if ta.stdout.Len() != 0 {
			t.Errorf("--env %q: stdout should be empty, got %q", bad, ta.stdout.String())
		}
	}
}

func TestRunRecordsHandoff(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00mytoken"] = "s3cret"
	ta.store.m["keysec\x00other"] = "o2"

	rc := ta.run(t, "run",
		"--env", "TOKEN=mytoken",
		"--env", "ALT=other",
		"--", "bash", "-c", "echo $TOKEN $ALT")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}

	raw, ok := ta.store.m["keysec\x00.runlog"]
	if !ok {
		t.Fatal("expected a .runlog entry in the store")
	}
	var log runlog.Log
	if err := json.Unmarshal([]byte(raw), &log); err != nil {
		t.Fatalf("stored run log is not JSON: %v", err)
	}
	if log.Seq != 1 || len(log.Entries) != 1 {
		t.Fatalf("log = %+v, want one entry", log)
	}
	e := log.Entries[0]
	if e.Cmd != "bash -c echo $TOKEN $ALT" {
		t.Errorf("cmd = %q", e.Cmd)
	}
	if len(e.Env) != 2 || e.Env[0] != "mytoken" || e.Env[1] != "other" {
		t.Errorf("logged keys = %v, want sorted [mytoken other]", e.Env)
	}
}

func TestRunRecordsHandoffDedupesKeys(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00tok"] = "v"

	rc := ta.run(t, "run", "--env", "A=tok", "--env", "B=tok", "--", "echo", "hi")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	raw := ta.store.m["keysec\x00.runlog"]
	var log runlog.Log
	if err := json.Unmarshal([]byte(raw), &log); err != nil {
		t.Fatalf("stored run log is not JSON: %v", err)
	}
	if len(log.Entries) != 1 || len(log.Entries[0].Env) != 1 || log.Entries[0].Env[0] != "tok" {
		t.Errorf("expected one unique key tok, got %+v", log.Entries)
	}
}

func TestRunNoEnvLeavesNoTrace(t *testing.T) {
	ta := newTestApp(t)
	rc := ta.run(t, "run", "--", "echo", "hi")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	if _, ok := ta.store.m["keysec\x00.runlog"]; ok {
		t.Error("a run with no secrets should not be logged")
	}
}

func TestRunAppendsChainedEntries(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00tok"] = "v"

	for i := 0; i < 3; i++ {
		if rc := ta.run(t, "run", "--env", "TOKEN=tok", "--", "echo", "hi"); rc != 0 {
			t.Fatalf("run %d exit = %d", i, rc)
		}
	}
	var log runlog.Log
	if err := json.Unmarshal([]byte(ta.store.m["keysec\x00.runlog"]), &log); err != nil {
		t.Fatalf("stored run log is not JSON: %v", err)
	}
	if len(log.Entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(log.Entries))
	}
	for i := 1; i < 3; i++ {
		if log.Entries[i].Prev != log.Entries[i-1].Sha {
			t.Errorf("entry %d does not chain to entry %d", i, i-1)
		}
	}
}

func TestRunAbortsWhenLogWriteFails(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00tok"] = "v"
	ta.store.putErr = keychain.ErrLocked

	rc := ta.run(t, "run", "--env", "TOKEN=tok", "--", "bash", "-c", "echo SHOULD_NOT_RUN")
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if strings.Contains(ta.stdout.String(), "SHOULD_NOT_RUN") {
		t.Error("child ran despite the log write failing")
	}
	if !strings.Contains(strings.ToLower(ta.stderr.String()), "lock") {
		t.Errorf("stderr should mention a locked keychain, got %q", ta.stderr.String())
	}
}

func TestRunMask(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00mytoken"] = "s3cret-tok"

	rc := ta.run(t, "run", "--mask", "--env", "TOKEN=mytoken", "--", "bash", "-c", "echo $TOKEN")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", rc, ta.stderr.String())
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "***" {
		t.Errorf("stdout = %q, want '***' (secret must not leak)", got)
	}
}

func TestRunMaskOffLeaksAsBefore(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00mytoken"] = "s3cret-tok"

	rc := ta.run(t, "run", "--env", "TOKEN=mytoken", "--", "bash", "-c", "echo $TOKEN")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	if got := strings.TrimSpace(ta.stdout.String()); got != "s3cret-tok" {
		t.Errorf("stdout = %q, want the raw secret (mask is opt-in)", got)
	}
}

func TestRunMaskScrubsBothStreams(t *testing.T) {
	ta := newTestApp(t)
	ta.store.m["keysec\x00mytoken"] = "s3cret-tok"

	rc := ta.run(t, "run", "--mask", "--env", "TOKEN=mytoken", "--",
		"bash", "-c", "echo out:$TOKEN; echo err:$TOKEN >&2")
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	if strings.Contains(ta.stdout.String(), "s3cret-tok") || strings.Contains(ta.stderr.String(), "s3cret-tok") {
		t.Errorf("secret leaked: stdout=%q stderr=%q", ta.stdout.String(), ta.stderr.String())
	}
	if !strings.Contains(ta.stdout.String(), "***") || !strings.Contains(ta.stderr.String(), "***") {
		t.Errorf("marker missing: stdout=%q stderr=%q", ta.stdout.String(), ta.stderr.String())
	}
}
