package cmd

import (
	"strings"
	"testing"
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
