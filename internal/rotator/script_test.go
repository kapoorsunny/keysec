package rotator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScriptInlineLenient(t *testing.T) {
	r, _ := New(&Spec{Kind: KindScript, Interpreter: "/bin/sh", Body: `printf '%s' "$KEYSEC_VALUE"-NEW`})
	res, err := r.Rotate(context.Background(), Input{Key: "k", Value: "old"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "old-NEW" {
		t.Errorf("value = %q, want old-NEW", res.Value)
	}
}

func TestScriptJSONContract(t *testing.T) {
	r, _ := New(&Spec{Kind: KindScript, Interpreter: "/bin/sh", Body: `printf '%s' '{"value":"bound","expires_at":"2030-01-01T00:00:00Z","old_valid_until":"2026-12-31T00:00:00Z"}'`})
	res, err := r.Rotate(context.Background(), Input{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "bound" {
		t.Errorf("value = %q", res.Value)
	}
	if res.ExpiresAt == nil || res.ExpiresAt.Year() != 2030 {
		t.Errorf("expiresAt = %v, want 2030", res.ExpiresAt)
	}
	if res.OldValidUntil == nil || res.OldValidUntil.Year() != 2026 {
		t.Errorf("oldValidUntil = %v, want 2026", res.OldValidUntil)
	}
}

func TestScriptEnvironments(t *testing.T) {
	r, _ := New(&Spec{Kind: KindScript, Interpreter: "/bin/sh",
		Body: `printf '%s=%s' "$KEYSEC_KEY" "$KEYSEC_META_ENDPOINT"`})
	res, err := r.Rotate(context.Background(), Input{
		Key:  "db.password",
		Meta: map[string]string{"endpoint": "prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "db.password=prod" {
		t.Errorf("value = %q", res.Value)
	}
}

func TestScriptFile(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "rotate.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' FILE-$KEYSEC_VALUE\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, _ := New(&Spec{Kind: KindScript, Script: script})
	res, err := r.Rotate(context.Background(), Input{Value: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "FILE-v" {
		t.Errorf("value = %q", res.Value)
	}
}

func TestScriptNonZeroExit(t *testing.T) {
	r, _ := New(&Spec{Kind: KindScript, Interpreter: "/bin/sh", Body: `echo oops >&2; exit 3`})
	_, err := r.Rotate(context.Background(), Input{})
	if err == nil {
		t.Fatal("expected error for failing script")
	}
	if !strings.Contains(err.Error(), "oops") {
		t.Errorf("err = %v, want stderr snippet", err)
	}
}

func TestScriptTimeout(t *testing.T) {
	r, _ := New(&Spec{Kind: KindScript, Interpreter: "/bin/sh", Timeout: "50ms", Body: `sleep 10`})
	start := time.Now()
	_, err := r.Rotate(context.Background(), Input{})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want timeout", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("timeout took too long: %s", time.Since(start))
	}
}

func TestScriptEmptyOutput(t *testing.T) {
	r, _ := New(&Spec{Kind: KindScript, Interpreter: "/bin/sh", Body: `:`})
	if _, err := r.Rotate(context.Background(), Input{}); err == nil {
		t.Fatal("empty output should error")
	}
}

// TestParseScriptOutputHoldsJSONToTheContract: a script that correctly
// reports it got nothing used to fall through to the lenient branch,
// storing the JSON text itself over the live credential.
func TestParseScriptOutputHoldsJSONToTheContract(t *testing.T) {
	for _, out := range []string{`{"value":""}`, `{"old_valid_until":"2030-01-01"}`, `{"meta":{}}`} {
		res, err := parseScriptOutput(out)
		if err == nil {
			t.Errorf("parseScriptOutput(%s) = %q, want an error", out, res.Value)
		}
	}
	// A JSON object that is not the contract is still a plain value.
	res, err := parseScriptOutput(`{"unrelated":1}`)
	if err != nil || res.Value != `{"unrelated":1}` {
		t.Errorf("non-contract JSON should pass through: %q, %v", res.Value, err)
	}
	res, err = parseScriptOutput(`{"value":"tok","expires_at":"2030-01-01"}`)
	if err != nil || res.Value != "tok" || res.ExpiresAt == nil {
		t.Errorf("contract JSON: %+v, %v", res, err)
	}
}
