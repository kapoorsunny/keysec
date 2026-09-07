package rotator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// scriptRotator rotates a secret by running an interpreter (inline body)
// or a script file. Secrets travel by environment only: KEYSEC_KEY,
// KEYSEC_VALUE and KEYSEC_META_<NAME>.
type scriptRotator struct {
	spec *Spec
}

func (s *scriptRotator) Rotate(ctx context.Context, in Input) (Result, error) {
	spec := s.spec
	timeout := parseDurationOrDefault(spec.Timeout, defaultTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	interpreter := spec.Interpreter
	if interpreter == "" {
		interpreter = "bash"
	}
	var cmd *exec.Cmd
	var stdin *bytes.Buffer
	switch {
	case spec.Body != "":
		// Inline body: pipe the script to the interpreter, which it
		// reads from stdin and runs with the rotate action as $1.
		cmd = exec.CommandContext(ctx, interpreter, "-s", "rotate")
		stdin = bytes.NewBufferString(spec.Body)
	default:
		if spec.Script == "" {
			return Result{}, errf("script rotator needs a script or a body")
		}
		cmd = exec.CommandContext(ctx, spec.Script, "rotate")
	}

	env := []string{
		"KEYSEC_KEY=" + in.Key,
		"KEYSEC_VALUE=" + in.Value,
	}
	for k, v := range in.Meta {
		env = append(env, "KEYSEC_META_"+EnvMetaName(k)+"="+v)
	}
	cmd.Env = append(os.Environ(), env...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	// Run the script in its own process group so a timeout can reap
	// child processes too; otherwise a foreground child keeps the
	// stdout/stderr pipes open and Run hangs well past the deadline.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start in this goroutine so cmd.Process is set before the timeout
	// branch below can read it: Run() would assign it from the watcher
	// goroutine, racing the kill and sometimes skipping it entirely.
	if err := cmd.Start(); err != nil {
		return Result{}, errf("script failed to start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return parseScriptOutput(stdout.String())
		}
		detail := ""
		if stderr.Len() > 0 {
			detail = ": " + snippet(stderr.String(), 200)
		}
		return Result{}, errf("script failed%s", detail)
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{}, errf("script timed out after %s", timeout)
		}
		return Result{}, errf("script was cancelled")
	}
}

// scriptResult mirrors the JSON contract a script may emit on stdout.
type scriptResult struct {
	Value         string            `json:"value"`
	ExpiresAt     string            `json:"expires_at"`
	OldValidUntil string            `json:"old_valid_until"`
	Meta          map[string]string `json:"meta"`
}

// parseScriptOutput reads the lenient script contract: a JSON object
// with a "value" field (plus optional expiry/meta), or, failing that,
// the trimmed stdout as the new value.
//
// A reply that is recognisably the JSON contract is held to it. Judging
// that by whether a field came back non-empty would let {"value": ""} —
// a script correctly reporting it got nothing — fall through to the
// lenient branch and store the JSON text itself over the live secret.
func parseScriptOutput(out string) (Result, error) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return Result{}, errf("script produced no output")
	}
	if !isContractJSON(trimmed) {
		// Lenient fallback: whole trimmed stdout is the new value.
		return Result{Value: trimmed}, nil
	}
	var sr scriptResult
	if err := json.Unmarshal([]byte(trimmed), &sr); err != nil {
		return Result{}, errf("script JSON: %v", err)
	}
	expires, err := ParseExpiry(sr.ExpiresAt)
	if err != nil {
		return Result{}, errf("script expiry: %v", err)
	}
	old, err := ParseExpiry(sr.OldValidUntil)
	if err != nil {
		return Result{}, errf("script old_valid_until: %v", err)
	}
	if sr.Value == "" {
		return Result{}, errf("script JSON has no value")
	}
	return Result{Value: sr.Value, ExpiresAt: expires, OldValidUntil: old}, nil
}

// isContractJSON reports whether out is a JSON object carrying at least
// one field of the script contract. Anything else — including a JSON
// object that happens to be the secret itself — is treated as a raw
// value by the lenient branch.
func isContractJSON(out string) bool {
	if !strings.HasPrefix(out, "{") {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(out), &fields) != nil {
		return false
	}
	for _, name := range []string{"value", "expires_at", "old_valid_until", "meta"} {
		if _, ok := fields[name]; ok {
			return true
		}
	}
	return false
}
