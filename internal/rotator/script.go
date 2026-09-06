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

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
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
func parseScriptOutput(out string) (Result, error) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return Result{}, errf("script produced no output")
	}
	var sr scriptResult
	if json.Unmarshal([]byte(trimmed), &sr) == nil && (sr.Value != "" || sr.ExpiresAt != "" || sr.Meta != nil) {
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
	// Lenient fallback: whole trimmed stdout is the new value.
	return Result{Value: trimmed}, nil
}
