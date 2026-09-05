package keychain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Runner executes external commands. It is an interface so tests can
// substitute a fake without touching the Keychain.
type Runner interface {
	// Run starts name with args, wiring stdin if non-nil, and
	// returns the captured output and any error from the process.
	Run(ctx context.Context, stdin io.Reader, name string, args ...string) (stdout, stderr []byte, err error)
}

// Security is a Store backed by the macOS Keychain, driven through the
// system "security" CLI so it works from shells, launchd jobs and git.
type Security struct {
	binary string
	run    Runner
}

// New returns a Security store using the system security tool.
func New() *Security {
	return &Security{binary: "/usr/bin/security", run: systemRunner{}}
}

// NewWithRunner returns a Security store driven by the given Runner
// (used by tests).
func NewWithRunner(run Runner) *Security {
	return &Security{binary: "security", run: run}
}

type systemRunner struct{}

func (systemRunner) Run(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// devNullReader never supplies input, so the security tool can never
// prompt the user mid-operation. A locked keychain therefore fails
// deterministically and we can tell the user the next step.
type devNullReader struct{}

func (devNullReader) Read(p []byte) (int, error) { return 0, io.EOF }

// Put saves value under (service, account), replacing any existing item.
//
// The security CLI asks for the password and then retypes it, reading
// both from stdin when stdin is not a terminal. So the value is piped
// in twice. Values containing newlines cannot survive that line-based
// exchange and are passed as an argument instead.
func (s *Security) Put(ctx context.Context, service, account, value string) error {
	args := []string{"add-generic-password", "-U", "-a", account, "-s", service}
	var stdin io.Reader
	if strings.Contains(value, "\n") {
		args = append(args, "-w", value)
	} else {
		args = append(args, "-w")
		stdin = strings.NewReader(value + "\n" + value + "\n")
	}
	_, stderr, err := s.run.Run(ctx, stdin, s.binary, args...)
	if err != nil {
		return s.classify(stderr, err)
	}
	return nil
}

// Get returns the value stored under (service, account).
func (s *Security) Get(ctx context.Context, service, account string) (string, error) {
	stdout, stderr, err := s.run.Run(ctx, devNullReader{}, s.binary,
		"find-generic-password", "-a", account, "-s", service, "-w")
	if err != nil {
		return "", s.classify(stderr, err)
	}
	return strings.TrimSuffix(string(stdout), "\n"), nil
}

// Delete removes the secret at (service, account).
func (s *Security) Delete(ctx context.Context, service, account string) error {
	_, stderr, err := s.run.Run(ctx, devNullReader{}, s.binary,
		"delete-generic-password", "-a", account, "-s", service)
	if err != nil {
		return s.classify(stderr, err)
	}
	return nil
}

// Has reports whether a secret exists at (service, account).
func (s *Security) Has(ctx context.Context, service, account string) (bool, error) {
	_, stderr, err := s.run.Run(ctx, devNullReader{}, s.binary,
		"find-generic-password", "-a", account, "-s", service)
	if err == nil {
		return true, nil
	}
	if errors.Is(s.classify(stderr, err), ErrNotFound) {
		return false, nil
	}
	return false, s.classify(stderr, err)
}

// classify maps security CLI failures onto Store sentinels so callers
// can produce friendly, specific messages.
func (s *Security) classify(stderr []byte, err error) error {
	msg := strings.ToLower(string(stderr))
	if strings.Contains(msg, "interaction is not allowed") ||
		strings.Contains(msg, "locked") {
		return ErrLocked
	}
	if isNotFound(err, msg) {
		return ErrNotFound
	}
	detail := strings.TrimSpace(string(stderr))
	if detail == "" {
		detail = err.Error()
	}
	return fmt.Errorf("keychain access failed: %s", firstLine(detail))
}

// isNotFound matches the security CLI's not-found signal: exit status
// 44 (errSecItemNotFound) or its stderr wording.
func isNotFound(err error, lowerStderr string) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
		return true
	}
	return strings.Contains(lowerStderr, "unable to find") ||
		strings.Contains(lowerStderr, "could not be found") ||
		strings.Contains(lowerStderr, "no such item")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
