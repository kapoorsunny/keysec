package keychain

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/kapoorsunny/keysec/internal/key"
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

// interactiveLineMax is the largest input line security(1) accepts in
// interactive mode: 4095 bytes including the newline, measured against
// the whole line rather than the value (a longer service or account
// leaves room for a correspondingly shorter secret). Overflow is not
// reliably an error — the tail is parsed as a second command and the
// stored secret is silently truncated, sometimes still exiting 0 — so
// keysec measures the line itself instead of trusting the exit code.
const interactiveLineMax = 4095

// Put saves value under (service, account), replacing any existing item.
//
// The secret is handed over on stdin, never in argv: security(1) reads
// commands from stdin in interactive mode (-i), so the process this
// spawns is visible in ps only as "security -i". The value rides in
// hex (-X), which needs no quoting — no secret, whatever bytes it
// contains, can end the line or be read as a second command.
//
// Values too large for the interactive line buffer fall back to the
// "-w <value>" argument, which is bounded only by ARG_MAX. That path
// is briefly visible in ps to processes running as this user, so it is
// the exception, not the rule: it takes a value over ~2KB, which in
// practice means the run log or a rotator spec — documents that hold
// key names and configuration, never a credential.
func (s *Security) Put(ctx context.Context, service, account, value string) error {
	if line, ok := interactiveAdd(service, account, value); ok {
		_, stderr, err := s.run.Run(ctx, strings.NewReader(line), s.binary, "-i")
		if err != nil {
			return s.classify(stderr, err)
		}
		return nil
	}
	args := []string{"add-generic-password", "-U", "-a", account, "-s", service, "-w", value}
	_, stderr, err := s.run.Run(ctx, nil, s.binary, args...)
	if err != nil {
		return s.classify(stderr, err)
	}
	return nil
}

// interactiveAdd builds the one interactive-mode command that stores
// value with the secret hex-encoded. ok is false when the line would
// overflow security's buffer, or when the coordinates are not plain
// tokens — hex protects the value, but the service and account sit on
// the same line unquoted. Callers fall back to argv.
func interactiveAdd(service, account, value string) (string, bool) {
	if value == "" || !plainToken(service) || !plainToken(account) {
		return "", false
	}
	line := "add-generic-password -U -a " + account + " -s " + service +
		" -X " + hex.EncodeToString([]byte(value)) + "\n"
	if len(line) > interactiveLineMax {
		return "", false
	}
	return line, true
}

// plainToken reports whether s can sit bare on a security(1) command
// line. It is keysec's own key alphabet plus a leading dot for the
// reserved overlay accounts, so there is nothing for the tokenizer to
// interpret: no spaces, quotes, backslashes or newlines.
func plainToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// Get returns the value stored under (service, account).
//
// "find-generic-password -w" prints the value raw when it is printable
// ASCII and as a bare hex string otherwise, with nothing to tell the two
// apart — so a secret holding a tab, a newline or any non-ASCII byte came
// back as unusable hex digits. When the output could be either, "-g" is
// asked to settle it: that form prefixes genuinely hex-encoded data with
// "0x", so the ambiguity disappears.
func (s *Security) Get(ctx context.Context, service, account string) (string, error) {
	stdout, stderr, err := s.run.Run(ctx, devNullReader{}, s.binary,
		"find-generic-password", "-a", account, "-s", service, "-w")
	if err != nil {
		return "", s.classify(stderr, err)
	}
	out := strings.TrimSuffix(string(stdout), "\n")
	if !looksHexEncoded(out) {
		return out, nil
	}
	if decoded, ok := s.getViaDisplay(ctx, service, account); ok {
		return decoded, nil
	}
	return out, nil
}

// getViaDisplay reads the value through "-g", which reports non-ASCII
// data as `password: 0x<HEX>  "..."` and printable data as
// `password: "<value>"`, on stderr. ok is false if the reply cannot be
// parsed, leaving the caller with the "-w" text it already has.
func (s *Security) getViaDisplay(ctx context.Context, service, account string) (string, bool) {
	_, stderr, err := s.run.Run(ctx, devNullReader{}, s.binary,
		"find-generic-password", "-a", account, "-s", service, "-g")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(stderr), "\n") {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), "password: ")
		if !found {
			continue
		}
		if hexPart, isHex := strings.CutPrefix(rest, "0x"); isHex {
			hexPart, _, _ = strings.Cut(hexPart, " ")
			raw, err := hex.DecodeString(hexPart)
			if err != nil {
				return "", false
			}
			return string(raw), true
		}
		// Printable value, printed quoted. Any quote inside is not
		// escaped, so the value runs to the last quote on the line.
		if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
			return rest[1 : len(rest)-1], true
		}
		return "", false
	}
	return "", false
}

// looksHexEncoded reports whether s could be security(1)'s hex rendering
// of a non-printable value: an even number of hex digits. Such a value
// might equally be a secret that is itself hex, so it only signals that
// the reading is ambiguous, not that it is encoded.
func looksHexEncoded(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
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

// List enumerates every keysec item in the default keychains. It speaks
// the same security CLI as the rest of the Store, parsing
// dump-keychain output (values are withheld by macOS, so nothing secret
// leaves the Keychain). It returns ErrDumpFormat if the dump existed
// but could not be parsed, rather than silently reporting an empty list.
func (s *Security) List(ctx context.Context) ([]Entry, error) {
	stdout, stderr, err := s.run.Run(ctx, devNullReader{}, s.binary, "dump-keychain")
	if err != nil {
		return nil, s.classify(stderr, err)
	}
	all, err := ParseDump(stdout)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(all))
	for _, e := range all {
		if e.Service == key.ReservedService {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// classify maps security CLI failures onto Store sentinels so callers
// can produce friendly, specific messages.
func (s *Security) classify(stderr []byte, err error) error {
	msg := strings.ToLower(string(stderr))
	// "locked" alone is too broad (a filesystem can report it too); a
	// locked keychain always names the keychain in the same message.
	if strings.Contains(msg, "interaction is not allowed") ||
		(strings.Contains(msg, "keychain") && strings.Contains(msg, "locked")) {
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
