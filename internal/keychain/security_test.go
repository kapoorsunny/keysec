package keychain

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// fakeRunner records calls and replays canned output, so store tests
// never touch the real Keychain.
type fakeRunner struct {
	stdout   string
	stderr   string
	err      error
	lastArgs []string
	lastIn   string
}

func (f *fakeRunner) Run(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, []byte, error) {
	f.lastArgs = append([]string{name}, args...)
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		f.lastIn = string(b)
	}
	return []byte(f.stdout), []byte(f.stderr), f.err
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestPutPipesValueTwice(t *testing.T) {
	fr := &fakeRunner{}
	s := NewWithRunner(fr)
	if err := s.Put(context.Background(), "svc", "acct", "topsecret"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !hasArg(fr.lastArgs, "-U") {
		t.Errorf("Put should upsert (-U): %v", fr.lastArgs)
	}
	if want := "topsecret\ntopsecret\n"; fr.lastIn != want {
		t.Errorf("stdin = %q, want %q (value piped, no argv leak)", fr.lastIn, want)
	}
	for _, a := range fr.lastArgs {
		if a == "topsecret" {
			t.Errorf("value leaked into argv: %v", fr.lastArgs)
		}
	}
}

func TestPutMultiLineUsesArgv(t *testing.T) {
	fr := &fakeRunner{}
	s := NewWithRunner(fr)
	if err := s.Put(context.Background(), "svc", "acct", "line1\nline2"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if fr.lastIn != "" {
		t.Errorf("multi-line value must not be piped, got stdin %q", fr.lastIn)
	}
	if !hasArg(fr.lastArgs, "line1\nline2") {
		t.Errorf("multi-line value passed via argv: %v", fr.lastArgs)
	}
}

func TestGetStripsTrailingNewline(t *testing.T) {
	fr := &fakeRunner{stdout: "the-value\n"}
	s := NewWithRunner(fr)
	got, err := s.Get(context.Background(), "svc", "acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "the-value" {
		t.Errorf("Get = %q, want %q", got, "the-value")
	}
}

// TestGetNotFoundExitCode exercises the true exit-code path: a real
// process exiting 44 (errSecItemNotFound), as the security tool does.
func TestGetNotFoundExitCode(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 44").Run()
	s := NewWithRunner(&fakeRunner{})
	if got := s.classify(nil, err); !errors.Is(got, ErrNotFound) {
		t.Errorf("classify = %v, want ErrNotFound", got)
	}
}

func TestGetNotFoundStderr(t *testing.T) {
	fr := &fakeRunner{
		stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
		err:    errors.New("exit status 44"),
	}
	s := NewWithRunner(fr)
	_, err := s.Get(context.Background(), "svc", "acct")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get err = %v, want ErrNotFound", err)
	}
}

func TestLockedKeychain(t *testing.T) {
	fr := &fakeRunner{
		stderr: "security: The keychain is locked. user interaction is not allowed\n",
		err:    errors.New("exit status 1"),
	}
	s := NewWithRunner(fr)
	for name, fn := range map[string]func() error{
		"Get":    func() error { _, e := s.Get(context.Background(), "s", "a"); return e },
		"Delete": func() error { return s.Delete(context.Background(), "s", "a") },
		"Has":    func() error { _, e := s.Has(context.Background(), "s", "a"); return e },
		"Put":    func() error { return s.Put(context.Background(), "s", "a", "v") },
	} {
		if err := fn(); !errors.Is(err, ErrLocked) {
			t.Errorf("%s err = %v, want ErrLocked", name, err)
		}
	}
}

func TestHasFound(t *testing.T) {
	fr := &fakeRunner{stdout: "keychain: ...\n"}
	s := NewWithRunner(fr)
	ok, err := s.Has(context.Background(), "s", "a")
	if err != nil || !ok {
		t.Errorf("Has = %v, %v; want true, nil", ok, err)
	}
}

func TestHasNotFound(t *testing.T) {
	fr := &fakeRunner{
		stderr: "The specified item could not be found in the keychain.\n",
		err:    errors.New("exit status 44"),
	}
	s := NewWithRunner(fr)
	ok, err := s.Has(context.Background(), "s", "a")
	if err != nil {
		t.Fatalf("Has on missing item should not error: %v", err)
	}
	if ok {
		t.Error("Has = true for missing item")
	}
}

func TestUnknownFailureKeepsDetail(t *testing.T) {
	fr := &fakeRunner{stderr: "some weird failure\nmore detail\n", err: errors.New("boom")}
	s := NewWithRunner(fr)
	err := s.Delete(context.Background(), "s", "a")
	if err == nil || !strings.Contains(err.Error(), "some weird failure") {
		t.Errorf("err = %v, want the first stderr line preserved", err)
	}
}
