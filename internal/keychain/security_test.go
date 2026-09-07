package keychain

import (
	"context"
	"encoding/hex"
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

// TestPutKeepsSecretOutOfArgv is the security property: the value must
// never reach the process arguments, where any process running as this
// user could read it out of ps.
func TestPutKeepsSecretOutOfArgv(t *testing.T) {
	fr := &fakeRunner{}
	s := NewWithRunner(fr)
	if err := s.Put(context.Background(), "keysec", "acct", "topsecret"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for _, a := range fr.lastArgs {
		if strings.Contains(a, "topsecret") {
			t.Fatalf("secret leaked into argv: %v", fr.lastArgs)
		}
	}
	if fr.lastArgs[len(fr.lastArgs)-1] != "-i" {
		t.Errorf("expected interactive mode, got args %v", fr.lastArgs)
	}
	want := "add-generic-password -U -a acct -s keysec -X " +
		hex.EncodeToString([]byte("topsecret")) + "\n"
	if fr.lastIn != want {
		t.Errorf("stdin command\n got %q\nwant %q", fr.lastIn, want)
	}
}

// TestPutHexSurvivesHostileValues covers the bytes that would otherwise
// break out of the command line. A newline used to truncate the secret
// and feed its tail to security as a second command, at exit code 0.
func TestPutHexSurvivesHostileValues(t *testing.T) {
	hostile := map[string]string{
		"newline":   "abc\nlist-keychains",
		"quote":     `a"b`,
		"backslash": `a\b`,
		"space":     "a b c",
		"unicode":   "héllo-✓",
		"nul":       "a\x00b",
	}
	for name, value := range hostile {
		t.Run(name, func(t *testing.T) {
			fr := &fakeRunner{}
			s := NewWithRunner(fr)
			if err := s.Put(context.Background(), "keysec", "acct", value); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if strings.Count(fr.lastIn, "\n") != 1 || !strings.HasSuffix(fr.lastIn, "\n") {
				t.Fatalf("value must stay on one line, got %q", fr.lastIn)
			}
			_, encoded, _ := strings.Cut(fr.lastIn, " -X ")
			got, err := hex.DecodeString(strings.TrimSuffix(encoded, "\n"))
			if err != nil {
				t.Fatalf("decoding %q: %v", encoded, err)
			}
			if string(got) != value {
				t.Errorf("round-trip: got %q want %q", got, value)
			}
		})
	}
}

// TestPutOversizeFallsBackToArgv pins the documented exception. Past
// security's 4095-byte interactive line buffer the tail is silently
// reinterpreted as a command, so keysec measures the line and takes the
// argv path instead of corrupting the secret.
func TestPutOversizeFallsBackToArgv(t *testing.T) {
	fits := strings.Repeat("x", 2020)
	fr := &fakeRunner{}
	s := NewWithRunner(fr)
	if err := s.Put(context.Background(), "keysec", "acct", fits); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if fr.lastIn == "" {
		t.Errorf("a %d-byte value should still fit the interactive line", len(fits))
	}
	if len(fr.lastIn) > interactiveLineMax {
		t.Errorf("line is %d bytes, over the %d limit", len(fr.lastIn), interactiveLineMax)
	}

	big := strings.Repeat("x", 4000)
	fr2 := &fakeRunner{}
	s2 := NewWithRunner(fr2)
	if err := s2.Put(context.Background(), "keysec", "acct", big); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if fr2.lastIn != "" {
		t.Errorf("oversize value must not go through the interactive line")
	}
	if !hasArg(fr2.lastArgs, "-w") || !hasArg(fr2.lastArgs, big) {
		t.Errorf("oversize value should fall back to argv: %v", fr2.lastArgs)
	}
}

// TestPutRejectsUnsafeCoordinates guards the half of the line hex does
// not cover: service and account sit there unquoted.
func TestPutRejectsUnsafeCoordinates(t *testing.T) {
	for _, c := range []struct{ service, account string }{
		{"keysec", "acct with space"},
		{"keysec", `acct"quote`},
		{"keysec", "acct\nadd-generic-password"},
		{"svc space", "acct"},
	} {
		fr := &fakeRunner{}
		s := NewWithRunner(fr)
		if err := s.Put(context.Background(), c.service, c.account, "secret"); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if fr.lastIn != "" {
			t.Errorf("unsafe coordinates %q/%q must not build a command line, got %q",
				c.service, c.account, fr.lastIn)
		}
	}
}

// TestPlainTokenAcceptsRealAccounts keeps the fast path actually fast:
// every account keysec really writes must qualify.
func TestPlainTokenAcceptsRealAccounts(t *testing.T) {
	for _, acct := range []string{"mytoken", "gitlab.api_token", "foo.rotator", ".runlog",
		"git.gitlab.example.com.root.keysec", "a-b_c.d"} {
		if !plainToken(acct) {
			t.Errorf("plainToken(%q) = false, want true", acct)
		}
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

func TestUnrelatedLockedWordIsNotKeychainLocked(t *testing.T) {
	fr := &fakeRunner{
		stderr: "the database file is locked by another process\n",
		err:    errors.New("exit status 1"),
	}
	s := NewWithRunner(fr)
	_, err := s.Get(context.Background(), "s", "a")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrLocked) {
		t.Errorf("err = %v, an unrelated 'locked' word must not read as a locked keychain", err)
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

// scriptRunner replays a different canned reply per security subcommand,
// so a Get that falls back to "-g" can be exercised.
type scriptRunner struct {
	wOut  string // stdout for "find-generic-password ... -w"
	gErr  string // stderr for "find-generic-password ... -g"
	calls int
}

func (s *scriptRunner) Run(_ context.Context, _ io.Reader, _ string, args ...string) ([]byte, []byte, error) {
	s.calls++
	if hasArg(args, "-g") {
		return nil, []byte(s.gErr), nil
	}
	return []byte(s.wOut), nil, nil
}

// TestGetDecodesHexReadback: "find-generic-password -w" prints a value
// containing non-ASCII bytes as bare hex digits, so those secrets came
// back as unusable hex. "-g" marks genuine hex with an 0x prefix.
func TestGetDecodesHexReadback(t *testing.T) {
	const want = "unicode-é-✓"
	sr := &scriptRunner{
		wOut: hex.EncodeToString([]byte(want)) + "\n",
		gErr: `password: 0x` + strings.ToUpper(hex.EncodeToString([]byte(want))) + `  "unicode-\303\251-\342\234\223"` + "\n",
	}
	got, err := NewWithRunner(sr).Get(context.Background(), "keysec", "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != want {
		t.Errorf("Get = %q, want %q", got, want)
	}
}

// TestGetKeepsHexLookingPlainValue: a secret that is genuinely the text
// "61626364" is printable, so -g reports it quoted and it must come
// back unchanged rather than being decoded into "abcd".
func TestGetKeepsHexLookingPlainValue(t *testing.T) {
	sr := &scriptRunner{wOut: "61626364\n", gErr: "password: \"61626364\"\n"}
	got, err := NewWithRunner(sr).Get(context.Background(), "keysec", "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "61626364" {
		t.Errorf("Get = %q, want the literal value", got)
	}
}

// TestGetOrdinaryValueSkipsSecondCall keeps the common path at one
// subprocess: only an ambiguous, hex-looking reply consults -g.
func TestGetOrdinaryValueSkipsSecondCall(t *testing.T) {
	sr := &scriptRunner{wOut: "ghp_notHexAtAll\n"}
	got, err := NewWithRunner(sr).Get(context.Background(), "keysec", "k")
	if err != nil || got != "ghp_notHexAtAll" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if sr.calls != 1 {
		t.Errorf("made %d calls, want 1", sr.calls)
	}
}
