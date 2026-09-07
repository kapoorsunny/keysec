package runlog

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kapoorsunny/keysec/internal/key"
	"github.com/kapoorsunny/keysec/internal/keychain"
)

func svcKey() string        { return key.ReservedService + "\x00" + key.ReservedRunLog }
func macKeyAccount() string { return key.ReservedService + "\x00" + key.ReservedRunLogKey }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// stub is a minimal ReadWriter backed by a map.
type stub struct {
	m      map[string]string
	delErr error
}

func (s *stub) Get(_ context.Context, service, account string) (string, error) {
	v, ok := s.m[service+"\x00"+account]
	if !ok {
		return "", keychain.ErrNotFound
	}
	return v, nil
}
func (s *stub) Put(_ context.Context, service, account, value string) error {
	s.m[service+"\x00"+account] = value
	return nil
}
func (s *stub) Delete(_ context.Context, service, account string) error {
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.m, service+"\x00"+account)
	return nil
}

func TestAppendSingleEntry(t *testing.T) {
	s := &stub{m: map[string]string{}}
	e, err := Append(context.Background(), s, "echo hi", []string{"mytoken"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e.Seq != 1 || e.At == "" || e.Prev != "" || e.Sha == "" {
		t.Errorf("entry = %+v", e)
	}
	if len(e.Env) != 1 || e.Env[0] != "mytoken" {
		t.Errorf("env = %v", e.Env)
	}
	entries, tampered, err := Load(context.Background(), s)
	if err != nil || tampered {
		t.Fatalf("Load: err=%v tampered=%v", err, tampered)
	}
	if len(entries) != 1 || entries[0].Sha != e.Sha {
		t.Errorf("stored entries = %+v", entries)
	}
}

func TestAppendChainsEntries(t *testing.T) {
	s := &stub{m: map[string]string{}}
	first, _ := Append(context.Background(), s, "cmd one", []string{"a"})
	second, _ := Append(context.Background(), s, "cmd two", []string{"b", "a"})

	if second.Seq != 2 {
		t.Errorf("second seq = %d, want 2", second.Seq)
	}
	if second.Prev != first.Sha {
		t.Errorf("second.Prev = %q, want first.Sha %q", second.Prev, first.Sha)
	}
	if len(second.Env) != 2 || second.Env[0] != "a" || second.Env[1] != "b" {
		t.Errorf("env not deduped/sorted = %v", second.Env)
	}
	entries, tampered, err := Load(context.Background(), s)
	if err != nil || tampered {
		t.Fatalf("Load: err=%v tampered=%v", err, tampered)
	}
	if len(entries) != 2 {
		t.Errorf("want 2 entries, got %d", len(entries))
	}
}

func TestLoadEmpty(t *testing.T) {
	s := &stub{m: map[string]string{}}
	entries, tampered, err := Load(context.Background(), s)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tampered || len(entries) != 0 {
		t.Errorf("empty log = entries=%d tampered=%v", len(entries), tampered)
	}
}

func TestAppendRepeatedEnvDedupes(t *testing.T) {
	s := &stub{m: map[string]string{}}
	e, _ := Append(context.Background(), s, "cmd", []string{"tok", "tok", "other"})
	if len(e.Env) != 2 || e.Env[0] != "other" || e.Env[1] != "tok" {
		t.Errorf("env = %v, want sorted unique [other tok]", e.Env)
	}
}

func TestAppendDetectsTamperedChain(t *testing.T) {
	s := &stub{m: map[string]string{}}
	Append(context.Background(), s, "cmd one", []string{"a"})
	Append(context.Background(), s, "cmd two", []string{"b"})

	raw := s.m["keysec\x00.runlog"]
	s.m["keysec\x00.runlog"] = strings.Replace(raw, "cmd one", "cmd ONE", 1)

	entries, tampered, err := Load(context.Background(), s)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !tampered {
		t.Fatal("tampered chain not detected")
	}
	if len(entries) != 2 {
		t.Errorf("tampered view should still expose entries, got %d", len(entries))
	}
}

func TestAppendRefusesTampered(t *testing.T) {
	s := &stub{m: map[string]string{}}
	Append(context.Background(), s, "cmd one", []string{"a"})
	raw := s.m["keysec\x00.runlog"]
	s.m["keysec\x00.runlog"] = strings.Replace(raw, "cmd one", "cmd ONE", 1)

	_, err := Append(context.Background(), s, "more", []string{"c"})
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestLoadCorruptDocument(t *testing.T) {
	s := &stub{m: map[string]string{"keysec\x00.runlog": "not-json"}}
	_, _, err := Load(context.Background(), s)
	if err == nil {
		t.Fatal("corrupt document should error, not report an empty log")
	}
}

func TestPruneRebasesChain(t *testing.T) {
	old := maxEntries
	maxEntries = 3
	defer func() { maxEntries = old }()

	s := &stub{m: map[string]string{}}
	for i := 0; i < 5; i++ {
		if _, err := Append(context.Background(), s, "cmd", []string{"k"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	entries, tampered, err := Load(context.Background(), s)
	if err != nil || tampered {
		t.Fatalf("Load: err=%v tampered=%v", err, tampered)
	}
	if len(entries) != 3 {
		t.Errorf("want 3 entries after prune, got %d", len(entries))
	}
	if entries[0].Prev != "" {
		t.Errorf("re-based head Prev = %q, want empty", entries[0].Prev)
	}
	if entries[0].Seq != 1 {
		t.Errorf("re-based head Seq = %d, want 1 (renumbered head)", entries[0].Seq)
	}
}

func TestResetClearsLog(t *testing.T) {
	s := &stub{m: map[string]string{}}
	Append(context.Background(), s, "cmd one", []string{"a"})
	Append(context.Background(), s, "cmd two", []string{"b"})

	if err := Reset(context.Background(), s); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	entries, tampered, err := Load(context.Background(), s)
	if err != nil || tampered || len(entries) != 0 {
		t.Errorf("after reset: entries=%d tampered=%v err=%v", len(entries), tampered, err)
	}
}

func TestResetIdempotentWhenAbsent(t *testing.T) {
	s := &stub{m: map[string]string{}}
	if err := Reset(context.Background(), s); err != nil {
		t.Fatalf("Reset on an absent log should be a no-op, got %v", err)
	}
}

func TestResetPropagatesStoreFailure(t *testing.T) {
	s := &stub{m: map[string]string{}, delErr: keychain.ErrLocked}
	if err := Reset(context.Background(), s); !errors.Is(err, keychain.ErrLocked) {
		t.Fatalf("Reset = %v, want the store's failure", err)
	}
}

// TestFieldFramingIsUnambiguous is the collision that let the record of
// which secrets a run received be rewritten in place: with a bare "|"
// separator, moving a key name from env onto the end of cmd produced an
// identical seal.
func TestFieldFramingIsUnambiguous(t *testing.T) {
	mac := []byte("test-key")
	withEnv := hashEntryV2(mac, "", 1, "T", "deploy.sh", []string{"prod_token"})
	inCmd := hashEntryV2(mac, "", 1, "T", "deploy.sh|prod_token", nil)
	if withEnv == inCmd {
		t.Error("distinct entries must not seal identically")
	}
	if hashEntryV1("", 1, "T", "deploy.sh", []string{"prod_token"}) !=
		hashEntryV1("", 1, "T", "deploy.sh|prod_token", nil) {
		t.Error("v1 collision expected; this test no longer proves anything")
	}
}

// TestSealIsKeyed shows a rewritten log can no longer be re-sealed from
// the document alone, which was the whole weakness of the plain digest.
func TestSealIsKeyed(t *testing.T) {
	a := hashEntryV2([]byte("key-one"), "", 1, "T", "cmd", []string{"k"})
	b := hashEntryV2([]byte("key-two"), "", 1, "T", "cmd", []string{"k"})
	if a == b {
		t.Error("seal must depend on the MAC key")
	}
}

// TestLegacyV1LogStillVerifies protects the upgrade: a log written by
// the previous keysec must not be reported as tampered, which would
// block every subsequent run.
func TestLegacyV1LogStillVerifies(t *testing.T) {
	e := Entry{Seq: 1, At: "2026-01-01T00:00:00Z", Cmd: "deploy.sh", Env: []string{"tok"}}
	e.Sha = hashEntryV1(e.Prev, e.Seq, e.At, e.Cmd, e.Env)
	s := &stub{m: map[string]string{}}
	// Version omitted, exactly as v1 wrote it.
	s.m[svcKey()] = `{"seq":1,"entries":[` + mustJSON(e) + `]}`

	entries, tampered, err := Load(context.Background(), s)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tampered {
		t.Fatal("an honest v1 log must not read as tampered")
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	// Appending re-seals the whole chain under v2 and keeps the history.
	if _, err := Append(context.Background(), s, "next.sh", []string{"tok2"}); err != nil {
		t.Fatalf("Append onto a v1 log: %v", err)
	}
	entries, tampered, err = Load(context.Background(), s)
	if err != nil || tampered {
		t.Fatalf("after upgrade: tampered=%v err=%v", tampered, err)
	}
	if len(entries) != 2 || entries[0].Cmd != "deploy.sh" {
		t.Errorf("upgrade lost history: %+v", entries)
	}
}

// TestMissingMACKeyReadsAsTampered: a sealed log whose key was removed
// cannot be proven honest, so it must not be trusted.
func TestMissingMACKeyReadsAsTampered(t *testing.T) {
	s := &stub{m: map[string]string{}}
	if _, err := Append(context.Background(), s, "deploy.sh", []string{"tok"}); err != nil {
		t.Fatal(err)
	}
	delete(s.m, macKeyAccount())
	_, tampered, err := Load(context.Background(), s)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !tampered {
		t.Error("a sealed log with no key must read as tampered")
	}
}

// TestRewrittenEntryIsDetected is the core promise of the chain.
func TestRewrittenEntryIsDetected(t *testing.T) {
	s := &stub{m: map[string]string{}}
	for _, c := range []string{"one.sh", "two.sh", "three.sh"} {
		if _, err := Append(context.Background(), s, c, []string{"tok"}); err != nil {
			t.Fatal(err)
		}
	}
	raw := s.m[svcKey()]
	s.m[svcKey()] = strings.Replace(raw, "two.sh", "evil.sh", 1)
	if _, tampered, err := Load(context.Background(), s); err != nil || !tampered {
		t.Errorf("edited entry not detected: tampered=%v err=%v", tampered, err)
	}
	if _, err := Append(context.Background(), s, "after.sh", []string{"tok"}); !errors.Is(err, ErrTampered) {
		t.Errorf("Append onto a tampered log = %v, want ErrTampered", err)
	}
}
