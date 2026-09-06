package runlog

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kapoorsunny/keysec/internal/keychain"
)

// stub is a minimal ReadWriter backed by a map.
type stub struct{ m map[string]string }

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
