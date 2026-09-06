package redact

import (
	"bytes"
	"testing"
)

func maskOnce(t *testing.T, secrets []string, input string) string {
	t.Helper()
	var out bytes.Buffer
	r := NewReplacing(&out, secrets)
	if _, err := r.Write([]byte(input)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := r.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	return out.String()
}

func TestReplaceBasic(t *testing.T) {
	got := maskOnce(t, []string{"sk-live-abc"}, "prefix sk-live-abc suffix")
	want := "prefix *** suffix"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReplaceMultipleOccurrences(t *testing.T) {
	got := maskOnce(t, []string{"secret"}, "secret and secret")
	if got != "*** and ***" {
		t.Errorf("got %q", got)
	}
}

func TestNoSecretsPassthrough(t *testing.T) {
	got := maskOnce(t, nil, "hello world")
	if got != "hello world" {
		t.Errorf("got %q", got)
	}
}

func TestEmptyAndDuplicateSecretsIgnored(t *testing.T) {
	got := maskOnce(t, []string{"", "tok", "tok"}, "a tok b")
	if got != "a *** b" {
		t.Errorf("got %q", got)
	}
}

func TestSingleByteSecret(t *testing.T) {
	got := maskOnce(t, []string{"a"}, "banana")
	if got != "b***n***n***" {
		t.Errorf("got %q", got)
	}
}

func TestLongestWinsAtSameOffset(t *testing.T) {
	// "token" is a prefix of "token-value"; both start at the same spot,
	// the longer must win so no residual "token" stays visible.
	got := maskOnce(t, []string{"token", "token-value"}, "x token-value y")
	if got != "x *** y" {
		t.Errorf("got %q", got)
	}
}

func TestEarliestMatchFirst(t *testing.T) {
	got := maskOnce(t, []string{"aa", "bb"}, "x aa y bb z")
	if got != "x *** y *** z" {
		t.Errorf("got %q", got)
	}
}

func TestStreamingAcrossChunkBoundaries(t *testing.T) {
	secret := "secretvalue"
	secrets := []string{secret}
	input := "prefix secretvalue mid secretvalue end"
	full := maskOnce(t, secrets, input)

	var out bytes.Buffer
	r := NewReplacing(&out, secrets)
	for i := 0; i < len(input); i += 2 {
		end := i + 2
		if end > len(input) {
			end = len(input)
		}
		if _, err := r.Write([]byte(input[i:end])); err != nil {
			t.Fatalf("chunked Write: %v", err)
		}
	}
	if err := r.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if chunked := out.String(); chunked != full {
		t.Errorf("chunked = %q, full = %q", chunked, full)
	}
}

func TestChunkBoundaryInsideSecret(t *testing.T) {
	// The secret is split across two Write calls; the buffer must hold the
	// partial prefix until the match completes.
	var out bytes.Buffer
	r := NewReplacing(&out, []string{"topsecret"})
	if _, err := r.Write([]byte("pre top")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte("secret post")); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "pre *** post" {
		t.Errorf("got %q", got)
	}
}

func TestFlushEmitsTail(t *testing.T) {
	// The tail is shorter than the longest secret and never matches;
	// without Flush it would be lost.
	var out bytes.Buffer
	r := NewReplacing(&out, []string{"verylongsecret"})
	if _, err := r.Write([]byte("hello wo")); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "hello wo" {
		t.Errorf("got %q, want the untruncated tail", got)
	}
}

func TestMatchSpanningWriteBoundaryFlushed(t *testing.T) {
	// The secret is complete at flush time only because the tail arrived
	// fully in an earlier write; identical output to a single write.
	got := maskOnce(t, []string{"abc"}, "x abc y")
	if got != "x *** y" {
		t.Errorf("got %q", got)
	}
}
