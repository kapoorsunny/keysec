package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestConfirmYes(t *testing.T) {
	p := NewPrompts(strings.NewReader("yes\n"), &strings.Builder{})
	ok, err := p.Confirm("remove 'k'", false)
	if err != nil || !ok {
		t.Errorf("Confirm = %v, %v; want true, nil", ok, err)
	}
}

func TestConfirmNoDefault(t *testing.T) {
	p := NewPrompts(strings.NewReader("nope\n"), &strings.Builder{})
	ok, err := p.Confirm("remove 'k'", false)
	if err != nil || ok {
		t.Errorf("Confirm = %v, %v; want false, nil", ok, err)
	}
}

func TestConfirmEmptyInputIsNotConfirmed(t *testing.T) {
	p := NewPrompts(strings.NewReader(""), &strings.Builder{})
	_, err := p.Confirm("remove 'k'", false)
	if !errors.Is(err, ErrNotConfirmed) {
		t.Errorf("Confirm = %v; want ErrNotConfirmed", err)
	}
}

func TestConfirmAssumeYesSkipsPrompt(t *testing.T) {
	p := NewPrompts(strings.NewReader(""), &strings.Builder{})
	ok, err := p.Confirm("remove 'k'", true)
	if err != nil || !ok {
		t.Errorf("Confirm(assumeYes) = %v, %v; want true, nil", ok, err)
	}
}

// Hidden falls back to plain line reading when the input is not a
// terminal; that path is what we can exercise in tests.
func TestHiddenNonTerminalFallback(t *testing.T) {
	p := NewPrompts(strings.NewReader("s3cret\n"), &strings.Builder{})
	got, err := p.Hidden("  value for 'k' (hidden): ")
	if err != nil {
		t.Fatalf("Hidden: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("Hidden = %q, want s3cret", got)
	}
}

func TestHiddenEmptyInput(t *testing.T) {
	p := NewPrompts(strings.NewReader(""), &strings.Builder{})
	if _, err := p.Hidden("  value: "); err == nil {
		t.Error("Hidden with no input should error")
	}
}

// TestColorFollowsStderr: every decorated line (Success, Fail) is
// written to stderr, so probing stdout meant colour appeared exactly
// when it should not and vanished when it should.
func TestColorFollowsStderr(t *testing.T) {
	// Neither writer is a terminal, so colour must be off and no escape
	// codes may reach a redirected stderr.
	var out, errb bytes.Buffer
	o := New(&out, &errb)
	o.Success("saved '%s'", "k")
	if strings.Contains(errb.String(), "\x1b[") {
		t.Errorf("escape codes written to a non-terminal stderr: %q", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("Success must not write to stdout, got %q", out.String())
	}
}
