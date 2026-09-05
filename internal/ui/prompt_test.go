package ui

import (
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
