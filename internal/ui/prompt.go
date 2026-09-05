package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNotConfirmed is returned when a confirmation could not be
// obtained, e.g. because there is no terminal to ask on.
var ErrNotConfirmed = errors.New("not confirmed")

// Prompts collects interactive input (hidden values, confirmations).
type Prompts struct {
	in   io.Reader
	out  io.Writer
	line *bufio.Reader
}

// NewPrompts returns Prompts reading from in and writing prompt text
// to out. In production both are the user's terminal.
func NewPrompts(in io.Reader, out io.Writer) *Prompts {
	return &Prompts{in: in, out: out, line: bufio.NewReader(in)}
}

// Hidden asks for a secret value, echoing nothing while the user types
// (like a password field). Input is read from the controlling
// terminal even when stdin has been redirected.
func (p *Prompts) Hidden(label string) (string, error) {
	fmt.Fprint(p.out, label)
	src, opened, ok := p.hiddenSource()
	if !ok {
		return p.plainLine()
	}
	if opened {
		defer src.Close()
	}
	b, err := term.ReadPassword(int(src.Fd()))
	fmt.Fprintln(p.out) // the password read swallows the newline
	if err != nil {
		return "", errors.New("no value entered — the secret was not saved")
	}
	return string(b), nil
}

// Confirm asks a yes/no question, defaulting to no. It returns
// ErrNotConfirmed when there is no input to read from, so callers can
// point the user at --yes.
func (p *Prompts) Confirm(label string, assumeYes bool) (bool, error) {
	if assumeYes {
		return true, nil
	}
	fmt.Fprintf(p.out, "%s [y/N] ", label)
	line, err := p.line.ReadString('\n')
	switch {
	case err != nil && strings.TrimSpace(line) == "":
		return false, ErrNotConfirmed
	case err != nil && !errors.Is(err, io.EOF):
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// hiddenSource picks where hidden input comes from: stdin when it is a
// terminal, otherwise the controlling terminal at /dev/tty. The boolean
// reports whether the returned file was opened here (and must be
// closed by the caller). In-memory readers (tests) get the plain-line
// fallback instead, so tests never touch the real terminal.
func (p *Prompts) hiddenSource() (*os.File, bool, bool) {
	f, isFile := p.in.(*os.File)
	if !isFile {
		return nil, false, false
	}
	if term.IsTerminal(int(f.Fd())) {
		return f, false, true
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, false, false
	}
	if !term.IsTerminal(int(tty.Fd())) {
		tty.Close()
		return nil, false, false
	}
	return tty, true, true
}

func (p *Prompts) plainLine() (string, error) {
	line, err := p.line.ReadString('\n')
	line = strings.TrimSuffix(line, "\n")
	if err != nil && line == "" {
		return "", errors.New("no value entered — the secret was not saved")
	}
	return line, nil
}
