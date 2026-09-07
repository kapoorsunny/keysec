// Package ui renders keysec's output: friendly, colored messages for
// humans on a terminal, plain text when piped, and JSON when the
// caller has requested machine mode (--json).
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Output writes keysec's messages. Decorations (✓, ✗, hints) always go
// to stderr; data such as "get" values and the "list" table go to
// stdout, so scripts can rely on clean output.
type Output struct {
	stdout   io.Writer
	stderr   io.Writer
	color    bool
	jsonMode bool
}

// New returns an Output writing to the given writers. Color is enabled
// only when stderr is an interactive terminal: every decorated line
// (Success, Fail) goes to stderr, while stdout carries plain data.
// Probing stdout instead would strip color from messages the user is
// watching whenever data is piped, and write escape codes into a
// redirected stderr log.
func New(stdout, stderr io.Writer) *Output {
	color := false
	if f, ok := stderr.(*os.File); ok {
		color = term.IsTerminal(int(f.Fd()))
	}
	return &Output{stdout: stdout, stderr: stderr, color: color}
}

const (
	cReset  = "\x1b[0m"
	cRed    = "\x1b[31m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cDim    = "\x1b[2m"
)

// paint wraps s in the color code when color is enabled.
func (o *Output) paint(code, s string) string {
	if !o.color {
		return s
	}
	return code + s + cReset
}

// Success prints "✓ msg" in green to stderr.
func (o *Output) Success(format string, args ...any) {
	fmt.Fprintln(o.stderr, o.paint(cGreen, "✓")+" "+fmt.Sprintf(format, args...))
}

// Fail prints "✗ msg" in red to stderr.
func (o *Output) Fail(format string, args ...any) {
	fmt.Fprintln(o.stderr, o.paint(cRed, "✗")+" "+fmt.Sprintf(format, args...))
}

// Hint prints an indented follow-up line (a next step or suggestion)
// to stderr.
func (o *Output) Hint(format string, args ...any) {
	fmt.Fprintln(o.stderr, "   "+fmt.Sprintf(format, args...))
}

// Note prints a plain informational line to stderr.
func (o *Output) Note(format string, args ...any) {
	fmt.Fprintln(o.stderr, fmt.Sprintf(format, args...))
}

// Out prints to stdout. Use only for non-secret data (values, tables).
func (o *Output) Out(format string, args ...any) {
	fmt.Fprintf(o.stdout, format, args...)
}

// Outln prints a line to stdout.
func (o *Output) Outln(format string, args ...any) {
	fmt.Fprintf(o.stdout, format+"\n", args...)
}

// Stdout returns the writer data goes to. The run command uses it so a
// child process inherits exactly what keysec would write, keeping output
// on stdout and testable via injected buffers.
func (o *Output) Stdout() io.Writer { return o.stdout }

// Stderr returns the writer messages go to, so callers (like the
// git-credential shim) can emit protocol errors there.
func (o *Output) Stderr() io.Writer { return o.stderr }

// SetJSON switches between human and machine output. Machine mode turns
// off color; JSON is written raw so it stays parseable.
func (o *Output) SetJSON(on bool) {
	o.jsonMode = on
	if on {
		o.color = false
	}
}

// InJSON reports whether machine (JSON) output is active.
func (o *Output) InJSON() bool { return o.jsonMode }

// JSON writes v as a single JSON object (plus newline) to stdout.
func (o *Output) JSON(v any) error {
	return o.writeJSON(o.stdout, v)
}

// JSONErr writes v as a single JSON object (plus newline) to stderr,
// for machine-readable error reporting.
func (o *Output) JSONErr(v any) error {
	return o.writeJSON(o.stderr, v)
}

func (o *Output) writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v) // appends a trailing newline
}

// Table renders rows as a fixed-width text table on stdout. Column
// widths derive from the widest cell in each column.
func (o *Output) Table(header []string, rows [][]string) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	printRow := func(cells []string) {
		line := make([]string, len(cells))
		for i, c := range cells {
			if i < len(widths) {
				line[i] = pad(c, widths[i])
			} else {
				line[i] = c
			}
		}
		o.Outln("%s", strings.Join(line, "  "))
	}
	printRow(header)
	for _, row := range rows {
		printRow(row)
	}
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
