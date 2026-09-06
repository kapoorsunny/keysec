// Package redact streams output through a bounded-memory writer that
// replaces configured secret values with a fixed marker. It is built for
// "keysec run --mask": a child process's stdout and stderr flow through
// it live, so secrets that a script echoes cannot land in logs or
// transcripts. Memory use is bounded by the longest secret, not by the
// output size.
package redact

import (
	"bytes"
	"io"
	"sort"
)

// Redacted is the marker replacing each found secret.
const Redacted = "***"

// Replacing is an io.Writer that scrubs the configured secrets from the
// bytes passing through. Flush must be called once the producer is done
// so any bytes still held back across the longest-secret boundary are
// emitted. Writes always report the input length as written, so callers
// like os/exec see a well-behaved writer even when a match short-circuits
// the underlying sink.
type Replacing struct {
	w        io.Writer
	secrets  [][]byte
	longest  int
	buf      []byte
	redacted int
}

// NewReplacing wraps w, masking every occurrence of any value in
// secrets. Empty strings and duplicates are ignored; when two secrets
// begin at the same offset the longer one wins, so a value that is a
// substring of another masks the maximal span.
func NewReplacing(w io.Writer, secrets []string) *Replacing {
	seen := map[string]bool{}
	longest := 0
	for _, s := range secrets {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		if len(s) > longest {
			longest = len(s)
		}
	}
	all := make([][]byte, 0, len(seen))
	for s := range seen {
		all = append(all, []byte(s))
	}
	// Longest first: when two secrets tie at an offset, the first in
	// list order wins, and stable sorting puts the longest candidate
	// there.
	sort.SliceStable(all, func(i, j int) bool { return len(all[i]) > len(all[j]) })
	return &Replacing{w: w, secrets: all, longest: longest}
}

// Write streams p through the scrubber.
func (r *Replacing) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.secrets) == 0 {
		return r.w.Write(p)
	}
	r.buf = append(r.buf, p...)
	for {
		at, si := r.match(r.buf)
		if at >= 0 {
			if err := r.emit(at, si); err != nil {
				return len(p), err
			}
			continue
		}
		// No secret sits fully inside the buffer, so everything before
		// the trailing (longest-1) bytes can never be part of a future
		// match and is safe to flush now. With only one-byte secrets the
		// whole buffer goes.
		if len(r.buf) >= r.longest {
			n := len(r.buf) - (r.longest - 1)
			if _, err := r.w.Write(r.buf[:n]); err != nil {
				return len(p), err
			}
			r.buf = r.buf[n:]
		}
		return len(p), nil
	}
}

// Flush emits any unprocessed tail. Without it, bytes shorter than the
// longest secret still buffered at end-of-stream would be lost.
func (r *Replacing) Flush() error {
	if len(r.secrets) == 0 {
		return nil
	}
	for {
		at, si := r.match(r.buf)
		if at < 0 {
			break
		}
		if err := r.emit(at, si); err != nil {
			return err
		}
	}
	if len(r.buf) > 0 {
		_, err := r.w.Write(r.buf)
		r.buf = r.buf[:0]
		return err
	}
	r.buf = r.buf[:0]
	return nil
}

// RedactedCount reports how many secrets have been masked so far.
func (r *Replacing) RedactedCount() int {
	return r.redacted
}

// emit masks the secret at offset at and drops the covered bytes.
func (r *Replacing) emit(at, si int) error {
	if at > 0 {
		if _, err := r.w.Write(r.buf[:at]); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(r.w, Redacted); err != nil {
		return err
	}
	r.redacted++
	r.buf = r.buf[at+len(r.secrets[si]):]
	return nil
}

// match returns the offset of the earliest match in b and the index of
// the matched secret. Ties resolve to the longest secret because the
// list is sorted longest-first.
func (r *Replacing) match(b []byte) (at, si int) {
	bestAt, best := -1, -1
	for i, s := range r.secrets {
		idx := bytes.Index(b, s)
		if idx < 0 {
			continue
		}
		if best < 0 || idx < bestAt {
			bestAt, best = idx, i
		}
	}
	return bestAt, best
}
