// Package runlog implements the tamper-evident handoff log that
// records every "keysec run" that injects a secret into a child
// process. It lives in one reserved Keychain entry (keysec/.runlog)
// and stores a single JSON document whose entries form a hash chain:
// each entry carries the hash of the one before it, so reordering,
// removal, or rewriting of an entry is detectable on the next read.
package runlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/kapoorsunny/keysec/internal/key"
	"github.com/kapoorsunny/keysec/internal/keychain"
)

// ErrTampered reports a chain whose stored entries do not verify, i.e.
// the log was modified, reordered, or truncated without going through
// Append. keysec refuses to keep appending to a tampered log.
var ErrTampered = errors.New("run log integrity check failed")

// maxEntries caps how many handoffs the log keeps. When Append would
// exceed it, the oldest entries are pruned and the surviving chain is
// re-based (the fresh head starts a new chain).
var maxEntries = 1000

// ReadWriter is the store access Append and Load need. keychain.Store
// satisfies it.
type ReadWriter interface {
	Get(ctx context.Context, service, account string) (string, error)
	Put(ctx context.Context, service, account, value string) error
}

// Entry is one recorded handoff. Prev is the hash of the previous
// entry ("" for the head of a chain); Sha is this entry's own hash over
// its fields and Prev, so verification needs no external state.
type Entry struct {
	Seq  int      `json:"seq"`
	At   string   `json:"at"`
	Cmd  string   `json:"cmd"`
	Env  []string `json:"env"`
	Prev string   `json:"prev"`
	Sha  string   `json:"sha"`
}

// Log is the on-disk document stored at the reserved account.
type Log struct {
	Seq     int     `json:"seq"`
	Entries []Entry `json:"entries"`
}

// Append records one handoff. cmd is the child command line, env the
// ordered, de-duplicated names of the secret keys that were injected.
// It fails with ErrTampered if the existing chain does not verify, so a
// corrupted or modified log is never silently continued. The returned
// Entry is the handoff just recorded.
func Append(ctx context.Context, rw ReadWriter, cmd string, env []string) (Entry, error) {
	keys := append([]string(nil), env...)
	sort.Strings(keys)
	keys = dedupe(keys)

	existing, tampered, err := Load(ctx, rw)
	if err != nil {
		return Entry{}, err
	}
	if tampered {
		return Entry{}, ErrTampered
	}

	seq := len(existing) + 1
	prev := ""
	if n := len(existing); n > 0 {
		prev = existing[n-1].Sha
	}
	e := Entry{
		Seq:  seq,
		At:   time.Now().UTC().Format(time.RFC3339),
		Cmd:  cmd,
		Env:  keys,
		Prev: prev,
	}
	e.Sha = hashEntry(e.Prev, e.Seq, e.At, e.Cmd, e.Env)

	entries := append(append([]Entry(nil), existing...), e)
	entries = prune(entries)

	log := Log{Seq: len(entries), Entries: entries}
	raw, err := json.Marshal(log)
	if err != nil {
		return Entry{}, err
	}
	if err := rw.Put(ctx, key.ReservedService, key.ReservedRunLog, string(raw)); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Load reads and verifies the log. A log that has never been written
// returns empty entries with tampered=false. A present-but-corrupt
// document (not JSON or the wrong shape) is an io error, not silently
// an empty log. tampered=true means the stored chain does not verify.
func Load(ctx context.Context, rw ReadWriter) (entries []Entry, tampered bool, err error) {
	raw, err := rw.Get(ctx, key.ReservedService, key.ReservedRunLog)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var log Log
	if err := json.Unmarshal([]byte(raw), &log); err != nil {
		return nil, false, fmt.Errorf("run log is corrupted: %w", err)
	}
	return log.Entries, !verify(log.Entries), nil
}

// verify walks the chain and reports whether every entry is consistent:
// sequence numbers count up from 1, each Prev equals the previous
// entry's Sha (except the head), and each stored Sha matches a fresh
// hash of its own fields.
func verify(entries []Entry) bool {
	var prevSha string
	for i, e := range entries {
		if e.Seq != i+1 {
			return false
		}
		if e.Prev != prevSha {
			return false
		}
		if e.Sha != hashEntry(e.Prev, e.Seq, e.At, e.Cmd, e.Env) {
			return false
		}
		prevSha = e.Sha
	}
	return true
}

// dedupe removes adjacent duplicates from a sorted slice.
func dedupe(keys []string) []string {
	uniq := keys[:0]
	for i, k := range keys {
		if i == 0 || keys[i-1] != k {
			uniq = append(uniq, k)
		}
	}
	return uniq
}

// prune keeps at most maxEntries records. When it trims the head of the
// chain, the surviving tail is re-based: Seqs restart at 1 and the new
// head's Prev is cleared, so the result is a valid standalone chain. It
// is only ever called on a chain that Load already verified.
func prune(entries []Entry) []Entry {
	if len(entries) <= maxEntries {
		return entries
	}
	kept := append([]Entry(nil), entries[len(entries)-maxEntries:]...)
	prev := ""
	for i := range kept {
		kept[i].Seq = i + 1
		kept[i].Prev = prev
		kept[i].Sha = hashEntry(kept[i].Prev, kept[i].Seq, kept[i].At, kept[i].Cmd, kept[i].Env)
		prev = kept[i].Sha
	}
	return kept
}

// hashEntry derives an entry's fingerprint from its fields and the
// previous entry's hash. Every field participates, so any edit to a
// stored entry breaks the chain at its own link.
func hashEntry(prev string, seq int, at, cmd string, env []string) string {
	h := sha256.New()
	io.WriteString(h, prev)
	io.WriteString(h, "|"+strconv.Itoa(seq))
	io.WriteString(h, "|"+at)
	io.WriteString(h, "|"+cmd)
	for _, k := range env {
		io.WriteString(h, "|"+k)
	}
	return hex.EncodeToString(h.Sum(nil))
}
