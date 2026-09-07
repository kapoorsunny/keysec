// Package runlog implements the tamper-evident handoff log that
// records every "keysec run" that injects a secret into a child
// process. It lives in one reserved Keychain entry (keysec/.runlog)
// and stores a single JSON document whose entries form a hash chain:
// each entry carries the hash of the one before it, so reordering,
// removal, or rewriting of an entry is detectable on the next read.
package runlog

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
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

// Deleter is the store access Reset needs. keychain.Store satisfies it.
type Deleter interface {
	Delete(ctx context.Context, service, account string) error
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

// chainVersion is the format of the links in a freshly written chain.
// Version 1 was an unkeyed SHA-256 over fields joined by "|", which
// both allowed forgery by anyone who could recompute a digest and made
// distinct entries collide (a secret name moved from env onto the end
// of cmd hashed identically). Version 2 is an HMAC over a canonical,
// length-prefixed encoding. Logs written by v1 still verify under the
// v1 rule, so upgrading keysec does not flag an honest log as tampered.
const chainVersion = 2

// Log is the on-disk document stored at the reserved account.
type Log struct {
	Seq     int     `json:"seq"`
	Version int     `json:"version,omitempty"`
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
	mac, err := ensureMACKey(ctx, rw)
	if err != nil {
		return Entry{}, err
	}

	e := Entry{
		At:  time.Now().UTC().Format(time.RFC3339),
		Cmd: cmd,
		Env: keys,
	}
	entries := prune(append(append([]Entry(nil), existing...), e))
	// Re-link the whole chain under the current version. The entries just
	// verified, so re-sealing them is not a rewrite of history; it is what
	// carries a v1 log forward and what re-bases a pruned one.
	reseal(entries, mac)

	log := Log{Seq: len(entries), Version: chainVersion, Entries: entries}
	raw, err := json.Marshal(log)
	if err != nil {
		return Entry{}, err
	}
	if err := rw.Put(ctx, key.ReservedService, key.ReservedRunLog, string(raw)); err != nil {
		return Entry{}, err
	}
	return entries[len(entries)-1], nil
}

// ensureMACKey returns the log's MAC key, minting one on first use.
func ensureMACKey(ctx context.Context, rw ReadWriter) ([]byte, error) {
	mac, err := readMACKey(ctx, rw)
	if err == nil {
		return mac, nil
	}
	if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("run log key: %w", err)
	}
	if err := rw.Put(ctx, key.ReservedService, key.ReservedRunLogKey, hex.EncodeToString(fresh)); err != nil {
		return nil, err
	}
	return fresh, nil
}

// readMACKey loads the MAC key without creating one.
func readMACKey(ctx context.Context, rw ReadWriter) ([]byte, error) {
	raw, err := rw.Get(ctx, key.ReservedService, key.ReservedRunLogKey)
	if err != nil {
		return nil, err
	}
	mac, err := hex.DecodeString(raw)
	if err != nil || len(mac) == 0 {
		return nil, fmt.Errorf("run log key is corrupted")
	}
	return mac, nil
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
	var mac []byte
	if log.Version >= 2 {
		mac, err = readMACKey(ctx, rw)
		if err != nil {
			if errors.Is(err, keychain.ErrNotFound) {
				// A sealed log whose key is gone can no longer be proven
				// honest. Report it as tampered rather than trusting it.
				return log.Entries, true, nil
			}
			return nil, false, err
		}
	}
	return log.Entries, !verify(log.Entries, log.Version, mac), nil
}

// Reset clears the run log entirely by removing its reserved Keychain
// entry. It is the deliberate escape hatch after a chain fails to verify
// (or simply to start fresh); callers must gate it behind explicit
// confirmation. Deleting an absent log is a no-op.
func Reset(ctx context.Context, dw Deleter) error {
	err := dw.Delete(ctx, key.ReservedService, key.ReservedRunLog)
	if err != nil && !errors.Is(err, keychain.ErrNotFound) {
		return err
	}
	return nil
}

// verify walks the chain and reports whether every entry is consistent:
// sequence numbers count up from 1, each Prev equals the previous
// entry's Sha (except the head), and each stored Sha matches a fresh
// seal over its own fields. version selects the sealing rule so a log
// written by an older keysec still verifies.
func verify(entries []Entry, version int, mac []byte) bool {
	var prevSha string
	for i, e := range entries {
		if e.Seq != i+1 {
			return false
		}
		if e.Prev != prevSha {
			return false
		}
		if !hmac.Equal([]byte(e.Sha), []byte(sealEntry(version, mac, e))) {
			return false
		}
		prevSha = e.Sha
	}
	return true
}

// sealEntry produces an entry's link under the given chain version.
func sealEntry(version int, mac []byte, e Entry) string {
	if version >= 2 {
		return hashEntryV2(mac, e.Prev, e.Seq, e.At, e.Cmd, e.Env)
	}
	return hashEntryV1(e.Prev, e.Seq, e.At, e.Cmd, e.Env)
}

// reseal re-numbers and re-links entries in place under the current
// chain version, so the result is a valid standalone chain.
func reseal(entries []Entry, mac []byte) {
	prev := ""
	for i := range entries {
		entries[i].Seq = i + 1
		entries[i].Prev = prev
		entries[i].Sha = hashEntryV2(mac, prev, entries[i].Seq, entries[i].At, entries[i].Cmd, entries[i].Env)
		prev = entries[i].Sha
	}
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

// prune keeps at most maxEntries records, dropping the oldest. The
// caller reseals the survivors, which re-bases the chain. It is only
// ever called on a chain that Load already verified.
func prune(entries []Entry) []Entry {
	if len(entries) <= maxEntries {
		return entries
	}
	return append([]Entry(nil), entries[len(entries)-maxEntries:]...)
}

// hashEntryV2 seals an entry with an HMAC over a canonical encoding.
//
// Every field is length-prefixed, so no two different entries can
// produce the same input: with a bare "|" separator, a secret name
// moved from env onto the end of cmd hashed identically, which let the
// record of which secrets a run received be rewritten undetected.
func hashEntryV2(mac []byte, prev string, seq int, at, cmd string, env []string) string {
	h := hmac.New(sha256.New, mac)
	field := func(s string) {
		io.WriteString(h, strconv.Itoa(len(s)))
		io.WriteString(h, ":")
		io.WriteString(h, s)
	}
	field(prev)
	field(strconv.Itoa(seq))
	field(at)
	field(cmd)
	field(strconv.Itoa(len(env)))
	for _, k := range env {
		field(k)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hashEntryV1 is the original unkeyed, unframed digest. It exists only
// so a log written by an earlier keysec still verifies on first read;
// nothing writes it any more.
func hashEntryV1(prev string, seq int, at, cmd string, env []string) string {
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
