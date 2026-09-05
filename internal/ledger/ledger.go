// Package ledger keeps a small index of known key names and dates.
// It records names and timestamps only — never secret values — so that
// "keysec list" is instant and deletions can warn about history.
package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	fileName = "keys.json"
	dirPerm  = 0o700
	filePerm = 0o600
)

// Entry is one row of the ledger.
type Entry struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// file is the on-disk shape of the ledger.
type file struct {
	Version int     `json:"version"`
	Keys    []Entry `json:"keys"`
}

// Ledger is the key index at a fixed file path.
type Ledger struct {
	path string
}

// New returns a Ledger rooted in $KEYSEC_HOME or ~/.config/keysec.
func New() (*Ledger, error) {
	dir := os.Getenv("KEYSEC_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot locate your home directory: %v", err)
		}
		dir = filepath.Join(home, ".config", "keysec")
	}
	return &Ledger{path: filepath.Join(dir, fileName)}, nil
}

// NewAt returns a Ledger backed by the given file path (used by tests).
func NewAt(path string) *Ledger {
	return &Ledger{path: path}
}

// Path returns the ledger file location.
func (l *Ledger) Path() string { return l.path }

// Load returns all entries, sorted by name. A missing file yields an
// empty list, not an error.
func (l *Ledger) Load() ([]Entry, error) {
	var f file
	data, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read the key index at %s: %v", l.path, err)
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf(
			"the key index at %s is unreadable — move it aside (e.g. mv %s keys.json.bak) and try again",
			l.path, l.path)
	}
	entries := f.Keys
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// Upsert records name as existing, touching created/updated as needed.
func (l *Ledger) Upsert(name string) error {
	entries, err := l.Load()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for i := range entries {
		if entries[i].Name == name {
			entries[i].Updated = now
			return l.write(entries)
		}
	}
	return l.write(append(entries, Entry{Name: name, Created: now, Updated: now}))
}

// Remove deletes name from the index. Removing an unknown name is a
// no-op.
func (l *Ledger) Remove(name string) error {
	entries, err := l.Load()
	if err != nil {
		return err
	}
	kept := entries[:0]
	for _, e := range entries {
		if e.Name != name {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(entries) {
		return nil // nothing to do
	}
	return l.write(kept)
}

// write persists entries atomically (temp file + rename) with strict
// permissions.
func (l *Ledger) write(entries []Entry) error {
	if err := os.MkdirAll(filepath.Dir(l.path), dirPerm); err != nil {
		return fmt.Errorf("cannot create the keysec folder: %v", err)
	}
	data, err := json.MarshalIndent(file{Version: 1, Keys: entries}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(l.path), ".keys.json.tmp-*")
	if err != nil {
		return fmt.Errorf("cannot write the key index: %v", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write the key index: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write the key index: %v", err)
	}
	if err := os.Chmod(tmpName, filePerm); err != nil {
		return fmt.Errorf("cannot write the key index: %v", err)
	}
	return os.Rename(tmpName, l.path)
}
