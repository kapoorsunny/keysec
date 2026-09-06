// Package migrate moves a v0.1 keysec installation into the v0.2
// keychain-only model. v0.1 indexed every key in a keys.json file and
// mapped names onto Keychain coordinates itself; v0.2 treats the
// Keychain as the only index and puts everything under one reserved
// service. Migration reads the legacy index, relocates each secret to
// its v0.2 coordinates, and deletes the file once every move succeeded.
package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kapoorsunny/keysec/internal/key"
	"github.com/kapoorsunny/keysec/internal/keychain"
)

const (
	fileName = "keys.json"
	dirPerm  = 0o700
)

// Entry is one row of the legacy index.
type Entry struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

type legacyFile struct {
	Version int     `json:"version"`
	Keys    []Entry `json:"keys"`
}

// Summary reports what the migration did.
type Summary struct {
	Moved       []string
	Skipped     []Skip
	FileRemoved bool
}

// Skip is one legacy entry that was left in place.
type Skip struct {
	Name   string
	Reason string
}

// Path resolves the legacy index location: $KEYSEC_HOME/keys.json, or
// ~/.config/keysec/keys.json.
func Path() (string, error) {
	if dir := os.Getenv("KEYSEC_HOME"); dir != "" {
		return filepath.Join(dir, fileName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate your home directory: %v", err)
	}
	return filepath.Join(home, ".config", "keysec", fileName), nil
}

// Exists reports whether a legacy index is present on disk.
func Exists() (bool, error) {
	p, err := Path()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Load reads the legacy index. A missing file yields an empty list.
func Load() ([]Entry, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f legacyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("the legacy index at %s is unreadable — move it aside and try again", p)
	}
	sort.Slice(f.Keys, func(i, j int) bool { return f.Keys[i].Name < f.Keys[j].Name })
	return f.Keys, nil
}

// Run relocates every legacy entry to its v0.2 coordinates. Each move
// is Get→Put→Delete on the Keychain; a failure anywhere stops the run
// with an error and leaves the index file in place. warn receives
// advisory notes (skips) as they happen.
func Run(ctx context.Context, store keychain.Store, warn func(string)) (*Summary, error) {
	entries, err := Load()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return &Summary{}, nil
	}

	sum := &Summary{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name, key.ReservedSuffix) {
			sum.Skipped = append(sum.Skipped, Skip{e.Name, "ends in .rotator (reserved in v0.2)"})
			continue
		}
		oldSvc, oldAcct := v01Coordinates(e.Name)
		k, err := key.Parse(e.Name)
		if err != nil {
			sum.Skipped = append(sum.Skipped, Skip{e.Name, "no longer a valid key name: " + err.Error()})
			continue
		}
		if exists, err := store.Has(ctx, k.Service, k.Account); err != nil {
			return sum, err
		} else if exists {
			sum.Skipped = append(sum.Skipped, Skip{e.Name, "already present at its v0.2 location"})
			continue
		}
		value, err := store.Get(ctx, oldSvc, oldAcct)
		if errors.Is(err, keychain.ErrNotFound) {
			sum.Skipped = append(sum.Skipped, Skip{e.Name, "secret missing from the keychain"})
			continue
		}
		if err != nil {
			return sum, err
		}
		if err := store.Put(ctx, k.Service, k.Account, value); err != nil {
			return sum, err
		}
		if err := store.Delete(ctx, oldSvc, oldAcct); err != nil && !errors.Is(err, keychain.ErrNotFound) {
			return sum, err
		}
		sum.Moved = append(sum.Moved, e.Name)
	}

	p, err := Path()
	if err != nil {
		return sum, err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return sum, fmt.Errorf("cannot remove the legacy index at %s: %v", p, err)
	}
	sum.FileRemoved = true
	// Tidy an empty legacy directory that no longer serves a purpose.
	_ = os.Remove(filepath.Dir(p))
	return sum, nil
}

// v01Coordinates reproduces the v0.1 mapping so a legacy secret can be
// read from where it actually lives.
func v01Coordinates(name string) (service, account string) {
	service, account = key.ReservedService, name
	if i := strings.IndexByte(name, '.'); i >= 0 {
		service, account = name[:i], name[i+1:]
	}
	return service, account
}
