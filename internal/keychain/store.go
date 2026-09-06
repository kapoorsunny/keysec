// Package keychain defines the secret store used by keysec and its
// macOS Keychain implementation.
package keychain

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when no secret exists at the given location.
var ErrNotFound = errors.New("no such secret")

// ErrLocked is returned when the Keychain cannot be accessed, typically
// because it is locked or user interaction is not allowed.
var ErrLocked = errors.New("keychain is locked")

// ErrConflict is returned when a secret already exists where a new one
// is being added without replacement.
var ErrConflict = errors.New("secret already exists")

// ErrDumpFormat is the fail-loud sentinel for enumeration: the
// dump-keychain output was produced (item blocks exist) but none of the
// blocks were structurally parseable. A changed output format must not
// silently hide every key, so we refuse to report an empty list instead.
var ErrDumpFormat = errors.New("unrecognized 'security dump-keychain' output")

// Store is a key-value store for secrets.
type Store interface {
	// Put saves value under (service, account), replacing any
	// existing value there.
	Put(ctx context.Context, service, account, value string) error

	// Get returns the value stored under (service, account).
	// It returns ErrNotFound if no such secret exists.
	Get(ctx context.Context, service, account string) (string, error)

	// Delete removes the secret at (service, account).
	// It returns ErrNotFound if no such secret exists.
	Delete(ctx context.Context, service, account string) error

	// Has reports whether a secret exists at (service, account).
	Has(ctx context.Context, service, account string) (bool, error)
}

// Entry is one item enumerated from the Keychain. It carries metadata
// only — never a secret value — which is exactly what dump-keychain
// exposes.
type Entry struct {
	Service  string
	Account  string
	Created  time.Time
	Modified time.Time
}

// Enumerator lists Keychain items so keysec can operate with the
// Keychain as its only index. Implementations must fail loudly
// (ErrDumpFormat) rather than silently report an empty list when the
// underlying output changes shape.
type Enumerator interface {
	List(ctx context.Context) ([]Entry, error)
}
