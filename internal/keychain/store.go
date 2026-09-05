// Package keychain defines the secret store used by keysec and its
// macOS Keychain implementation.
package keychain

import (
	"context"
	"errors"
)

// ErrNotFound is returned when no secret exists at the given location.
var ErrNotFound = errors.New("no such secret")

// ErrLocked is returned when the Keychain cannot be accessed, typically
// because it is locked or user interaction is not allowed.
var ErrLocked = errors.New("keychain is locked")

// ErrConflict is returned when a secret already exists where a new one
// is being added without replacement.
var ErrConflict = errors.New("secret already exists")

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
