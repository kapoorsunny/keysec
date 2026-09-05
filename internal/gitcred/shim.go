package gitcred

import (
	"context"
	"errors"
	"fmt"
	"io"

	"repo.flay.ai/root/keysec/internal/key"
	"repo.flay.ai/root/keysec/internal/keychain"
)

// LedgerLike is the slice of the key index the shim needs.
// *ledger.Ledger satisfies it.
type LedgerLike interface {
	Upsert(name string) error
	Remove(name string) error
}

// Shim implements the "git-credential" subcommand: it speaks git's
// credential-helper protocol and keeps the resulting tokens in the
// secret store.
type Shim struct {
	store  keychain.Store
	ledger LedgerLike
}

// New returns a Shim over the given store and ledger.
func New(store keychain.Store, ledger LedgerLike) *Shim {
	return &Shim{store: store, ledger: ledger}
}

// Run handles one git-credential invocation. action is one of
// get, approve, reject (store is accepted as a legacy alias for
// approve). The credential arrives on stdin; for "get" the answer is
// written to stdout in the protocol's percent-encoded form.
func (s *Shim) Run(ctx context.Context, action string, stdin io.Reader, stdout, stderr io.Writer) error {
	cred, err := Read(stdin)
	if err != nil {
		return err
	}
	name, err := KeyFor(cred)
	if err != nil {
		return err
	}
	switch action {
	case "get":
		return s.get(ctx, cred, name, stdout)
	case "approve", "store":
		return s.approve(ctx, cred, name)
	case "reject":
		return s.reject(ctx, name)
	default:
		fmt.Fprintf(stderr, "keysec: unknown git-credential action %q (expected get, approve or reject)\n", action)
		return fmt.Errorf("unknown git-credential action %q", action)
	}
}

// get answers a credential request: the stored password if there is
// one, silence if there is not (git then falls back to its normal
// flow).
func (s *Shim) get(ctx context.Context, cred Credential, name string, stdout io.Writer) error {
	k, err := key.Parse(name)
	if err != nil {
		return err
	}
	value, err := s.store.Get(ctx, k.Service, k.Account)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return nil // no stored credential for this host
		}
		return err // e.g. locked keychain: fail loudly, do not guess
	}
	cred.Password = value
	return cred.Write(stdout)
}

// approve saves a token git just verified.
func (s *Shim) approve(ctx context.Context, cred Credential, name string) error {
	if cred.Password == "" {
		return nil // nothing secret to keep
	}
	k, err := key.Parse(name)
	if err != nil {
		return err
	}
	if err := s.store.Put(ctx, k.Service, k.Account, cred.Password); err != nil {
		return err
	}
	return s.ledger.Upsert(name)
}

// reject forgets a token git rejected (invalid/expired).
func (s *Shim) reject(ctx context.Context, name string) error {
	k, err := key.Parse(name)
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, k.Service, k.Account); err != nil &&
		!errors.Is(err, keychain.ErrNotFound) {
		return err
	}
	return s.ledger.Remove(name)
}
