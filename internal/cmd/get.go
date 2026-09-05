package cmd

import (
	"context"
	"errors"

	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/machine"
)

// Get implements "keysec get <key>".
//
// In human mode the secret goes to stdout and nothing else, so
// $(keysec get k) is always clean. With --json it prints
// {"name":...,"value":...} instead, for agents that prefer structure.
func (a *App) Get(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return machine.Usage("usage: keysec get <key>", "")
	}
	k, err := parseKey(args[0])
	if err != nil {
		return err
	}
	value, err := a.store.Get(ctx, k.Service, k.Account)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return a.notFoundError(ctx, k.Name)
		}
		return a.storeError(err)
	}
	if a.ui.InJSON() {
		return a.ui.JSON(machine.Value{Name: k.Name, Value: value})
	}
	a.ui.Outln("%s", value)
	return nil
}
