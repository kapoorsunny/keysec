package cmd

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/machine"
	"repo.flay.ai/root/keysec/internal/ui"
)

// Remove implements "keysec rm <key>".
//
// It always confirms first, except when --yes is passed (for scripts
// and jobs). It never deletes silently. With --json it confirms with
// {"ok":true,"action":"removed",...}.
func (a *App) Remove(ctx context.Context, args []string) error {
	yes := slices.Contains(args, "--yes")
	positional := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--yes" {
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 {
		return machine.Usage("usage: keysec rm <key> [--yes]", "--yes skips the confirmation")
	}
	k, err := parseKey(positional[0])
	if err != nil {
		return err
	}
	exists, err := a.store.Has(ctx, k.Service, k.Account)
	if err != nil {
		return a.storeError(err)
	}
	if !exists {
		return a.notFoundError(k.Name)
	}
	ok, err := a.prompts.Confirm(fmt.Sprintf("remove '%s'", k.Name), yes)
	if err != nil {
		if errors.Is(err, ui.ErrNotConfirmed) {
			return machine.Usage("removal of '"+k.Name+"' was not confirmed", "pass --yes to remove without a prompt")
		}
		return machine.IO(err.Error())
	}
	if !ok {
		if a.ui.InJSON() {
			return a.ui.JSON(machine.Ack{OK: false, Action: "kept", Key: k.Name})
		}
		a.ui.Note("ok, kept '%s'", k.Name)
		return nil
	}
	if err := a.store.Delete(ctx, k.Service, k.Account); err != nil {
		if !errors.Is(err, keychain.ErrNotFound) {
			// Not "vanished between check and delete": a real failure.
			return a.storeError(err)
		}
	}
	if err := a.ledger.Remove(k.Name); err != nil {
		return machine.IO(err.Error())
	}
	if a.ui.InJSON() {
		return a.ui.JSON(machine.Ack{OK: true, Action: "removed", Key: k.Name})
	}
	a.ui.Success("removed '%s'", k.Name)
	a.ui.Hint("the keychain item and the index entry are both gone")
	return nil
}
