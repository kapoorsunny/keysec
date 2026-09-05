package cmd

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"repo.flay.ai/root/keysec/internal/key"
	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/machine"
	"repo.flay.ai/root/keysec/internal/ui"
)

// Remove implements "keysec rm <key>". It always confirms first, except
// when --yes is passed (for scripts and jobs), and it never deletes
// silently. If the key has a rotator, its companion spec goes with it.
// With --json it confirms with {"ok":true,"action":"removed",...}.
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
	hasRotator, err := a.store.Has(ctx, key.ReservedService, key.CompanionName(k.Name))
	if err != nil {
		return a.storeError(err)
	}
	if !exists && !hasRotator {
		return a.notFoundError(ctx, k.Name)
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
	if exists {
		if err := a.store.Delete(ctx, k.Service, k.Account); err != nil && !errors.Is(err, keychain.ErrNotFound) {
			return a.storeError(err)
		}
	}
	if hasRotator {
		if err := a.store.Delete(ctx, key.ReservedService, key.CompanionName(k.Name)); err != nil && !errors.Is(err, keychain.ErrNotFound) {
			return a.storeError(err)
		}
	}
	if a.ui.InJSON() {
		return a.ui.JSON(machine.Ack{OK: true, Action: "removed", Key: k.Name})
	}
	a.ui.Success("removed '%s'", k.Name)
	if hasRotator {
		a.ui.Hint("its rotator spec went with it")
	}
	return nil
}
