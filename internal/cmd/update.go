package cmd

import (
	"context"
	"fmt"

	"github.com/kapoorsunny/keysec/internal/machine"
)

// Update implements "keysec update <key> [value]".
//
// Like set, but only for keys that already exist: it never creates a
// new key. With --json it confirms with {"ok":true,"action":"updated",...}.
func (a *App) Update(ctx context.Context, args []string) error {
	if len(args) != 1 && len(args) != 2 {
		return machine.Usage("usage: keysec update <key> [value]", "without a value, it asks, hidden")
	}
	k, err := parseKey(args[0])
	if err != nil {
		return err
	}
	exists, err := a.store.Has(ctx, k.Service, k.Account)
	if err != nil {
		return a.storeError(err)
	}
	if !exists {
		return a.notFoundError(ctx, k.Name)
	}
	var value string
	if len(args) == 2 {
		value = args[1]
	} else {
		value, err = a.prompts.Hidden(fmt.Sprintf("  new value for '%s' (hidden): ", k.Name))
		if err != nil {
			return machine.Usage("no value entered — nothing changed", "pass the value as an argument: keysec update "+k.Name+" <value>")
		}
	}
	if value == "" {
		return machine.Usage("no new value for '"+k.Name+"' — nothing changed", "")
	}
	if err := a.store.Put(ctx, k.Service, k.Account, value); err != nil {
		return a.storeError(err)
	}
	if a.ui.InJSON() {
		return a.ui.JSON(machine.Ack{OK: true, Action: "updated", Key: k.Name})
	}
	a.ui.Success("updated '%s'", k.Name)
	a.ui.Hint("stored encrypted in your Mac's keychain")
	return nil
}
