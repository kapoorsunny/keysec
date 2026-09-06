package cmd

import (
	"context"
	"fmt"

	"github.com/kapoorsunny/keysec/internal/machine"
)

// Set implements "keysec set <key> [value]".
//
// With a value it saves it; without one it asks, hidden, like a
// password field. Setting a key that already exists updates it. With
// --json it confirms with {"ok":true,"action":...,"key":...}.
func (a *App) Set(ctx context.Context, args []string) error {
	if len(args) != 1 && len(args) != 2 {
		return machine.Usage("usage: keysec set <key> [value]", "without a value, it asks, hidden")
	}
	k, err := parseKey(args[0])
	if err != nil {
		return err
	}
	existed, err := a.store.Has(ctx, k.Service, k.Account)
	if err != nil {
		return a.storeError(err)
	}
	action := "saved"
	if existed {
		action = "updated"
	}
	var value string
	if len(args) == 2 {
		value = args[1]
	} else {
		value, err = a.prompts.Hidden(fmt.Sprintf("  value for '%s' (hidden): ", k.Name))
		if err != nil {
			return machine.Usage("no value entered — nothing saved", "pass the value as an argument: keysec set "+k.Name+" <value>")
		}
	}
	if value == "" {
		return machine.Usage("no value for '"+k.Name+"' — nothing saved", "remove it instead: keysec rm "+k.Name)
	}
	if err := a.store.Put(ctx, k.Service, k.Account, value); err != nil {
		return a.storeError(err)
	}
	if a.ui.InJSON() {
		return a.ui.JSON(machine.Ack{OK: true, Action: action, Key: k.Name})
	}
	if existed {
		a.ui.Success("updated '%s'", k.Name)
	} else {
		a.ui.Success("saved '%s'", k.Name)
	}
	a.ui.Hint("stored encrypted in your Mac's keychain")
	return nil
}
