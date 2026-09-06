package cmd

import (
	"context"

	"github.com/kapoorsunny/keysec/internal/machine"
	"github.com/kapoorsunny/keysec/internal/migrate"
)

// List implements "keysec list". It reads the Keychain itself — the
// only index — so what it shows is what is really stored. With --json
// it prints {"count":N,"keys":[...]}.
func (a *App) List(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return machine.Usage("usage: keysec list", "--json for machine output")
	}
	keys, err := a.listedKeys(ctx)
	if err != nil {
		return err
	}
	if a.ui.InJSON() {
		out := &machine.List{Count: len(keys)}
		for _, k := range keys {
			out.Keys = append(out.Keys, machine.KeyInfo{Name: k.name, Saved: day(k.saved), Rotates: k.rotates})
		}
		return a.ui.JSON(out)
	}
	if len(keys) == 0 {
		a.ui.Note("no keys yet")
	} else {
		rows := make([][]string, len(keys))
		for i, k := range keys {
			mark := "—"
			if k.rotates != "" {
				mark = k.rotates
			}
			rows[i] = []string{k.name, day(k.saved), mark}
		}
		a.ui.Table([]string{"KEY", "SAVED", "ROTATES"}, rows)
		a.ui.Hint("%d key%s", len(keys), plural(len(keys)))
	}
	if len(keys) == 0 && legacyPresent() {
		a.ui.Hint("found a v0.1 index — migrate it: keysec doctor --migrate")
	}
	return nil
}

// legacyPresent reports a legacy v0.1 keys.json without making list
// fail when it cannot be read (the migration command surfaces that).
func legacyPresent() bool {
	ok, _ := migrate.Exists()
	return ok
}
