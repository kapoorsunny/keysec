package cmd

import (
	"context"
	"time"

	"repo.flay.ai/root/keysec/internal/key"
	"repo.flay.ai/root/keysec/internal/ledger"
	"repo.flay.ai/root/keysec/internal/machine"
)

// List implements "keysec list". In human mode it prints a tidy table
// of every known key with its save date and whether it is present in
// the keychain; with --json it emits {"count":...,"keys":[...]}.
// Either way it contains names and dates only, never values.
func (a *App) List(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return machine.Usage("usage: keysec list", "")
	}
	entries, err := a.ledger.Load()
	if err != nil {
		return machine.IO(err.Error())
	}
	if a.ui.InJSON() {
		return a.listJSON(ctx, entries)
	}
	if len(entries) == 0 {
		a.ui.Note("no keys yet — save one: keysec set <name>")
		return nil
	}
	header := []string{"KEY", "SAVED", "STATE"}
	rows := make([][]string, 0, len(entries))
	var missing []string
	for _, e := range entries {
		k, err := key.Parse(e.Name)
		if err != nil {
			continue
		}
		present, err := a.store.Has(ctx, k.Service, k.Account)
		if err != nil {
			return a.storeError(err)
		}
		state := "✓ in keychain"
		if !present {
			state = "✗ missing from keychain"
			missing = append(missing, e.Name)
		}
		rows = append(rows, []string{e.Name, day(e.Updated), state})
	}
	a.ui.Table(header, rows)
	a.ui.Outln("%d key%s", len(rows), plural(len(rows)))
	for _, name := range missing {
		a.ui.Hint("'%s' is in the index but gone from the keychain — remove it: keysec rm %s", name, name)
	}
	return nil
}

// listJSON renders the machine form: one object per known key, with a
// state ("present"/"missing") an agent can branch on.
func (a *App) listJSON(ctx context.Context, entries []ledger.Entry) error {
	keys := make([]machine.KeyInfo, 0, len(entries))
	for _, e := range entries {
		k, err := key.Parse(e.Name)
		if err != nil {
			continue
		}
		state := "present"
		if present, err := a.store.Has(ctx, k.Service, k.Account); err != nil {
			return a.storeError(err)
		} else if !present {
			state = "missing"
		}
		keys = append(keys, machine.KeyInfo{Name: e.Name, Saved: day(e.Updated), State: state})
	}
	return a.ui.JSON(machine.List{Count: len(keys), Keys: keys})
}

func day(t time.Time) string { return t.Format("2006-01-02") }

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
