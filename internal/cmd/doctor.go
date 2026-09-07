package cmd

import (
	"context"
	"errors"
	"strings"

	"github.com/kapoorsunny/keysec/internal/key"
	"github.com/kapoorsunny/keysec/internal/machine"
	"github.com/kapoorsunny/keysec/internal/migrate"
	"github.com/kapoorsunny/keysec/internal/ui"
)

// Doctor inspects the installation and, with --migrate, relocates a
// v0.1 keys.json index into the v0.2 keychain-only model.
func (a *App) Doctor(ctx context.Context, args []string) error {
	mig, yes := false, false
	var rest []string
	for _, arg := range args {
		switch arg {
		case "--migrate":
			mig = true
		case "--yes":
			yes = true
		default:
			rest = append(rest, arg)
		}
	}
	if len(rest) != 0 {
		return machine.Usage("usage: keysec doctor [--migrate] [--yes]", "")
	}
	if mig {
		return a.doctorMigrate(ctx, yes)
	}
	return a.doctorHealth(ctx)
}

// doctorHealth reports what the vault actually contains and points out
// anything worth fixing.
func (a *App) doctorHealth(ctx context.Context) error {
	entries, err := a.enum.List(ctx)
	if err != nil {
		// Diagnosing a locked keychain is this command's whole job, so it
		// must report the locked kind and its unlock hint, not "internal".
		return a.enumError(err)
	}
	var keys, rotators []string
	isParent := map[string]bool{}
	for _, e := range entries {
		if key.IsCompanion(e.Account) {
			rotators = append(rotators, e.Account)
			continue
		}
		if e.Account == key.ReservedRunLog {
			continue // the run handoff log lives in the Keychain, not the vault
		}
		keys = append(keys, e.Account)
		isParent[e.Account] = true
	}
	var orphans []string
	for _, r := range rotators {
		parent, _ := key.ParentName(r)
		if !isParent[parent] {
			orphans = append(orphans, parent)
		}
	}
	if a.ui.InJSON() {
		return a.ui.JSON(struct {
			Keys        int      `json:"keys"`
			Rotators    int      `json:"rotators"`
			OrphanSpecs []string `json:"orphan_specs,omitempty"`
			LegacyIndex bool     `json:"legacy_index"`
		}{Keys: len(keys), Rotators: len(rotators), OrphanSpecs: orphans, LegacyIndex: legacyPresent()})
	}
	a.ui.Outln("health of your keysec vault")
	a.ui.Outln("  keys:     %d", len(keys))
	a.ui.Outln("  rotators: %d", len(rotators))
	if len(orphans) > 0 {
		a.ui.Outln("  orphan specs: %d", len(orphans))
		a.ui.Hint("orphan specs (no parent key): %s", strings.Join(orphans, ", "))
	}
	if legacyPresent() {
		a.ui.Hint("a v0.1 index exists — migrate it: keysec doctor --migrate")
	} else {
		a.ui.Success("no legacy index — this is a clean v0.2 install")
	}
	return nil
}

// doctorMigrate moves each legacy entry onto its v0.2 coordinates and
// removes the index once everything succeeded.
func (a *App) doctorMigrate(ctx context.Context, yes bool) error {
	if !legacyPresent() {
		a.ui.Success("nothing to migrate — the Keychain is the only index")
		return nil
	}
	entries, err := migrate.Load()
	if err != nil {
		return machine.IO(err.Error())
	}
	if len(entries) == 0 {
		a.ui.Outln("the legacy index is empty")
	} else {
		a.ui.Outln("found %d v0.1 entr%s to relocate", len(entries), plural(len(entries)))
		for _, e := range entries {
			a.ui.Outln("  %s", e.Name)
		}
	}
	if !yes {
		ok, err := a.prompts.Confirm("migrate now", false)
		if err != nil {
			if errors.Is(err, ui.ErrNotConfirmed) {
				return machine.Usage("migration was not confirmed", "pass --yes to migrate without a prompt")
			}
			return machine.IO(err.Error())
		}
		if !ok {
			a.ui.Note("ok, nothing was migrated")
			return nil
		}
	}
	sum, err := migrate.Run(ctx, a.store, func(w string) { a.ui.Hint("%s", w) })
	if err != nil {
		return machine.IO(err.Error())
	}
	for _, m := range sum.Moved {
		a.ui.Success("moved '%s'", m)
	}
	for _, s := range sum.Skipped {
		a.ui.Hint("skipped '%s': %s", s.Name, s.Reason)
	}
	if sum.FileRemoved {
		a.ui.Success("removed the legacy index file")
	} else if sum.HasStranded() {
		a.ui.Hint("kept the legacy index: it is the only record of where the skipped secrets are stored")
		a.ui.Hint("save each one under a valid name, then delete the index by hand")
	}
	return nil
}
