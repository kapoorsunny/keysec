package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/kapoorsunny/keysec/internal/machine"
	"github.com/kapoorsunny/keysec/internal/runlog"
)

// Runs implements "keysec runs [--yes] [--json]".
//
// It prints the tamper-evident handoff log recorded by "keysec run": one
// row per secret-bearing run, oldest first. Verification always runs, so
// a modified, reordered, or truncated log is detected on every read. When
// the chain fails to verify, the table is still shown (it is the forensic
// evidence) but the command exits 1 and says so; --yes is the deliberate
// escape hatch that clears the log after the evidence has been reviewed.
func (a *App) Runs(ctx context.Context, args []string) error {
	reset := false
	rest := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "--yes":
			reset = true
		default:
			rest = append(rest, arg)
		}
	}
	if len(rest) != 0 {
		return machine.Usage("usage: keysec runs [--yes]", "--yes clears the log (after reviewing it); --json for machine output")
	}
	if reset {
		return a.runsReset(ctx)
	}
	return a.runsShow(ctx)
}

func (a *App) runsShow(ctx context.Context) error {
	entries, tampered, err := runlog.Load(ctx, a.store)
	if err != nil {
		return a.storeError(err)
	}
	out := make([]machine.RunEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, machine.RunEntry{
			Seq: e.Seq, At: e.At, Cmd: e.Cmd, Env: e.Env, Sha: e.Sha,
		})
	}
	if a.ui.InJSON() {
		if err := a.ui.JSON(machine.Runs{Count: len(out), Entries: out, Tampered: tampered}); err != nil {
			return err
		}
		if tampered {
			return &machine.Error{
				Kind:    machine.KindIO,
				Message: "run log integrity check failed — the stored handoff log does not verify",
				Hint:    "review the entries above, then clear it with: keysec runs --yes",
			}
		}
		return nil
	}
	if len(out) == 0 {
		a.ui.Note("no runs recorded yet — start one with: keysec run --env TOKEN=mytoken echo hi")
		return nil
	}
	rows := make([][]string, 0, len(out))
	for _, e := range out {
		rows = append(rows, []string{fmt.Sprint(e.Seq), e.At, strings.Join(e.Env, ","), e.Cmd})
	}
	a.ui.Table([]string{"SEQ", "WHEN", "SECRETS", "COMMAND"}, rows)
	if tampered {
		return &machine.Error{
			Kind:    machine.KindIO,
			Message: "run log integrity check failed",
			Hint:    "the log was modified, reordered, or truncated — the rows above are what remains; after reviewing, clear it with: keysec runs --yes",
		}
	}
	return nil
}

// runsReset clears the log. It is gated behind an explicit --yes in both
// output modes (JSON callers cannot be prompted) and is the only way to
// make progress after a chain fails to verify. The cleared count is
// best-effort: a log that cannot even be read is still reset.
func (a *App) runsReset(ctx context.Context) error {
	entries, _, _ := runlog.Load(ctx, a.store)
	if err := runlog.Reset(ctx, a.store); err != nil {
		return a.storeError(err)
	}
	cleared := len(entries)
	if a.ui.InJSON() {
		return a.ui.JSON(machine.RunsReset{OK: true, Action: "runs.reset", Cleared: cleared})
	}
	if cleared == 0 {
		a.ui.Note("run log was empty — nothing to clear")
		return nil
	}
	a.ui.Success("run log cleared (%d entr%s)", cleared, plural(cleared))
	return nil
}
