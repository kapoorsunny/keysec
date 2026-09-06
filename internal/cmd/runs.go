package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/kapoorsunny/keysec/internal/machine"
	"github.com/kapoorsunny/keysec/internal/runlog"
)

// Runs implements "keysec runs [--json]".
//
// It prints the tamper-evident handoff log recorded by "keysec run": one
// row per secret-bearing run, oldest first. Verification always runs, so
// a modified, reordered, or truncated log is detected on every read. When
// the chain fails to verify, the table is still shown (it is the forensic
// evidence) but the command exits 1 and says so.
func (a *App) Runs(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return machine.Usage("usage: keysec runs", "--json for machine output")
	}
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
			return machine.IO("run log integrity check failed — the stored handoff log does not verify")
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
		a.ui.Hint("the log was modified, reordered, or truncated — the rows above are what remains")
		return machine.IO("run log integrity check failed")
	}
	return nil
}
