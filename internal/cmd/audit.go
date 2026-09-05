package cmd

import (
	"context"
	"strings"
	"time"

	"repo.flay.ai/root/keysec/internal/machine"
	"repo.flay.ai/root/keysec/internal/rotator"
)

// Audit reviews every key's rotation status. --within is how close to
// expiry a key must be to count as EXPIRES_SOON (default 14 days; a Go
// duration like "100h"). With --json it prints the machine Audit shape.
func (a *App) Audit(ctx context.Context, args []string) error {
	within := 14 * 24 * time.Hour
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--within" {
			i++
			if i >= len(args) {
				return machine.Usage("--within needs a duration (e.g. 336h)", "")
			}
			d, err := rotator.ParseDuration(args[i])
			if err != nil {
				return machine.Usage("--within: "+err.Error(), "syntax is a Go duration like 48h or 720h")
			}
			within = d
			continue
		}
		if strings.HasPrefix(arg, "--within=") {
			d, err := rotator.ParseDuration(strings.TrimPrefix(arg, "--within="))
			if err != nil {
				return machine.Usage("--within: "+err.Error(), "syntax is a Go duration like 48h or 720h")
			}
			within = d
			continue
		}
		rest = append(rest, arg)
	}
	if len(rest) != 0 {
		return machine.Usage("usage: keysec audit [--within <duration>]", "--json for machine output")
	}
	keys, err := a.listedKeys(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	out := &machine.Audit{Count: len(keys)}
	for _, k := range keys {
		row := machine.AuditKey{Name: k.name, Saved: day(k.saved), Rotates: k.rotates, Status: machine.AuditNoRotator}
		if k.rotates != "" {
			spec, ok, serr := a.loadSpec(ctx, k.name)
			if serr != nil || !ok {
				out.Keys = append(out.Keys, row)
				continue
			}
			exp, perr := rotator.ParseExpiry(spec.ExpiresAt)
			switch {
			case perr != nil || exp == nil:
				row.Status = machine.AuditNever
			case exp.Before(now):
				row.Status = machine.AuditExpired
				row.ExpiresAt = strPtr(spec.ExpiresAt)
			case exp.Before(now.Add(within)):
				row.Status = machine.AuditExpiresSoon
				row.ExpiresAt = strPtr(spec.ExpiresAt)
			default:
				row.Status = machine.AuditOK
				row.ExpiresAt = strPtr(spec.ExpiresAt)
			}
		}
		out.Keys = append(out.Keys, row)
	}
	if a.ui.InJSON() {
		return a.ui.JSON(out)
	}
	rows := make([][]string, 0, len(out.Keys))
	for _, k := range out.Keys {
		mark := "—"
		if k.Rotates != "" {
			mark = k.Rotates
		}
		expires := ""
		if k.ExpiresAt != nil {
			expires = *k.ExpiresAt
		}
		rows = append(rows, []string{k.Name, k.Saved, mark, string(k.Status), expires})
	}
	a.ui.Table([]string{"KEY", "SAVED", "ROTATES", "STATUS", "EXPIRES"}, rows)
	return nil
}
