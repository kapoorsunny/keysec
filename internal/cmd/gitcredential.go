package cmd

import (
	"context"
	"errors"
	"os"
)

// GitCredential implements "keysec git-credential <action>".
//
// This speaks git's credential-helper protocol, not our human UX: it
// reads a percent-encoded credential on stdin and answers on stdout,
// quietly. Errors go to stderr.
func (a *App) GitCredential(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: keysec git-credential <get|approve|reject>")
	}
	return a.shim.Run(ctx, args[0], a.stdin, os.Stdout, a.ui.Stderr())
}
