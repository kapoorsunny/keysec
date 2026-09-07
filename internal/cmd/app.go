// Package cmd implements keysec's subcommands. Each command is one
// file; the App bundles their shared dependencies.
package cmd

import (
	"context"
	"io"

	"github.com/kapoorsunny/keysec/internal/gitcred"
	"github.com/kapoorsunny/keysec/internal/key"
	"github.com/kapoorsunny/keysec/internal/keychain"
	"github.com/kapoorsunny/keysec/internal/machine"
	"github.com/kapoorsunny/keysec/internal/ui"
)

// App bundles the dependencies shared by all commands.
type App struct {
	store   keychain.Store
	enum    keychain.Enumerator
	ui      *ui.Output
	prompts *ui.Prompts
	stdin   io.Reader
	shim    *gitcred.Shim
}

// New wires the application together. store reads and writes secrets;
// enum lists them (the Keychain is the only index).
func New(store keychain.Store, enum keychain.Enumerator, out *ui.Output, prompts *ui.Prompts, stdin io.Reader) *App {
	return &App{
		store:   store,
		enum:    enum,
		ui:      out,
		prompts: prompts,
		stdin:   stdin,
		shim:    gitcred.New(store),
	}
}

// Execute dispatches to a subcommand and renders its outcome.
// It returns the process exit code.
func (a *App) Execute(ctx context.Context, args []string) int {
	// run is special: it executes a child process and must not have its
	// arguments reinterpreted. In particular --json after the command
	// belongs to the child, so splitJSON (which strips every occurrence)
	// must not see these args. Only a --json that leads, before the
	// subcommand, can be keysec's own.
	lead := 0
	for lead < len(args) && args[lead] == "--json" {
		lead++
	}
	if lead < len(args) && args[lead] == "run" {
		a.ui.SetJSON(lead > 0)
		return a.Run(ctx, args[lead+1:])
	}
	rest, jsonMode := splitJSON(args)
	a.ui.SetJSON(jsonMode)
	if len(rest) == 0 {
		Help(a.ui)
		return 0
	}
	cmd, cmdArgs := rest[0], rest[1:]
	var run func(context.Context, []string) error
	switch cmd {
	case "set":
		run = a.Set
	case "get":
		run = a.Get
	case "update":
		run = a.Update
	case "rm":
		run = a.Remove
	case "list":
		run = a.List
	case "rotate":
		run = a.Rotate
	case "rotator":
		run = a.Rotator
	case "audit":
		run = a.Audit
	case "runs":
		run = a.Runs
	case "doctor":
		run = a.Doctor
	case "git-credential":
		// Speaks git's own protocol; --json is irrelevant and already
		// stripped, so it is deliberately left unaffected by mode.
		run = a.GitCredential
	case "help", "--help", "-h":
		Help(a.ui)
		return 0
	default:
		e := machine.Usage("unknown command '"+cmd+"'", "available: run, set, get, update, rm, list, rotate, rotator, audit, runs, doctor, git-credential, help")
		a.renderError(e)
		return e.ExitCode()
	}
	if err := run(ctx, cmdArgs); err != nil {
		e := machine.FromError(err)
		a.renderError(e)
		return e.ExitCode()
	}
	return 0
}

// renderError prints an error in the active mode: structured JSON on
// stderr in machine mode, friendly text for humans otherwise.
func (a *App) renderError(e *machine.Error) {
	if a.ui.InJSON() {
		a.ui.JSONErr(e)
		return
	}
	a.ui.Fail("%s", e.Message)
	if e.Hint != "" {
		a.ui.Hint("%s", e.Hint)
	}
}

// splitJSON strips --json from anywhere in args and reports whether it
// was present, so machine mode works whether the flag leads or trails.
func splitJSON(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	jsonMode := false
	for _, arg := range args {
		if arg == "--json" {
			jsonMode = true
			continue
		}
		out = append(out, arg)
	}
	return out, jsonMode
}

// parseKey parses and validates a key name, translating failures into a
// typed invalid_key error carrying the offending name. It returns the
// error interface so callers can chain it with other error returns.
func parseKey(name string) (key.Key, error) {
	k, err := key.Parse(name)
	if err != nil {
		return key.Key{}, machine.InvalidKey(name, "invalid key name")
	}
	return k, nil
}
