package cmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/machine"
)

// envFlag is one --env mapping: the child's variable NAME and the keysec
// secret that supplies its value.
type envFlag struct {
	name string // environment variable name in the child
	key  string // keysec key holding the value
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// parseEnvArg parses a "NAME=key" mapping into an envFlag.
func parseEnvArg(s string) (envFlag, error) {
	name, keyName, ok := strings.Cut(s, "=")
	if !ok || name == "" || keyName == "" {
		return envFlag{}, machine.Usage("--env expects NAME=key", "e.g. --env TOKEN=mytoken")
	}
	if !envNameRe.MatchString(name) {
		return envFlag{}, machine.Usage("invalid environment variable name '"+name+"'",
			"names look like TOKEN or AWS_ACCESS_KEY_ID")
	}
	return envFlag{name: name, key: keyName}, nil
}

// Run implements "keysec run --env NAME=key [--env ...] [--] <cmd> [args...]".
//
// It resolves each requested secret from the vault and injects it as an
// environment variable into a single child process. The child inherits this
// process's stdin/stdout/stderr, so nothing is captured or echoed: secrets
// exist only in that one subprocess, never written to disk, shell history,
// or .env files.
//
// run returns the child's own exit code (or 2 for a usage error before it
// starts), which lets scripts chain on real success/failure rather than
// keysec's fixed codes. --json is deliberately not interpreted: any flags
// after '--' belong to the child command.
func (a *App) Run(ctx context.Context, args []string) int {
	var envs []envFlag
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			// Everything after a literal -- is the child command.
			rest = append(rest, args[i+1:]...)
			goto done
		case arg == "--env" || strings.HasPrefix(arg, "--env="):
			v := arg
			if arg == "--env" {
				i++
				if i >= len(args) {
					return a.runUsage("--env needs a value (NAME=key)", "e.g. --env TOKEN=mytoken")
				}
				v = args[i]
			} else {
				v = strings.TrimPrefix(arg, "--env=")
			}
			e, err := parseEnvArg(v)
			if err != nil {
				return a.runUsage(err.Error(), "e.g. --env TOKEN=mytoken")
			}
			envs = append(envs, e)
		default:
			rest = append(rest, args[i:]...)
			goto done
		}
	}
done:

	if len(rest) == 0 {
		return a.runUsage("usage: keysec run --env NAME=key [--] <cmd> [args...]", "no command to run")
	}

	injected := make([]string, 0, len(envs))
	for _, e := range envs {
		k, err := parseKey(e.key)
		if err != nil {
			return a.runUsage(err.Error(), "")
		}
		value, err := a.store.Get(ctx, k.Service, k.Account)
		if err != nil {
			a.renderError(machine.FromError(a.runStoreErr(ctx, e.key, err)))
			return 1
		}
		injected = append(injected, e.name+"="+value)
	}

	c := exec.CommandContext(ctx, rest[0], rest[1:]...)
	c.Stdin = a.stdin
	c.Stdout = a.ui.Stdout()
	c.Stderr = a.ui.Stderr()
	c.Env = append(append([]string{}, os.Environ()...), injected...)

	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ProcessState != nil && !ee.Success() {
			return normalizeChildCode(ee.ExitCode())
		}
		a.renderError(machine.FromError(runStartError(rest[0], err)))
		return 1
	}
	return 0
}

// runUsage renders a usage error (exit 2) the same way other commands do.
func (a *App) runUsage(message, hint string) int {
	e := machine.Usage(message, hint)
	a.renderError(e)
	return e.ExitCode()
}

// runStoreErr translates a store read failure into a typed error: a missing
// key becomes not_found (with the friendly suggestion), anything else maps to
// locked or io.
func (a *App) runStoreErr(ctx context.Context, keyName string, err error) *machine.Error {
	if errors.Is(err, keychain.ErrNotFound) {
		return a.notFoundError(ctx, keyName)
	}
	return a.storeError(err)
}

// runStartError wraps a child-start failure (e.g. the binary is missing).
func runStartError(prog string, err error) *machine.Error {
	var ee *exec.Error
	if errors.As(err, &ee) && errors.Is(ee.Err, os.ErrNotExist) {
		return machine.IO("no such command '"+prog+"'")
	}
	return machine.IO("could not run '" + prog + "': " + err.Error())
}

// normalizeChildCode returns the child's exit status for a normal exit, or a
// generic failure when it was killed by a signal. Exit codes are already in
// the 8-bit range on Unix; only signal deaths yield an out-of-range value.
func normalizeChildCode(code int) int {
	if code >= 0 && code <= 255 {
		return code
	}
	return 1 // killed by a signal (e.g. SIGINT)
}
