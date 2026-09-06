package cmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/kapoorsunny/keysec/internal/keychain"
	"github.com/kapoorsunny/keysec/internal/machine"
	"github.com/kapoorsunny/keysec/internal/redact"
	"github.com/kapoorsunny/keysec/internal/runlog"
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
	if strings.ContainsAny(keyName, "*?") {
		return envFlag{}, machine.Usage("run hands over only the keys you name",
			"no wildcards in --env — list every key, e.g. --env TOKEN=prod_token")
	}
	return envFlag{name: name, key: keyName}, nil
}

// Run implements "keysec run [--mask] --env NAME=key [--env ...] [--] <cmd> [args...]".
//
// It resolves each requested secret from the vault and injects it as an
// environment variable into a single child process. The child inherits this
// process's stdin/stdout/stderr, so nothing is captured or echoed: secrets
// exist only in that one subprocess, never written to disk, shell history,
// or .env files.
//
// The handoff is first recorded in the tamper-evident run log (one entry per
// secret-bearing run); a run refuses to start if the log cannot be written
// or no longer verifies. With --mask, the child's stdout and stderr are
// scrubbed live so secret values a script prints come out as "***".
//
// run returns the child's own exit code (or 2 for a usage error before it
// starts), which lets scripts chain on real success/failure rather than
// keysec's fixed codes. --json is deliberately not interpreted: any flags
// after '--' belong to the child command.
func (a *App) Run(ctx context.Context, args []string) int {
	var envs []envFlag
	mask := false
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			// Everything after a literal -- is the child command.
			rest = append(rest, args[i+1:]...)
			goto done
		case arg == "--mask":
			mask = true
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
	values := make([]string, 0, len(envs))
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
		values = append(values, value)
	}

	// Record the handoff before the child starts. A run that injects
	// secrets cannot begin until its handoff is on the record; a failed
	// or tampered log aborts it (security-over-convenience).
	if err := a.logRun(ctx, envs, rest); err != nil {
		a.renderError(a.runLogErr(err))
		return 1
	}

	c := exec.CommandContext(ctx, rest[0], rest[1:]...)
	c.Stdin = a.stdin
	stdout, stderr := a.ui.Stdout(), a.ui.Stderr()
	var maskOut, maskErr *redact.Replacing
	if mask {
		maskOut = redact.NewReplacing(stdout, values)
		maskErr = redact.NewReplacing(stderr, values)
		stdout, stderr = maskOut, maskErr
	}
	c.Stdout = stdout
	c.Stderr = stderr
	c.Env = append(append([]string{}, os.Environ()...), injected...)

	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ProcessState != nil && !ee.Success() {
			code := normalizeChildCode(ee.ExitCode())
			flushMask(maskOut, maskErr)
			return code
		}
		a.renderError(machine.FromError(runStartError(rest[0], err)))
		flushMask(maskOut, maskErr)
		return 1
	}
	flushMask(maskOut, maskErr)
	return 0
}

// flushMask drains any bytes the scrubbers still hold back after the
// child exits. A flush failure is not worth overriding the child's own
// outcome; the child's stdout/stderr is a terminal, not a pipe keysec
// must report on.
func flushMask(maskOut, maskErr *redact.Replacing) {
	if maskOut != nil {
		maskOut.Flush()
	}
	if maskErr != nil {
		maskErr.Flush()
	}
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
		return machine.IO("no such command '" + prog + "'")
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

// logKeys collects the distinct secret names a run will inject, sorted,
// for the handoff log.
func logKeys(envs []envFlag) []string {
	if len(envs) == 0 {
		return nil
	}
	uniq := make(map[string]bool, len(envs))
	names := make([]string, 0, len(envs))
	for _, e := range envs {
		if !uniq[e.key] {
			uniq[e.key] = true
			names = append(names, e.key)
		}
	}
	sort.Strings(names)
	return names
}

// logRun records one handoff in the run log before the child starts.
// Runs that inject nothing (no --env) leave no trace. The logged command
// line is truncated so a long child line cannot bloat the log.
func (a *App) logRun(ctx context.Context, envs []envFlag, rest []string) error {
	keys := logKeys(envs)
	if len(keys) == 0 {
		return nil
	}
	_, err := runlog.Append(ctx, a.store, truncateCmd(strings.Join(rest, " ")), keys)
	return err
}

// runLogErr maps a handoff-logging failure onto the error vocabulary: a
// tampered chain is deliberate sabotage worth a specific message,
// anything else is a store failure.
func (a *App) runLogErr(err error) *machine.Error {
	if errors.Is(err, runlog.ErrTampered) {
		return &machine.Error{
			Kind:    machine.KindIO,
			Message: "run log integrity check failed — the handoff log was modified or corrupted; refusing to run",
			Hint:    "review the log (keysec runs), then clear it with: keysec runs --yes",
		}
	}
	return a.storeError(err)
}

// truncateCmd caps a logged command line to a sane width, keeping the
// cut at a rune boundary.
func truncateCmd(s string) string {
	const max = 500
	if len(s) <= max {
		return s
	}
	t := s[:max]
	for len(t) > 0 && !utf8.RuneStart(t[len(t)-1]) {
		t = t[:len(t)-1]
	}
	return t + "…"
}
