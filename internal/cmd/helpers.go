package cmd

import (
	"errors"

	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/machine"
)

// lockedError builds a typed locked-keychain error with the next-step
// hint embedded, so Execute renders it (text or JSON) in one place.
func (a *App) lockedError() *machine.Error {
	return machine.Locked("unlock it: security unlock  (or open Keychain Access)", "your keychain is locked")
}

// storeError translates a store failure into a typed error: a locked
// keychain becomes a locked error, anything else an io error.
// not_found is handled by the caller, which knows the key name.
func (a *App) storeError(err error) *machine.Error {
	if errors.Is(err, keychain.ErrLocked) {
		return a.lockedError()
	}
	return machine.IO(err.Error())
}

// notFoundError builds the standard "no key called ..." error, with a
// "did you mean" / "try list" hint embedded for the active output mode.
func (a *App) notFoundError(needle string) *machine.Error {
	hint := "try: keysec list"
	if s := a.suggest(needle); s != "" {
		hint = "did you mean '" + s + "'? try: keysec list"
	}
	return machine.NotFound(needle, hint, "no key called '"+needle+"'")
}
