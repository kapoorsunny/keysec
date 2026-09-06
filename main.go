// keysec is a pocket secret vault for your Mac: a key-value store for
// secrets, locked inside the macOS Keychain, with pluggable rotation.
package main

import (
	"context"
	"os"

	"github.com/kapoorsunny/keysec/internal/cmd"
	"github.com/kapoorsunny/keysec/internal/keychain"
	"github.com/kapoorsunny/keysec/internal/ui"
)

func main() {
	out := ui.New(os.Stdout, os.Stderr)
	store := keychain.New()
	app := cmd.New(store, store, out, ui.NewPrompts(os.Stdin, os.Stderr), os.Stdin)
	os.Exit(app.Execute(context.Background(), os.Args[1:]))
}
