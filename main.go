// keysec is a pocket secret vault for your Mac: a key-value store for
// secrets, locked inside the macOS Keychain.
package main

import (
	"context"
	"fmt"
	"os"

	"repo.flay.ai/root/keysec/internal/cmd"
	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/ledger"
	"repo.flay.ai/root/keysec/internal/ui"
)

func main() {
	led, err := ledger.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %s\n", err)
		os.Exit(1)
	}
	out := ui.New(os.Stdout, os.Stderr)
	app := cmd.New(
		keychain.New(),
		led,
		out,
		ui.NewPrompts(os.Stdin, os.Stderr),
		os.Stdin,
	)
	os.Exit(app.Execute(context.Background(), os.Args[1:]))
}
