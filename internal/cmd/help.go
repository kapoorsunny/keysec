package cmd

import (
	"repo.flay.ai/root/keysec/internal/ui"
)

// Help prints keysec's friendly help with examples.
func Help(o *ui.Output) {
	o.Outln(`keysec — a pocket secret vault for your Mac

Store, read and update secrets as key-value pairs, locked safely
inside the macOS Keychain. Nothing is ever stored in plaintext on
disk; the operating system encrypts it with your login password.

Commands
  keysec set <key> [value]    save a secret (asks hidden if no value)
  keysec get <key>            print a secret (clean for scripts)
  keysec update <key> [value] change a secret that already exists
  keysec rm <key> [--yes]     delete a secret (confirms first)
  keysec list                 show every key you have, with dates
  keysec git-credential <a>   for git, not for humans (see below)

Keys are friendly names: a word, or a word with a dot.
  mytoken        -> service "keysec", account "mytoken"
  gitlab.repo_flay -> service "gitlab", account "repo_flay"

Examples
  $ keysec set gitlab.repo_flay
    value for 'gitlab.repo_flay' (hidden): ********
  ✓ saved 'gitlab.repo_flay'
    stored encrypted in your Mac's keychain

  $ keysec get gitlab.repo_flay
  glpat-abc123...

  $ keysec list
    KEY                SAVED        STATE
    gitlab.repo_flay   2026-09-04   ✓ in keychain
    1 key

Let git keep its tokens in the Keychain — one line in your git config:

  [credential "https://repo.flay.ai"]
      helper = /usr/local/bin/keysec git-credential

Then git pulls tokens from the Keychain, and no plaintext
git-credentials file is ever written. Tokens git approves are stored;
tokens git rejects are forgotten.

For agents and scripts: --json
  Add --json (anywhere) for machine-readable output:
    keysec get --json <key>   -> {"name":...,"value":...}
    keysec list --json        -> {"count":N,"keys":[{"name","saved","state"}]}
    keysec set/update/rm --json -> {"ok":true,"action":...,"key":...}
  Errors are structured JSON on stderr, e.g.
    {"error":"not_found","key":"x","hint":"did you mean 'y'? try: keysec list",...}
  Exit codes: 0 ok, 1 runtime error (not_found, locked, io), 2 usage.
  Human defaults are unchanged; --json is opt-in and never affects
  git-credential (which speaks git's own protocol).
`)
}
