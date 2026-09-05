---
name: keysec
description: Use when a task needs a secret (API token, git credential, password) on this Mac — store, read, update or delete it via keysec, the pocket vault that keeps secrets in the macOS Keychain. Covers installing the binary, all commands, machine-readable --json mode with exit codes, and wiring git to pull tokens from the Keychain.
---

# keysec — pocket secret vault (macOS Keychain)

keysec is a small Go CLI (this repo) that stores secrets as key–value pairs,
encrypted inside the macOS Keychain. **Nothing is ever written in plaintext
to disk.** The only file on disk is a tiny index — `~/.config/keysec/keys.json`
(override with `$KEYSEC_HOME`) — holding key names and dates, never values.

- Human mode: plain-English messages, colors on a TTY, decorations on stderr,
  data (e.g. `get` values) on stdout — so `$(keysec get k)` is always clean.
- Machine mode: append `--json` (works in any flag position) for structured
  JSON output aimed at agents and scripts.
- macOS only (Keychain + `/usr/bin/security`). Not a team manager: one Mac,
  one login, no server.

## Install

If `command -v keysec` finds nothing, build it from this repo:

```bash
go build -o keysec .
sudo install -m 755 keysec /usr/local/bin/keysec   # or place in any PATH dir
keysec help                                        # verify: prints usage, exit 0
```

The prebuilt `keysec` file at the repo root is git-ignored; always build
fresh so the installed binary matches the checkout.

## Commands

| Command | What it does |
|---|---|
| `keysec set <key> [value]` | Save (or replace) a secret. Without a value it prompts hidden, like a password field |
| `keysec get <key>` | Print the raw secret to stdout |
| `keysec update <key> [value]` | Like `set`, but refuses keys that don't exist yet |
| `keysec rm <key> [--yes]` | Delete. Always confirms first; `--yes` skips the prompt (for scripts) |
| `keysec list` | Table of every known key with date and keychain state (names/dates only) |
| `keysec git-credential <get\|approve\|reject>` | For git, not for humans — see Git integration |

**Key names:** letters, digits, dots, dashes; 1–255 chars; no leading/trailing
dot or `..`. The part before the first dot is the Keychain *service*, the rest
the *account*; keys without a dot go under service `keysec`.

## Patterns for agents and scripts

Prefer `--json`; it makes success and failure machine-readable.

```bash
keysec set --json mytoken "$TOKEN"      # {"ok":true,"action":"saved","key":"mytoken"}
keysec get --json mytoken               # {"name":"mytoken","value":"..."}
keysec list --json                      # {"count":N,"keys":[{"name","saved","state"}]}  state: present|missing
keysec rm --json mytoken --yes          # {"ok":true,"action":"removed","key":"mytoken"}
```

- **Exit codes:** `0` ok (or rm declined), `1` runtime error
  (not_found / locked / io / internal), `2` usage or invalid key name.
- **Errors are JSON on stderr:** `{"error":"<kind>","key":...,"hint":...,"message":...}`
  where `<kind>` is one of `not_found`, `locked`, `usage`, `invalid_key`,
  `io`, `internal`. Branch on `error`, act on `hint`.
- **Non-interactive rule:** pass values as arguments and use `--yes`; never
  rely on prompts in a job with no TTY (hidden prompts fall back to a stdin
  line; unconfirmed `rm` exits 2 pointing you at `--yes`).
- **Consume values inline:** `curl -H "Authorization: Bearer $(keysec get mytoken)" ...`
  — never redirect a `get` into a file, log, or commit.

## Git integration (the killer feature)

Point git at keysec so tokens live in the Keychain instead of a plaintext
`~/.git-credentials`:

```
git config --global credential.'https://repo.flay.ai'.helper '/usr/local/bin/keysec git-credential'
```

Then git's normal flow runs over the vault: keysec stores tokens git
approves, forgets tokens git rejects, and answers `get` silently (empty
output = "no credential here", so git falls back to its usual prompts).
The derived key is deterministic: `git.<host>` plus a dot-joined segment per
path piece (`.git` dropped) — e.g. `git.repo.flay.ai.root.keysec`. Do not call
`git-credential` by hand; it speaks git's percent-encoded wire protocol.

## Safety rules (non-negotiable)

1. Never print, log, commit, or paste secret values — not in chat output,
   files, or error reports. Key names and dates are fine to show.
2. `rm` always confirms; only use `--yes` when the user explicitly asked to
   delete, and say what you deleted.
3. A locked keychain fails deterministically (`{"error":"locked"}`, exit 1) —
   the next step is `security unlock` or asking the user to unlock Keychain
   Access. Do not retry in a loop.
4. First time a given program touches a keychain item, macOS shows a one-time
   "allow" approval; afterwards it is silent. If a script fails with a
   keychain error right after a rebuild, the user may need to click "Always
   allow" once.
5. Values containing newlines are handed to `security` as a command-line
   argument (stdin is line-based), so they are transiently visible in the
   process list. Prefer single-line tokens for any value that matters.

## Troubleshooting

| Symptom | Meaning / next step |
|---|---|
| `no key called 'x'` + "did you mean 'y'?" | Typo — the hint names the closest key |
| `your keychain is locked` | `security unlock` or open Keychain Access, then retry |
| `list` shows a key as missing from keychain | Item was deleted out-of-band — `keysec rm <key>` to clean the index |
| index unreadable error | The message tells the user to `mv` the file aside |
| keysec not found | See Install above |
