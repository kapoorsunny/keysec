---
name: keysec
description: Use when a task needs a secret (API token, git credential, password) on this Mac — store, read, update, rotate or delete it via keysec, the pocket vault that keeps secrets in the macOS Keychain. Covers installing the binary, all commands, rotator setup, machine-readable --json mode with exit codes, and wiring git to pull tokens from the Keychain.
---

# keysec — pocket secret vault (macOS Keychain)

keysec is a small Go CLI (this repo) that stores secrets as key–value pairs,
encrypted inside the macOS Keychain. **Nothing is ever written in plaintext
to disk** — there is no index file, the Keychain is the only index
(`security dump-keychain`), so `list` always reflects reality.

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
| `keysec rm <key> [--yes]` | Delete a secret **and its rotator spec**. Always confirms first; `--yes` skips the prompt |
| `keysec list` | Table of every key straight from the Keychain, with date and rotator kind |
| `keysec rotate <key> [--plan]` | Rotate one secret through its rotator (dry-run with `--plan`) |
| `keysec rotate --all [--due] [--plan]` | Rotate every key that has a rotator (default: only keys whose expiry has passed) |
| `keysec rotator set <key> [flags]` | Create/update a rotation plan (spec lives at `<key>.rotator`) |
| `keysec rotator get <key>` | Show a rotation plan (never reads the secret) |
| `keysec rotator rm <key> [--yes]` | Remove a rotation plan (the secret is untouched) |
| `keysec audit [--within <dur>]` | Lifecycle report; `--within` (default 14d) marks `EXPIRES_SOON` |
| `keysec doctor [--migrate] [--yes]` | Health report, or migrate a v0.1 `keys.json` index |
| `keysec git-credential <get\|approve\|reject>` | For git, not for humans — see Git integration |

**Key names:** letters, digits, dots, dashes; 1–255 chars; no leading/trailing
dot or `..`. Every key maps to Keychain service `keysec` with the **full name**
as the account — `keysec / gitlab.api_token`. Names ending in `.rotator` are
reserved for rotation specs.

## Rotators

A rotator is a non-secret spec (kind + config) stored at `<key>.rotator` that
describes how to produce the key's next value. Set one up and rotate:

```bash
# random secret, 48 chars
keysec rotator set backup.token --kind generate --length 48

# real GitLab PAT via the stored credential of another key
keysec rotator set gitlab.token --kind vendor/gitlab \
  --meta url=https://gitlab.com \
  --auth-key git.gitlab.example.com.root.keysec

# GitHub fine-grained PAT
keysec rotator set gh.token --kind vendor/github \
  --meta 'permissions=administration:write' --meta title=keysec-rotate

# Cloudflare API token via a separate "API Tokens Edit" credential key
keysec rotator set cf.token --kind vendor/cloudflare \
  --meta 'policies=[{"effect":"allow","resources":{"com.cloudflare.api.account.<acct>":"*"},"permission_groups":[{"id":"<perm-group-id>"}]}]' \
  --auth-key cf.admin

# sweep: rotate everything whose recorded expiry has passed
keysec rotate --all --due
```

Kinds: `generate`, `http`, `script`, `vendor/github`, `vendor/gitlab`,
`vendor/cloudflare`.
The credential sent to a vendor is `--auth-key`'s stored value, or the key's
own current value if no `--auth-key` is set. Rotation is atomic: the provider
runs first and nothing is written until it succeeds, so a failure leaves the
old secret live. Vendor rotation creates a new token and revokes the previous
one it created (tracked via `last_created_id` in the spec state).

`vendor/cloudflare` specifics: the credential must itself be a Cloudflare API
token with "API Tokens Write" permission (dashboard template "Create
additional tokens" — User > API Tokens > Edit). The new token is pinned via
`--meta policies='<json array>'` (Cloudflare policy objects with `effect`,
`resources`, `permission_groups`) and `--meta expiration_days` (default 90,
max 365). The token value is shown only once at creation, so keysec must
rotate into it to see it.

`script` contract: keysec runs `<script> rotate` (file) or
`<interpreter> -s rotate` (inline body) with `KEYSEC_KEY`, `KEYSEC_VALUE` and
`KEYSEC_META_<NAME>` in the environment. Stdout is either a JSON object
`{"value","expires_at","old_valid_until","meta"}` or the whole trimmed stdout
as the new value. Whatever service the script talks to is the script's own
concern — keysec only reads stdout, so there is no server-side schema. Live
test: `test/run-script-rotation.sh` (dummy Python rotation server + adapter
script), documented in `docs/script-rotation.md`.

`rotator set` flags: `--kind --length --charset --url --method --auth
--auth-key --value --new-expires --grace --script --body --body-file
--interpreter --timeout --meta k=v` (repeatable) or a wholesale `--spec
'<json>'`. Switching kind clears the previous kind's fields but keeps
`--grace`, `--timeout`, `--meta`.

## Patterns for agents and scripts

Prefer `--json`; it makes success and failure machine-readable.

```bash
keysec set --json mytoken "$TOKEN"      # {"ok":true,"action":"saved","key":"mytoken"}
keysec get --json mytoken               # {"name":"mytoken","value":"..."}
keysec list --json                      # {"count":N,"keys":[{"name","saved","rotates"}]}  rotates: kind or ""
keysec rm --json mytoken --yes          # {"ok":true,"action":"removed","key":"mytoken"}
keysec rotate --json mytoken            # {"ok":true,"action":"rotated","key":...,"expires_at":...}
keysec audit --json                     # {"count":N,"keys":[{"status":"EXPIRES_SOON",...}]}
```

- **Exit codes:** `0` ok (or rm declined), `1` runtime error
  (`not_found` / `locked` / `rotation` / `io` / `internal`), `2` usage or
  invalid key name. `rotate --all` exits `1` if any key in the sweep failed.
- **Errors are JSON on stderr:** `{"error":"<kind>","key":...,"hint":...,"message":...}`
  where `<kind>` is one of `not_found`, `locked`, `usage`, `invalid_key`,
  `rotation`, `io`, `internal`. Branch on `error`, act on `hint`.
- **Non-interactive rule:** pass values as arguments and use `--yes`; never
  rely on prompts in a job with no TTY (hidden prompts fall back to a stdin
  line; unconfirmed `rm`/`rotator rm`/`doctor --migrate` exit 2 pointing you at `--yes`).
- **Consume values inline:** `curl -H "Authorization: Bearer $(keysec get mytoken)" ...`
  — never redirect a `get` into a file, log, or commit.
- **Read specs without secrets:** `keysec rotator get --json <key>` prints the
  spec and lifecycle state, never the value.

## Git integration (the killer feature)

Point git at keysec so tokens live in the Keychain instead of a plaintext
`~/.git-credentials`:

```
git config --global credential.'https://gitlab.example.com'.helper '/usr/local/bin/keysec git-credential'
```

Then git's normal flow runs over the vault: keysec stores tokens git
approves, forgets tokens git rejects, and answers `get` silently (empty
output = "no credential here", so git falls back to its usual prompts).
The derived key is deterministic: `git.<host>` plus a dot-joined segment per
path piece (`.git` dropped) — e.g. `git.gitlab.example.com.root.keysec`. Do not call
`git-credential` by hand; it speaks git's percent-encoded wire protocol.

## Migrating from v0.1

v0.1 kept `~/.config/keysec/keys.json` and mapped a key's first dot segment to
a Keychain service. v0.2 has no index file. After upgrading the binary, run
`keysec doctor --migrate` once: it relocates every secret to service `keysec`
and removes the legacy file. `keysec list` hints at this when it finds the old
index.

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
6. Rotation runs the provider before touching the keychain. Never suggest
   rotating a key that lacks a rotator — point at `keysec rotator set` instead.

## Troubleshooting

| Symptom | Meaning / next step |
|---|---|
| `no key called 'x'` + "did you mean 'y'?" | Typo — the hint names the closest key |
| `no rotator configured for 'x'` | Rotate not possible yet — `keysec rotator set <key> --kind ...` |
| `your keychain is locked` | `security unlock` or open Keychain Access, then retry |
| `list` is empty but keys exist | Probably a v0.1 install — `keysec doctor --migrate` |
| `{"error":"rotation",...}` | Provider failed; nothing was written, the old value is still live |
| keysec not found | See Install above |