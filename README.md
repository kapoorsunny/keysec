# keysec — a pocket secret vault for your Mac

**What it is:** a small command-line tool that stores, reads, updates, and
**rotates** your secrets as simple key–value pairs — locked safely inside the
macOS Keychain. Type a key, type a value, done. Everything is encrypted by the
operating system. **Nothing is ever stored in plaintext on disk.**

---

## The problem this solves

Secrets today live in scattered, fragile places on a Mac:

- a plaintext `git-credentials` file that git **silently empties** the moment a token goes stale,
- tool config files (like `~/.config/rubric/config`) with tokens in them, in the open,
- tokens that never rotate, so the one that leaked stays good for years,
- background jobs that then fail at 9am with cryptic errors like
  `could not read Username: Device not configured` — and nobody knows why,
- no single place to answer the question: *"what secrets do I have, and where?"*

**keysec gives you one place** — a key-value store for secrets, backed by the
Keychain, with a friendly face, and optional **rotators** that renew a secret
in place.

## The promise (safety)

| Property | How |
|---|---|
| No plaintext on disk | Values live encrypted inside the macOS Keychain (`login.keychain-data`), sealed with your login password |
| Only you can read them | The Keychain is unlocked only while you're logged in |
| Auditable | Open **Keychain Access** and see exactly what's stored |
| No index file | The Keychain is the only index — `list` reads it directly |
| Safe for scripts & jobs | `security` CLI under the hood — works in launchd jobs, shell scripts, and git, non-interactively |
| One-time setup per helper | macOS asks for a single "allow" approval the first time a new program touches a secret; silent forever after |

## What you can do

| Command | What it does (plain English) |
|---|---|
| `keysec set <key>` | Save a secret. If you don't type a value, it **asks you, hidden** (like a password field) |
| `keysec get <key>` | Print the secret — for you, or for a script |
| `keysec update <key>` | Change a secret, but only if it already exists |
| `keysec rm <key>` | Delete a secret (and its rotator) — **asks you to confirm first** |
| `keysec list` | Show everything keysec has saved, straight from the Keychain, with dates and rotator kinds |
| `keysec rotate <key>` | Rotate one secret through its rotator |
| `keysec rotate --all [--due]` | Rotate every key (or just the ones whose expiry has passed) |
| `keysec rotator get\|set\|rm` | Inspect or configure a key's rotation plan |
| `keysec audit [--within <dur>]` | Lifecycle report: which keys are healthy, due, or past due |
| `keysec doctor [--migrate]` | Check the vault, or import a v0.1 index into the keychain-only model |
| `keysec git-credential` | *For git, not for humans* — lets git read/write tokens straight from the Keychain (see below) |
| `keysec help` | Friendly help with examples |

**Keys are friendly names.** `mytoken` or `gitlab.repo_flay` — a word, or a
word with a dot. Letters, digits, dots, dashes. No paths, no JSON, no flags
you must know.

### A typical 30 seconds

```
$ keysec set gitlab.repo_flay
  value for 'gitlab.repo_flay' (hidden): ********
✓ saved 'gitlab.repo_flay'
   stored encrypted in your Mac's keychain

$ keysec get gitlab.repo_flay
glpat-abc123...

$ keysec list
  KEY                 SAVED       ROTATES
  gitlab.repo_flay    2026-09-04  vendor/gitlab
```

## How it works (in one paragraph)

Every key maps to exactly one **Keychain item**: the reserved service `keysec`
plus the full key name as the account — `keysec / gitlab.repo_flay`. Dots in a
name are just characters, not coordinates. The Keychain is the **only index**:
`list` enumerates it with `security dump-keychain` (names and dates only;
macOS never dumps values), so there is no `keys.json` and no way for the index
and the storage to disagree. A key that has a **rotator** also keeps a tiny,
non-secret spec at `keysec / <key>.rotator` describing how to produce the next
value — the secret's value itself lives only inside the Keychain.

## Rotators

A rotator is a small, secret-free plan for producing new values. Set one per
key, then rotation is one command:

```
keysec rotator set gitlab.token --kind vendor/gitlab \
  --meta url=https://gitlab.com \
  --auth-key git.repo.flay.ai.root.keysec

keysec rotate gitlab.token          # new token created, stored, old one revoked
keysec rotate --all --due           # sweep everything past its expiry
keysec audit                        # who is healthy / due / past due?
```

Kinds: `generate` (fresh random secret), `http` (ask an API), `script` (run
your own program), `vendor/github` and `vendor/gitlab` (create a real PAT and
revoke the previous one). The credential used to authenticate to a vendor is
`--auth-key`'s value, or the key's own current value.

Rotation is **atomic**: the provider runs first, and nothing is written until
it succeeds — a failed rotation leaves the old secret live and the keychain
untouched.

## The killer feature: git integration

One line in your git config:

```
[credential "https://repo.flay.ai"]
    helper = /usr/local/bin/keysec git-credential
```

Now **git itself** pulls tokens from the Keychain — no plaintext
`git-credentials` file anywhere. When git approves a token, keysec stores it;
when git rejects one, keysec forgets it (git's protocol, faithfully followed).
Background jobs that use git work the same way, and the whole class of bug we
debugged — *token silently evicted, job fails with a cryptic error* — is
structurally gone, because the token has a durable, encrypted home.

## Upgrading from v0.1

v0.1 kept a `keys.json` index and mapped a key's first dot segment to the
Keychain *service*. v0.2 makes the Keychain the only index and puts every key
under service `keysec`. One command moves your vault:

```
keysec doctor --migrate
```

It relocates each secret to its v0.2 coordinates and removes the legacy file.

## For agents and scripts: `--json`

Append `--json` (any flag position) for machine output:

```
keysec list --json    -> {"count":N,"keys":[{"name","saved","rotates"}]}
keysec get --json     -> {"name":"...","value":"..."}
keysec rotate --json  -> {"ok":true,"action":"rotated","key":...}
keysec audit --json   -> {"count":N,"keys":[{"status":"EXPIRES_SOON",...}]}
```

Errors are structured JSON on stderr: `{"error":"<kind>","hint":...}`.
Kinds: `not_found`, `locked`, `usage`, `invalid_key`, `rotation`, `io`, `internal`.
Exit codes: `0` ok, `1` runtime error, `2` usage. `git-credential` always
speaks git's own protocol and ignores `--json`.

## How it talks to you (UX principles)

1. **Plain English, always.** No jargon in messages: never "genp blob", "rc=5", "errSecItemNotFound".
2. **One obvious action per command.** No required flags. `keysec set x` just works.
3. **Secrets are entered hidden** (like a password field) and never echoed back.
4. **Destructive actions confirm first** — and scripts can pass `--yes` to skip the question.
5. **Every error tells you the next step.**
   - `✗ no key called 'gitlab.tken'` → `   did you mean 'gitlab.repo_flay'? try: keysec list`
   - `✗ your keychain is locked` → `   unlock it: security unlock  (or open Keychain Access)`
6. **Colors when you're in a terminal, plain text when piped** — pretty for humans, safe for scripts.
7. **`get` prints only the raw value to stdout** — decorations go to stderr, so `$(keysec get k)` is always clean.

## What keysec is *not*

- **Not a workflow engine.** Attractor is for multi-step, agentic, asynchronous
  work (your paper-watcher, fork-sync). A secret lookup is a dictionary
  lookup — it needs a 5-millisecond synchronous tool, not a pipeline.
- **Not a team secret manager.** No server, no sharing, no web UI. It's *your*
  Mac, *your* login, *your* keys.
- **Not cross-platform (yet).** The Keychain is macOS. If you later need
  Linux, the plan is an encrypted-file backend behind the same commands.

## v0.2 scope

1. `set` / `get` / `update` / `rm` / `list` — generic key-value over the Keychain
2. Keychain-only index (no `keys.json`): `list` enumerates via `security dump-keychain`, migration via `doctor --migrate`
3. Relations: rotator specs at `<key>.rotator`, `rm` cascades
4. hidden prompts, confirmations, colors, friendly errors
5. `git-credential` shim (git protocol → Keychain), no index anymore
6. `rotator set|get|rm` and `rotate`, `rotate --all [--due]`, `audit`, `doctor`
7. one Go binary, no dependencies beyond the standard toolchain, installs to `/usr/local/bin/keysec`

**Success looks like:** `keysec set`/`get`/`list` feel like a friendly app;
your `repo.flay.ai` token lives in the Keychain; git authenticates through it;
`keysec audit` reports nothing overdue; the 9am `laa-self-update` job runs
clean with zero plaintext token files on disk.