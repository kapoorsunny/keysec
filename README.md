# keysec — a pocket secret vault for your Mac

**What it is:** a small command-line tool that stores, reads, and updates your
secrets as simple key–value pairs — locked safely inside the macOS Keychain.
Type a key, type a value, done. Everything is encrypted by the operating
system. **Nothing is ever stored in plaintext on disk.**

---

## The problem this solves

Secrets today live in scattered, fragile places on a Mac:

- a plaintext `git-credentials` file that git **silently empties** the moment a token goes stale,
- tool config files (like `~/.config/rubric/config`) with tokens in them, in the open,
- background jobs that then fail at 9am with cryptic errors like
  `could not read Username: Device not configured` — and nobody knows why,
- no single place to answer the question: *"what secrets do I have, and where?"*

**keysec gives you one place** — a key-value store for secrets, backed by the
Keychain, with a friendly face.

## The promise (safety)

| Property | How |
|---|---|
| No plaintext on disk | Values live encrypted inside the macOS Keychain (`login.keychain-data`), sealed with your login password |
| Only you can read them | The Keychain is unlocked only while you're logged in |
| Auditable | Open **Keychain Access** and see exactly what's stored |
| Safe for scripts & jobs | `security` CLI under the hood — works in launchd jobs, shell scripts, and git, non-interactively |
| One-time setup per helper | macOS asks for a single "allow" approval the first time a new program touches a secret; silent forever after |

## What you can do

| Command | What it does (plain English) |
|---|---|
| `keysec set <key>` | Save a secret. If you don't type a value, it **asks you, hidden** (like a password field) |
| `keysec get <key>` | Print the secret — for you, or for a script |
| `keysec update <key>` | Change a secret, but only if it already exists |
| `keysec rm <key>` | Delete a secret — **asks you to confirm first** (never deletes silently) |
| `keysec list` | Show everything keysec has saved, in a tidy table, with dates |
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
  KEY                    SAVED           STATE
  gitlab.repo_flay       2026-09-04      ✓ in keychain
  1 key
```

## How it works (in one paragraph)

Each key maps to one **Keychain item**: the part before the dot is the item's
*service* (`gitlab`), the part after is the *account* (`repo_flay`), and the
value is the item's password. Keys without a dot go under the default service
`keysec`. keysec also keeps a tiny ledger file — `~/.config/keysec/keys.json`
— that remembers which keys exist (names and dates **only, never values**) so
that `list` is instant and deletion can warn you. All actual secret material
exists only inside the Keychain.

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

## How it talks to you (UX principles)

1. **Plain English, always.** No jargon in messages: never "genp blob",
   "rc=5", "errSecItemNotFound".
2. **One obvious action per command.** No required flags. `keysec set x` just works.
3. **Secrets are entered hidden** (like a password field) and never echoed back.
4. **Destructive actions confirm first** — and scripts can pass `--yes` to skip the question.
5. **Every error tells you the next step.**
   - `✗ no key called 'gitlab.tken'` → `   did you mean 'gitlab.repo_flay'? try: keysec list`
   - `✗ your keychain is locked` → `   unlock it: security unlock  (or open Keychain Access)`
6. **Colors when you're in a terminal, plain text when piped** — so it's pretty for humans and safe for scripts.
7. **`get` prints only the raw value to stdout** — decorations go to stderr, so `$(keysec get k)` is always clean.

## What keysec is *not*

- **Not a workflow engine.** Attractor is for multi-step, agentic, asynchronous
  work (your paper-watcher, fork-sync). A secret lookup is a dictionary
  lookup — it needs a 5-millisecond synchronous tool, not a pipeline.
- **Not a team secret manager.** No server, no sharing, no web UI. It's *your*
  Mac, *your* login, *your* keys.
- **Not cross-platform (yet).** The Keychain is macOS. If you later need
  Linux, the plan is an encrypted-file backend behind the same commands.

## v0.1 scope (the first build)

1. `set` / `get` / `update` / `rm` / `list` — generic key-value over the Keychain
2. hidden prompts, confirmations, colors, friendly errors, the ledger file
3. `git-credential` shim (git protocol → Keychain)
4. one Go binary, no dependencies beyond the standard toolchain, installs to `/usr/local/bin/keysec`

**Success looks like:** `keysec set`/`get`/`list` feel like a friendly app;
your `repo.flay.ai` token lives in the Keychain; git authenticates through it;
the 9am `laa-self-update` job runs clean with zero plaintext token files on disk.
