# keysec — a pocket secret vault for your Mac

**What it is:** a small command-line tool that stores, reads, updates, and
**rotates** your secrets as simple key–value pairs — locked safely inside the
macOS Keychain. Type a key, type a value, done. Everything is encrypted by the
operating system. **Nothing is ever stored in plaintext on disk.**

---

## Requirements

- **macOS** — secrets live in the system Keychain.
- **Go 1.25+** to build from source.

That's it. The only external program keysec shells out to is the built-in
`security` CLI, so it works in scripts, launchd jobs, and git, non-interactively.

## Install

### Option A — Homebrew (recommended)

```bash
brew tap kapoorsunny/tap
brew trust kapoorsunny/tap   # one-time approval; non-interactive, safe in scripts/CI
brew install keysec
```

A prebuilt macOS binary (Apple Silicon or Intel) is installed, and releases are
pushed to the tap automatically when a new version is tagged.

**Agents using keysec should also grab the skill** so they know how to drive it.
Install it into your agent's skill/instructions directory (the convention varies
by agent — e.g. Codex, Gemini, or another tool each has its own). The raw file
is always available, so point your skill loader at it:

```
https://raw.githubusercontent.com/kapoorsunny/keysec/main/skills/keysec/SKILL.md
```

A typical install into a local skill directory looks like:

```bash
mkdir -p <your-agent-skill-dir>/keysec
curl -fsSL https://raw.githubusercontent.com/kapoorsunny/keysec/main/skills/keysec/SKILL.md \
  -o <your-agent-skill-dir>/keysec/SKILL.md
```

The skill is the agent-facing manual — every command, `--json` machine mode,
rotator setup, git integration, and troubleshooting. An agent reading this
README in the recommended option can fetch and install it as part of setup.

### Option B — `go install` from the module

```bash
go install github.com/kapoorsunny/keysec@latest
```

### Option C — build from source (always matches this checkout)

```bash
git clone https://github.com/kapoorsunny/keysec
cd keysec
go build -o keysec .
sudo install -m 755 keysec /usr/local/bin/keysec   # or any directory on $PATH
keysec help                                        # verify: usage + examples, exit 0
```

Agents and automation can rely on any of the three: `brew install keysec`
(Option A) is the fastest one-line install for a machine that has Homebrew.

Whichever option you pick, the prebuilt `keysec` file at the repo root is
git-ignored; build fresh so the installed binary matches the checkout. The
first time a *new* program reads a secret, macOS asks you to "always allow" it
in an approval dialog; afterwards it is silent.

---

## Why we need this

Secrets today live in scattered, fragile places on a Mac:

- a plaintext `git-credentials` file that git **silently empties** the moment a token goes stale,
- tool config files (like `~/.config/yourtool/config`) with tokens in them, in the open,
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
| `keysec runs [--yes]` | The audit log of every secret handoff (`run`), sealed with a keyed hash chain. `--yes` clears it deliberately, after review |
| `keysec run --env NAME=key [--mask] [--] cmd` | Inject exactly the secrets you name into one command as environment variables only — never disk, history, or `.env` files. With `--mask`, secret values a script prints come out as `***` |
| `keysec get <key>` | Print the secret — for you, or for a script |
| `keysec update <key>` | Change a secret, but only if it already exists |
| `keysec version` | Which keysec this is — release tag, commit, and platform (also `--version`) |
| `keysec rm <key>` | Delete a secret (and its rotator) — **asks you to confirm first** |
| `keysec list` | Show everything keysec has saved, straight from the Keychain, with dates and rotator kinds |
| `keysec rotate <key>` | Rotate one secret through its rotator |
| `keysec rotate --all [--due]` | Rotate every key (or just the ones whose expiry has passed) |
| `keysec rotator get\|set\|rm` | Inspect or configure a key's rotation plan |
| `keysec audit [--within <dur>]` | Lifecycle report: which keys are healthy, due, or past due |
| `keysec doctor [--migrate]` | Health check for the vault; optionally migrate a legacy key index |
| `keysec git-credential` | *For git, not for humans* — lets git read/write tokens straight from the Keychain (see below) |
| `keysec help` | Friendly help with examples |

**Keys are friendly names.** `mytoken` or `github.repo` — a word, or a
word with a dot. Letters, digits, dots, dashes. No paths, no JSON, no flags
you must know.

### A typical 30 seconds

```
$ keysec set gitlab.api_token
  value for 'gitlab.api_token' (hidden): ********
✓ saved 'gitlab.api_token'
   stored encrypted in your Mac's keychain

$ keysec get gitlab.api_token
glpat-abc123...

$ keysec list
  KEY                 SAVED       ROTATES
  gitlab.api_token    2026-09-04  vendor/gitlab
```

## How it works (in one paragraph)

Every key maps to exactly one **Keychain item**: the reserved service `keysec`
plus the full key name as the account — `keysec / gitlab.api_token`. Dots in a
name are just characters, not coordinates. The Keychain is the **only index**:
`list` enumerates it with `security dump-keychain` (names and dates only;
macOS never dumps values), so there is no `keys.json` and no way for the index
and the storage to disagree. A key that has a **rotator** also keeps a tiny,
non-secret spec at `keysec / <key>.rotator` describing how to produce the next
value — the secret's value itself lives only inside the Keychain.

## Every secret handoff is audited (`keysec runs`)

Every time `keysec run --env ...` injects a secret, it appends one record
to an append-only handoff log: which key, which command, when. Each record
locks in the one before it (a chain of HMACs, keyed by a separate Keychain
entry), so editing, reordering, or truncating the log is detected the next
time it is read:

```
$ keysec runs
  SEQ  WHEN                        SECRETS    COMMAND
  1    2026-09-06T12:00:00Z        mytoken    bash -c deploy
```

The log lives in the Keychain itself (`keysec / .runlog`), so `keysec list`
stays clean and only your real keys show up. Three rules keep the handoff
honest:

1. **`run` names every key it hands over.** Wildcards are refused, so a
   command can never receive "some of everything".
2. **`run` refuses to start on a broken log.** If the chain fails to
   verify — or the log can't be written (e.g. locked keychain) — the child
   never starts. No handoff without a record of it.
3. **Clearing is deliberate.** `keysec runs --yes` wipes the log after
   you've reviewed the evidence (scripts: `keysec runs --yes --json`).
   It's the *only* way past a failed check.

What this does and does not prove: the chain is keyed, so rewriting the log
means also reading its MAC key (`keysec / .runlog.key`) — casual edits and
corruption are caught. It is not proof against something already running as
you with Keychain access, which could read both and re-seal a forged log.
For a guarantee that survives that, ship the records off the machine.

`--mask` is a transcript safety net for the same handoff: the child's
stdout and stderr are scrubbed live, so secret *values* a script echoes
come out as `***`:

```
$ keysec run --mask --env TOKEN=mytoken -- ./report.sh
```

## Rotators

A rotator is a small, secret-free plan for producing new values. Set one per
key, then rotation is one command:

```
keysec rotator set gitlab.token --kind vendor/gitlab \
  --meta url=https://gitlab.com \
  --auth-key git.gitlab.example.com.root.keysec

keysec rotate gitlab.token          # new token created, stored, old one revoked
keysec rotate --all --due           # sweep everything past its expiry
keysec audit                        # who is healthy / due / past due?
```

Kinds: `generate` (fresh random secret), `http` (ask an API), `script` (run
your own program), `vendor/github`, `vendor/gitlab` and `vendor/cloudflare`
(create a real token via the provider API and revoke the previous one). The
credential used to authenticate to a vendor is `--auth-key`'s value, or the
key's own current value.

Rotation is **atomic**: the provider runs first, and nothing is written until
it succeeds — a failed rotation leaves the old secret live and the keychain
untouched.

## The killer feature: git integration

One line in your git config:

```
[credential "https://gitlab.example.com"]
    helper = /usr/local/bin/keysec git-credential
```

Now **git itself** pulls tokens from the Keychain — no plaintext
`git-credentials` file anywhere. When git approves a token, keysec stores it;
when git rejects one, keysec forgets it (git's protocol, faithfully followed).
Background jobs that use git work the same way, and the whole class of bug we
debugged — *token silently evicted, job fails with a cryptic error* — is
structurally gone, because the token has a durable, encrypted home.

## For agents and scripts: `--json`

Append `--json` (any flag position) for machine output:

```
keysec list --json    -> {"count":N,"keys":[{"name","saved","rotates"}]}
keysec get --json     -> {"name":"...","value":"..."}
keysec rotate --json  -> {"ok":true,"action":"rotated","key":...}
keysec audit --json   -> {"count":N,"keys":[{"status":"EXPIRES_SOON",...}]}
keysec runs --json    -> {"count":N,"entries":[{"seq","at","command","secret_keys","sha"}],"tampered":...}
keysec runs --yes --json -> {"ok":true,"action":"runs.reset","cleared":N}
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
   - `✗ no key called 'gitlab.tken'` → `   did you mean 'gitlab.api_token'? try: keysec list`
   - `✗ your keychain is locked` → `   unlock it: security unlock  (or open Keychain Access)`
6. **Colors when you're in a terminal, plain text when piped** — pretty for humans, safe for scripts.
7. **`get` prints only the raw value to stdout** — decorations go to stderr, so `$(keysec get k)` is always clean.

## What keysec is *not*

- **Not a workflow engine.** Multi-step, agentic, asynchronous work is what a
  workflow engine is for. A secret lookup is a dictionary
  lookup — it needs a 5-millisecond synchronous tool, not a pipeline.
- **Not a team secret manager.** No server, no sharing, no web UI. It's *your*
  Mac, *your* login, *your* keys.
- **Not cross-platform (yet).** The Keychain is macOS. If you later need
  Linux, the plan is an encrypted-file backend behind the same commands.

## Repository layout

- `main.go`, `internal/` — the CLI, package per capability (`key`, `keychain`,
  `gitcred`, `migrate`, `machine`, `rotator`, `ui`, `cmd`)
- `docs/script-rotation.md` — the `script` rotator contract + its live test
- `skills/keysec/SKILL.md` — the agent-facing manual: install, every command,
  `--json` machine mode, git integration, and troubleshooting
- `test/` — live integration fixtures (a dummy Python rotation server for the
  `script` rotator)

## Scope

1. `set` / `get` / `update` / `rm` / `list` — generic key-value over the Keychain
2. Keychain-only index (no `keys.json`): `list` enumerates via `security dump-keychain`, migration via `doctor --migrate`
3. Relations: rotator specs at `<key>.rotator`, `rm` cascades
4. hidden prompts, confirmations, colors, friendly errors
5. `git-credential` shim (git protocol → Keychain), no index anymore
6. `rotator set|get|rm` and `rotate`, `rotate --all [--due]`, `audit`, `doctor`
7. one Go binary (standard library plus `golang.org/x/term` for hidden prompts), installs to `/usr/local/bin/keysec`
8. audited handoffs: `run` requires explicit keys, records every handoff in a sealed, append-only log (`runs`, `--yes`), `--mask` scrubs child output

**Success looks like:** `keysec set`/`get`/`list` feel like a friendly app;
your `gitlab.example.com` token lives in the Keychain; git authenticates through it;
`keysec audit` reports nothing overdue; the scheduled job at 09:00 runs
clean with zero plaintext token files on disk.