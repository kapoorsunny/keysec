package cmd

import (
	"github.com/kapoorsunny/keysec/internal/ui"
)

// Help prints keysec's friendly help with examples.
func Help(o *ui.Output) {
	o.Outln(`keysec — a pocket secret vault for your Mac

Secrets live as key-value pairs inside the macOS Keychain; the
operating system encrypts them with your login password. Nothing is
ever stored in plaintext on disk. Rotators can renew a secret on
demand or on a sweep.

Commands
  keysec run --env NAME=key ...  inject secrets into one command only
  keysec set <key> [value]      save a secret (asks hidden if no value)
  keysec get <key>              print a secret (clean for scripts)
  keysec update <key> [value]   change a secret that already exists
  keysec rm <key> [--yes]       delete a secret and its rotator
  keysec list                   enumeration straight from the Keychain
  keysec rotate <key> [--plan]  rotate one secret via its rotator
  keysec rotate --all [--due]   rotate every (due) key at once
  keysec rotator get|set|rm     inspect or configure a key's rotator
  keysec audit [--within <dur>] lifecycle report of every key
  keysec runs [--yes]           sealed log of every secret handoff
  keysec doctor [--migrate]     check the vault, or import a v0.1 index
  keysec version                which keysec this is (also --version)
  keysec git-credential <act>   for git, not for humans (see below)

Keys are friendly names; every key lives under one reserved service.
  mytoken         -> service "keysec", account "mytoken"
  git.gitlab.example.com -> service "keysec", account "git.gitlab.example.com"

Run (inject secrets into one command only)
  Run a command with selected secrets as environment variables, so they
  never touch disk, shell history or .env files. The child inherits your
  terminal's stdin/out; keysec exits with the child's own status.

    keysec run --env TOKEN=mytoken [--] ./deploy.sh
    keysec run --env AWS_ACCESS_KEY_ID=aws.key \
               --env AWS_SECRET_ACCESS_KEY=aws.secret -- aws s3 sync . s3://b

  Use a literal "--" to pass flags that belong to the child command:
    keysec run --env TOKEN=mytoken -- some-tool --json --verbose

  run hands over only the keys you name: wildcards are refused, and
  every secret-bearing run is recorded in an append-only log sealed with
  a keyed hash chain ("keysec runs"). If the log has been modified or
  cannot be written,
  run refuses to start. After reviewing the evidence, clear a corrupted
  log deliberately with "keysec runs --yes". With --mask, secret values a
  script prints are replaced by "***" in the child's output:
    keysec run --mask --env TOKEN=mytoken -- ./report.sh

Rotators
  A rotator is a small, non-secret plan for producing new values. A key
  with a rotator shows its kind in "keysec list" and can be rotated in
  place, which keeps invalidation consistent:

    keysec rotator set gitlab.token --kind vendor/gitlab \
      --meta url=https://gitlab.com \
      --auth-key git.gitlab.example.com.root.keysec

    keysec rotator set backup.token --kind generate --length 48

  Kinds: generate | http | script | vendor/github | vendor/gitlab | vendor/cloudflare
  The spec is stored next to the secret as <key>.rotator.

  Rotation is then one command, or a sweep of everything due:
    keysec rotate gitlab.token
    keysec rotate --all --due
    keysec audit          # who is healthy, due, or past due?

For agents and scripts: --json
  Add --json (anywhere) for machine-readable output, for example
    keysec list --json     -> {"count":N,"keys":[{"name","saved","rotates"}]}
    keysec rotate --json   -> {"ok":true,"action":"rotated","key",...}
    keysec audit --json    -> {"count":N,"keys":[{"status":"EXPIRES_SOON",...}]}
  Errors are structured JSON on stderr, e.g.
    {"error":"not_found","key":"x","hint":"did you mean 'y'? ..."}
  Exit codes: 0 ok, 1 runtime error (not_found, locked, io, rotation),
  2 usage. Human defaults are unchanged; --json is opt-in and never
  affects git-credential (which speaks git's own protocol).

Let git keep its tokens in the Keychain — one line in your git config:
  [credential "https://gitlab.example.com"]
      helper = /usr/local/bin/keysec git-credential

Then git pulls tokens from the Keychain and never writes a plaintext
git-credentials file. Tokens git approves are stored; tokens git
rejects are forgotten.
`)
}
