# keysec v0.2 — Rotation, Keychain-Only Storage, and Lifecycle

Status: accepted. This spec defines the full v0.2 release. Everything that
was previously deferred to a hypothetical v0.3 (vendor adapters, `audit`,
`rotate --all --due`) is rolled into this release. The one prior "fallback"
idea that is deliberately **not** built is the cgo enumerator backend.

## 1. Goals

1. Make the Keychain the single source of truth: no `keys.json`, no
   `$KEYSEC_HOME`, no project files, no external dependencies.
2. Enumerate keys without cgo by parsing `security dump-keychain`, scoped
   to the reserved `keysec` service.
3. Rotate secrets through pluggable providers behind one `Rotator`
   interface: `generate`, `http`, `script`, `vendor/github`,
   `vendor/gitlab`.
4. Manage rotator configuration as in-keychain companion entries
   (`<key>.rotator`), never on disk.
5. Add lifecycle surface: `audit`, `rotate --all --due`, `doctor`.
6. Keep the machine contract honest for agents: typed errors, stable JSON
   shapes, documented exit codes.

## 2. Current state (v0.1) — recalled for reference

- Secrets are stored in the macOS Keychain via the `security` CLI, but every
  key is *indexed* in `~/.config/keysec/keys.json` (or `$KEYSEC_HOME`).
- v0.1 key→Keychain mapping: part before the first dot becomes the Keychain
  *service*, the rest the *account*; dotless names use service `keysec`.
  e.g. `git.repo.flay.ai.root.keysec` → service `git`, account
  `repo.flay.ai.root.keysec`. (This is the one real secret on this machine:
  the repo.flay.ai GitLab token.)
- The lockfile's `lock()` op and most commands serialise around it.
- `list` combines the ledger with `store.Has` to compute a `STATE` column.
- `git-credential` helper derives keys via `gitcred.KeyFor`
  (`git.` + sanitised host + dot-joined path segments, `.git` stripped) and
  writes them through a shim that also upserts the ledger.
- `machine` defines kinds `not_found|locked|usage|invalid_key|io|internal`,
  exit code 2 for usage/invalid_key, 1 otherwise.

### Code archaeology (relevant seams)

- `internal/cmd/app.go` — `App{store, ledger, ui, prompts, stdin, shim}`;
  `New(store, led, out, prompts, stdin)`; `Execute` dispatch; `renderError`;
  `suggest(needle)` currently reads the ledger.
- `internal/key/key.go` — `Parse` → `{Name, Service, Account}`, regex
  `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`, max 255, `DefaultService = "keysec"`,
  split-on-first-dot.
- `internal/keychain/store.go` — `Store` interface
  `Put/Get/Delete/Has(ctx, service, account, value)`, errors
  `ErrNotFound/ErrLocked/ErrConflict`.
- `internal/keychain/security.go` — `Security` over `/usr/bin/security`,
  `Runner` seam, `devNullReader` to suppress interactive prompts.
- `internal/machine/machine.go` — kinds, `Error`, `Value`, `KeyInfo{name,
  saved, state}`, `List`, `Ack`.
- `internal/gitcred/protocol.go` — `KeyFor`, `sanitizeKeyPart`,
  percent-encoding.
- Tests: `fakeStore`, `testApp`, `newTestApp(t)` in `cmd_test.go`;
  `fakeStore`+`fakeLedger` in `shim_test.go`.

## 3. Storage model (v0.2)

**Every keysec key maps to one Keychain item:**

| Keychain field | Value |
|---|---|
| service | `keysec` (reserved, constant) |
| account | the full friendly key name, e.g. `gitlab.repo_flay` |

No `keys.json`, no `$KEYSEC_HOME`, no files anywhere. The keychain is the
only index and the only vault.

### Key names

- Alphabet: `[a-zA-Z0-9][a-zA-Z0-9._-]*`, max 255 chars.
- Reserved suffix: `.rotator`. `key.Parse` rejects any name ending in
  `.rotator`; these accounts are *companion/rotator spec* entries, never
  user keys.
- There is no longer a "dot = service" rule; dots are just name characters.

### Rotator companion entries

A key `foo` may have a companion at service `keysec`, account `foo.rotator`
holding the rotator spec as UTF-8 JSON. Specs are **non-secret** and are the
only thing `rotator get` prints raw. The companion never holds credentials —
second credentials are referenced by key name via `auth_key` and resolved at
rotate time.

### Enumeration

`keysec list` (and other commands) enumerate with:

```
security dump-keychain
```

Parsed in Go (no cgo) by splitting on block-start lines (`keychain: "…"`),
reading attribute lines by their ASCII-alias form:

- `"svce"<blob>="…"` → service
- `"acct"<blob>="…"` → account
- `"cdat"<timedate>=… "YYYYMMDDHHMMSSZ\000"` / `"mdat"<timedate>=…` → dates
- `"class"<blob>="genp"` → generic-password item

Filter to `svce == "keysec"`. Empirical facts (this machine, darwin 25.3.0):
`dump-keychain` redacts secrets — 350 items, **zero** password values and
zero non-null `0x00000010` attributes — so enumeration leaks nothing.

**Fail-loud sentinel:** if the dump yielded a non-empty number of item
blocks yet zero of them were parseable as keysec items, return
`ErrDumpFormat` instead of reporting an empty list. A format change must
crash loudly, not silently hide keys.

A companion `foo.rotator` contributes one entry; commands treat it as
companion metadata and never present it as a key.

## 4. Rotator system

### Interface

```go
type Rotator interface {
    Rotate(ctx context.Context, in Input) (Result, error)
}

type Input struct {
    Key        string            // friendly key name being rotated
    Value      string            // current secret value
    Credential string            // auth_key resolved value, else Value
    Meta       map[string]string // spec.meta + built-ins (see per-kind)
}

type Result struct {
    Value          string     // new secret; "" => reuse input.Value? (generate/http always set)
    ExpiresAt      *time.Time // nil = no known expiry
    OldValidUntil  *time.Time // when the previous value may be revoked/culled
    Warning        string     // advisory, printed but not fatal
}
```

### Atomicity (non-negotiable)

1. Provider runs first. If it fails, **nothing is written** to the keychain
   and the old value stays live.
2. Only after provider success is `store.Put(key, newValue)` executed.
3. Only after the value write succeeds is the spec state updated
   (`rotated_at`, `expires_at`, `old_valid_until`, `spec_updated_at`). If
   step 3's write fails, the rotation is still success — but emit a warning.

### Spec schema

```json
{
  "kind":             "generate | http | script | vendor/github | vendor/gitlab",
  "length":           32,              // generate
  "charset":          "…",             // generate (default: letters+digits)
  "url":              "https://…",     // http, templates {key} {value} {meta.K}
  "method":           "POST",          // http, default POST
  "auth":             "bearer | basic:<user> | header:<Name> | query:<name>", // http
  "auth_key":         "some.other.key",// any kind; resolved at rotate time
  "value":            "data.token",    // http/vendor: JSON dot-path into response
  "new_expires":      "data.expires_at", // http/vendor: dot-path (number s/ms or ISO 8601)
  "grace":            "24h",           // http/vendor: fallback when no old_valid_until
  "script":           "/abs/path",     // script: absolute script path
  "body":             "#!/bin/bash …", // script: inline body (wins over script)
  "interpreter":      "bash",          // script, default bash
  "timeout":          "30s",           // http/script
  "meta":             {"k": "v"},      // arbitrary config, passed through to providers
  "rotated_at":       "RFC3339",       // state, written by rotate
  "expires_at":       "RFC3339",       // state, written by rotate
  "old_valid_until":  "RFC3339",       // state, written by rotate
  "last_created_id":  "…",             // state, vendor adapters (revoke-old of a token we created)
  "spec_updated_at":  "RFC3339"        // state, written by every rotator set
}
```

### Kinds

#### `generate`
Cryptographically random bytes. `length` default 32. `charset` optional; the
default alphabet is `[A-Za-z0-9]`. Never reads `Value`. Result has no
expiry.

#### `http`
Perform one authenticated HTTP request described by the spec:
- URL and body templates: `{key}`, `{value}`, `{meta.<K>}`.
- Auth styles (all use `Credential`, never embed it in spec):
  - `bearer` → `Authorization: Bearer <credential>`
  - `basic:<user>` → `Authorization: Basic base64(user:credential)`
  - `header:<Name>` → `<Name>: <credential>`
  - `query:<name>` → query param `<name>=<credential>`
- Response handling, JSON:
  - `value` dot-path extracts the new secret (dot-path walks JS object keys,
    `data.token` → `{"data":{"token":…}}`); absent → trimmed whole body.
  - `new_expires` dot-path: number > 10^12 → ms, else seconds; ISO 8601
    string accepted.
  - `old_valid_until`: from `old_valid_until`/`grace`; default grace 24h.
- Non-2xx response → error carrying status + first 200 bytes of body.
- Request timeout: spec `timeout` (default 30s), applied via `ctx`.

#### `script`
Run an interpreter with the script body or run a script file:
- Inline body → envar-avoiding stdin pipe: `interpreter -s rotate`
  (default `bash -s rotate`).
- File → `script rotate` as argv `["<script>", "rotate"]`.
- Secrets travel by environment only, never argv/stdin:
  `KEYSEC_KEY`, `KEYSEC_VALUE`, and `KEYSEC_META_<UPPER_SNAKE>` per
  `meta` entry.
- Stdout: if it parses as JSON object with a usable form, read
  `{"value","expires_at","old_valid_until","meta"}`; otherwise the trimmed
  stdout is the new value (lenient).
- Non-zero exit → error including the last 200 bytes of stderr.
- Timeout default 30s; on timeout the process is killed.

#### `vendor/github`
Create a new GitHub fine-grained personal access token via the GitHub API,
using `Credential` as auth:
- `POST https://api.github.com/user/personal_access_tokens`
  body `{title, permissions, scopes, expiration}` (expiration `YYYY-MM-DD`,
  default 30 days, max 365). Config via spec `meta`
  (`title`, `permissions`, `scopes`, `expiration_days`).
- Response `{id, token, expires_at, …}` → new Value, `ExpiresAt`, and store
  `id` in state `last_created_id`.
- **Revoke-old caveat:** GitHub cannot revoke a PAT from its token string.
  A token **we created** (we know its `id`) is deleted on the next rotation
  via `DELETE /user/personal_access_tokens/{id}`; a pre-existing token is
  left to expire naturally. `OldValidUntil` is set accordingly.

#### `vendor/gitlab`
Create a new GitLab personal access token:
- `POST https://gitlab.example/api/v4/personal_access_tokens`
  header `PRIVATE-TOKEN: <credential>`, body
  `{name, scopes, expires_at}` from spec `meta` (`name`, `scopes`,
  `expiration_days`).
- Response `{id, token, expires_at, …}` → new Value + `ExpiresAt`; store
  `id` in `last_created_id`.
- Revoke the previous token **only if we created it** (state
  `last_created_id`): `DELETE /api/v4/personal_access_tokens/{id}`. First
  rotation is create-only.

Both vendor adapters are implemented against the documented API shapes and
tested with `httptest` mocks; live integration is opt-in and out of test
scope.

## 5. Commands

### `list`
- Enumerate service `keysec` (dump-parse). Exclude `.rotator` companions.
- Columns: `KEY`, `SAVED` (mdat day, `2026-09-05`), `ROTATES` (spec kind, or
  `—`).
- JSON:
  ```json
  {"count": 2, "keys": [{"name": "foo", "saved": "2026-09-05",
                        "rotates": "http"}]}
  ```
  (`state` field dropped.)
- If zero keys found **and** a legacy `keys.json` exists, print a hint:
  `run 'keysec doctor --migrate'`.

### `rm <key> [--yes]`
- Delete the secret *and* cascade its companion: remove both
  `foo` and `foo.rotator`.

### `rotate <key> [--plan]`
- `--plan`: dry run — print kind, target (url/script/vendor), resolved
  expiry, without calling the provider or writing to the keychain.
- Load spec companion; missing spec → `not_found` error with
  hint `keysec rotator set <key> ...`.
- Read current value from keychain (must exist).
- Resolve `Credential`: `auth_key` value if set, else current value.
- Dispatch rotator → write value → update spec state (warn on state write
  failure).
- Human: `✓ rotated <key>` + expiry line. JSON:
  ```json
  {"ok": true, "action": "rotated", "key": "foo",
   "rotated_at": "…", "expires_at": "…", "old_valid_until": "…"}
  ```
- Provider failure → error kind `rotation`, exit 1, keychain untouched.

### `rotate --all [--due] [--dry-run]`
- `--all`: rotate every key that has a rotator.
- `--due` (default when neither flag given): rotate keys whose spec state
  `expires_at` is set and `expires_at <= now`. Keys with no expiry state are
  skipped (they are not "due").
- `--dry-run`: report what *would* rotate, change nothing.
- Failure on one key does not abort the rest; each key reports success or a
  typed error, and the process exits 1 if any failed. JSON summarizes:

  ```json
  {"ok": false, "action": "rotated", "rotated": [{"key": "…", "rotated_at": "…"}],
   "failed": [{"key": "…", "error": "rotation", "message": "…"}]}
  ```

### `rotator get <key> [--json]`
Print the (non-secret) spec. Human: readable key/value lines. JSON:
`{"name": "foo", "spec": {…}}`.

### `rotator set <key>` (merge) / `rotator set <key> --spec '<json>'`
Merge semantics: load existing spec, apply only the provided fields, keep
the rest. Changing `kind` resets kind-specific fields but preserves common
`grace`/`timeout`/`meta`. Flags:

```
--kind generate|http|script|vendor/github|vendor/gitlab  (required on first set)
--url --method --auth --auth-key --value --new-expires --grace
--script --body --body-file --interpreter --timeout
--length --charset
--meta k=v        (repeatable)
--spec '<json>'   (wholesale replace, overrides all flags)
```

`--body-file -` reads stdin. Validates the assembled spec; sets
`spec_updated_at`. JSON ack `{"ok": true, "action": "rotator.set",
"key": "foo"}`.

### `rotator rm <key> [--yes]`
Remove only the companion (`foo.rotator`). The secret itself is untouched.

### `doctor [--migrate] [--yes]`
- Without `--migrate`: health report — keychain readable (dump parses, or
  a probe Put/Get/Delete of a transient probe key), count of keys under
  service `keysec`, orphan companions (`.rotator` without a parent),
  presence of a legacy `keys.json`.
- With `--migrate`: perform the v0.1 → v0.2 migration (see §6), then delete
  `keys.json` only after every move succeeded.
- `--yes` suppresses the confirmation prompt for the migration.

### `audit [--json]`
Enumerate keys and their specs; report lifecycle status per key:
`OK` (expires later), `EXPIRES_SOON` (within `--within`, default 14d),
`EXPIRED` (`expires_at < now`), `NEVER_EXPIRES` (rotator with no expiry
info), `NO_ROTATOR`. Keys without a rotator are listed as `NO_ROTATOR`
(searchable via JSON). Human: table with statuses; JSON:
```json
{"count": 2, "keys": [{"name": "foo", "saved": "…", "rotates": "http",
                       "status": "EXPIRES_SOON", "expires_at": "…"}]}
```
Exit 0 (pure report).

### `git-credential`
Unchanged protocol (`protocol.go` untouched, `KeyFor` unchanged) — but the
shim drops its ledger dependency entirely.

### `help` / exit codes
Document all new commands in help. Exit codes: 0 success; 1 runtime
(including `locked`, `io`, `internal`, and **`rotation`**); 2 usage /
invalid key; `rotate --all` = 1 if any key failed, else 0.

## 6. Migration (v0.1 → v0.2)

Run by `doctor --migrate`:

1. Locate legacy `keys.json` (`$KEYSEC_HOME/keys.json` or
   `~/.config/keysec/keys.json`). Absent → nothing to do.
2. For each legacy entry `{name, created, updated}`:
   - Old coordinates (v0.1 rule): no dot → service `keysec`, account `name`;
     dot → service = part before first dot, account = rest.
   - New coordinates: service `keysec`, account = full `name`.
   - Skip + warn if `name` ends in `.rotator` (reserved) or if the target
     already exists as a keysec key with a different... value — conservative:
     skip + warn if `Has(new)` is true.
   - Else `Get(old)` → `Put(new)` → `Delete(old)`.
3. Only when every move succeeded: delete `keys.json` and the empty
   directory if it becomes empty.
4. Report moved / skipped counts.

Real impact on this machine: `git.repo.flay.ai.root.keysec` moves from
service `git` / account `repo.flay.ai.root.keysec` to service `keysec` /
account `git.repo.flay.ai.root.keysec`.

## 7. Machine layer changes

- New kind: `KindRotation = "rotation"` (runtime, exit 1).
- `KeyInfo`: `{name, saved, rotates}` — `state` removed.
- New shapes: `RotateAck` (§5), bulk summary (§5 rotate --all), `Audit`
  (§5), `RotatorAck` (`rotator set/rm`).
- `gitcred.Shim`: `New(store)` only; `LedgerLike` removed.
- `App`: `New(store, enum, out, prompts, stdin)`; `suggest` lists via `enum`.

## 8. Explicitly cut (not in this release)

- cgo enumerator backend. (Chosen: dump-parse + fail-loud sentinel.)
- HTTP `cleanup` request (revoke) — the `old_valid_until`/grace mechanics
  and vendor adapters cover the same need; revisit later.
- Structured/JSON secret values (only string values).
- Any non-Darwin platform or `security`-equivalent backends.
- `rotate --all` scheduling daemon or persistence of "last success" beyond
  the spec state fields.

## 9. Testing strategy

- Unit: key names (`.rotator` rejection, charset), dump parser against
  fixture text (block boundaries, ASCII-alias attrs, `cdat`/`mdat`,
  sentinel firing), date parsing, dot-path extraction.
- Rotators: `generate` determinism, `http` against `httptest` (auth styles,
  templates, value/new_expires paths, non-2xx, timeout), `script` with a
  fake interpreter (`sh -c '…'` recording env) covering JSON and lenient
  stdout, vendor/github and vendor/gitlab against `httptest` mocks
  (create, revoke-own-previous, first-rotation create-only).
- Spec merge: field semantics, kind-switch reset preserving grace/timeout/
  meta.
- cmd: `fakeStore` + new `fakeEnum`; `list` companions/ROTATES col,
  `rm` cascade, `rotate --plan` no-write, `rotate` failure leaves vault
  untouched, `doctor --migrate` moves + deletes keys.json, `audit` statuses.
- End-to-end on the real keychain (manual): reinstall, `doctor --migrate`,
  `list`, `get`, `rotate`.