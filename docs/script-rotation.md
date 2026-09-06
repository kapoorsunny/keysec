# keysec `script` rotator — contract and live test

The `script` rotator runs *your program* to produce a new value for a
secret. This document pins down the one contract keysec cares about (keysec
↔ script) and why there is deliberately **no schema for the server** a script
talks to. A live, end-to-end test lives under `test/`.

## The two interfaces

```
                  keysec ↔ script (a real contract)
 +---------+   env in, stdout out    +-----------+  any HTTP shape  +--------+
 | keysec  | ----------------------> |  script   | ---------------> | server |
 +---------+                         +-----------+ <--------------- +--------+
                                     (the adapter)   whatever it    (your own
                                      parses the reply    returns     backend)
```

- **Interface A — keysec ↔ script: the contract.** Fixed, documented, tested
  (`internal/rotator/script.go`, unit-tested with a fake interpreter). This is
  the only thing a script author must implement.
- **Interface B — script ↔ server: no schema.** The script owns request
  shape, authentication and parsing of its server's reply. That is the point
  of `script`: arbitrary backends. Baking a server-side schema in would just
  re-create a vendor adapter.

## Interface A — what keysec guarantees

Invocation (one `rotate` action):

| Spec | Command |
|---|---|
| `--script <path>` (file) | runs `<path> rotate` |
| `--body` (inline) | runs `<interpreter> -s rotate` (default `bash`) |

Environment (secrets travel by environment only, never argv/stdin):

| Variable | Meaning |
|---|---|
| `KEYSEC_KEY` | the key being rotated |
| `KEYSEC_VALUE` | the current value of that key |
| `KEYSEC_META_<UPPER_SNAKE>` | one per spec `meta` entry (e.g. `--meta url=x` → `KEYSEC_META_URL=x`) |

Stdout contract, in order of preference:

1. A JSON object, parsed when it has a usable field:

   | Field | Meaning |
   |---|---|
   | `value` | the new secret (**required**) |
   | `expires_at` | RFC 3339, `YYYY-MM-DD`, or unix seconds (optional) |
   | `old_valid_until` | when the previous value may be culled (optional) |
   | `meta` | returned to keysec (ignored by providers today) |

2. Otherwise the whole trimmed stdout is taken as the new value (lenient).

Failure: non-zero exit (or a JSON with no usable `value`) → rotation error,
keychain untouched. Timeout defaults to 30s and kills the process group.

## Why no server schema

A "schema for what we expect from the server" would force every internal
service to adopt keysec's vocabulary. Instead the script is the adapter: it
translates *its* backend's reply into Interface A. That keeps `script`
general and the responsibility boundary explicit — keysec never sees the
server.

## The live test (`test/`)

Fixtures:

| File | Role |
|---|---|
| `test/dummy_rotate_server.py` | a fake password service: `POST /rotate` returns `{"password", "expires_at"}` (a deliberately *different* shape) and rejects stale `old_value` with 401 |
| `test/rotate_dummy.py` | the keysec script (the adapter): reads `KEYSEC_KEY`/`KEYSEC_VALUE`/`KEYSEC_META_URL`, calls the server, reshapes the reply into Interface A's `{"value", "expires_at"}` JSON |
| `test/run-script-rotation.sh` | harness: boots the server, sets a key + `script` rotator, rotates twice, cleans up |

Run it:

```bash
test/run-script-rotation.sh            # or: test/run-script-rotation.sh 8799
```

What it proves, by rotating the same key **twice**:

1. **First rotation (create):** the seed value is passed to the script as
   `KEYSEC_VALUE`; the server accepts it because it has never seen the key.
2. **Second rotation (old-value chaining):** the server now insists the
   submitted `old_value` equals the current password — so the rotation only
   succeeds if keysec handed the script the value the *first* rotation just
   produced. This is the real end-to-end proof that the script path carries
   values through the Keychain correctly.

Manual steps (what the harness runs, minus the server boot):

```bash
keysec set dummy.rotating "seed"
keysec rotator set dummy.rotating --kind script \
    --script "$(pwd)/test/rotate_dummy.py" \
    --meta url=http://127.0.0.1:8765
keysec rotate dummy.rotating
keysec rotate dummy.rotating        # proves old-value chaining
keysec rm dummy.rotating --yes
```