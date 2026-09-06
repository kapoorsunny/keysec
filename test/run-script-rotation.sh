#!/usr/bin/env bash
# End-to-end exercise of keysec's `script` rotator against the dummy Python
# rotation server (docs/script-rotation.md). Rotates the same key twice:
# the second rotation only succeeds if keysec handed the script the value
# the first rotation just produced (the server rejects stale old values).
#
# Usage: test/run-script-rotation.sh [port]       (default port 8765)

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8765}"
URL="http://127.0.0.1:${PORT}"
KEY="dummy.rotating"

command -v keysec >/dev/null 2>&1 || { echo "keysec not on PATH (is it installed?)" >&2; exit 1; }

"${DIR}/dummy_rotate_server.py" --port "${PORT}" &
SRV=$!
trap 'kill "${SRV}" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
    curl -sf "${URL}/ping" >/dev/null 2>&1 && break
    sleep 0.1
done
echo "== server up at ${URL}"

# Fresh key with a first value (the server treats the first rotation for a
# key as a create, accepting any old value).
keysec rm "${KEY}" --yes >/dev/null 2>&1 || true
keysec set --json "${KEY}" "initial-password-${RANDOM}" >/dev/null

# Point the key's rotator at the Python client script; it is the adapter
# that decodes whatever the server returns.
keysec rotator set "${KEY}" --kind script \
    --script "${DIR}/rotate_dummy.py" \
    --meta url="${URL}"

echo "== first rotation (create: server accepts the seed value)"
keysec rotate "${KEY}" --json
v1=$(keysec get "${KEY}")

echo "== second rotation (server insists on the CURRENT value)"
keysec rotate "${KEY}" --json
v2=$(keysec get "${KEY}")

if [ -z "${v1}" ] || [ -z "${v2}" ] || [ "${v1}" = "${v2}" ]; then
    echo "FAIL: rotations did not advance the secret" >&2
    exit 1
fi

echo "OK: two rotations through the script rotator succeeded."
echo "    The second rotation used the first rotation's new value (old-value chaining)."

keysec rm "${KEY}" --yes >/dev/null
echo "== cleaned up (removed '${KEY}' and its rotator)"