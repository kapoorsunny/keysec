#!/usr/bin/env python3
"""Client script for keysec's `script` rotator (see docs/script-rotation.md).

keysec runs this as:
    rotate_dummy.py rotate

with these variables in the environment:
    KEYSEC_KEY         the key being rotated
    KEYSEC_VALUE       the current value of that key
    KEYSEC_META_<NAME> each spec meta entry (here KEYSEC_META_URL)

The script asks the dummy rotation server for a new password and emits
keysec's stdout contract on stdout:
    {"value": "...", "expires_at": "...", "old_valid_until": "..."}

This script is the adapter: it owns how it talks to the server (URL, payload,
parsing). The server's reply shape is none of keysec's business — keysec only
ever reads this script's stdout.
"""

import json
import os
import sys
import urllib.error
import urllib.request


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "rotate"
    if action != "rotate":
        sys.stderr.write("unknown action %r (keysec runs scripts with 'rotate')\n" % action)
        return 2
    key = os.environ.get("KEYSEC_KEY", "")
    old_value = os.environ.get("KEYSEC_VALUE", "")
    url = os.environ.get("KEYSEC_META_URL", "http://127.0.0.1:8765").rstrip("/")
    if not key:
        sys.stderr.write("KEYSEC_KEY is empty\n")
        return 1

    body = json.dumps({"key": key, "old_value": old_value}).encode()
    request = urllib.request.Request(url + "/rotate", data=body,
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            reply = json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:200]
        sys.stderr.write("server rejected rotation: %d %s\n" % (exc.code, detail))
        return 1
    except urllib.error.URLError as exc:
        sys.stderr.write("cannot reach rotation server at %s: %s\n" % (url, exc.reason))
        return 1

    if "password" not in reply:
        sys.stderr.write("server reply has no 'password': %r\n" % reply)
        return 1
    # Adapt the server's shape into keysec's stdout contract.
    print(json.dumps({"value": reply["password"],
                      "expires_at": reply.get("expires_at")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())