#!/usr/bin/env python3
"""Dummy rotation backend used to exercise keysec's `script` rotator.

Listens on 127.0.0.1 and answers two endpoints:

  GET  /ping            -> 200 {"ok": true, "service": "keysec-dummy-rotate"}
  POST /rotate          -> body {"key": "...", "old_value": "..."}
        200 {"password": "<new 32-byte secret>", "expires_at": "<ISO +30 days>"}
        401 {"error": "old value mismatch"}

The response shape is intentionally arbitrary: the script that calls this
server is responsible for adapting the reply into keysec's own stdout
contract. The server does not know keysec exists; it just models a real
password service that insists the caller proves it still holds the current
value before issuing a new one.

Standard library only (no pip dependencies).
"""

import argparse
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class Mismatch(Exception):
    pass


class RotationStore:
    """One current password per key. The first rotation for a key accepts any
    old value (create); after that the old value must match the current one."""

    def __init__(self):
        self._passwords = {}

    def rotate(self, key, old_value):
        if key in self._passwords and self._passwords[key] != old_value:
            raise Mismatch()
        self._passwords[key] = secrets.token_urlsafe(32)
        return {
            "password": self._passwords[key],
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        }


MAX_BODY = 1 << 16


class Handler(BaseHTTPRequestHandler):
    store = RotationStore()

    def do_GET(self):
        if urlparse(self.path).path == "/ping":
            self._json(200, {"ok": True, "service": "keysec-dummy-rotate"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/rotate":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > MAX_BODY:
                self._json(400, {"error": "bad Content-Length"})
                return
            payload = json.loads(self.rfile.read(length))
            key = str(payload.get("key", ""))
            old_value = str(payload.get("old_value", ""))
            if not key:
                self._json(400, {"error": "key required"})
                return
            try:
                self._json(200, self.store.rotate(key, old_value))
            except Mismatch:
                self._json(401, {"error": "old value mismatch"})
        except (json.JSONDecodeError, ValueError):
            self._json(400, {"error": "invalid JSON"})

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    print("dummy rotation server on %s:%d (Ctrl-C to stop)" % (args.host, args.port),
          file=sys.stderr)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()