#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stand up a vulnerable localhost agent endpoint, attack it, then fix it.

This runs for real. It binds an actual HTTP server to 127.0.0.1 on an
ephemeral port, sends actual HTTP requests over actual sockets, and reports
whether the "run this code" route fired -- measured by a canary file appearing
on disk, not by reading the response.

Nothing leaves the machine. Nothing binds beyond loopback. The one case that
cannot be produced honestly on loopback -- a request arriving from the LAN --
is simulated by overriding the peer address the socket layer reports, which is
exactly what the guard reads, so the simulation is faithful where it matters.

    $ python3 examples/rce_demo.py

    ── NAIVE GUARD (custom header + Sec-Fetch-Site + Origin == Host) ──
      cross-site POST, no custom header               blocked   ok
      cross-site POST, custom header set              blocked   ok
      old browser: no Sec-Fetch, foreign Origin       blocked   ok
      DNS rebinding: Host carries a domain name       RAN CODE  <-- breach
      LAN peer with perfectly forged headers          RAN CODE  <-- breach
      the real dashboard, same-origin over loopback   ran       ok

    ── LoopbackGuard (all four locks) ──
      ... all six correct ...

The two breaches are the point. Both requests are indistinguishable from
legitimate traffic by header inspection alone.

MIT licensed. Part of `agentbus`.
"""
from __future__ import annotations

import http.server
import os
import socket
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentbus.loopback import LoopbackGuard  # noqa: E402

CANARY = os.path.join(tempfile.mkdtemp(prefix="agentbus-demo-"), "code-ran")

# The peer address the handler will claim to see. `None` means "tell the truth".
SPOOF_PEER = [None]


def naive_check(headers, peer):
    """The three-lock guard most people write first. Reasons only about claims."""
    site = str(headers.get("Sec-Fetch-Site") or "").lower()
    if site and site not in ("same-origin", "none"):
        return False
    host = str(headers.get("Host") or "")
    origin = str(headers.get("Origin") or "")
    if origin and origin != "http://" + host:
        return False
    return bool(headers.get("X-Agent"))


def make_handler(check):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        @property
        def _peer(self):
            return SPOOF_PEER[0] or (self.client_address or ("",))[0]

        def do_POST(self):
            if not check(self.headers, self._peer):
                self.send_response(403)
                self.end_headers()
                return
            # This stands in for "start an assistant with shell and file-write
            # permissions". The canary is how we detect the side effect without
            # trusting anything the response says.
            with open(CANARY, "w") as f:
                f.write("x")
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    return H


def serve(check):
    srv = http.server.HTTPServer(("127.0.0.1", 0), make_handler(check))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def fire(port, headers, body=b"{}"):
    """Raw HTTP over a real socket, so the headers are exactly what we typed."""
    lines = ["POST /run HTTP/1.0"]
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    lines.append("Content-Length: %d" % len(body))
    req = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(req)
        s.recv(64)
    finally:
        s.close()


CASES = [
    ("cross-site POST, no custom header",
     {"Sec-Fetch-Site": "cross-site", "Host": "127.0.0.1", "Origin": "https://evil.example"},
     None, False),
    ("cross-site POST, custom header set",
     {"Sec-Fetch-Site": "cross-site", "Host": "127.0.0.1",
      "Origin": "https://evil.example", "X-Agent": "1"}, None, False),
    ("old browser: no Sec-Fetch, foreign Origin",
     {"Host": "127.0.0.1", "Origin": "https://evil.example", "X-Agent": "1"}, None, False),
    ("DNS rebinding: Host carries a domain name",
     {"Sec-Fetch-Site": "same-origin", "Host": "evil.example",
      "Origin": "http://evil.example", "X-Agent": "1"}, None, False),
    ("LAN peer with perfectly forged headers",
     {"Sec-Fetch-Site": "same-origin", "Host": "127.0.0.1",
      "Origin": "http://127.0.0.1", "X-Agent": "1"}, "192.168.1.44", False),
    ("the real dashboard, same-origin over loopback",
     {"Sec-Fetch-Site": "same-origin", "Host": "127.0.0.1",
      "Origin": "http://127.0.0.1", "X-Agent": "1"}, None, True),
]


def run(title, check):
    print("\n── %s ──" % title)
    srv = serve(check)
    port = srv.server_address[1]
    breaches = 0
    try:
        for name, headers, peer, should_run in CASES:
            # Host must carry the real port or the server rejects the request
            # before the guard ever sees it; keep the *name* the attacker chose.
            h = dict(headers)
            h["Host"] = "%s:%d" % (h["Host"], port)
            if h.get("Origin"):
                h["Origin"] = h["Origin"] + (":%d" % port if "evil.example" in h["Origin"]
                                             or "127.0.0.1" in h["Origin"] else "")
            if os.path.exists(CANARY):
                os.unlink(CANARY)
            SPOOF_PEER[0] = peer
            fire(port, h)
            ran = os.path.exists(CANARY)
            if ran == should_run:
                verdict = "ran     " if ran else "blocked "
                note = "ok"
            else:
                verdict = "RAN CODE" if ran else "BLOCKED "
                note = "<-- breach" if ran else "<-- broke the real client"
                breaches += 1
            print("  %-46s %s %s" % (name, verdict, note))
    finally:
        SPOOF_PEER[0] = None
        srv.shutdown()
        srv.server_close()
    return breaches


def main():
    print(__doc__.split("    $ ")[0].strip())
    naive = run("NAIVE GUARD (custom header + Sec-Fetch-Site + Origin == Host)", naive_check)
    guard = LoopbackGuard(custom_header="X-Agent")
    hard = run("LoopbackGuard (all four locks)", lambda h, p: guard.check(h, p).ok)

    print("\n── result ──")
    print("  naive guard:   %d of %d cases wrong" % (naive, len(CASES)))
    print("  LoopbackGuard: %d of %d cases wrong" % (hard, len(CASES)))
    if os.path.exists(CANARY):
        os.unlink(CANARY)
    os.rmdir(os.path.dirname(CANARY))
    if hard != 0:
        return 1
    if naive == 0:
        print("\n  WARNING: the naive guard passed everything. The control is no longer")
        print("  a control -- check that the cases still model the real attacks.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
