# -*- coding: utf-8 -*-
"""Four locks for a localhost endpoint that can run code.

Read this part even if you skip the rest of the package.

The setup
---------
You have a small HTTP server on 127.0.0.1 so your own dashboard can talk to
your agent. One of its routes starts a coding assistant with file-write and
shell permissions. It is on loopback, so it is private. There is no login,
because who would you log in as?

This is an extremely common shape, and by default it is remote code execution
on your workstation, triggerable by any web page you happen to have open.

Why "it's only on localhost" is not a control
---------------------------------------------
A page on `evil.example` can issue `fetch("http://127.0.0.1:8000/api/run",
{method:"POST", mode:"no-cors", body:...})`. It cannot read your response —
the same-origin policy holds there. It does not need to. **The side effect
still happens.** The request arrives, your route runs, the assistant writes
files. The attacker never sees a byte and does not care.

Four locks, and why three is not enough
---------------------------------------
**1. A custom request header.** Require something like `X-Agent: 1`. A
cross-origin `fetch` that sets a non-safelisted header must first send a
CORS preflight `OPTIONS`; if you never answer preflights, the real request is
never sent. Cheap and effective — against browsers.

**2. `Sec-Fetch-Site` and `Origin`.** Browsers attach `Sec-Fetch-Site`
themselves and scripts cannot forge it. Reject anything that is not
`same-origin` or `none`.

**3. `Host` must be a literal address.** This is the lock people miss, and it
was missed here too until a proof-of-concept demonstrated it.

    Locks 1 and 2 are both defeated by DNS rebinding. The attacker's domain
    resolves, on the second lookup, to 127.0.0.1. The attacker's page is now
    same-origin *with respect to itself*, so `Sec-Fetch-Site: same-origin` is
    attached honestly, the custom header can be set with no preflight, and a
    naive check of `Origin == "http://" + Host` passes — because both sides
    are the attacker's domain and they match each other perfectly.

    Every header-based lock agrees. The request is malicious.

    The one thing rebinding cannot do is put a bare IP in `Host`: rebinding
    works *through a name*, so `Host` always carries the domain. Requiring
    `Host` to be an IP literal or `localhost` is the only place the two cases
    diverge.

**4. The peer address.** All three above are things the *client says*. `curl`
says whatever you like. The moment the server is bound to anything wider than
loopback — a `--lan` flag for reading a panel from a phone, a container
publishing `0.0.0.0` — one line of `curl` from anywhere on the network passes
locks 1 through 3 trivially. The only fact the client cannot author is which
socket the connection actually arrived on. Check `client_address`.

Locks 1 to 3 are header inspection. Lock 4 is provenance. You need both,
because headers are a claim and the peer address is evidence.

Scope
-----
Apply this to routes with side effects. Plain `GET` on read-only pages can
stay open if you want a phone to load the dashboard over the LAN; it is the
mutating and executing routes that must be loopback-only.

Usage
-----
    from agentbus.loopback import LoopbackGuard

    guard = LoopbackGuard(custom_header="X-Agent")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            ok, reason = guard.check(self.headers, self.client_address[0])
            if not ok:
                return self.send_error(403)     # log `reason`; do not return it
            ...

Do not return the reason to the caller. "Wrong header" versus "wrong host"
versus "wrong peer" is a free map of your defences. Log it; serve a flat 403.

MIT licensed. Part of `agentbus`.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Mapping, Optional, Tuple

__all__ = ["host_is_literal", "addr_is_loopback", "LoopbackGuard", "GuardResult"]


# ══════════════════════════════════════════════════════════════ primitives ══
def host_is_literal(host: str) -> bool:
    """True when the `Host` header carries an IP literal or `localhost`.

    A domain name here is the signature of DNS rebinding: rebinding operates
    through a name, so the name is always what lands in `Host`. Legitimate
    local traffic reaches you as `127.0.0.1:8000`, `[::1]:8000`, or
    `localhost:8000`.

    Handles the three shapes: `h`, `h:port`, and `[v6]:port`.
    """
    if not host:
        return False
    host = host.strip()
    if host.startswith("["):                       # [::1] or [::1]:8000
        end = host.find("]")
        h = host[1:end] if end > 0 else ""
    elif host.count(":") == 1:                     # 127.0.0.1:8000 or name:8000
        h = host.rsplit(":", 1)[0]
    else:                                          # bare name, or bare IPv6
        h = host
    if h == "localhost":
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def addr_is_loopback(addr: str) -> bool:
    """True when the peer address is this machine. Unwraps IPv4-mapped IPv6.

    A connection from `::ffff:127.0.0.1` is a loopback connection wearing an
    IPv6 costume; `ipaddress` will not call it loopback until it is unmapped.
    Also strips the `%en0` zone suffix that link-local addresses carry.
    """
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(str(addr).split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_loopback)


# ═════════════════════════════════════════════════════════════════ result ══
class GuardResult(tuple):
    """`(ok, reason)` — truthy on pass, with the failing lock named for the log."""

    __slots__ = ()

    def __new__(cls, ok: bool, reason: str = ""):
        return super().__new__(cls, (bool(ok), reason))

    @property
    def ok(self) -> bool:
        return self[0]

    @property
    def reason(self) -> str:
        return self[1]

    def __bool__(self) -> bool:
        return self[0]


# ══════════════════════════════════════════════════════════════════ guard ══
class LoopbackGuard:
    """The four locks, in the order that fails cheapest first.

    Args:
        custom_header:  header name required on every guarded request. Any
                        non-safelisted name works; it exists to force a CORS
                        preflight that you never answer.
        require_peer:   check the socket peer (lock 4). Leave this on. Turning
                        it off is only defensible behind a reverse proxy that
                        does its own authentication, and in that case the proxy
                        connects from loopback anyway, so you still do not need
                        to turn it off.
        allow_missing_sec_fetch:
                        older clients omit `Sec-Fetch-Site`. Default True
                        accepts absence but still requires `Origin` (when
                        present) to be a loopback literal matching `Host`.
                        Set False to reject any client that does not send it.
    """

    def __init__(
        self,
        custom_header: str = "X-Agent",
        require_peer: bool = True,
        allow_missing_sec_fetch: bool = True,
    ) -> None:
        self.custom_header = custom_header
        self.require_peer = require_peer
        self.allow_missing_sec_fetch = allow_missing_sec_fetch

    def check(self, headers: Mapping[str, Any], peer_addr: Optional[str]) -> GuardResult:
        """Evaluate all four locks. Returns `(ok, reason)`; never raises."""
        get = headers.get

        # Lock 4 first: it is the only one the client cannot author, and it is
        # a single comparison. Evidence before claims.
        if self.require_peer and not addr_is_loopback(peer_addr or ""):
            return GuardResult(False, "peer %r is not loopback" % (peer_addr,))

        # Lock 2a: Sec-Fetch-Site. Browser-set, script-unforgeable.
        site = str(get("Sec-Fetch-Site") or "").lower()
        if site:
            if site not in ("same-origin", "none"):
                return GuardResult(False, "Sec-Fetch-Site=%s" % site)
        elif not self.allow_missing_sec_fetch:
            return GuardResult(False, "Sec-Fetch-Site absent")

        # Lock 3: Host must be a literal. This is the anti-rebinding lock.
        host = str(get("Host") or "").strip()
        if not host_is_literal(host):
            return GuardResult(False, "Host %r is not a loopback literal" % host)

        # Lock 2b: Origin, when present, must itself be a literal AND match Host.
        # Both halves are needed. Matching alone passes rebinding, because the
        # attacker's domain matches the attacker's domain.
        origin = str(get("Origin") or "").strip()
        if origin:
            oh = origin.split("://", 1)[-1]
            if not host_is_literal(oh):
                return GuardResult(False, "Origin %r is not a loopback literal" % origin)
            if oh != host:
                return GuardResult(False, "Origin %r != Host %r" % (oh, host))

        # Lock 1: the custom header, which forces a preflight we never answer.
        if self.custom_header and not get(self.custom_header):
            return GuardResult(False, "missing %s" % self.custom_header)

        return GuardResult(True, "")

    # ------------------------------------------------------------- integration
    def wrap_handler(self, handler_cls, methods=("POST", "PUT", "PATCH", "DELETE")):
        """Return a subclass of a `BaseHTTPRequestHandler` with the guard applied.

        Guards the mutating verbs by default and leaves `GET` alone, so a phone
        on the LAN can still load a read-only panel while nothing on the LAN can
        make the machine do anything.
        """
        guard = self

        class Guarded(handler_cls):  # type: ignore[misc,valid-type]
            def _guard_ok(self) -> bool:
                res = guard.check(self.headers, (self.client_address or ("",))[0])
                if not res.ok:
                    self.log_message("guard refused: %s", res.reason)
                    # Flat 403. The caller learns nothing about which lock held.
                    self.send_error(403, "Forbidden")
                    return False
                return True

        for verb in methods:
            name = "do_" + verb.upper()
            inner = getattr(handler_cls, name, None)
            if inner is None:
                continue

            def make(inner_fn):
                def wrapper(self):
                    if not self._guard_ok():
                        return None
                    return inner_fn(self)

                return wrapper

            setattr(Guarded, name, make(inner))

        Guarded.__name__ = "Guarded" + handler_cls.__name__
        return Guarded
