# -*- coding: utf-8 -*-
"""Invariants for LoopbackGuard, with a negative control that must go red.

The point of this file is not that `LoopbackGuard` passes. Any test the
implementation was written against will pass; that proves nothing. The point
is `test_negative_control_naive_guard_is_defeated`, which runs the *same*
invariants against the obvious three-lock implementation people actually
write, and asserts that it is defeated by DNS rebinding.

If a change to the guard ever made the naive version pass too, the negative
control fails, and you learn that the test suite has stopped measuring
anything. A suite with no failing control is measuring the tests, not the code.

Run:  python3 -m pytest tests/ -q      (or: python3 tests/test_loopback.py)
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentbus.loopback import LoopbackGuard, addr_is_loopback, host_is_literal  # noqa: E402

LOOPBACK = "127.0.0.1"
LAN = "192.168.1.44"


# ═══════════════════════════════════════════════════════════ the six cases ══
# Each case is (name, headers, peer, must_pass). They model how the request
# actually arrives, not how the implementation happens to be structured.
CASES = [
    (
        "cross-site POST, no custom header",
        {"Sec-Fetch-Site": "cross-site", "Host": "127.0.0.1:8000",
         "Origin": "https://evil.example"},
        LOOPBACK,
        False,
    ),
    (
        "cross-site POST, custom header set",
        {"Sec-Fetch-Site": "cross-site", "Host": "127.0.0.1:8000",
         "Origin": "https://evil.example", "X-Agent": "1"},
        LOOPBACK,
        False,
    ),
    (
        "old browser: no Sec-Fetch, foreign Origin",
        {"Host": "127.0.0.1:8000", "Origin": "https://evil.example", "X-Agent": "1"},
        LOOPBACK,
        False,
    ),
    (
        # The one that defeats header-only defences. The attacker's domain now
        # resolves to 127.0.0.1, so the page is same-origin with itself: the
        # browser honestly reports same-origin, the custom header needs no
        # preflight, and Origin matches Host exactly -- both being evil.example.
        # Only "Host must be an IP literal" separates this from real traffic.
        "DNS rebinding: Host carries a domain name",
        {"Sec-Fetch-Site": "same-origin", "Host": "evil.example:8000",
         "Origin": "http://evil.example:8000", "X-Agent": "1"},
        LOOPBACK,
        False,
    ),
    (
        # curl from the LAN. Every header is whatever the attacker typed.
        "LAN peer with perfectly forged headers",
        {"Sec-Fetch-Site": "same-origin", "Host": "127.0.0.1:8000",
         "Origin": "http://127.0.0.1:8000", "X-Agent": "1"},
        LAN,
        False,
    ),
    (
        "the real dashboard, same-origin over loopback",
        {"Sec-Fetch-Site": "same-origin", "Host": "127.0.0.1:8000",
         "Origin": "http://127.0.0.1:8000", "X-Agent": "1"},
        LOOPBACK,
        True,
    ),
]


def _run(check, cases=CASES):
    """Returns {name: (got, want)} for every case."""
    return {name: (bool(check(h, p)), want) for name, h, p, want in cases}


# ═══════════════════════════════════════════════════════════════ the guard ══
def test_guard_holds_all_six():
    guard = LoopbackGuard(custom_header="X-Agent")
    for name, (got, want) in _run(lambda h, p: guard.check(h, p).ok).items():
        assert got == want, "%s: got %s, want %s" % (name, got, want)


def test_ipv6_loopback_and_mapped_forms_pass():
    guard = LoopbackGuard(custom_header="X-Agent")
    for peer in ("::1", "::ffff:127.0.0.1", "127.0.0.1"):
        h = {"Sec-Fetch-Site": "same-origin", "Host": "[::1]:8000", "X-Agent": "1"}
        assert guard.check(h, peer).ok, peer


def test_reason_is_specific_for_the_log():
    guard = LoopbackGuard(custom_header="X-Agent")
    res = guard.check({"Sec-Fetch-Site": "same-origin", "Host": "evil.example:8000",
                       "X-Agent": "1"}, LOOPBACK)
    assert not res.ok
    assert "Host" in res.reason


def test_host_literal_shapes():
    assert host_is_literal("127.0.0.1:8000")
    assert host_is_literal("localhost:8000")
    assert host_is_literal("[::1]:8000")
    assert host_is_literal("203.0.113.5")      # any literal, not just loopback
    assert not host_is_literal("evil.example:8000")
    assert not host_is_literal("localhost.evil.example")
    assert not host_is_literal("")


def test_peer_forms():
    assert addr_is_loopback("127.0.0.1")
    assert addr_is_loopback("::1")
    assert addr_is_loopback("::ffff:127.0.0.1")
    assert addr_is_loopback("fe80::1%en0") is False
    assert not addr_is_loopback("192.168.1.44")
    assert not addr_is_loopback("")


# ══════════════════════════════════════════════════════ the negative control ══
def naive_check(headers, peer):
    """The three-lock guard almost everyone writes first.

    Custom header, Sec-Fetch-Site, and `Origin == "http://" + Host`. It looks
    complete. It reasons entirely about what the client says.
    """
    site = str(headers.get("Sec-Fetch-Site") or "").lower()
    if site and site not in ("same-origin", "none"):
        return False
    host = str(headers.get("Host") or "")
    origin = str(headers.get("Origin") or "")
    if origin and origin != "http://" + host:
        return False
    return bool(headers.get("X-Agent"))


def test_negative_control_naive_guard_is_defeated():
    """The naive guard must fail exactly the two cases header inspection cannot see.

    This test asserts a *vulnerability*. If it ever starts failing, either the
    naive implementation above was quietly improved -- in which case it is no
    longer the control -- or the six cases stopped modelling the real attacks.
    Either way the suite has lost its calibration and someone must look.
    """
    results = _run(naive_check)

    rebinding = results["DNS rebinding: Host carries a domain name"]
    assert rebinding == (True, False), (
        "the naive guard was expected to ALLOW the rebinding request; "
        "got %r. The control is no longer controlling." % (rebinding,)
    )

    lan = results["LAN peer with perfectly forged headers"]
    assert lan == (True, False), (
        "the naive guard was expected to ALLOW the forged LAN request; got %r." % (lan,)
    )

    # And it must still get the easy ones right -- otherwise it is a straw man,
    # not a control. A control that is bad at everything proves nothing.
    for easy in ("cross-site POST, no custom header",
                 "cross-site POST, custom header set",
                 "the real dashboard, same-origin over loopback"):
        got, want = results[easy]
        assert got == want, "%s: control should handle this correctly" % easy


if __name__ == "__main__":
    fails = 0
    for fn in sorted(k for k in dict(globals()) if k.startswith("test_")):
        try:
            globals()[fn]()
            print("PASS %s" % fn)
        except AssertionError as e:
            fails += 1
            print("FAIL %s\n     %s" % (fn, e))
    print("\n%d failed" % fails)
    raise SystemExit(1 if fails else 0)
