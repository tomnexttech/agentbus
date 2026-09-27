# -*- coding: utf-8 -*-
"""Invariants for Bus / Reading / AtomicJSON / Tri.

The interesting ones:

  * `take()` must never raise, for any state of the directory, including
    states a well-behaved writer can never produce -- because the states you
    actually meet at 3am are the ones no well-behaved writer produced.
  * `value()` must raise on everything that is not fresh.
  * "absent" and "unreadable" must not be the same exception.
  * concurrent `update()` must not lose a write. That test is the whole reason
    the lock is held across the read.

Run:  python3 -m pytest tests/ -q      (or: python3 tests/test_bus.py)
"""
from __future__ import annotations

import json
import multiprocessing
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentbus import (  # noqa: E402
    AtomicJSON,
    Bus,
    BusAbsent,
    BusStale,
    BusUnreadable,
    Topic,
    Tri,
    UnknownRefused,
    unknown_aborts,
)

TOPICS = {
    "prices": Topic(writer="fetcher", max_age_s=900, ceiling_s=3600, hard_s=86400,
                    basis="upstream refreshes at most every 5 min; 5 min x 3"),
    "digest": Topic(writer="mailer", max_age_s=3600,
                    basis="mail is polled hourly; one hour x 3 rounded down"),
}


def _bus():
    d = tempfile.mkdtemp(prefix="agentbus-test-")
    return Bus(d, TOPICS), d


# ══════════════════════════════════════════════════════════════════ basics ══
def test_publish_then_fresh():
    bus, _ = _bus()
    bus.publish("prices", "fetcher", {"usd_jpy": 147.02})
    r = bus.take("prices")
    assert r.ok and r.status == "fresh"
    assert r.value()["usd_jpy"] == 147.02


def test_absent_is_not_unreadable():
    bus, _ = _bus()
    r = bus.take("prices")
    assert r.status == "absent" and not r.ok
    try:
        r.value()
        raise AssertionError("value() must raise on absent")
    except BusAbsent:
        pass


def test_corrupt_payload_is_unreadable_not_absent():
    bus, d = _bus()
    with open(os.path.join(d, "prices.json"), "w") as f:
        f.write("{not json")
    r = bus.take("prices")
    assert r.status == "unreadable", r.status
    try:
        r.value()
        raise AssertionError("value() must raise on unreadable")
    except BusUnreadable:
        pass


def test_truncated_to_zero_bytes_is_unreadable():
    """The classic crash artefact: the file exists and is empty.

    An `open(path, "w")` that died before writing leaves this behind. It must
    read as "broken", never as "nothing was published" -- the two call for
    opposite responses.
    """
    bus, d = _bus()
    open(os.path.join(d, "prices.json"), "w").close()
    assert bus.take("prices").status == "unreadable"


def test_envelope_without_payload_is_unreadable():
    bus, d = _bus()
    with open(os.path.join(d, "prices.json"), "w") as f:
        json.dump({"published_at": time.time()}, f)
    assert bus.take("prices").status == "unreadable"


def test_stale_after_expiry():
    bus, d = _bus()
    bus.publish("prices", "fetcher", {"x": 1}, max_age_s=1)
    p = os.path.join(d, "prices.json")
    env = json.load(open(p))
    env["published_at"] = time.time() - 60          # age it without sleeping
    json.dump(env, open(p, "w"))
    r = bus.take("prices")
    assert r.status == "stale"
    try:
        r.value()
        raise AssertionError("value() must raise on stale")
    except BusStale:
        pass
    assert r.stale_ok("shown beside the word stale on a courtesy panel")["x"] == 1


def test_stale_ok_demands_a_real_reason():
    bus, d = _bus()
    bus.publish("prices", "fetcher", {"x": 1}, max_age_s=1)
    p = os.path.join(d, "prices.json")
    env = json.load(open(p)); env["published_at"] = time.time() - 60
    json.dump(env, open(p, "w"))
    r = bus.take("prices")
    for bad in ("", "ok", "why"):
        try:
            r.stale_ok(bad)
            raise AssertionError("stale_ok(%r) should be refused" % bad)
        except ValueError:
            pass


def test_stale_ok_cannot_manufacture_an_absent_value():
    """There is no old value to accept when nothing was ever published."""
    bus, _ = _bus()
    try:
        bus.take("prices").stale_ok("I would like a value please, any value")
        raise AssertionError("stale_ok must refuse on absent")
    except BusAbsent:
        pass


def test_take_never_raises_on_any_garbage():
    bus, d = _bus()
    p = os.path.join(d, "prices.json")
    for junk in ("", "null", "[]", '"a string"', "{", '{"payload":1}',
                 '{"payload":1,"published_at":"tuesday"}'):
        with open(p, "w") as f:
            f.write(junk)
        bus.take("prices")          # must not raise; status is what varies
    os.makedirs(os.path.join(d, "digest.json"), exist_ok=True)   # a directory!
    bus.take("digest")


# ══════════════════════════════════════════════════════════ writer identity ══
def test_second_writer_is_refused():
    bus, _ = _bus()
    bus.publish("prices", "fetcher", {"x": 1})
    try:
        bus.publish("prices", "someone_else", {"x": 2})
        raise AssertionError("a second writer must be refused")
    except PermissionError:
        pass
    bus.publish("prices", "someone_else", {"x": 2}, force=True)   # on purpose
    assert bus.take("prices").value()["x"] == 2


def test_undeclared_topic_is_refused_on_write_and_unwired_on_read():
    bus, _ = _bus()
    try:
        bus.publish("ghost", "fetcher", {})
        raise AssertionError("undeclared topic must be refused")
    except KeyError:
        pass
    assert bus.take("ghost").status == "unwired"


# ═══════════════════════════════════════════════════════════════ freshness ══
def test_ceiling_requires_a_written_reason():
    bus, _ = _bus()
    try:
        bus.publish("prices", "fetcher", {"x": 1}, max_age_s=7200)
        raise AssertionError("past the ceiling without a reason must be refused")
    except ValueError:
        pass
    bus.publish("prices", "fetcher", {"x": 1}, max_age_s=7200,
                extend_why="market closed overnight; the value cannot move")
    assert bus.take("prices").ok


def test_hard_limit_cannot_be_bought_with_a_reason():
    bus, _ = _bus()
    try:
        bus.publish("prices", "fetcher", {"x": 1}, max_age_s=999999,
                    extend_why="I would very much like this to never expire")
        raise AssertionError("the hard limit must not be reachable with a reason")
    except ValueError:
        pass


def test_topic_requires_a_basis():
    try:
        Topic(writer="w", max_age_s=60, basis="")
        raise AssertionError("Topic must require a basis")
    except ValueError:
        pass


# ═══════════════════════════════════════════════════════════════════ atomic ══
def _bump(path):
    AtomicJSON(path).update(lambda cur: {"n": (cur or {}).get("n", 0) + 1})


def test_concurrent_updates_lose_nothing():
    """Eight processes, one counter. Any lost update shows up as n < 8.

    This is the test that justifies re-reading *inside* the lock. Serialising
    only the writes gives you a counter that reaches roughly 3.
    """
    d = tempfile.mkdtemp(prefix="agentbus-atomic-")
    path = os.path.join(d, "counter.json")
    AtomicJSON(path).write({"n": 0})
    procs = [multiprocessing.Process(target=_bump, args=(path,)) for _ in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert AtomicJSON(path).read()["n"] == 8, AtomicJSON(path).read()


def test_backup_written_before_overwrite():
    d = tempfile.mkdtemp(prefix="agentbus-backup-")
    path = os.path.join(d, "s.json")
    s = AtomicJSON(path)
    s.write({"v": 1})
    s.write({"v": 2})
    backups = os.listdir(os.path.join(d, "backups"))
    assert len(backups) == 1, backups
    assert json.load(open(os.path.join(d, "backups", backups[0])))["v"] == 1


def test_no_temp_files_left_behind():
    d = tempfile.mkdtemp(prefix="agentbus-tmp-")
    path = os.path.join(d, "s.json")
    for i in range(5):
        AtomicJSON(path).write({"v": i})
    assert not [f for f in os.listdir(d) if f.startswith(".tmp-")]


# ══════════════════════════════════════════════════════════════════════ tri ══
def test_tri_has_no_truth_value():
    for t in (Tri.YES, Tri.NO, Tri.UNKNOWN):
        try:
            bool(t)
            raise AssertionError("Tri must not be usable as a bool")
        except TypeError:
            pass


def test_tri_value_raises_only_on_unknown():
    assert Tri.of(True).value() is True
    assert Tri.of(False).value() is False
    try:
        Tri.unknown("region not loaded").value()
        raise AssertionError("value() must raise on UNKNOWN")
    except UnknownRefused:
        pass


def test_tri_otherwise_is_the_only_quiet_path():
    assert Tri.unknown("region not loaded").otherwise(False) is False
    assert Tri.of(True).otherwise(False) is True


def test_unknown_aborts_blocks_the_destructive_call():
    calls = []

    @unknown_aborts
    def release(cell, still_mine):
        calls.append(cell)
        return "released"

    assert release("a1", Tri.NO) == "released"
    try:
        release("b2", Tri.unknown("region not loaded"))
        raise AssertionError("must refuse to act on UNKNOWN")
    except UnknownRefused as e:
        assert "region not loaded" in str(e)
    assert calls == ["a1"]


def test_unknown_requires_a_reason():
    try:
        Tri.unknown("")
        raise AssertionError("Tri.unknown() must require a reason")
    except ValueError:
        pass


if __name__ == "__main__":
    fails = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        try:
            globals()[name]()
            print("PASS %s" % name)
        except AssertionError as e:
            fails += 1
            print("FAIL %s\n     %s" % (name, e))
    print("\n%d failed" % fails)
    raise SystemExit(1 if fails else 0)
