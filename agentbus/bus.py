# -*- coding: utf-8 -*-
"""A one-writer bus for agents that must agree on the same facts.

The problem it solves
---------------------
Once you have more than one long-running agent, they start fetching the same
things separately. One process pulls an exchange rate to draw a chart; another
pulls it again, from a different source, at a different minute, to convert a
balance. Now the same number appears twice on the same screen with two
different values, and no amount of careful arithmetic downstream will fix it,
because the disagreement was created upstream.

The obvious fix is a shared cache. The obvious fix has a subtler failure, and
that failure is the reason this module is shaped the way it is.

The failure that shapes the design
----------------------------------
A shared cache was built. Each payload carried `published_at`, `max_age_s`,
and a `stale` flag. Everything a careful reader needed was right there.

Then the fetchers stopped running. Nobody noticed for hours. And two separate
consumers read the stale payloads and displayed them anyway:

  * one appended the word "STALE" to the label and printed the value unchanged
  * the other had no freshness check at all and rendered a seven-day-old price
    stamped with the *current* time

The flag was present. It was correct. It was ignored twice, by two different
authors, without malice — because *reading a flag is optional and reading a
value is not*. A discipline that depends on every future caller remembering
to check something will be broken by the first caller who is in a hurry.

So the flag was removed as a mechanism and replaced with a shape:

  1. **One way in.** `take()` returns a `Reading`, never a bare payload.
  2. **The exception fires at extraction.** `Reading.value()` raises when the
     data is stale, absent, or unreadable. There is no way to get the payload
     out by accident. The only way to get a stale value is to write
     `stale_ok("because...")`, which is a string a human has to type and
     `grep -rn 'stale_ok('` can enumerate for the rest of the project's life.
  3. **Expiry needs a stated basis.** Every topic declares *why* its deadline
     is what it is. Extending past the ceiling requires `extend_why=`, and
     `publish()` refuses without it. "Effectively infinite" becomes something
     the machine rejects rather than something a tired human types.
  4. **Missing and broken are different types.** `absent` (nothing was ever
     published), `unreadable` (the file is there and corrupt), `unwired` (this
     process could not even load the bus) and `stale` are four distinct states,
     and a caller that flattens them into `None` has to do so on purpose.

Rule 4 matters more than it looks. "There is no data" and "I cannot read the
data" call for opposite responses: the first is often normal, the second is an
incident. Collapsing them into a falsy value means the incident never surfaces.

The rule underneath all four
----------------------------
    When the layer is missing, say it is missing. Never fill it with a default.

A default is indistinguishable from a real value one function call later.

Usage
-----
    from agentbus import Bus, Topic

    bus = Bus("~/.myagents", topics={
        "prices": Topic(writer="fetcher", max_age_s=900, ceiling_s=3600,
                        hard_s=86400,
                        basis="upstream refreshes every 5 min; 5 min x 3"),
    })

    # the one writer
    bus.publish("prices", writer="fetcher", payload={"usd_jpy": 147.02})

    # any number of readers
    r = bus.take("prices")
    if r.ok:
        prices = r.value()
    else:
        show(r.label())          # "stale - observed 04:12 (7.1 hours ago)"

MIT licensed. Part of `agentbus`.
"""
from __future__ import annotations

import json
import os
import socket
import time
from typing import Any, Dict, Iterable, Optional

from .atomic import AtomicJSON
from .stamp import fmt_age, observed_line

SCHEMA = 1


# ══════════════════════════════════════════════════════════════════ topics ══
class Topic:
    """Declaration of one topic: who writes it, and how long it stays true.

    Args:
        writer:     the single process name permitted to publish. Anyone else
                    is refused unless they pass `force=True`, which is loud on
                    purpose: crossing this line should be a decision, not an
                    accident.
        max_age_s:  default expiry.
        ceiling_s:  the longest expiry allowed *without* a written reason.
        hard_s:     the longest expiry allowed *with* a reason. This is the
                    floor under the floor. It exists so that "just set it to a
                    week" cannot be typed at 2am.
        basis:      one sentence on why these numbers. Required. A deadline
                    with no stated basis is a number somebody guessed once and
                    everyone since has treated as physics.

    A serviceable default for `max_age_s`: the shortest interval at which the
    value could genuinely change, times three. Three consecutive missed
    refreshes is no longer bad luck; it means the thing that refreshes has
    stopped. Times one makes every hiccup an outage; times ten makes an outage
    invisible.
    """

    __slots__ = ("writer", "max_age_s", "ceiling_s", "hard_s", "basis")

    def __init__(
        self,
        writer: str,
        max_age_s: int,
        basis: str,
        ceiling_s: Optional[int] = None,
        hard_s: Optional[int] = None,
    ) -> None:
        if not basis:
            raise ValueError(
                "Topic(basis=...) is required: state why this expiry is this number"
            )
        self.writer = writer
        self.max_age_s = int(max_age_s)
        self.ceiling_s = int(ceiling_s if ceiling_s is not None else max_age_s * 2)
        self.hard_s = int(hard_s if hard_s is not None else self.ceiling_s * 6)
        self.basis = basis
        if not (self.max_age_s <= self.ceiling_s <= self.hard_s):
            raise ValueError("Topic requires max_age_s <= ceiling_s <= hard_s")


# ══════════════════════════════════════════════════════════════ exceptions ══
class BusError(Exception):
    """Base. Raised only at the moment a value is extracted, never on read."""


class BusAbsent(BusError):
    """Nothing has ever been published on this topic. Often normal."""


class BusUnreadable(BusError):
    """The payload exists and cannot be parsed. Never normal."""


class BusUnwired(BusError):
    """This process could not reach the bus at all (import failed, dir missing)."""


class BusStale(BusError):
    """The payload exists, parses, and is past its expiry."""


_EXC = {
    "absent": BusAbsent,
    "unreadable": BusUnreadable,
    "unwired": BusUnwired,
    "stale": BusStale,
}


# ═════════════════════════════════════════════════════════════════ reading ══
class Reading:
    """The result of `take()`. Construction never raises; extraction may.

    That split is the entire safety property. Reading is something code does
    incidentally; extracting is something code does because it depends on the
    answer. The exception belongs where the dependency is.
    """

    __slots__ = ("topic", "status", "payload", "published_at", "max_age_s", "writer", "detail")

    def __init__(
        self,
        topic: str,
        status: str,
        payload: Any = None,
        published_at: Optional[float] = None,
        max_age_s: Optional[int] = None,
        writer: str = "",
        detail: str = "",
    ) -> None:
        self.topic = topic
        self.status = status          # fresh | stale | absent | unreadable | unwired
        self.payload = payload
        self.published_at = published_at
        self.max_age_s = max_age_s
        self.writer = writer
        self.detail = detail

    # --- inspection ---------------------------------------------------------
    @property
    def ok(self) -> bool:
        return self.status == "fresh"

    @property
    def age_s(self) -> Optional[float]:
        return None if self.published_at is None else max(0.0, time.time() - self.published_at)

    def label(self) -> str:
        """A line fit to put on a panel. Always absolute-first when there is a time."""
        if self.status == "fresh":
            return observed_line(self.published_at or time.time())
        if self.status == "stale":
            return "stale - %s" % observed_line(self.published_at or time.time())
        if self.status == "absent":
            return "not published"
        if self.status == "unreadable":
            return "unreadable (%s)" % (self.detail or "corrupt payload")
        return "not wired (%s)" % (self.detail or "bus unavailable")

    # --- extraction ---------------------------------------------------------
    def value(self) -> Any:
        """The payload, or raise. There is no non-raising path to a stale value."""
        if self.status == "fresh":
            return self.payload
        exc = _EXC.get(self.status, BusError)
        age = "" if self.age_s is None else " (%s)" % fmt_age(self.age_s)
        raise exc("%s: %s%s. %s" % (self.topic, self.status, age, self.detail or self.label()))

    def stale_ok(self, why: str) -> Any:
        """Take the payload anyway, in writing.

        Legitimate uses exist — showing a last-known value beside the word
        "stale", or degrading a nice-to-have panel rather than blanking it.
        This method exists so those uses are *countable*:

            grep -rn 'stale_ok(' .

        should return a list a maintainer can read in one sitting. If it does
        not, the discipline has already failed and no amount of further API
        design will save it.

        Refuses on `absent` / `unreadable` / `unwired`: there is no old value
        to accept in those cases. Accepting nothing is not a decision, it is a
        bug wearing a decision's clothes.
        """
        if not why or len(why.strip()) < 8:
            raise ValueError("stale_ok(why=...) requires a real reason, in writing")
        if self.status == "fresh":
            return self.payload
        if self.status != "stale":
            raise _EXC.get(self.status, BusError)(
                "%s: %s - stale_ok() cannot manufacture a value that was never there"
                % (self.topic, self.status)
            )
        return self.payload


# ═════════════════════════════════════════════════════════════════════ bus ══
class Bus:
    """A directory of JSON payloads, one file per topic, one writer per topic."""

    def __init__(self, root: str, topics: Dict[str, Topic]) -> None:
        self.root = os.path.abspath(os.path.expanduser(root))
        self.topics = dict(topics)
        os.makedirs(self.root, exist_ok=True)

    # --- paths --------------------------------------------------------------
    def path(self, topic: str) -> str:
        return os.path.join(self.root, "%s.json" % topic)

    def _store(self, topic: str) -> AtomicJSON:
        return AtomicJSON(self.path(topic), backup_dir=os.path.join(self.root, "backups"))

    # --- write --------------------------------------------------------------
    def publish(
        self,
        topic: str,
        writer: str,
        payload: Any,
        max_age_s: Optional[int] = None,
        extend_why: Optional[str] = None,
        force: bool = False,
    ) -> None:
        """Place a payload. Refuses the wrong writer and unjustified expiries.

        Raises:
            KeyError:   the topic is not declared. Declare topics in one place;
                        a bus whose topic list is discovered from the files on
                        disk cannot tell you who is *supposed* to write them.
            PermissionError: `writer` is not this topic's writer and `force` is
                        not set.
            ValueError: the requested expiry exceeds the ceiling without a
                        reason, or exceeds the hard limit at all.
        """
        spec = self.topics.get(topic)
        if spec is None:
            raise KeyError(
                "topic %r is not declared. Add it to Bus(topics=...) with a writer "
                "and a basis before publishing." % topic
            )
        if writer != spec.writer and not force:
            raise PermissionError(
                "topic %r is written by %r, not %r. Two writers on one topic is how "
                "records start disappearing. Pass force=True only on purpose."
                % (topic, spec.writer, writer)
            )

        age = int(spec.max_age_s if max_age_s is None else max_age_s)
        if age > spec.hard_s:
            raise ValueError(
                "max_age_s=%d exceeds the hard limit %d for %r. No reason authorises "
                "this; the value cannot be meaningfully that old." % (age, spec.hard_s, topic)
            )
        if age > spec.ceiling_s and not extend_why:
            raise ValueError(
                "max_age_s=%d exceeds the ceiling %d for %r. Pass extend_why='...' "
                "so the reason is recorded in the envelope and visible to readers."
                % (age, spec.ceiling_s, topic)
            )

        envelope = {
            "schema": SCHEMA,
            "topic": topic,
            "writer": writer,
            "host": socket.gethostname(),
            "pid": os.getpid(),
            "published_at": time.time(),
            "max_age_s": age,
            "max_age_basis": spec.basis,
            "max_age_why": extend_why or "",
            "forced": bool(force and writer != spec.writer),
            "payload": payload,
        }
        self._store(topic).write(envelope)

    # --- read ---------------------------------------------------------------
    def take(self, topic: str) -> Reading:
        """Read a topic. **Never raises.** Inspect `.ok`, then call `.value()`.

        The no-raise guarantee is what lets a panel render "not published"
        instead of crashing when a fetcher is down. The layer being absent must
        not take the surface down with it.
        """
        spec = self.topics.get(topic)
        if spec is None:
            return Reading(topic, "unwired", detail="topic %r is not declared" % topic)

        p = self.path(topic)
        if not os.path.exists(p):
            return Reading(topic, "absent")

        try:
            with open(p, "r", encoding="utf-8") as f:
                env = json.load(f)
        except ValueError as e:
            return Reading(topic, "unreadable", detail="malformed JSON: %s" % e)
        except OSError as e:
            return Reading(topic, "unreadable", detail="cannot open: %s" % e)

        if not isinstance(env, dict) or "payload" not in env or "published_at" not in env:
            return Reading(topic, "unreadable", detail="envelope missing payload/published_at")

        pub = env.get("published_at")
        try:
            pub = float(pub)
        except (TypeError, ValueError):
            return Reading(topic, "unreadable", detail="published_at is not a timestamp")

        max_age = int(env.get("max_age_s") or spec.max_age_s)
        status = "fresh" if (time.time() - pub) <= max_age else "stale"
        return Reading(
            topic,
            status,
            payload=env.get("payload"),
            published_at=pub,
            max_age_s=max_age,
            writer=str(env.get("writer") or ""),
            detail=str(env.get("max_age_why") or ""),
        )

    # --- overview -----------------------------------------------------------
    def survey(self, topics: Optional[Iterable[str]] = None) -> Dict[str, Dict[str, Any]]:
        """Every topic's status in one dict — for a health panel or a probe.

        Note this reports "never published" as a first-class state rather than
        omitting the row. A dashboard that only lists topics it found on disk
        cannot show you the one that stopped being written last Tuesday.
        """
        out: Dict[str, Dict[str, Any]] = {}
        for t in (topics if topics is not None else self.topics.keys()):
            r = self.take(t)
            out[t] = {
                "status": r.status,
                "ok": r.ok,
                "label": r.label(),
                "age_s": r.age_s,
                "writer": r.writer or (self.topics[t].writer if t in self.topics else ""),
            }
        return out
