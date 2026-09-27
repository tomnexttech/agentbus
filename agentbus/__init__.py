# -*- coding: utf-8 -*-
"""agentbus — small, boring primitives for agents that run unattended.

Four things, each extracted from a production incident rather than from a
design document:

    Bus / Topic / Reading   one writer per topic; expiry with a stated basis;
                            "missing", "corrupt" and "stale" as distinct types
    AtomicJSON              flock -> re-read -> backup -> tmp -> os.replace
    Tri                     three-valued answers, because unknown is not no
    LoopbackGuard           four locks for a localhost endpoint that can run code

No dependencies. Python 3.9+. MIT.

Start with `agentbus.loopback` if you have an agent listening on 127.0.0.1;
that one is a security fix, not a nicety.
"""

from .atomic import AtomicJSON
from .bus import (
    SCHEMA,
    Bus,
    BusAbsent,
    BusError,
    BusStale,
    BusUnreadable,
    BusUnwired,
    Reading,
    Topic,
)
from .loopback import GuardResult, LoopbackGuard, addr_is_loopback, host_is_literal
from .stamp import fmt_age, observed_line, stamp
from .tri import Tri, UnknownRefused, unknown_aborts

__version__ = "0.1.0"

__all__ = [
    "AtomicJSON",
    "Bus",
    "Topic",
    "Reading",
    "BusError",
    "BusAbsent",
    "BusUnreadable",
    "BusUnwired",
    "BusStale",
    "SCHEMA",
    "LoopbackGuard",
    "GuardResult",
    "host_is_literal",
    "addr_is_loopback",
    "Tri",
    "UnknownRefused",
    "unknown_aborts",
    "stamp",
    "fmt_age",
    "observed_line",
    "__version__",
]
