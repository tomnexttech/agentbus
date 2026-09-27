# -*- coding: utf-8 -*-
"""Timestamps that stay true after the screen stops updating.

"3 minutes ago" is true for exactly as long as something keeps redrawing it.
The instant the renderer stalls — the tab is backgrounded, the daemon dies,
the websocket drops, the screenshot is taken — that label starts lying, and
it lies in the most dangerous possible way: it looks fine.

"observed 23:45" is still true after the renderer stops. The reader can work
out the age themselves, and if they cannot, at least they know they cannot.

There is a second half to this, learned the expensive way. An absolute time
without a date is *also* a lie with a longer fuse. A panel reading
"observed 02:05" reads as "this morning" whether the observation was 40
minutes ago or 43 days ago. On one audit, 15 of 16 status cards were stamped
with time-of-day only; a value from six weeks earlier sat there looking like
breakfast. So: past a threshold, print the date.

The rule this module enforces:

    Any surface that shows a *measured value* must carry an absolute
    timestamp. Relative age may be added as a courtesy. It may never be the
    only thing there.

    >>> import time
    >>> observed_line(time.time() - 300)          # doctest: +SKIP
    'observed 14:22 (5 min ago)'
    >>> observed_line(time.time() - 86400 * 43)   # doctest: +SKIP
    'observed 07/11 02:05 (43 days ago)'

MIT licensed. Part of `agentbus`.
"""
from __future__ import annotations

import time
from typing import Optional

#: Past this age, the stamp includes the date. Twenty hours, not twenty-four:
#: a "yesterday evening" reading must not be able to masquerade as "this
#: morning" simply because the clock has not yet wrapped.
DATE_AFTER_S = 20 * 3600


def fmt_age(seconds: float) -> str:
    """Human age, coarse on purpose. Precision here implies a freshness you do not have."""
    s = max(0.0, float(seconds))
    if s < 90:
        return "%d sec ago" % int(s)
    if s < 90 * 60:
        return "%d min ago" % int(round(s / 60))
    if s < 36 * 3600:
        return "%.1f hours ago" % (s / 3600.0)
    return "%d days ago" % int(round(s / 86400.0))


def stamp(ts: float, now: Optional[float] = None) -> str:
    """Absolute local time. Includes the date once the reading is old enough."""
    now = time.time() if now is None else now
    lt = time.localtime(ts)
    if (now - ts) > DATE_AFTER_S:
        return time.strftime("%m/%d %H:%M", lt)
    return time.strftime("%H:%M", lt)


def observed_line(ts: float, now: Optional[float] = None, label: str = "observed") -> str:
    """The full line to put on a panel: absolute first, relative in parentheses.

    Order matters. Absolute first means that when the line is truncated,
    screenshotted, pasted into a ticket, or read aloud, the part that survives
    is the part that stays true.
    """
    now = time.time() if now is None else now
    return "%s %s (%s)" % (label, stamp(ts, now), fmt_age(now - ts))
