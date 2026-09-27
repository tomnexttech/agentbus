# -*- coding: utf-8 -*-
"""Three-state answers — because "I don't know" is not "no".

This module exists because of one incident, and the incident is worth
telling before the API.

An audit routine was written to *protect* a shared world. Before reclaiming
a cell, it asked the world "is this cell still the thing I put there?" If the
answer was no, the agent released its claim rather than overwrite something a
human had built. Correct, careful, defensive.

The underlying query had three possible answers: matches, does not match, and
*"that position is not loaded"* — the region had been paged out because nobody
was standing near it. The code collapsed three answers into a boolean. The
third answer became "does not match". And so, one afternoon, 953 cells that
were merely *unobserved* were classified as "someone else's" and the agent
quietly released its claim to all of them.

Nothing crashed. No error was logged. The count in the report looked healthy.
The mechanism built to prevent destruction had become the destruction, and it
did so with a completely normal face.

The general rule:

    When one branch of a decision is destructive, collapsing a three-valued
    answer into two values will always push "unknown" toward the dangerous
    side, and it will do so silently.

So: carry the third value. `Tri` is deliberately not a `bool` subclass and
deliberately raises when you try to use it as one — the whole failure mode is
code that treats it as a boolean without noticing.

    >>> from agentbus.tri import Tri, unknown_aborts
    >>> ans = Tri.UNKNOWN
    >>> bool(ans)
    Traceback (most recent call last):
        ...
    TypeError: Tri.UNKNOWN has no truth value...

    >>> @unknown_aborts
    ... def reclaim(cell, still_mine: Tri):
    ...     return "reclaimed"
    >>> reclaim("a1", Tri.UNKNOWN)
    Traceback (most recent call last):
        ...
    agentbus.tri.UnknownRefused: reclaim: refusing to act on Tri.UNKNOWN...

MIT licensed. Part of `agentbus`.
"""
from __future__ import annotations

import functools
from typing import Any, Callable, Optional


class UnknownRefused(RuntimeError):
    """Raised when a destructive path is reached with an UNKNOWN answer."""


class Tri:
    """YES / NO / UNKNOWN. Not a bool, on purpose."""

    __slots__ = ("_v", "_why")

    YES: "Tri"
    NO: "Tri"
    UNKNOWN: "Tri"

    def __init__(self, v: Optional[bool], why: str = "") -> None:
        self._v = v
        self._why = why

    # --- construction -------------------------------------------------------
    @classmethod
    def of(cls, v: Optional[bool], why: str = "") -> "Tri":
        """`True` -> YES, `False` -> NO, `None` -> UNKNOWN."""
        if v is None:
            return cls(None, why)
        return cls(bool(v), why)

    @classmethod
    def unknown(cls, why: str) -> "Tri":
        """UNKNOWN, with the reason attached. Always give a reason.

        "unknown" with no explanation is indistinguishable from a bug in the
        code that produced it. `why` is what a human reads at 3am.
        """
        if not why:
            raise ValueError("Tri.unknown() requires a reason")
        return cls(None, why)

    # --- inspection ---------------------------------------------------------
    @property
    def is_yes(self) -> bool:
        return self._v is True

    @property
    def is_no(self) -> bool:
        return self._v is False

    @property
    def is_unknown(self) -> bool:
        return self._v is None

    @property
    def why(self) -> str:
        return self._why

    def value(self) -> bool:
        """The boolean, or raise if unknown.

        The mirror of `agentbus.bus.Reading.value()`: the exception fires at
        the moment of *extraction*, not at the moment of *reading*, so that
        every place which actually depends on the answer is forced to say what
        it does when the answer is missing.
        """
        if self._v is None:
            raise UnknownRefused("value() on Tri.UNKNOWN (%s)" % (self._why or "no reason given"))
        return self._v

    def otherwise(self, fallback: bool) -> bool:
        """Deliberately collapse to a boolean, in writing.

        This is the escape hatch, and it is spelled out so that
        `grep -rn 'otherwise(' ` finds every single place a three-valued answer
        was flattened. That grep is the point. A flattening you can enumerate
        is a decision; one you cannot is a latent incident.
        """
        return fallback if self._v is None else self._v

    # --- deliberate refusals ------------------------------------------------
    def __bool__(self) -> bool:
        raise TypeError(
            "%r has no truth value. Use .is_yes / .is_no / .is_unknown, "
            ".value(), or .otherwise(default)." % self
        )

    def __repr__(self) -> str:
        name = {True: "YES", False: "NO", None: "UNKNOWN"}[self._v]
        return "Tri.%s" % name if not self._why else "Tri.%s(%r)" % (name, self._why)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Tri) and other._v is self._v

    def __hash__(self) -> int:
        return hash(("Tri", self._v))


Tri.YES = Tri(True)
Tri.NO = Tri(False)
Tri.UNKNOWN = Tri(None, "unspecified")


def unknown_aborts(fn: Callable) -> Callable:
    """Decorator: refuse to run if any argument is an UNKNOWN `Tri`.

    Put this on the functions that delete, overwrite, release a claim, send,
    or spend. When the answer that guards them is unknown, the correct
    behaviour is to stop and say so — not to guess, and not to pick the
    "safe-looking" default, because which default is safe depends on which
    branch is destructive and that is not knowable here.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        for a in list(args) + list(kwargs.values()):
            if isinstance(a, Tri) and a.is_unknown:
                raise UnknownRefused(
                    "%s: refusing to act on Tri.UNKNOWN (%s). "
                    "Resolve the unknown or abort; do not default."
                    % (fn.__name__, a.why or "no reason given")
                )
        return fn(*args, **kwargs)

    return wrapper
