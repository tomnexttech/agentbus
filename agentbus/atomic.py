# -*- coding: utf-8 -*-
"""Atomic JSON state — the five-step write that survives concurrent agents.

Long-running agents share state through files far more often than anyone
admits. Two processes deciding to write the same ledger at the same moment
is not a rare event; it is the normal case the moment you have more than one
scheduled job.

The failure is quiet. `json.dump(open(path, "w"))` truncates the file the
instant it opens it. If the process dies between the truncate and the flush,
the file is now zero bytes and every reader sees "no data" instead of
"corrupt data". A crash at that moment does not look like a crash — it looks
like an empty inbox.

The write is five steps, in this order, and the order is the whole point:

    1. flock          take an exclusive lock on a *separate* lock file
    2. re-read        read the current state INSIDE the lock, not before it
    3. backup         copy the previous good file aside
    4. tmp write      write the new content to a temp file in the same dir
    5. os.replace     atomically swap it into place

Step 2 is the one people skip, and skipping it is what silently loses data.
If you read the state, then take the lock, then write, you have serialised
the *writes* but not the *decisions* — two processes both read version N,
both write version N+1, and one of them is gone. The lock has to be held
across the read as well as the write, or it is decoration.

Step 4 must be in the same directory as the target. `os.replace` is only
atomic within a filesystem; a temp file in /tmp and a target on another
volume degrades to copy-then-delete, which is exactly the non-atomic thing
you were avoiding.

Readers never lock. `read()` either sees the old complete file or the new
complete file, never a half-written one, because `os.replace` swaps the
directory entry rather than editing bytes in place.

MIT licensed. Part of `agentbus`.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from typing import Any, Callable, Optional

try:                                    # POSIX only. Degrade, do not crash.
    import fcntl
except ImportError:                     # pragma: no cover - Windows
    fcntl = None                        # type: ignore[assignment]


class AtomicJSON:
    """A JSON file that two processes may write without losing each other's work.

    >>> store = AtomicJSON("/tmp/demo.json")
    >>> store.update(lambda cur: {**(cur or {}), "hits": (cur or {}).get("hits", 0) + 1})
    {'hits': 1}

    Args:
        path:        the file to keep.
        backup_dir:  where previous versions go. Defaults to `<dir>/backups`.
                     Pass `None` to disable backups (not recommended: a ledger
                     you cannot roll back is a ledger you cannot repair).
        keep:        how many backups to retain.
        lock_path:   the lock file. Defaults to `<dir>/.<name>.lock`.
                     Deliberately a *different* file from the target — locking
                     the target itself races with `os.replace`, which swaps the
                     inode out from under the lock you are holding.
    """

    def __init__(
        self,
        path: str,
        backup_dir: Optional[str] = "__default__",
        keep: int = 10,
        lock_path: Optional[str] = None,
    ) -> None:
        self.path = os.path.abspath(path)
        d = os.path.dirname(self.path)
        base = os.path.basename(self.path)
        if backup_dir == "__default__":
            backup_dir = os.path.join(d, "backups")
        self.backup_dir = backup_dir
        self.keep = int(keep)
        self.lock_path = lock_path or os.path.join(d, "." + base + ".lock")
        os.makedirs(d, exist_ok=True)

    # ------------------------------------------------------------------ read
    def read(self, default: Any = None) -> Any:
        """Read without locking. Returns `default` if absent or unparseable.

        Note what this deliberately does *not* do: it does not distinguish
        "the file is missing" from "the file is corrupt". If that distinction
        matters to your caller — and for anything destructive it does — use
        `read_strict()` and handle the two cases separately. Collapsing
        "unknown" into "empty" is how a repair job becomes a delete job.
        """
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, ValueError, OSError):
            return default

    def read_strict(self) -> Any:
        """Read, raising `FileNotFoundError` if absent and `ValueError` if corrupt.

        Two different failures, two different exceptions, on purpose.
        """
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ----------------------------------------------------------------- write
    def update(self, fn: Callable[[Any], Any], default: Any = None) -> Any:
        """Apply `fn(current) -> new` under an exclusive lock, atomically.

        `fn` must be pure enough to be re-run: it is called exactly once here,
        but it is called with state read *inside* the lock, which may differ
        from anything you read before calling. Write `fn` against its argument,
        never against a snapshot you took earlier.

        Returns the new state.
        """
        with self._locked():
            current = self.read(default)
            new = fn(current)
            self._backup()
            self._write_unlocked(new)
            return new

    def write(self, data: Any) -> Any:
        """Overwrite unconditionally (still locked, backed up, and atomic).

        Prefer `update()`. Use this only when the new content genuinely does
        not depend on the old — a full recompute from an upstream source, say.
        Anything that reads-then-writes belongs in `update()`.
        """
        with self._locked():
            self._backup()
            self._write_unlocked(data)
            return data

    # --------------------------------------------------------------- internals
    class _Lock:
        def __init__(self, path: str, timeout: float) -> None:
            self.path, self.timeout, self.fh = path, timeout, None

        def __enter__(self):
            if fcntl is None:                       # pragma: no cover
                return self
            self.fh = open(self.path, "a+")
            deadline = time.time() + self.timeout
            while True:
                try:
                    fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except OSError:
                    if time.time() >= deadline:
                        self.fh.close()
                        raise TimeoutError(
                            "another writer holds %s after %.1fs" % (self.path, self.timeout)
                        )
                    time.sleep(0.02)

        def __exit__(self, *exc):
            if self.fh is not None:
                try:
                    fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
                finally:
                    self.fh.close()
            return False

    def _locked(self, timeout: float = 10.0) -> "AtomicJSON._Lock":
        return AtomicJSON._Lock(self.lock_path, timeout)

    def _backup(self) -> None:
        if not self.backup_dir or not os.path.exists(self.path):
            return
        os.makedirs(self.backup_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.basename(self.path)
        dst = os.path.join(self.backup_dir, "%s.%s" % (base, stamp))
        try:
            shutil.copy2(self.path, dst)
        except OSError:
            return
        self._prune(base)

    def _prune(self, base: str) -> None:
        try:
            kept = sorted(
                f for f in os.listdir(self.backup_dir) if f.startswith(base + ".")
            )
        except OSError:
            return
        for old in kept[: max(0, len(kept) - self.keep)]:
            try:
                os.remove(os.path.join(self.backup_dir, old))
            except OSError:
                pass

    def _write_unlocked(self, data: Any) -> None:
        d = os.path.dirname(self.path)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())        # the bytes, before the swap
            os.replace(tmp, self.path)      # the swap: atomic within one filesystem
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
