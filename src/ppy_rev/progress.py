"""Progress lines for the phases that can run long enough for silence to look like a hang.

Nothing here changes what a command computes: reports go to a separate stream, only after a
run has already been quiet for a while, and at most once every few seconds after that.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol, TextIO


class Progress(Protocol):
    def report(self, phase: str, detail: str) -> None:
        """Note that `phase` is still running, having reached `detail`."""
        ...


class Silent:
    """The default: a run that reports nothing."""

    def report(self, phase: str, detail: str) -> None:
        del phase, detail


@dataclass(slots=True)
class Periodic:
    """Writes `phase: detail` to `stream`, throttled by wall-clock time.

    `after` keeps fast runs silent — most solves finish in a second or two — and `every`
    bounds how much a slow one writes.
    """

    stream: TextIO
    after: float = 10.0
    every: float = 5.0
    started: float = field(default_factory=time.monotonic)
    _last: float = field(default=0.0, init=False)

    def report(self, phase: str, detail: str) -> None:
        elapsed = time.monotonic() - self.started
        if elapsed < self.after or (self._last and elapsed - self._last < self.every):
            return
        self._last = elapsed
        self.stream.write(f"[ppy-rev {elapsed:.0f}s] {phase}: {detail}\n")
        self.stream.flush()


def reporter(stream: TextIO, enabled: bool | None = None) -> Progress:
    """A reporter writing to `stream`; by default only when it is a terminal."""
    if enabled is None:
        enabled = bool(getattr(stream, "isatty", bool)())
    return Periodic(stream) if enabled else Silent()


def plural(value: int, noun: str) -> str:
    """`1 path`, `620 paths`, `22.4k operations`."""
    return f"{count(value)} {noun}" + ("" if value == 1 else "s")


def count(value: int) -> str:
    """Large counts, short: `812`, `12.3k`, `4.1M`."""
    if value < 10_000:
        return str(value)
    if value < 1_000_000:
        return f"{value / 1000:.1f}k"
    return f"{value / 1_000_000:.1f}M"
