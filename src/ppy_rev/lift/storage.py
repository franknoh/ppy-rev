"""Partitioning register and temporary storage into SSA variables.

Machine registers overlap (RAX/EAX/AX/AL share bytes). Each maximal group of overlapping
varnodes becomes one variable; reads and writes of a part of the group are lifted as
explicit subpiece/piece operations on the whole value.
"""

from __future__ import annotations

import bisect
from collections.abc import Iterable
from dataclasses import dataclass

from ppy_rev.ghidra.schema import Register as GhidraRegister


@dataclass(frozen=True, slots=True)
class StorageGroup:
    name: str
    offset: int
    size: int
    """Size in bytes."""

    @property
    def end(self) -> int:
        return self.offset + self.size

    def contains(self, offset: int, size: int) -> bool:
        return self.offset <= offset and offset + size <= self.end


class StoragePartition:
    """Maps varnode byte ranges within one address space to their storage group."""

    def __init__(self, groups: Iterable[StorageGroup]) -> None:
        self.groups = tuple(sorted(groups, key=lambda group: group.offset))
        self._starts = [group.offset for group in self.groups]

    def group_of(self, offset: int, size: int) -> StorageGroup:
        index = bisect.bisect_right(self._starts, offset) - 1
        if index >= 0:
            group = self.groups[index]
            if group.contains(offset, size):
                return group
        raise KeyError((offset, size))


def partition(
    ranges: Iterable[tuple[int, int]], name_for: dict[tuple[int, int], str], prefix: str
) -> StoragePartition:
    """Merge overlapping (offset, size) ranges into groups.

    A group is named after the register occupying exactly its range when one exists.
    """
    merged: list[list[int]] = []
    for offset, size in sorted(set(ranges)):
        if merged and offset < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], offset + size)
        else:
            merged.append([offset, offset + size])
    return StoragePartition(
        StorageGroup(
            name=name_for.get((start, end - start), f"{prefix}_{start:x}_{end - start}"),
            offset=start,
            size=end - start,
        )
        for start, end in merged
    )


def register_names(registers: Iterable[GhidraRegister]) -> dict[tuple[int, int], str]:
    names: dict[tuple[int, int], str] = {}
    for register in registers:
        # The export lists registers widest-first at each offset; keep the first name seen
        # for each exact range so aliases do not replace the canonical name.
        names.setdefault((register.offset, register.size), register.name)
    return names
