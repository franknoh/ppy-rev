"""Concrete byte-addressed memory with explicit mappings and permissions."""

from __future__ import annotations

import bisect
from dataclasses import dataclass

from ppy_rev.ir.model import Endianness, Module

PAGE_SIZE = 0x1000


class MemoryFaultError(Exception):
    def __init__(self, address: int, size: int, access: str) -> None:
        super().__init__(f"{access} of {size} byte(s) at {address:#x} faults")
        self.address = address
        self.size = size
        self.access = access


@dataclass(frozen=True, slots=True)
class Mapping:
    name: str
    start: int
    size: int
    readable: bool
    writable: bool
    initial: bytes | None
    """Initial contents; shorter than `size` (or None) means the rest reads as zero."""

    @property
    def end(self) -> int:
        return self.start + self.size


class ConcreteMemory:
    """Sparse writes over immutable initial mappings.

    Reads and writes outside a mapping, and writes to read-only mappings, raise
    `MemoryFaultError` rather than inventing contents.
    """

    def __init__(self, endianness: Endianness) -> None:
        self.endianness = endianness
        self._mappings: list[Mapping] = []
        self._starts: list[int] = []
        self._writes: dict[int, int] = {}

    @classmethod
    def for_module(cls, module: Module) -> ConcreteMemory:
        """The module's sections, and the rest of every page they occupy.

        The loader maps whole pages, so bytes past the end of a section (a short `.bss`)
        are accessible, with the section's permissions, and read as zero. Without them, a
        write the real program makes safely would fault and hide a path.
        """
        memory = cls(module.target.endianness)
        regions = sorted(module.memory, key=lambda region: region.start)
        for region in regions:
            memory.map(
                Mapping(
                    name=region.name,
                    start=region.start,
                    size=region.size,
                    readable=region.readable,
                    writable=region.writable,
                    initial=region.data,
                )
            )
        # A gap between sections belongs to the section before it; a gap at the start
        # of a page, to the section after it.
        for index, region in enumerate(regions):
            if region.size == 0:
                continue
            following = regions[index + 1].start if index + 1 < len(regions) else None
            page_end = -(-region.end // PAGE_SIZE) * PAGE_SIZE
            tail_end = page_end if following is None else min(page_end, following)
            page_start = region.start // PAGE_SIZE * PAGE_SIZE
            for start, end in ((region.end, tail_end), (page_start, region.start)):
                for gap_start, gap_end in memory._unmapped(start, end):
                    memory.map(
                        Mapping(
                            name=f"{region.name} (page)",
                            start=gap_start,
                            size=gap_end - gap_start,
                            readable=region.readable,
                            writable=region.writable,
                            initial=None,
                        )
                    )
        return memory

    def _unmapped(self, start: int, end: int) -> list[tuple[int, int]]:
        """The parts of [start, end) no mapping covers."""
        gaps: list[tuple[int, int]] = []
        position = start
        for mapping in self._mappings:
            if mapping.end <= position or mapping.start >= end:
                continue
            if mapping.start > position:
                gaps.append((position, mapping.start))
            position = max(position, mapping.end)
        if position < end:
            gaps.append((position, end))
        return gaps

    @property
    def mappings(self) -> tuple[Mapping, ...]:
        return tuple(self._mappings)

    def map(self, mapping: Mapping) -> None:
        index = bisect.bisect_left(self._starts, mapping.start)
        previous = self._mappings[index - 1] if index > 0 else None
        following = self._mappings[index] if index < len(self._mappings) else None
        if (previous is not None and previous.end > mapping.start) or (
            following is not None and mapping.end > following.start
        ):
            raise ValueError(f"mapping {mapping.name} overlaps an existing mapping")
        self._mappings.insert(index, mapping)
        self._starts.insert(index, mapping.start)

    def mapping_at(self, address: int) -> Mapping | None:
        index = bisect.bisect_right(self._starts, address) - 1
        if index >= 0 and address < self._mappings[index].end:
            return self._mappings[index]
        return None

    def _checked(self, address: int, size: int, write: bool) -> Mapping:
        mapping = self.mapping_at(address)
        access = "write" if write else "read"
        if mapping is None or address + size > mapping.end:
            raise MemoryFaultError(address, size, access)
        if (write and not mapping.writable) or (not write and not mapping.readable):
            raise MemoryFaultError(address, size, access)
        return mapping

    def read(self, address: int, size: int) -> bytes:
        mapping = self._checked(address, size, write=False)
        initial = mapping.initial or b""
        result = bytearray(size)
        for index in range(size):
            location = address + index
            written = self._writes.get(location)
            if written is not None:
                result[index] = written
            elif location - mapping.start < len(initial):
                result[index] = initial[location - mapping.start]
        return bytes(result)

    def write(self, address: int, data: bytes) -> None:
        self._checked(address, len(data), write=True)
        for index, byte in enumerate(data):
            self._writes[address + index] = byte

    def load(self, address: int, width: int) -> int:
        order = "little" if self.endianness is Endianness.LITTLE else "big"
        return int.from_bytes(self.read(address, width // 8), order)

    def store(self, address: int, value: int, width: int) -> None:
        order = "little" if self.endianness is Endianness.LITTLE else "big"
        self.write(address, value.to_bytes(width // 8, order))

    def read_c_string(self, address: int, limit: int = 1 << 16) -> bytes:
        result = bytearray()
        while len(result) < limit:
            byte = self.read(address + len(result), 1)[0]
            if byte == 0:
                return bytes(result)
            result.append(byte)
        return bytes(result)
