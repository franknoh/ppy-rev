"""Minimal ELF header inspection.

Only enough to reject unsupported inputs before starting Ghidra and to relate ELF virtual
addresses to Ghidra's image base. Nothing here executes or maps the file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from ppy_rev.diagnostics import UnsupportedBinaryError

_MACHINES = {
    3: "x86",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}
_TYPES = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
_PT_LOAD = 1
_HEADER_LIMIT = 1 << 20


@dataclass(frozen=True, slots=True)
class ElfHeader:
    bits: int
    endianness: str
    type: int
    machine: int
    entry: int
    load_addresses: tuple[int, ...]

    @property
    def machine_name(self) -> str:
        return _MACHINES.get(self.machine, f"machine {self.machine}")

    @property
    def type_name(self) -> str:
        return _TYPES.get(self.type, f"type {self.type}")

    @property
    def is_position_independent(self) -> bool:
        return self.type == 3

    def rebase(self, address: int, image_base: int) -> int:
        """Map an ELF virtual address to Ghidra's address for the same byte."""
        if not self.load_addresses:
            return address
        return address - min(self.load_addresses) + image_base


def read_elf_header(path: Path) -> ElfHeader:
    try:
        with path.open("rb") as stream:
            data = stream.read(_HEADER_LIMIT)
    except OSError as error:
        raise UnsupportedBinaryError(f"cannot read {path}: {error.strerror}") from error
    return parse_elf_header(data, str(path))


def parse_elf_header(data: bytes, name: str = "input") -> ElfHeader:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise UnsupportedBinaryError(f"{name} is not an ELF file")
    bits = {1: 32, 2: 64}.get(data[4])
    endianness = {1: "little", 2: "big"}.get(data[5])
    if bits is None or endianness is None:
        raise UnsupportedBinaryError(f"{name} has an invalid ELF identification header")
    order = "<" if endianness == "little" else ">"
    word = "Q" if bits == 64 else "I"
    header_format = f"{order}HHI{word}{word}{word}IHHHHHH"
    header_size = struct.calcsize(header_format)
    if len(data) < 16 + header_size:
        raise UnsupportedBinaryError(f"{name} has a truncated ELF header")
    (
        elf_type,
        machine,
        _version,
        entry,
        program_offset,
        _section_offset,
        _flags,
        _header_size,
        program_entry_size,
        program_count,
        _section_entry_size,
        _section_count,
        _section_names,
    ) = struct.unpack_from(header_format, data, 16)
    return ElfHeader(
        bits=bits,
        endianness=endianness,
        type=elf_type,
        machine=machine,
        entry=entry,
        load_addresses=_load_addresses(
            data, order, bits, program_offset, program_entry_size, program_count
        ),
    )


def _load_addresses(
    data: bytes, order: str, bits: int, offset: int, entry_size: int, count: int
) -> tuple[int, ...]:
    # p_type is the first field in both layouts; p_vaddr follows p_offset.
    layout = f"{order}IIQQ" if bits == 64 else f"{order}III"
    needed = struct.calcsize(layout)
    addresses: list[int] = []
    for index in range(count):
        start = offset + index * entry_size
        if entry_size < needed or start + needed > len(data):
            break
        fields = struct.unpack_from(layout, data, start)
        if fields[0] == _PT_LOAD:
            addresses.append(fields[3] if bits == 64 else fields[2])
    return tuple(addresses)
