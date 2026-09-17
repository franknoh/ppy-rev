import struct

import pytest

from ppy_rev.diagnostics import UnsupportedBinaryError
from ppy_rev.elf import parse_elf_header


def _elf64(elf_type: int, entry: int, load_addresses: list[int]) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    program_offset = 64
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        elf_type,
        62,
        1,
        entry,
        program_offset,
        0,
        0,
        64,
        56,
        len(load_addresses),
        64,
        0,
        0,
    )
    programs = b"".join(
        struct.pack("<IIQQQQQQ", 1, 5, 0, vaddr, vaddr, 0x1000, 0x1000, 0x1000)
        for vaddr in load_addresses
    )
    return ident + header + programs


def test_parses_pie_header_and_rebases_entry() -> None:
    header = parse_elf_header(_elf64(3, 0x1080, [0x0, 0x1000, 0x3DB0]))
    assert header.bits == 64
    assert header.endianness == "little"
    assert header.machine_name == "x86-64"
    assert header.is_position_independent
    assert header.rebase(header.entry, image_base=0x100000) == 0x101080


def test_non_pie_entry_is_unchanged_when_image_base_matches() -> None:
    header = parse_elf_header(_elf64(2, 0x401040, [0x400000, 0x401000]))
    assert header.type_name == "executable"
    assert header.rebase(header.entry, image_base=0x400000) == 0x401040


@pytest.mark.parametrize(
    "data",
    [b"", b"MZ\x90\x00" + bytes(60), b"\x7fELF" + bytes([9, 1]) + bytes(58)],
)
def test_rejects_non_elf_and_invalid_identification(data: bytes) -> None:
    with pytest.raises(UnsupportedBinaryError):
        parse_elf_header(data)


def test_rejects_truncated_header() -> None:
    with pytest.raises(UnsupportedBinaryError, match="truncated"):
        parse_elf_header(_elf64(2, 0, [])[:40])
