"""Whole-program process setup: arguments, environment, heap, and libc data imports.

Execution starts at `main` as `__libc_start_main` would call it: argc in the first
integer argument register, argv in the second, envp in the third, and a return address
that ends the program when reached. Everything here is concrete; symbolic inputs are
written over the reserved argument bytes by the symbolic layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from ppy_rev.abi import calling_convention
from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.execution.process import RETURN_SENTINEL, enter_call, standard_memory
from ppy_rev.ir.model import Module
from ppy_rev.summaries import ctype, cxx

ARGUMENTS_START = 0x7FFF_FFFF_1000
ARGUMENTS_SIZE = 0x1_0000
LIBC_DATA_START = 0x7FFF_F7E0_0000
LIBC_DATA_SIZE = 0x4000
HEAP_START = 0x0000_5555_A000_0000
HEAP_SIZE = 0x100_0000
STANDARD_STREAMS = {
    "stdin": LIBC_DATA_START + 0x100,
    "stdout": LIBC_DATA_START + 0x200,
    "stderr": LIBC_DATA_START + 0x300,
}
"""Addresses standing in for glibc's FILE objects; summaries recognise them by value."""
FILE_HANDLES = LIBC_DATA_START + 0x400
"""Where `fopen` hands out stand-ins for FILE objects, one 0x40 bytes after another."""
FILE_HANDLE_STEP = 0x40
ERRNO_ADDRESS = LIBC_DATA_START + 0x900
"""What `__errno_location` returns: a zeroed cell, since no modeled call ever fails."""
CTYPE_POINTERS = {
    "__ctype_b_loc": LIBC_DATA_START + 0x800,
    "__ctype_toupper_loc": LIBC_DATA_START + 0x808,
    "__ctype_tolower_loc": LIBC_DATA_START + 0x810,
}
"""What each `__ctype_*_loc` function returns: the address of a pointer into its table."""
_CTYPE_TABLES = {
    "__ctype_b_loc": (LIBC_DATA_START + 0x1000, 2, ctype.classification_table),
    "__ctype_toupper_loc": (LIBC_DATA_START + 0x1400, 4, ctype.upper_table),
    "__ctype_tolower_loc": (LIBC_DATA_START + 0x2000, 4, ctype.lower_table),
}
_STREAM_LABEL = re.compile(r"^(stdin|stdout|stderr)(@@?GLIBC.*)?$")
_CXX_STREAM_LABEL = re.compile(r"^(?:std::)?(cin|cout|cerr)(@@?GLIBCXX.*)?$")
CXX_STREAMS = LIBC_DATA_START + 0x3000
"""Where a C++ stream object goes when the image has no place of its own for it."""
CXX_CTYPE = LIBC_DATA_START + 0x3800
"""The one `std::ctype<char>` every stream in the program shares."""
CXX_IOS_VTABLE = LIBC_DATA_START + 0x3A00
"""A stand-in vtable: only the offset before it, to the `basic_ios` subobject, is read.

It sits clear of the facet, because that offset is read from before the vtable itself.
"""


@dataclass(frozen=True, slots=True)
class ProgramEntry:
    registers: dict[str, int]
    return_address: int
    argv_strings: tuple[int, ...]
    """Address of each argv string."""


def program_memory(module: Module) -> ConcreteMemory:
    """The module image plus stack, TLS, heap, and libc data objects."""
    memory = standard_memory(module)
    memory.map(Mapping("[args]", ARGUMENTS_START, ARGUMENTS_SIZE, True, True, None))
    memory.map(Mapping("[libc]", LIBC_DATA_START, LIBC_DATA_SIZE, True, True, None))
    memory.map(Mapping("[heap]", HEAP_START, HEAP_SIZE, True, True, None))
    pointer_width = module.target.pointer_width
    for name, (table, entry_size, content) in _CTYPE_TABLES.items():
        memory.write(table, content())
        index_zero = table - ctype.FIRST * entry_size
        memory.store(CTYPE_POINTERS[name], index_zero, pointer_width)
    for label in module.labels:
        match = _STREAM_LABEL.match(label.name)
        if match is None:
            continue
        address = label.address
        if memory.mapping_at(address) is None:
            # Imports reached through the GOT land in Ghidra's unmapped EXTERNAL block.
            name = f"[import {label.name}]"
            memory.map(Mapping(name, address, pointer_width // 8, True, True, None))
        memory.store(address, STANDARD_STREAMS[match.group(1)], pointer_width)
    _map_cxx_streams(module, memory)
    return memory


def _map_cxx_streams(module: Module, memory: ConcreteMemory) -> None:
    """Give `std::cin` and friends the object libstdc++ would have put there.

    Unoptimized code only ever passes the stream to a library call, which is modeled, but
    optimized code reads the object itself: the state `getline` leaves behind, and the
    `ctype` facet it widens the delimiter with. Those reads have to find something, and
    what they find has to be what the models agree with — a stream that is in good state.

    Where the object lives depends on how the program reaches it. A copy relocation puts
    it in the image's own `.bss`, which is where the code points; otherwise Ghidra gives
    the symbol an address outside the image, and the pointers to it are redirected here.
    """
    if not any(external.symbol.startswith(("_ZSt", "_ZNSt")) for external in module.externals):
        return  # no libstdc++ here, so a global named `cout` is the program's own
    pointer_width = module.target.pointer_width
    streams = [label for label in module.labels if _CXX_STREAM_LABEL.match(label.name) is not None]
    if not streams:
        return
    memory.store(CXX_CTYPE + cxx.CTYPE_WIDEN_OK, 1, 8)
    memory.write(CXX_CTYPE + cxx.CTYPE_WIDEN, bytes(range(256)))
    for index, label in enumerate(sorted(streams, key=lambda item: item.address)):
        object_at = label.address
        if memory.mapping_at(object_at) is None:
            object_at = CXX_STREAMS + index * cxx.IOS_SIZE
            _redirect(module, memory, label.address, object_at, pointer_width)
        memory.store(object_at, CXX_IOS_VTABLE, pointer_width)
        if memory.mapping_at(object_at + cxx.IOS_FACET) is not None:
            memory.store(object_at + cxx.IOS_FACET, CXX_CTYPE, pointer_width)


def _redirect(
    module: Module, memory: ConcreteMemory, from_address: int, to_address: int, width: int
) -> None:
    """Point every stored pointer to `from_address` at `to_address` instead.

    A program that reaches `std::cin` through the GOT loads an address Ghidra made up for
    the symbol, in a block that is not part of the image. The entry is rewritten so the
    load lands on the object modeled here instead.
    """
    size = width // 8
    order: Literal["little", "big"] = module.target.endianness.value
    wanted = from_address.to_bytes(size, order)
    for region in module.memory:
        if region.data is None or region.executable:
            continue
        start = region.data.find(wanted)
        while start >= 0:
            if start % size == 0:
                memory.relocate(region.start + start, to_address, width)
            start = region.data.find(wanted, start + 1)


def enter_main(
    module: Module,
    memory: ConcreteMemory,
    arguments: list[bytes],
    reserve: dict[int, int] | None = None,
) -> ProgramEntry:
    """Lay out argv and envp and set up registers for a call to main.

    `reserve` maps argv indexes to a minimum number of bytes (excluding the terminator)
    to set aside for that string, so symbolic content of up to that length fits.
    """
    reserve = reserve or {}
    pointer_size = module.target.pointer_width // 8
    cursor = ARGUMENTS_START
    strings: list[int] = []
    for index, argument in enumerate(arguments):
        strings.append(cursor)
        memory.write(cursor, argument + b"\0")
        cursor += max(len(argument), reserve.get(index, 0)) + 1
        cursor = (cursor + 15) & ~15
    argv = cursor
    for index, address in enumerate(strings):
        memory.store(argv + index * pointer_size, address, pointer_size * 8)
    memory.store(argv + len(strings) * pointer_size, 0, pointer_size * 8)
    envp = argv + (len(strings) + 1) * pointer_size
    memory.store(envp, 0, pointer_size * 8)
    argc_register, argv_register, envp_register = calling_convention(
        module.target
    ).integer_parameters[:3]
    frame = enter_call(
        module,
        memory,
        {argc_register: len(arguments), argv_register: argv, envp_register: envp},
    )
    return ProgramEntry(frame.registers, RETURN_SENTINEL, tuple(strings))
