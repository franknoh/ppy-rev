"""Whole-program process setup: arguments, environment, heap, and libc data imports.

Execution starts at `main` as `__libc_start_main` would call it: argc in the first
integer argument register, argv in the second, envp in the third, and a return address
that ends the program when reached. Everything here is concrete; symbolic inputs are
written over the reserved argument bytes by the symbolic layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ppy_rev.abi import calling_convention
from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.execution.process import RETURN_SENTINEL, enter_call, standard_memory
from ppy_rev.ir.model import Module
from ppy_rev.summaries import ctype

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
    return memory


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
