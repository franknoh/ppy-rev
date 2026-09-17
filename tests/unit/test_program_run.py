"""Whole-program concrete execution: process setup, C library summaries, and watches."""

from __future__ import annotations

import pytest

from ppy_rev.abi import SYSV_X86_64
from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.execution.run import Watch, run_program
from ppy_rev.ir.model import Endianness, Module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.summaries.concrete import ConcreteIO, ConcreteLibc, ProgramExitError
from ppy_rev.summaries.formatting import FormatError, format_printf
from ppy_rev.summaries.libc import modeled_reads
from support.exports import ProgramBuilder, call, const, op, reg, ret, tmp

DATA = 0x10000


def _memory(content: bytes) -> ConcreteMemory:
    memory = ConcreteMemory(Endianness.LITTLE)
    memory.map(Mapping("data", DATA, 0x1000, True, True, None))
    memory.write(DATA, content)
    return memory


def _echo_program() -> Module:
    """main: puts(argv[1]); return 3"""
    program = ProgramBuilder()
    program.import_("puts", 0x3000)
    after = program.code(
        0x1000,
        [
            op("INT_ADD", [reg("RSI"), const(8, 8)], tmp(0x10, 8)),
            op("LOAD", [tmp(0x10, 8)], reg("RDI")),
        ],
    )
    after = program.code(after, call(0x3000, after + 4))
    after = program.code(after, [op("COPY", [const(3, 8)], reg("RAX"))])
    program.code(after, ret(), length=1)
    program.function("main", 0x1000)
    module = lift_export(program.build()).module
    return simplify_module(module, modeled_reads(SYSV_X86_64))


def test_program_runs_from_main_with_arguments() -> None:
    module = _echo_program()
    main = module.function_named("main")
    assert main is not None
    run = run_program(module, main, [b"./echo", b"hello"])
    assert (run.stdout, run.outcome, run.first_watch) == (b"hello\n", "main returned 3", None)
    watched = run_program(module, main, [b"./echo", b"hi"], watches=(Watch("ret", 0x100C),))
    assert watched.first_watch == Watch("ret", 0x100C)
    assert watched.stdout == b"hi\n"


def test_string_summaries_compare_bytes_like_c() -> None:
    libc = ConcreteLibc(SYSV_X86_64)
    memory = _memory(b"abc\0abd\0ab\0")
    registers = {"RDI": DATA, "RSI": DATA + 4}
    assert libc("strcmp", registers, memory)["RAX"] == (ord("c") - ord("d")) & 0xFFFFFFFF
    assert libc("strncmp", {**registers, "RDX": 2}, memory)["RAX"] == 0
    assert libc("strcmp", {"RDI": DATA, "RSI": DATA + 8}, memory)["RAX"] == ord("c")
    assert libc("strlen", {"RDI": DATA + 8}, memory)["RAX"] == 2


def test_stdin_summaries_consume_the_input_in_order() -> None:
    io = ConcreteIO(stdin=b"first\nsecond")
    libc = ConcreteLibc(SYSV_X86_64, io)
    memory = _memory(bytes(64))
    assert libc("read", {"RDI": 0, "RSI": DATA, "RDX": 3}, memory)["RAX"] == 3
    assert memory.read(DATA, 3) == b"fir"
    assert libc("getchar", {}, memory)["RAX"] == ord("s")
    assert io.stdin_position == 4


def test_exit_and_formatting() -> None:
    libc = ConcreteLibc(SYSV_X86_64)
    with pytest.raises(ProgramExitError) as exited:
        libc("exit", {"RDI": 7}, _memory(b""))
    assert exited.value.status == 7
    memory = _memory(b"key\0")
    formatted = format_printf(b"%s=%d %04x|%-3c|%%", [DATA, (-5) & 0xFFFFFFFF, 0xAB, 0x41], memory)
    assert formatted == b"key=-5 00ab|A  |%"
    with pytest.raises(FormatError):
        format_printf(b"%f", [0], memory)
