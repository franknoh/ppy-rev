"""The C library summaries against glibc itself, through a compiled probe program.

tests/fixtures/src/libc_probe.c runs scanf with each of its formats over given input, and
reports strtol/atoi results and the C locale's character functions.
"""

from __future__ import annotations

import random
import re
import subprocess
from pathlib import Path

import pytest

from conftest import FixtureCompiler
from ppy_rev.abi import SYSV_X86_64
from ppy_rev.execution.memory import ConcreteMemory
from ppy_rev.ir.model import Endianness
from ppy_rev.summaries import ctype
from ppy_rev.summaries.concrete import ConcreteLibc
from ppy_rev.summaries.scanning import DirectiveKind, parse_format, parse_long, scan

pytestmark = pytest.mark.native

SOURCE = Path(__file__).parents[1] / "fixtures" / "src" / "libc_probe.c"
_FORMAT_BLOCK = re.search(r"formats\[\] = \{(.*?)\};", SOURCE.read_text(), flags=re.DOTALL)
assert _FORMAT_BLOCK is not None
FORMATS = [
    text.replace("\\n", "\n").encode()
    for text in re.findall(r'"((?:[^"\\]|\\.)*)"', _FORMAT_BLOCK.group(1))
]
SCAN_INPUTS = [
    b"",
    b" ",
    b"abc",
    b"  abc def\n",
    b"12 34",
    b"12,34",
    b"-5x",
    b"+",
    b"- 5",
    b"99999999999999999999 1",
    b"-99999999999999999999",
    b"\t\n7",
    b"%42",
    b"x-7",
    b"123abc",
    b"a",
    b"ab",
    b"abcdefgh 9",
    b"\x00\xff z",
    b"300 70000",
]
NUMBERS = [
    b"",
    b"0",
    b"42",
    b"-42",
    b"+7",
    b"  \t\n12x",
    b"+-1",
    b"- 1",
    b"9223372036854775807",
    b"9223372036854775808",
    b"-9223372036854775808",
    b"-9223372036854775809",
    b"123456789012345678901234567890",
    b"4294979641",
    b"0x10",
    b"00000000000000000000000000012",
    b"\x0b\x0c\r-3",
]


def _random_inputs(count: int) -> list[bytes]:
    generator = random.Random("libc_probe")
    alphabet = b" \t\n+-0123456789ax,%"
    return [
        bytes(generator.choice(alphabet) for _ in range(generator.randrange(0, 14)))
        for _ in range(count)
    ]


@pytest.fixture(scope="module")
def probe(compile_fixture: type[FixtureCompiler]) -> Path:
    return compile_fixture.build("libc_probe", "gcc", "O0")


def _modeled_scan(template: bytes, data: bytes) -> tuple[int, list[bytes], bytes]:
    scanned = scan(parse_format(template), data)
    buffers = [bytearray(64) for _ in range(4)]
    for buffer, assignment in zip(buffers, scanned.assignments, strict=False):
        match assignment.content:
            case bytes() as content:
                terminator = b"\0" if assignment.directive.kind is DirectiveKind.STRING else b""
                content += terminator
                buffer[: len(content)] = content
            case int() as value:
                size = assignment.directive.store_size
                buffer[:size] = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
    return scanned.result, [bytes(buffer[:16]) for buffer in buffers], data[scanned.consumed :]


@pytest.mark.parametrize("index", range(len(FORMATS)))
def test_scanf_matches_glibc(probe: Path, index: int) -> None:
    for data in SCAN_INPUTS + _random_inputs(20):
        completed = subprocess.run(
            [str(probe), "scanf", str(index)], input=data, capture_output=True, check=True
        )
        lines = completed.stdout.decode().split("\n")
        native = (
            int(lines[0]),
            [bytes.fromhex(line) for line in lines[1:5]],
            bytes.fromhex(lines[5]),
        )
        assert _modeled_scan(FORMATS[index], data) == native, (FORMATS[index], data)


def test_strtol_and_atoi_match_glibc(probe: Path) -> None:
    for text in NUMBERS + [data.replace(b"\0", b"") for data in _random_inputs(60)]:
        completed = subprocess.run(
            [str(probe), "strtol", text], capture_output=True, text=True, check=True
        )
        value, end, atoi = map(int, completed.stdout.split())
        number = parse_long(text)
        assert (number.value, number.end) == (value, end), text
        truncated = number.value & 0xFFFFFFFF
        assert truncated - (1 << 32) * (truncated >> 31) == atoi, text


def test_character_functions_match_glibc(probe: Path) -> None:
    completed = subprocess.run([str(probe), "ctype"], capture_output=True, text=True, check=True)
    libc = ConcreteLibc(SYSV_X86_64)
    memory = ConcreteMemory(Endianness.LITTLE)
    names = ("isalpha", "isdigit", "isspace", "isalnum", "ispunct", "toupper", "tolower")
    for line in completed.stdout.splitlines():
        character, *native = map(int, line.split())
        registers = {"RDI": character & 0xFFFFFFFFFFFFFFFF}
        modeled = [libc(name, registers, memory)["RAX"] & 0xFFFFFFFF for name in names]
        assert modeled == [value & 0xFFFFFFFF for value in native], character
        assert ctype.to_upper(character) & 0xFFFFFFFF == native[5] & 0xFFFFFFFF
