"""`ppy-rev solve` on compiled C++ crackmes, with every solution confirmed by the binary.

C++ is where the gap between what a program says and what it compiles to is widest: the
same `std::string` is a library call at `-O0` and a handful of loads at `-O2`. These
fixtures are compiled both ways with both compilers, and the table below records which
combinations are solved today, so that a change that loses one is visible.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from conftest import FixtureCompiler
from fixtures.compile import BUILD_ROOT
from ppy_rev import Analyzer
from ppy_rev.cli import main

pytestmark = [pytest.mark.ghidra, pytest.mark.native]

SUCCESS = {
    "cpp_algorithm_transform": b"Correct!",
    "cpp_array_check": b"Access granted",
    "cpp_cin_token": b"Correct!",
    "cpp_getline": b"Access granted",
    "cpp_global_string": b"Correct!",
    "cpp_iostream_integer": b"Correct!",
    "cpp_lambda_check": b"Correct!",
    "cpp_nested_helpers": b"Access granted",
    "cpp_static_constructor": b"Correct!",
    "cpp_string_data": b"Correct!",
    "cpp_string_index": b"Correct!",
    "cpp_string_loop": b"Correct!",
    "cpp_string_size": b"Access granted",
    "cpp_vector_check": b"Correct!",
}
"""What each fixture prints when the input is right; all of them read stdin."""
SOLVED = [
    (name, compiler, optimization)
    for compiler in ("g++", "clang++")
    for optimization in ("O0", "O2")
    for name in SUCCESS
]
"""Every fixture, both compilers, with and without optimization.

`cpp_string_compare` is not here: it builds a `std::string` from `argv[1]`, whose length
the input decides, and the allocation that follows needs a size the analysis does not
have. See docs/scope.md.
"""


def _solve(binary: Path, *options: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = main(["solve", str(binary), "--cache-dir", str(BUILD_ROOT / "cache"), *options])
    return code, capsys.readouterr().out


@pytest.mark.parametrize(("name", "compiler", "optimization"), SOLVED)
def test_solution_is_accepted_by_the_binary(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    name: str,
    compiler: str,
    optimization: str,
) -> None:
    del analyzer  # requires Ghidra; the CLI finds it through the environment
    binary = compile_fixture.build(name, compiler, optimization)
    output = tmp_path / "solution"
    code, text = _solve(binary, "--output", str(output), capsys=capsys)
    assert code == 0, text
    assert "result: sat" in text
    assert "RevIR execution: passed (reaches the goal)" in text
    assert "Input:\n  stdin\n" in text
    completed = subprocess.run(
        [str(binary)], input=output.read_bytes(), capture_output=True, timeout=30, check=False
    )
    assert SUCCESS[name] in completed.stdout


@pytest.mark.parametrize("compiler", ["g++", "clang++"])
def test_a_constructor_decides_the_answer(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    compiler: str,
) -> None:
    """The key table is built before main; solving from main would answer for zeros.

    That answer used to come out `sat`, verify against RevIR, and be rejected by the real
    binary — so this checks the recovered input against the program itself.
    """
    binary = compile_fixture.build("cpp_static_constructor", compiler, "O0")
    del analyzer
    output = tmp_path / "solution"
    code, text = _solve(binary, "--output", str(output), capsys=capsys)
    assert code == 0, text
    assert output.read_bytes().rstrip(b"\n") == b"st4t1c"


@pytest.mark.parametrize("compiler", ["g++", "clang++"])
def test_a_string_of_unknown_length_is_refused_not_guessed(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    compiler: str,
) -> None:
    """`std::string s(argv[1])` allocates for a length the input decides.

    The honest answer is that the analysis stops there. It must not be `unsat`, which
    would claim every path was explored.
    """
    del analyzer
    binary = compile_fixture.build("cpp_string_compare", compiler, "O0")
    code, text = _solve(binary, capsys=capsys)
    assert code == 2, text
    assert "result: unsupported semantics" in text
    assert "is symbolic" in text
