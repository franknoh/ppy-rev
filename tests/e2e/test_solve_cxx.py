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
    "cpp_cin_token": b"Correct!",
    "cpp_getline": b"Access granted",
    "cpp_lambda_check": b"Correct!",
    "cpp_nested_helpers": b"Access granted",
    "cpp_string_data": b"Correct!",
    "cpp_string_index": b"Correct!",
    "cpp_string_loop": b"Correct!",
    "cpp_string_size": b"Access granted",
}
"""What each fixture prints when the input is right."""
SOLVED = [
    (name, compiler, "O0")
    for compiler in ("g++", "clang++")
    for name in SUCCESS
    if not (compiler == "g++" and name == "cpp_string_index")
] + [("cpp_cin_token", compiler, "O2") for compiler in ("g++", "clang++")]
"""Which (fixture, compiler, optimization) combinations solve with no options at all.

`cpp_string_index` under `g++ -O0` stops at the approximation `std::getline` makes when
the line's length is up to the input. At `-O2` everything but `cpp_cin_token` inlines the
library into loads and stores that no model recognizes; see docs/scope.md.
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
