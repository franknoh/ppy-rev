"""`ppy-rev solve` on compiled crackmes, with every solution confirmed by the real binary.

The fixtures are this repository's own C sources; running them natively is how the tests
check that a solution RevIR verified is also accepted by the program itself.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from conftest import FixtureCompiler
from fixtures.compile import BUILD_ROOT
from ppy_rev import Analyzer
from ppy_rev.cli import main
from support.sandbox import write_fake_runtime

pytestmark = [pytest.mark.ghidra, pytest.mark.native]

SUCCESS = {
    "xor_check": b"Correct!",
    "strcmp_argv": b"Correct!",
    "nested_branch": b"Congratulations",
    "checksum_loop": b"Correct\n",
    "lookup_table": b"Valid",
    "switch_check": b"You got it",
    "helper_function": b"Correct!",
    "fgets_check": b"Access granted",
    "stdin_read": b"Success!",
    "scanf_check": b"Unlocked",
    "atoi_check": b"Correct!",
    "ctype_check": b"Well done",
    "recursive_check": b"Correct!",
    "dispatch_check": b"Access granted",
}
STDIN_FIXTURES = frozenset({"fgets_check", "stdin_read", "scanf_check"})
SHORTEST = {"xor_check": b"rev_is_easy", "atoi_check": b"12345", "recursive_check": b"recursive"}
"""Solutions that are unique once the shortest input is preferred."""
VARIANTS = [(compiler, level) for compiler in ("gcc", "clang") for level in ("O0", "O2")]


def _solve(binary: Path, *options: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = main(["solve", str(binary), "--cache-dir", str(BUILD_ROOT / "cache"), *options])
    return code, capsys.readouterr().out


def _native_output(binary: Path, name: str, solution: bytes) -> bytes:
    if name in STDIN_FIXTURES:
        command, stdin = [str(binary)], solution
    else:
        command, stdin = [str(binary), solution.decode("latin-1")], b""
    completed = subprocess.run(command, input=stdin, capture_output=True, timeout=30, check=False)
    return completed.stdout


@pytest.mark.parametrize("name", sorted(SUCCESS))
@pytest.mark.parametrize(("compiler", "optimization"), VARIANTS)
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
    expected_input = "stdin" if name in STDIN_FIXTURES else "argv[1]"
    assert f"Input:\n  {expected_input}\n" in text
    assert SUCCESS[name] in _native_output(binary, name, output.read_bytes())
    if name in SHORTEST:
        assert output.read_bytes() == SHORTEST[name]


def test_explicit_goal_string_and_constraints(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    del analyzer
    binary = compile_fixture.build("checksum_loop", "gcc", "O2")
    output = tmp_path / "solution"
    code, text = _solve(
        binary, "--charset", "digits", "--length", "4", "--output", str(output), capsys=capsys
    )
    assert code == 0, text
    assert output.read_bytes() == b"4096"
    code, text = _solve(binary, "--goal-string", "Wrong", "--output", str(output), capsys=capsys)
    assert code == 0, text
    assert b"Wrong" in _native_output(binary, "checksum_loop", output.read_bytes())


def test_contradictory_constraints_are_unsat_with_an_explanation(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
) -> None:
    del analyzer
    binary = compile_fixture.build("xor_check", "clang", "O2")
    code, text = _solve(binary, "--prefix", "zzz", capsys=capsys)
    assert code == 2
    assert "result: unsat" in text
    assert "none reaches the goal with argv[1] up to 64 bytes" in text


def test_several_distinct_solutions_and_smt2(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    del analyzer
    binary = compile_fixture.build("stdin_read", "gcc", "O0")
    smt2 = tmp_path / "constraints.smt2"
    code, text = _solve(binary, "--solutions", "3", "--emit-smt2", str(smt2), capsys=capsys)
    assert code == 0, text
    assert text.count("RevIR execution: passed") == 3
    assert "(assert" in smt2.read_text(encoding="utf-8")


def test_native_verification_is_reported(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del analyzer
    monkeypatch.setenv("FAKE_RUNTIME_LOG", str(tmp_path / "runtime.log"))
    runtime = write_fake_runtime(tmp_path / "runtime")
    binary = compile_fixture.build("fgets_check", "clang", "O2")
    code, text = _solve(binary, "--verify", "--sandbox-runtime", str(runtime), capsys=capsys)
    assert code == 0, text
    assert 'native (sandboxed): passed (exit status 0, prints "Access granted")' in text
