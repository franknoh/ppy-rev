"""`ppy-rev solve` on compiled crackmes, with every solution confirmed by the real binary.

The fixtures are this repository's own C sources; running them natively is how the tests
check that a solution RevIR verified is also accepted by the program itself.
"""

from __future__ import annotations

import json
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
    "vm_check": b"Granted",
    "simple_vm": b"Accepted",
    "format_goal": b"Welcome back, 0pen!",
    "float_check": b"Correct!",
}
STDIN_FIXTURES = frozenset({"fgets_check", "stdin_read", "scanf_check"})
SHORTEST = {
    "format_goal": b"0pen",
    "xor_check": b"rev_is_easy",
    "atoi_check": b"12345",
    "float_check": b"*",
    "recursive_check": b"recursive",
    "vm_check": b"Vm_0k!",
    "simple_vm": b"vM_l1ft!",
}
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


def test_flag_format_hints(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    del analyzer
    output = tmp_path / "solution"
    argv_binary = compile_fixture.build("xor_check", "gcc", "O2")
    code, text = _solve(
        argv_binary, "--flag-format", "rev_*easy", "--output", str(output), capsys=capsys
    )
    assert code == 0, text
    assert output.read_bytes() == b"rev_is_easy"
    code, text = _solve(argv_binary, "--suffix", "zz", capsys=capsys)
    assert code == 2
    assert "result: unsat" in text
    stdin_binary = compile_fixture.build("fgets_check", "clang", "O2")
    code, text = _solve(
        stdin_binary, "--flag-format", "gg*sr", "--output", str(output), capsys=capsys
    )
    assert code == 0, text
    assert output.read_bytes() == b"gg/dq2_o2sr\n"
    assert main(["solve", str(stdin_binary), "--flag-format", "CTF{"]) == 1
    assert "one '*'" in capsys.readouterr().err


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
    # A goal that is a format string: only the text around the conversions is printed.
    formatted = compile_fixture.build("format_goal", "gcc", "O2")
    code, text = _solve(formatted, "--verify", "--sandbox-runtime", str(runtime), capsys=capsys)
    assert code == 0, text
    assert "native (sandboxed): passed" in text


def test_vm_detect_reports_evidence(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler], capsys: pytest.CaptureFixture[str]
) -> None:
    del analyzer
    arguments = ["--cache-dir", str(BUILD_ROOT / "cache")]
    binary = compile_fixture.build("simple_vm", "clang", "O2")
    assert main(["vm", "detect", str(binary), *arguments]) == 0
    text = capsys.readouterr().out
    assert "Candidate dispatcher:" in text
    assert "[proven] indirect branch at" in text
    assert "VM program counter:" in text
    plain = compile_fixture.build("xor_check", "gcc", "O2")
    assert main(["vm", "detect", str(plain), *arguments]) == 2
    assert "No VM dispatcher found." in capsys.readouterr().out


def test_vm_lift_and_solve(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    del analyzer
    arguments = ["--cache-dir", str(BUILD_ROOT / "cache")]
    binary = compile_fixture.build("simple_vm", "clang", "O2")
    isa = tmp_path / "isa.json"
    assert main(["vm", "lift", str(binary), "--json", str(isa), *arguments]) == 0
    text = capsys.readouterr().out
    assert "Lifted: 18 instructions" in text
    assert "0x0012  op_0b  0b 04 01 30" in text
    description = json.loads(isa.read_text(encoding="utf-8"))
    assert {item["name"] for item in description["opcodes"]} >= {"op_01", "op_07", "op_0b"}
    assert main(["vm", "lift", str(binary), "--emit-ir", *arguments]) == 0
    assert "function execute.bytecode" in capsys.readouterr().out
    for name, answer in (("simple_vm", b"vM_l1ft!"), ("vm_check", b"Vm_0k!")):
        for compiler, level in (("gcc", "O0"), ("clang", "O2")):
            binary = compile_fixture.build(name, compiler, level)
            output = tmp_path / f"{name}-{compiler}-{level}"
            code = main(["vm", "solve", str(binary), "-v", "--output", str(output), *arguments])
            text = capsys.readouterr().out
            assert code == 0, text
            assert "verified on the original interpreter" in text
            assert output.read_bytes() == answer
            assert SUCCESS[name] in _native_output(binary, name, answer)


def test_concolic_strategy(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    del analyzer
    binary = compile_fixture.build("nested_branch", "gcc", "O2")
    output = tmp_path / "solution"
    code, text = _solve(
        binary,
        "--strategy",
        "concolic",
        "--seed",
        "nnnnnnnn",
        "-v",
        "--output",
        str(output),
        capsys=capsys,
    )
    assert code == 0, text
    assert "note: concolic search:" in text
    assert SUCCESS["nested_branch"] in _native_output(binary, "nested_branch", output.read_bytes())


def test_analyze_reports_what_solving_uses(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler], capsys: pytest.CaptureFixture[str]
) -> None:
    del analyzer
    arguments = ["--cache-dir", str(BUILD_ROOT / "cache")]
    assert (
        main(["analyze", str(compile_fixture.build("fgets_check", "gcc", "O2")), *arguments]) == 0
    )
    text = capsys.readouterr().out
    assert "Inputs:\n  stdin\n" in text
    assert 'puts("Access granted")' in text.split("Failure candidates:")[0]
    assert 'puts("Access denied")' in text.split("Failure candidates:")[1]
    assert "operations sliced away: " in text
    assert main(["analyze", str(compile_fixture.build("simple_vm", "gcc", "O2")), *arguments]) == 0
    assert "(confidence 0.9" in capsys.readouterr().out.split("VM dispatchers:")[1]


def test_exhausted_budgets_are_reported_not_unsat(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler], capsys: pytest.CaptureFixture[str]
) -> None:
    del analyzer
    binary = compile_fixture.build("strcmp_argv", "gcc", "O2")
    code, text = _solve(
        binary, "--strategy", "symbolic", "--max-loop-iterations", "2", capsys=capsys
    )
    assert code == 2
    assert "result: analysis incomplete" in text
    assert "forked more than 2 times on one path" in text
