import io
from pathlib import Path

import pytest

from ppy_rev import __version__
from ppy_rev.analysis.goals import GoalCandidate, Outcome
from ppy_rev.analysis.inputs import InputKind
from ppy_rev.cli import main
from ppy_rev.cli.render import render_solve
from ppy_rev.solve import (
    InputDescription,
    Solution,
    SolveResult,
    SolveStatistics,
    SolveStatus,
)


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"ppy-rev {__version__}"


def test_cache_clear_removes_cached_exports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exports = tmp_path / "exports"
    exports.mkdir()
    (exports / "abc.json.gz").write_bytes(b"")
    assert main(["cache", "clear", "--cache-dir", str(tmp_path)]) == 0
    assert capsys.readouterr().out == "removed 1 cached export\n"
    assert not any(exports.iterdir())


def test_solving_is_available_from_the_package() -> None:
    import ppy_rev

    request = ppy_rev.SolveRequest(binary=Path("chall"), goal_string="Correct!")
    assert request.strategy is ppy_rev.Strategy.AUTO
    assert ppy_rev.SolveStatus.SAT == "sat"


def _result(*solutions: Solution) -> SolveResult:
    goal = GoalCandidate(0x1000, Outcome.SUCCESS, "Correct!", "main", 0.9, ())
    argv = InputDescription(InputKind.ARGV, 1, 65, True, ())
    statistics = SolveStatistics(1, 1, 1, 0, 1, 1, 0.0)
    return SolveResult(
        "x86-64 Linux ELF",
        "main",
        (argv,),
        goal,
        (),
        SolveStatus.SAT,
        "z3",
        solutions,
        (),
        statistics,
        (),
    )


def test_empty_solutions_are_named() -> None:
    out = io.StringIO()
    render_solve(
        _result(
            Solution(b"", None, True, "reaches the goal"),
            Solution(None, b"\n", True, "reaches the goal"),
            Solution(b"key", None, True, "reaches the goal"),
        ),
        out,
        0,
    )
    text = out.getvalue()
    assert "Solution 1:\n  (empty)\n" in text
    assert "Solution 2:\n  (empty line)\n" in text
    assert "Solution 3:\n  key\n" in text
