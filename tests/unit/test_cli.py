from pathlib import Path

import pytest

from ppy_rev import __version__
from ppy_rev.cli import main


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
