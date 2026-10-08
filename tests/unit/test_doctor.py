"""The `doctor` command: user config, Ghidra discovery, and the dependency checks."""

from pathlib import Path

from ppy_rev import userconfig
from ppy_rev.doctor import diagnose, java_feature_version
from ppy_rev.ghidra.discover import discover_ghidra
from ppy_rev.ghidra.headless import installation_at


def _fake_installation(root: Path, version: str = "12.1.3") -> Path:
    (root / "Ghidra").mkdir(parents=True)
    (root / "Ghidra" / "application.properties").write_text(
        f"application.name=Ghidra\napplication.version={version}\n"
    )
    (root / "support").mkdir()
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\n")
    return root


def test_config_round_trip(tmp_path: Path) -> None:
    environ = {userconfig.HOME_VARIABLE: str(tmp_path / "home")}
    assert userconfig.cached_ghidra_home(environ) is None
    path = userconfig.save_ghidra_home(Path("/opt/ghidra_12.1.3_PUBLIC"), environ)
    assert path == tmp_path / "home" / "config.json"
    assert userconfig.cached_ghidra_home(environ) == Path("/opt/ghidra_12.1.3_PUBLIC")


def test_unreadable_config_is_no_config(tmp_path: Path) -> None:
    environ = {userconfig.HOME_VARIABLE: str(tmp_path)}
    (tmp_path / "config.json").write_text("not json")
    assert userconfig.load(environ) == {}
    assert userconfig.cached_ghidra_home(environ) is None


def test_installation_at_accepts_only_real_trees(tmp_path: Path) -> None:
    home = _fake_installation(tmp_path / "ghidra")
    found = installation_at(home)
    assert found is not None and found.version == "12.1.3"
    assert installation_at(tmp_path / "empty") is None


def test_discover_prefers_the_expected_version(tmp_path: Path) -> None:
    newest = _fake_installation(tmp_path / "ghidra_13", "13.0")
    expected = _fake_installation(tmp_path / "ghidra_1213", "12.1.3")
    environ = {
        "PPY_REV_GHIDRA_HOME": str(newest),
        "GHIDRA_INSTALL_DIR": str(expected),
        userconfig.HOME_VARIABLE: str(tmp_path / "home"),
    }
    ours = [item for item in discover_ghidra(environ) if str(tmp_path) in str(item.home)]
    assert [item.version for item in ours] == ["12.1.3", "13.0"]


def test_resolve_ghidra_precedence(tmp_path: Path) -> None:
    env_home = _fake_installation(tmp_path / "env", "12.0")
    config_home = _fake_installation(tmp_path / "cfg")
    environ = {userconfig.HOME_VARIABLE: str(tmp_path / "home")}
    userconfig.save_ghidra_home(config_home, environ)
    # The environment wins over the saved config.
    environ["PPY_REV_GHIDRA_HOME"] = str(env_home)
    chosen = diagnose(environ)
    assert chosen.source == "environment" and chosen.ghidra is not None
    assert chosen.ghidra.version == "12.0" and chosen.can_save
    # Without the environment, the saved config is used and nothing needs saving.
    del environ["PPY_REV_GHIDRA_HOME"]
    chosen = diagnose(environ)
    assert chosen.source == "config" and chosen.ghidra is not None
    assert chosen.ghidra.home == config_home.resolve() and not chosen.can_save


def test_diagnose_reports_the_saved_ghidra(tmp_path: Path) -> None:
    home = _fake_installation(tmp_path / "ghidra")
    environ = {userconfig.HOME_VARIABLE: str(tmp_path / "home")}
    userconfig.save_ghidra_home(home, environ)
    diagnosis = diagnose(environ)
    ghidra = next(check for check in diagnosis.checks if check.name == "Ghidra")
    assert ghidra.ok and "12.1.3" in ghidra.detail
    assert diagnosis.source == "config" and not diagnosis.can_save


def test_java_feature_version_parsing() -> None:
    assert java_feature_version("21.0.2") == 21
    assert java_feature_version("17") == 17
    assert java_feature_version("1.8.0_292") == 8
    assert java_feature_version("nonsense") is None
