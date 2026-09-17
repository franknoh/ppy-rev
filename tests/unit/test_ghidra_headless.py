from pathlib import Path

import pytest

from ppy_rev.config import GhidraOptions
from ppy_rev.diagnostics import ConfigurationError
from ppy_rev.ghidra.cache import ExportCache, export_cache_key
from ppy_rev.ghidra.headless import bridge_digest, locate_ghidra


def _fake_installation(root: Path, version: str = "12.1.3") -> Path:
    (root / "Ghidra").mkdir(parents=True)
    (root / "Ghidra" / "application.properties").write_text(
        f"application.name=Ghidra\napplication.version={version}\n"
    )
    (root / "support").mkdir()
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\n")
    return root


def test_locates_installation_from_environment(tmp_path: Path) -> None:
    home = _fake_installation(tmp_path / "ghidra")
    installation = locate_ghidra(None, {"PPY_REV_GHIDRA_HOME": str(home)})
    assert installation.version == "12.1.3"
    assert installation.analyze_headless == home.resolve() / "support" / "analyzeHeadless"


def test_explicit_home_overrides_environment(tmp_path: Path) -> None:
    explicit = _fake_installation(tmp_path / "explicit", "12.0")
    other = _fake_installation(tmp_path / "other")
    installation = locate_ghidra(explicit, {"PPY_REV_GHIDRA_HOME": str(other)})
    assert installation.version == "12.0"


def test_missing_configuration_is_reported() -> None:
    with pytest.raises(ConfigurationError, match="PPY_REV_GHIDRA_HOME"):
        locate_ghidra(None, {})


def test_directory_without_ghidra_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not a Ghidra installation"):
        locate_ghidra(tmp_path, {})


def test_bridge_digest_covers_java_sources() -> None:
    assert len(bridge_digest()) == 64


def test_cache_key_changes_with_every_input() -> None:
    base = export_cache_key("aa", "12.1.3", "bridge", GhidraOptions())
    assert base == export_cache_key("aa", "12.1.3", "bridge", GhidraOptions())
    variants = {
        export_cache_key("bb", "12.1.3", "bridge", GhidraOptions()),
        export_cache_key("aa", "12.1.4", "bridge", GhidraOptions()),
        export_cache_key("aa", "12.1.3", "bridge2", GhidraOptions()),
        export_cache_key("aa", "12.1.3", "bridge", GhidraOptions(decompile=False)),
    }
    assert base not in variants
    assert len(variants) == 4


def test_cache_store_and_clear(tmp_path: Path) -> None:
    cache = ExportCache(tmp_path / "cache")
    source = tmp_path / "export.json"
    source.write_text("{}")
    assert cache.lookup("k") is None
    stored = cache.store("k", source)
    assert cache.lookup("k") == stored
    assert cache.clear() == 1
    assert cache.lookup("k") is None
