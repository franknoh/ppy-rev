from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from fixtures.compile import BUILD_ROOT, Variant, build
from ppy_rev import Analyzer, AnalyzerConfig, CacheOptions, GhidraOptions
from ppy_rev.config import GHIDRA_HOME_VARIABLE

# Set in environments that must run every test (Docker, CI); a missing tool then fails
# the run instead of silently skipping.
REQUIRE_TOOLS = os.environ.get("PPY_REV_REQUIRE_TOOLS") == "1"


def _unavailable(reason: str) -> None:
    if REQUIRE_TOOLS:
        pytest.fail(f"{reason} (PPY_REV_REQUIRE_TOOLS=1)")
    pytest.skip(reason)


@pytest.fixture(scope="session")
def analyzer() -> Analyzer:
    home = os.environ.get(GHIDRA_HOME_VARIABLE)
    if not home:
        _unavailable(f"{GHIDRA_HOME_VARIABLE} is not set")
    return Analyzer(
        AnalyzerConfig(
            ghidra=GhidraOptions(home=Path(str(home))),
            cache=CacheOptions(directory=BUILD_ROOT / "cache"),
        )
    )


@pytest.fixture(scope="session")
def compile_fixture() -> type[FixtureCompiler]:
    return FixtureCompiler


class FixtureCompiler:
    @staticmethod
    def build(name: str, compiler: str = "gcc", optimization: str = "O0") -> Path:
        if shutil.which(compiler) is None:
            _unavailable(f"{compiler} is not installed")
        return build(name, Variant(compiler, optimization))
