"""Explicit, typed configuration shared by the library and the CLI."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

GHIDRA_HOME_VARIABLE = "PPY_REV_GHIDRA_HOME"
CACHE_DIR_VARIABLE = "PPY_REV_CACHE_DIR"


@dataclass(frozen=True, slots=True)
class GhidraOptions:
    home: Path | None = None
    """Ghidra installation; falls back to $PPY_REV_GHIDRA_HOME."""
    timeout_seconds: float = 900.0
    max_memory: str = "4G"
    decompile: bool = True
    decompile_timeout_seconds: int = 60


@dataclass(frozen=True, slots=True)
class CacheOptions:
    enabled: bool = True
    directory: Path | None = None
    """Cache root; falls back to $PPY_REV_CACHE_DIR, then the XDG cache directory."""

    def resolve_directory(self, environ: Mapping[str, str] = os.environ) -> Path:
        if self.directory is not None:
            return self.directory
        if configured := environ.get(CACHE_DIR_VARIABLE):
            return Path(configured)
        if xdg := environ.get("XDG_CACHE_HOME"):
            return Path(xdg) / "ppy-rev"
        return Path.home() / ".cache" / "ppy-rev"


@dataclass(frozen=True, slots=True)
class AnalyzerConfig:
    ghidra: GhidraOptions = field(default_factory=GhidraOptions)
    cache: CacheOptions = field(default_factory=CacheOptions)
