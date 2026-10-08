"""The small persistent settings ppy-rev keeps for a user, under `~/.ppy-rev`.

Only what is tedious to repeat lives here — chiefly the Ghidra installation `ppy-rev doctor`
found and the user confirmed — so that `solve`, `lift`, and the rest need no environment set
up on every run. It is a plain JSON file; a missing or unreadable one simply means nothing is
cached yet.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

HOME_VARIABLE = "PPY_REV_HOME"
"""Overrides where the settings live; otherwise `~/.ppy-rev`."""
GHIDRA_HOME_KEY = "ghidra_home"


def config_home(environ: Mapping[str, str] = os.environ) -> Path:
    override = environ.get(HOME_VARIABLE)
    return Path(override) if override else Path.home() / ".ppy-rev"


def config_path(environ: Mapping[str, str] = os.environ) -> Path:
    return config_home(environ) / "config.json"


def load(environ: Mapping[str, str] = os.environ) -> dict[str, str]:
    """The saved settings, or an empty mapping when there are none to read."""
    try:
        parsed = json.loads(config_path(environ).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    settings = cast("dict[str, object]", parsed)
    return {str(key): str(value) for key, value in settings.items()}


def cached_ghidra_home(environ: Mapping[str, str] = os.environ) -> Path | None:
    saved = load(environ).get(GHIDRA_HOME_KEY)
    return Path(saved) if saved else None


def save_ghidra_home(home: Path, environ: Mapping[str, str] = os.environ) -> Path:
    """Record the Ghidra installation to use, and return the file it was written to."""
    path = config_path(environ)
    settings = load(environ)
    settings[GHIDRA_HOME_KEY] = str(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
