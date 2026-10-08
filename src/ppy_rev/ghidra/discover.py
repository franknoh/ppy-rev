"""Finding a Ghidra installation already on the machine, for `ppy-rev doctor`.

Looks where Ghidra is usually unpacked and where its own and ppy-rev's environment variables
point, reads each candidate's version, and ranks the one the bridge expects first. Nothing
here runs Ghidra; it only reads directory contents.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator, Mapping
from pathlib import Path

from ppy_rev.config import GHIDRA_HOME_VARIABLE
from ppy_rev.ghidra.headless import EXPECTED_GHIDRA_VERSION, GhidraInstallation, installation_at
from ppy_rev.userconfig import cached_ghidra_home

_SEARCH_ROOTS = (
    "/opt",
    "/usr/share",
    "/usr/local",
    "/usr/local/share",
    "~",
    "~/ghidra",
    "~/.local/opt",
    "~/.local/share",
)
"""Directories Ghidra is commonly unpacked under; each is scanned for a `ghidra*` folder."""


def _candidate_homes(environ: Mapping[str, str]) -> Iterator[Path]:
    for variable in (GHIDRA_HOME_VARIABLE, "GHIDRA_INSTALL_DIR"):
        if value := environ.get(variable):
            yield Path(value)
    if cached := cached_ghidra_home(environ):
        yield cached
    if launcher := shutil.which("analyzeHeadless"):
        yield Path(launcher).resolve().parent.parent
    for root in _SEARCH_ROOTS:
        base = Path(root).expanduser()
        try:
            entries = sorted(base.glob("ghidra*"))
        except OSError:
            continue
        yield from entries


def discover_ghidra(environ: Mapping[str, str] = os.environ) -> list[GhidraInstallation]:
    """Every Ghidra installation found, the expected version first, then newest.

    De-duplicated by resolved path, so a directory reached both through the environment and
    through the search roots appears once.
    """
    found: dict[Path, GhidraInstallation] = {}
    for home in _candidate_homes(environ):
        installation = installation_at(home)
        if installation is not None and installation.home not in found:
            found[installation.home] = installation
    return sorted(found.values(), key=_rank)


def _rank(installation: GhidraInstallation) -> tuple[int, tuple[int, ...], str]:
    expected = 0 if installation.version == EXPECTED_GHIDRA_VERSION else 1
    newest = tuple(-part for part in _version_parts(installation.version))
    return expected, newest, str(installation.home)


def _version_parts(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in version.split("."):
        digits = "".join(c for c in piece if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)
