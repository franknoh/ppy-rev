"""`ppy-rev doctor`: check the tools ppy-rev needs, and find Ghidra once so it is saved.

The checks only read — versions, a directory listing, an import. Saving the Ghidra it found
is the one change it makes, and the command asks first.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ppy_rev.config import GHIDRA_HOME_VARIABLE
from ppy_rev.ghidra.discover import discover_ghidra
from ppy_rev.ghidra.headless import EXPECTED_GHIDRA_VERSION, GhidraInstallation, installation_at
from ppy_rev.userconfig import cached_ghidra_home

REQUIRED_JAVA = 21
REQUIRED_PYTHON = (3, 12)


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str
    """A version or path when found, or why not when missing."""
    hint: str = ""
    """What to do about it, shown when it is not satisfied."""


@dataclass(frozen=True, slots=True)
class Diagnosis:
    checks: tuple[Check, ...]
    ghidra: GhidraInstallation | None
    """The installation ppy-rev would use, or could use once saved."""
    source: str
    """Where that Ghidra came from: 'environment', 'config', 'discovered', or ''."""

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    @property
    def can_save(self) -> bool:
        """A Ghidra is available but not yet saved to the config (so it is worth offering)."""
        return self.ghidra is not None and self.source != "config"


def diagnose(environ: Mapping[str, str] = os.environ) -> Diagnosis:
    ghidra, source = _resolve_ghidra(environ)
    checks = (_python_check(), _java_check(), _z3_check(), _ghidra_check(ghidra, source))
    return Diagnosis(checks, ghidra, source)


def _resolve_ghidra(environ: Mapping[str, str]) -> tuple[GhidraInstallation | None, str]:
    if (configured := environ.get(GHIDRA_HOME_VARIABLE)) and (
        found := installation_at(Path(configured))
    ):
        return found, "environment"
    if (cached := cached_ghidra_home(environ)) and (found := installation_at(cached)):
        return found, "config"
    discovered = discover_ghidra(environ)
    return (discovered[0], "discovered") if discovered else (None, "")


def _python_check() -> Check:
    version = ".".join(str(part) for part in sys.version_info[:3])
    ok = sys.version_info[:2] >= REQUIRED_PYTHON
    hint = "" if ok else f"ppy-rev needs Python {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]} or newer"
    return Check("Python", ok, version, hint)


def _java_check() -> Check:
    version = _java_version()
    if version is None:
        return Check("Java (JDK)", False, "not found", f"install a JDK {REQUIRED_JAVA} for Ghidra")
    major = java_feature_version(version)
    ok = major is not None and major >= REQUIRED_JAVA
    hint = "" if ok else f"Ghidra needs a JDK {REQUIRED_JAVA}; this is {version}"
    return Check("Java (JDK)", ok, version, hint)


def _java_version() -> str | None:
    java = shutil.which("java")
    if java is None:
        return None
    try:
        completed = subprocess.run(
            [java, "-version"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r'version "([^"]+)"', completed.stderr or completed.stdout)
    return match.group(1) if match else None


def java_feature_version(version: str) -> int | None:
    """The feature release of a Java version string, e.g. 21 from `21.0.2`, 8 from `1.8.0`."""
    parts = version.split(".")
    try:
        first = int(parts[0])
    except ValueError:
        return None
    # Pre-9 Java numbered itself 1.8.0; everything since leads with the feature release.
    return int(parts[1]) if first == 1 and len(parts) > 1 and parts[1].isdigit() else first


def _z3_check() -> Check:
    try:
        import z3
    except ImportError:
        return Check("z3", False, "not importable", "reinstall ppy-rev so its solver is present")
    version = getattr(z3, "get_version_string", lambda: "?")()
    return Check("z3", True, version)


def _ghidra_check(ghidra: GhidraInstallation | None, source: str) -> Check:
    if ghidra is None:
        hint = f"install Ghidra {EXPECTED_GHIDRA_VERSION} and re-run `ppy-rev doctor`"
        return Check("Ghidra", False, "not found", hint)
    where = {"environment": GHIDRA_HOME_VARIABLE, "config": "saved", "discovered": "found"}[source]
    detail = f"{ghidra.version}  {ghidra.home}  ({where})"
    if ghidra.version != EXPECTED_GHIDRA_VERSION:
        return Check("Ghidra", True, detail, f"the bridge targets {EXPECTED_GHIDRA_VERSION}")
    return Check("Ghidra", True, detail)
