"""Validation of emitted PPy with the PPy compiler's own static checker."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from ppy_rev.diagnostics import PpyRevError

CHECKED_CONVERSION = "remark[R3001]"


@dataclass(frozen=True, slots=True)
class PpyCheckResult:
    errors: tuple[str, ...]
    checked_conversions: tuple[str, ...]
    """Places where PPy could not prove a fixed-width contract and inserted a runtime check."""
    output: str

    @property
    def ok(self) -> bool:
        return not self.errors and not self.checked_conversions


def check_ppy(directory: Path, timeout_seconds: float = 600.0) -> PpyCheckResult:
    """Run `ppy check --remarks` over an emitted directory."""
    command = [
        sys.executable,
        "-m",
        "ppy_compiler",
        "--color",
        "never",
        "check",
        "--remarks",
        str(directory),
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout_seconds, check=False
        )
    except subprocess.TimeoutExpired as error:
        raise PpyRevError(f"ppy check timed out after {timeout_seconds:g}s") from error
    output = completed.stdout + completed.stderr
    lines = output.splitlines()
    errors = tuple(line for line in lines if line.startswith("error["))
    conversions = tuple(line for line in lines if line.startswith(CHECKED_CONVERSION))
    if completed.returncode not in (0, 1):
        raise PpyRevError(
            f"ppy check failed to run (exit status {completed.returncode}):\n{output}"
        )
    return PpyCheckResult(errors, conversions, output)
