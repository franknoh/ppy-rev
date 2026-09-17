"""Running Ghidra's headless analyzer with the export bridge."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ppy_rev.config import GHIDRA_HOME_VARIABLE, GhidraOptions
from ppy_rev.diagnostics import ConfigurationError, GhidraError

BRIDGE_DIRECTORY = Path(__file__).with_name("bridge")
EXPORT_SCRIPT = "PpyRevExport.java"
_LOG_TAIL_LINES = 40


@dataclass(frozen=True, slots=True)
class GhidraInstallation:
    home: Path
    version: str

    @property
    def analyze_headless(self) -> Path:
        return self.home / "support" / "analyzeHeadless"


def locate_ghidra(
    explicit: Path | None, environ: Mapping[str, str] = os.environ
) -> GhidraInstallation:
    configured = explicit if explicit is not None else environ.get(GHIDRA_HOME_VARIABLE)
    if not configured:
        raise ConfigurationError(
            f"Ghidra installation not configured: set {GHIDRA_HOME_VARIABLE} or pass --ghidra-home"
        )
    home = Path(configured).expanduser().resolve()
    properties = home / "Ghidra" / "application.properties"
    installation = GhidraInstallation(home=home, version=_read_version(properties))
    if not installation.analyze_headless.is_file():
        raise ConfigurationError(
            f"{home} is not a Ghidra installation (no support/analyzeHeadless)"
        )
    return installation


def _read_version(properties: Path) -> str:
    try:
        text = properties.read_text(encoding="utf-8")
    except OSError:
        raise ConfigurationError(
            f"{properties.parent.parent} is not a Ghidra installation (no application.properties)"
        ) from None
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "application.version" and value.strip():
            return value.strip()
    raise ConfigurationError(f"{properties} does not declare application.version")


def bridge_digest() -> str:
    """Identify the bridge sources, so exports from an older bridge are never reused."""
    digest = hashlib.sha256()
    for source in sorted(BRIDGE_DIRECTORY.glob("*.java")):
        digest.update(source.name.encode())
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def run_export(
    installation: GhidraInstallation, binary: Path, output: Path, options: GhidraOptions
) -> None:
    """Import `binary` into a throwaway project, analyze it, and write the export to `output`.

    The binary is copied into the temporary workspace first, so the analyzed bytes cannot
    change underneath the import and odd file names never reach Ghidra's project layer.
    """
    with tempfile.TemporaryDirectory(prefix="ppy-rev-ghidra-") as workspace_name:
        workspace = Path(workspace_name)
        project = workspace / "project"
        project.mkdir()
        target = workspace / _safe_program_name(binary.name)
        shutil.copyfile(binary, target)
        log = workspace / "headless.log"
        command = [
            str(installation.analyze_headless),
            str(project),
            "ppy_rev_project",
            "-import",
            str(target),
            "-scriptPath",
            str(BRIDGE_DIRECTORY),
            "-postScript",
            EXPORT_SCRIPT,
            f"output={output}",
            f"decompile={'true' if options.decompile else 'false'}",
            f"decompile_timeout={options.decompile_timeout_seconds}",
            "-analysisTimeoutPerFile",
            str(max(1, int(options.timeout_seconds))),
            "-deleteProject",
        ]
        environment = dict(os.environ)
        environment["GHIDRA_HEADLESS_MAXMEM"] = options.max_memory
        with log.open("wb") as log_stream:
            returncode = _run_with_timeout(
                command, environment, log_stream.fileno(), options.timeout_seconds
            )
        log_text = log.read_text(encoding="utf-8", errors="replace")
        if returncode is None:
            raise GhidraError(
                f"Ghidra analysis of {binary} exceeded {options.timeout_seconds:g}s\n"
                + _tail(log_text)
            )
        if returncode != 0 or not output.is_file():
            raise GhidraError(
                f"Ghidra export of {binary} failed (exit status {returncode})\n" + _tail(log_text)
            )


def _run_with_timeout(
    command: list[str], environment: dict[str, str], log_fd: int, timeout: float
) -> int | None:
    """Run in a new session so a timeout kills the JVM, not just the launcher script."""
    process = subprocess.Popen(
        command,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=log_fd,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        return None


def _safe_program_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".-")
    return cleaned or "program"


def _tail(log_text: str) -> str:
    lines = log_text.splitlines()[-_LOG_TAIL_LINES:]
    return "\n".join(f"  | {line}" for line in lines)
