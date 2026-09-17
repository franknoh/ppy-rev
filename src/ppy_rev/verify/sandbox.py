"""Running the target natively, only when asked, inside a locked-down container.

Static analysis never executes the target. Native verification is an explicit opt-in that
runs a copy of the binary under Docker or Podman with no network, a read-only root file
system, no capabilities or privilege escalation, an unprivileged user, and limits on
memory, processes, CPU, wall time, and captured output. The image must already be present
locally: nothing is pulled.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from ppy_rev.diagnostics import ConfigurationError, PpyRevError

RUNTIMES = ("docker", "podman")
DEFAULT_IMAGE = "ubuntu:24.04"
MOUNT_POINT = "/sandbox"
TARGET_NAME = "target"
_SAFE_HOST_PATH = re.compile(r"^/[A-Za-z0-9/._-]+$")
_RUNTIME_FAILURE = 125
"""Docker and Podman exit with this status when the container itself could not run."""


class SandboxError(PpyRevError):
    pass


@dataclass(frozen=True, slots=True)
class SandboxOptions:
    runtime: Path | None = None
    """Container runtime executable; the first of docker or podman on PATH by default."""
    image: str = DEFAULT_IMAGE
    timeout_seconds: float = 10.0
    memory: str = "256m"
    pids: int = 64
    cpus: str = "1"
    output_limit: int = 1 << 20
    """Bytes of stdout and of stderr kept; the rest is read and discarded."""


@dataclass(frozen=True, slots=True)
class NativeRun:
    exit_status: int | None
    """None when the run was stopped at the time limit."""
    stdout: bytes
    stderr: bytes

    @property
    def timed_out(self) -> bool:
        return self.exit_status is None


def locate_runtime(explicit: Path | None) -> Path:
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigurationError(f"container runtime {explicit} does not exist")
        return explicit
    for name in RUNTIMES:
        found = shutil.which(name)
        if found is not None:
            return Path(found)
    raise ConfigurationError(
        "native verification needs docker or podman on PATH (or --sandbox-runtime)"
    )


def container_command(
    runtime: Path, name: str, directory: Path, arguments: list[bytes], options: SandboxOptions
) -> list[str | bytes]:
    """The runtime invocation: an argument vector, never a shell command line."""
    if not _SAFE_HOST_PATH.match(str(directory)):
        raise SandboxError(f"refusing to mount unusual path {str(directory)!r}")
    return [
        str(runtime),
        "run",
        "--rm",
        "--interactive",
        "--pull=never",
        f"--name={name}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        f"--pids-limit={options.pids}",
        f"--memory={options.memory}",
        f"--memory-swap={options.memory}",
        f"--cpus={options.cpus}",
        "--ulimit=core=0",
        "--ulimit=nofile=64:64",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
        f"--volume={directory}:{MOUNT_POINT}:ro",
        "--workdir=/tmp",
        f"--entrypoint={MOUNT_POINT}/{TARGET_NAME}",
        "--",
        options.image,
        *arguments,
    ]


def run_sandboxed(
    binary: Path, arguments: list[bytes], stdin: bytes, options: SandboxOptions
) -> NativeRun:
    """Run `binary` with `arguments` (argv[1:]) and `stdin` in a fresh container."""
    runtime = locate_runtime(options.runtime)
    if not binary.is_file():
        raise SandboxError(f"{binary} is not a regular file")
    with tempfile.TemporaryDirectory(prefix="ppy-rev-sandbox-") as scratch:
        directory = Path(scratch).resolve()
        target = directory / TARGET_NAME
        shutil.copyfile(binary, target)
        target.chmod(0o555)
        directory.chmod(0o755)
        name = f"ppy-rev-verify-{uuid.uuid4().hex}"
        command = container_command(runtime, name, directory, arguments, options)
        run = _run_bounded(command, stdin, options)
        if run.exit_status is None:
            _stop_container(runtime, name)
        elif run.exit_status == _RUNTIME_FAILURE and not run.stdout:
            detail = run.stderr.decode(errors="replace").strip()
            raise SandboxError(f"the container runtime could not run {options.image}: {detail}")
        return run


def _run_bounded(command: list[str | bytes], stdin: bytes, options: SandboxOptions) -> NativeRun:
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise AssertionError("pipes were requested for every stream")
    captured: dict[str, bytes] = {}
    workers = [
        threading.Thread(target=_feed, args=(process.stdin, stdin)),
        *(
            threading.Thread(target=_drain, args=(stream, options.output_limit, captured, key))
            for key, stream in (("stdout", process.stdout), ("stderr", process.stderr))
        ),
    ]
    for worker in workers:
        worker.start()
    try:
        status: int | None = process.wait(timeout=options.timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        status = None
    for worker in workers:
        worker.join()
    return NativeRun(status, captured.get("stdout", b""), captured.get("stderr", b""))


def _feed(stream: IO[bytes], data: bytes) -> None:
    try:
        stream.write(data)
        stream.close()
    except (BrokenPipeError, ValueError):
        pass  # the program stopped reading, or was stopped


def _drain(stream: IO[bytes], limit: int, captured: dict[str, bytes], key: str) -> None:
    kept = bytearray()
    while chunk := stream.read(65536):
        if len(kept) < limit:
            kept += chunk[: limit - len(kept)]
    captured[key] = bytes(kept)


def _stop_container(runtime: Path, name: str) -> None:
    """Killing the client does not stop the container; remove it explicitly."""
    subprocess.run(
        [str(runtime), "rm", "--force", name],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=False,
    )
