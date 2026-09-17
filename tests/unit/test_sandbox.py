"""The sandbox runner's command line and process handling, with a stand-in runtime."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ppy_rev.diagnostics import ConfigurationError
from ppy_rev.verify.sandbox import (
    SandboxError,
    SandboxOptions,
    container_command,
    locate_runtime,
    run_sandboxed,
)
from support.sandbox import write_fake_runtime

TARGET = f"""#!{sys.executable}
import sys, time
data = sys.stdin.buffer.read()
if sys.argv[1:] == ["spin"]:
    time.sleep(60)
if sys.argv[1:] == ["flood"]:
    sys.stdout.buffer.write(b"x" * 300000)
sys.stdout.buffer.write(repr((sys.argv[1:], data)).encode())
sys.exit(3)
"""


def _executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def fake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[SandboxOptions, Path, Path]:
    log = tmp_path / "runtime.log"
    monkeypatch.setenv("FAKE_RUNTIME_LOG", str(log))
    runtime = write_fake_runtime(tmp_path / "runtime")
    target = _executable(tmp_path / "target program", TARGET)
    return SandboxOptions(runtime=runtime, timeout_seconds=5.0), target, log


def test_command_is_locked_down_and_never_a_shell_line() -> None:
    command = container_command(
        Path("/usr/bin/docker"),
        "name",
        Path("/work/scratch/ppy-rev-sandbox-x"),
        [b"-v", b"\xff"],
        SandboxOptions(image="img:1"),
    )
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--pull=never",
        "--volume=/work/scratch/ppy-rev-sandbox-x:/sandbox:ro",
    ):
        assert flag in command
    assert command[-4:] == ["--", "img:1", b"-v", b"\xff"]
    with pytest.raises(SandboxError):
        container_command(Path("docker"), "n", Path("/work/a:b"), [], SandboxOptions())


def test_missing_runtime_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        locate_runtime(tmp_path / "no-such-runtime")


def test_arguments_input_and_exit_status_reach_the_program(
    fake: tuple[SandboxOptions, Path, Path],
) -> None:
    options, target, _ = fake
    run = run_sandboxed(target, [b"one", b"t w o"], b"line\n", options)
    assert run.exit_status == 3
    assert run.stdout == repr((["one", "t w o"], b"line\n")).encode()


def test_time_limit_stops_and_removes_the_container(
    fake: tuple[SandboxOptions, Path, Path],
) -> None:
    options, target, log = fake
    run = run_sandboxed(target, [b"spin"], b"", SandboxOptions(options.runtime, timeout_seconds=1))
    assert run.timed_out
    assert log.read_text(encoding="utf-8").startswith("rm --force ppy-rev-verify-")


def test_output_is_bounded(fake: tuple[SandboxOptions, Path, Path]) -> None:
    options, target, _ = fake
    limited = SandboxOptions(options.runtime, timeout_seconds=5, output_limit=1000)
    run = run_sandboxed(target, [b"flood"], b"", limited)
    assert run.exit_status == 3
    assert run.stdout == b"x" * 1000
