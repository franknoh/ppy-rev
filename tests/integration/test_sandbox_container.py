"""Native verification in a real container: isolation holds and time limits apply.

Opt in with PPY_REV_SANDBOX_IMAGE naming a local image that provides glibc (it is never
pulled); docker or podman must be on PATH.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from conftest import FixtureCompiler
from ppy_rev.verify.sandbox import SandboxOptions, locate_runtime, run_sandboxed

IMAGE = os.environ.get("PPY_REV_SANDBOX_IMAGE")
pytestmark = [
    pytest.mark.native,
    pytest.mark.sandbox,
    pytest.mark.skipif(
        IMAGE is None or not any(shutil.which(name) for name in ("docker", "podman")),
        reason="set PPY_REV_SANDBOX_IMAGE and install docker or podman",
    ),
]


def test_program_runs_isolated(compile_fixture: type[FixtureCompiler]) -> None:
    assert IMAGE is not None
    probe = compile_fixture.build("sandbox_probe", "gcc", "O2")
    run = run_sandboxed(probe, [b"hello"], b"input\n", SandboxOptions(image=IMAGE))
    assert run.exit_status == 3
    assert run.stdout.decode().splitlines() == [
        "uid=65534",
        "connect=-1",
        "write_root=0",
        "write_mount=0",
        "argv=2:hello",
        "stdin=input",
    ]


def test_time_limit_removes_the_container(compile_fixture: type[FixtureCompiler]) -> None:
    assert IMAGE is not None
    probe = compile_fixture.build("sandbox_probe", "gcc", "O2")
    options = SandboxOptions(image=IMAGE, timeout_seconds=2)
    run = run_sandboxed(probe, [b"spin", b"forever"], b"", options)
    assert run.timed_out
    runtime = locate_runtime(None)
    listed = subprocess.run(
        [str(runtime), "ps", "--all", "--filter", "name=ppy-rev-verify-", "--quiet"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert listed.stdout.strip() == ""
