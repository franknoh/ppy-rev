"""A stand-in container runtime for tests: it runs the entrypoint directly, unconfined."""

from __future__ import annotations

import sys
from pathlib import Path

FAKE_RUNTIME = f"""#!{sys.executable}
# Runs the entrypoint directly, mapping the mounted directory back to the host.
import os, sys
arguments = sys.argv[1:]
if arguments[0] == "rm":
    with open(os.environ["FAKE_RUNTIME_LOG"], "a") as log:
        log.write(" ".join(arguments) + "\\n")
    sys.exit(0)
host, mount, _ = next(a for a in arguments if a.startswith("--volume="))[9:].split(":")
entry = next(a for a in arguments if a.startswith("--entrypoint="))[13:]
program = entry.replace(mount, host, 1)
os.execv(program, [program, *arguments[arguments.index("--") + 2 :]])
"""


def write_fake_runtime(path: Path) -> Path:
    """Only `run` and `rm` are understood; `rm` calls are logged to $FAKE_RUNTIME_LOG."""
    path.write_text(FAKE_RUNTIME, encoding="utf-8")
    path.chmod(0o755)
    return path
