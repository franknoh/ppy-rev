"""Deterministic compilation of the C fixture corpus.

Builds are keyed by source contents, compiler identity, and flags, so tests rebuild only
when something that affects the binary changes. Outputs go to tests/fixtures/build/.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent
SOURCES = FIXTURES / "src"
BUILD_ROOT = FIXTURES / "build"
COMPILERS = ("gcc", "clang")
OPTIMIZATION_LEVELS = ("O0", "O1", "O2", "O3")
COMMON_FLAGS = ("-g0", "-fno-ident", "-Wall", "-Werror")


@dataclass(frozen=True, slots=True)
class Variant:
    compiler: str = "gcc"
    optimization: str = "O0"

    @property
    def label(self) -> str:
        return f"{self.compiler}-{self.optimization}"


def compiler_identity(compiler: str) -> str:
    executable = shutil.which(compiler)
    if executable is None:
        raise FileNotFoundError(f"compiler {compiler!r} is not installed")
    result = subprocess.run([executable, "--version"], capture_output=True, text=True, check=True)
    return result.stdout.splitlines()[0]


def fixture_names() -> list[str]:
    return sorted(path.stem for path in SOURCES.glob("*.c"))


def build(name: str, variant: Variant | None = None) -> Path:
    variant = variant or Variant()
    source = SOURCES / f"{name}.c"
    flags = [f"-{variant.optimization}", *COMMON_FLAGS]
    digest = hashlib.sha256()
    for part in (
        source.read_bytes(),
        compiler_identity(variant.compiler).encode(),
        *map(str.encode, flags),
    ):
        digest.update(part)
        digest.update(b"\0")
    output = BUILD_ROOT / f"{name}-{variant.label}-{digest.hexdigest()[:12]}"
    if output.is_file():
        return output
    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=BUILD_ROOT) as scratch:
        partial = Path(scratch) / name
        subprocess.run(
            [variant.compiler, *flags, "-o", str(partial), str(source)],
            check=True,
            capture_output=True,
        )
        partial.replace(output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the fixture corpus.")
    parser.add_argument("names", nargs="*", help="fixtures to build (default: all)")
    arguments = parser.parse_args()
    names: list[str] = arguments.names or fixture_names()
    for name in names:
        for compiler in COMPILERS:
            if shutil.which(compiler) is None:
                continue
            for level in OPTIMIZATION_LEVELS:
                sys.stdout.write(f"{build(name, Variant(compiler, level))}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
