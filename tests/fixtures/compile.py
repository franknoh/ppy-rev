"""Deterministic compilation of the C and C++ fixture corpus.

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
COMPILERS = {".c": ("gcc", "clang"), ".cpp": ("g++", "clang++")}
"""Which compilers build a source, by its extension."""
OPTIMIZATION_LEVELS = ("O0", "O1", "O2", "O3")
COMMON_FLAGS = ("-g0", "-fno-ident", "-Wall", "-Werror")
LANGUAGE_FLAGS = {".c": (), ".cpp": ("-std=c++17",)}
"""Extra flags a language needs; C builds keep the compiler's default dialect."""


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
    return sorted(path.stem for path in SOURCES.iterdir() if path.suffix in COMPILERS)


def source_for(name: str) -> Path:
    """The fixture's source, whichever language it is written in."""
    for suffix in COMPILERS:
        source = SOURCES / f"{name}{suffix}"
        if source.is_file():
            return source
    raise FileNotFoundError(f"no fixture source named {name!r}")


def compilers_for(name: str) -> tuple[str, ...]:
    return COMPILERS[source_for(name).suffix]


def build(name: str, variant: Variant | None = None) -> Path:
    source = source_for(name)
    variant = variant or Variant(compiler=COMPILERS[source.suffix][0])
    flags = [f"-{variant.optimization}", *LANGUAGE_FLAGS[source.suffix], *COMMON_FLAGS]
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
        for compiler in compilers_for(name):
            if shutil.which(compiler) is None:
                continue
            for level in OPTIMIZATION_LEVELS:
                sys.stdout.write(f"{build(name, Variant(compiler, level))}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
