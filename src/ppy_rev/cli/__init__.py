"""Command-line entry point. Handlers stay thin; analysis lives in the library."""

from __future__ import annotations

import argparse
import sys
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from ppy_rev._version import __version__
from ppy_rev.api import Analyzer
from ppy_rev.config import AnalyzerConfig, CacheOptions, GhidraOptions
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.info import ProgramInfo

EXIT_ERROR = 1
EXIT_INTERNAL = 70

type Handler = Callable[[argparse.Namespace, TextIO], int]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ppy-rev",
        description="Lift, analyze, and solve ELF reversing challenges.",
    )
    parser.add_argument("--version", action="version", version=f"ppy-rev {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0)
    common.add_argument("--ghidra-home", type=Path, help="Ghidra installation directory")
    common.add_argument("--cache-dir", type=Path, help="analysis cache directory")
    common.add_argument("--no-cache", action="store_true", help="always re-run Ghidra")
    subcommands = parser.add_subparsers(dest="command", metavar="command")

    info = subcommands.add_parser(
        "info", parents=[common], help="show architecture, entry point, sections, and functions"
    )
    info.add_argument("binary", type=Path)
    info.set_defaults(handler=_info)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    handler = _handler(arguments)
    if handler is None:
        parser.print_help(sys.stdout)
        return 0
    try:
        return handler(arguments, sys.stdout)
    except PpyRevError as error:
        sys.stderr.write(f"error: {error}\n")
        return EXIT_ERROR
    except Exception as error:  # noqa: BLE001 - last-resort report for unexpected failures
        if _verbosity(arguments) > 0:
            traceback.print_exc()
        else:
            sys.stderr.write(f"internal error: {error!r} (rerun with -v for a traceback)\n")
        return EXIT_INTERNAL


def _handler(arguments: argparse.Namespace) -> Handler | None:
    handler: Handler | None = getattr(arguments, "handler", None)
    return handler


def _verbosity(arguments: argparse.Namespace) -> int:
    verbose: int = getattr(arguments, "verbose", 0)
    return verbose


def _analyzer(arguments: argparse.Namespace) -> Analyzer:
    ghidra_home: Path | None = arguments.ghidra_home
    cache_dir: Path | None = arguments.cache_dir
    no_cache: bool = arguments.no_cache
    return Analyzer(
        AnalyzerConfig(
            ghidra=GhidraOptions(home=ghidra_home),
            cache=CacheOptions(enabled=not no_cache, directory=cache_dir),
        )
    )


def _info(arguments: argparse.Namespace, out: TextIO) -> int:
    binary: Path = arguments.binary
    render_info(_analyzer(arguments).info(binary), out)
    return 0


def render_info(info: ProgramInfo, out: TextIO) -> None:
    kind = f"{info.format} {info.elf_type}"
    out.write(f"Target: {info.architecture} {info.endianness}-endian {kind}\n")
    if info.sha256:
        out.write(f"SHA-256: {info.sha256}\n")
    entry_name = f" ({info.entry_symbol})" if info.entry_symbol else ""
    out.write(f"Entry: {info.entry:#x}{entry_name}\n")
    out.write(f"Ghidra language: {info.ghidra_language} ({info.compiler})\n")
    out.write(f"Image base: {info.image_base:#x}\n")
    out.write("\nSections:\n")
    width = max((len(section.name) for section in info.sections), default=0)
    for section in info.sections:
        out.write(
            f"  {section.name:<{width}}  {section.start:#010x}  "
            f"{section.size:>8}  {section.permissions}\n"
        )
    out.write(f"\nFunctions ({len(info.functions)}):\n")
    for function in info.functions:
        thunk = f"  -> {function.thunk_of}" if function.thunk_of else ""
        out.write(f"  {function.entry:#010x}  {function.name}{thunk}\n")
    if info.imports:
        out.write(f"\nImports: {', '.join(info.imports)}\n")
