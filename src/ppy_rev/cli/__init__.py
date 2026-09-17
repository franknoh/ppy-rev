"""Command-line entry point. Handlers stay thin; analysis lives in the library."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from ppy_rev._version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ppy-rev",
        description="Lift, analyze, and solve ELF reversing challenges.",
    )
    parser.add_argument("--version", action="version", version=f"ppy-rev {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help(sys.stdout)
    return 0
