"""Command-line entry point. Handlers stay thin; analysis lives in the library."""

from __future__ import annotations

import argparse
import sys
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from ppy_rev._version import __version__
from ppy_rev.cli import commands
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.symbolic.inputs import Charset

EXIT_INTERNAL = 70

type Handler = Callable[[argparse.Namespace, TextIO], int]


def _address(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid address {text!r}") from None


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
    info.set_defaults(handler=commands.info)

    lift = subcommands.add_parser("lift", parents=[common], help="lift a binary into RevIR")
    lift.add_argument("binary", type=Path)
    lift.add_argument("--emit-ir", action="store_true", help="print the RevIR text form")
    lift.add_argument(
        "--emit-ppy", action="store_true", help="write PPy source to the output directory"
    )
    lift.add_argument(
        "--check-ppy", action="store_true", help="validate emitted PPy with `ppy check`"
    )
    lift.add_argument("-o", "--output", type=Path, help="write output here instead of stdout")
    lift.add_argument("--function", action="append", help="limit output to these functions")
    lift.add_argument(
        "--no-simplify", action="store_true", help="show RevIR exactly as lifted from p-code"
    )
    lift.set_defaults(handler=commands.lift)

    solve = subcommands.add_parser(
        "solve", parents=[common], help="find an input that reaches the success outcome"
    )
    solve.add_argument("binary", type=Path)
    inputs = solve.add_argument_group("inputs (default: discovered)")
    inputs.add_argument("--argv", type=int, metavar="INDEX", help="solve for argv[INDEX]")
    inputs.add_argument("--stdin", type=int, metavar="LENGTH", help="solve for LENGTH stdin bytes")
    goals = solve.add_argument_group("goals (default: discovered from output strings)")
    goals.add_argument("--goal-address", type=_address, metavar="ADDRESS")
    goals.add_argument("--goal-string", metavar="TEXT")
    goals.add_argument("--avoid-address", type=_address, action="append", metavar="ADDRESS")
    goals.add_argument("--avoid-string", action="append", metavar="TEXT")
    constraints = solve.add_argument_group("constraints (never assumed unless given)")
    constraints.add_argument("--length", type=int, help="exact input length (first line for stdin)")
    constraints.add_argument(
        "--max-length", type=int, default=64, help="longest argv input considered (default 64)"
    )
    constraints.add_argument("--prefix", metavar="TEXT")
    constraints.add_argument("--charset", choices=[charset.value for charset in Charset])
    outputs = solve.add_argument_group("output")
    outputs.add_argument("--solutions", type=int, default=1, metavar="COUNT")
    outputs.add_argument("--output", type=Path, help="write the first solution's bytes here")
    outputs.add_argument("--emit-smt2", type=Path, metavar="PATH", help="write the solver input")
    limits = solve.add_argument_group("limits")
    limits.add_argument("--timeout", type=float, default=600.0, metavar="SECONDS")
    limits.add_argument("--max-states", type=int, default=20_000)
    solve.set_defaults(handler=commands.solve)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    handler: Handler | None = getattr(arguments, "handler", None)
    if handler is None:
        parser.print_help(sys.stdout)
        return 0
    try:
        return handler(arguments, sys.stdout)
    except PpyRevError as error:
        sys.stderr.write(f"error: {error}\n")
        return commands.EXIT_ERROR
    except Exception as error:  # noqa: BLE001 - last-resort report for unexpected failures
        if commands.verbosity(arguments) > 0:
            traceback.print_exc()
        else:
            sys.stderr.write(f"internal error: {error!r} (rerun with -v for a traceback)\n")
        return EXIT_INTERNAL
