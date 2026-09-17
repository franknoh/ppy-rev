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
from ppy_rev.solve import Strategy
from ppy_rev.symbolic.inputs import Charset
from ppy_rev.verify.sandbox import DEFAULT_IMAGE

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
    _solve_options(solve)
    solve.set_defaults(handler=commands.solve)

    cache = subcommands.add_parser("cache", help="manage cached Ghidra exports")
    cache_commands = cache.add_subparsers(dest="cache_command", metavar="command")
    clear = cache_commands.add_parser("clear", parents=[common], help="delete every cached export")
    clear.set_defaults(handler=commands.cache_clear)

    vm = subcommands.add_parser("vm", help="analyze bytecode interpreters")
    vm_commands = vm.add_subparsers(dest="vm_command", metavar="command")
    detect = vm_commands.add_parser(
        "detect", parents=[common], help="find VM dispatchers, with the evidence for each"
    )
    detect.add_argument("binary", type=Path)
    detect.add_argument(
        "--all", action="store_true", help="also show unlikely candidates (plain switches)"
    )
    detect.set_defaults(handler=commands.vm_detect)
    lift_vm = vm_commands.add_parser(
        "lift", parents=[common], help="translate the bytecode into RevIR and describe its ISA"
    )
    lift_vm.add_argument("binary", type=Path)
    lift_vm.add_argument("--emit-ir", action="store_true", help="print the bytecode as RevIR")
    lift_vm.add_argument("--json", type=Path, metavar="PATH", help="write the ISA description")
    lift_vm.set_defaults(handler=commands.vm_lift)
    solve_vm = vm_commands.add_parser(
        "solve",
        parents=[common],
        help="solve with the interpreter replaced by its lifted bytecode",
    )
    _solve_options(solve_vm)
    solve_vm.set_defaults(handler=commands.vm_solve)
    return parser


def _solve_options(solve: argparse.ArgumentParser) -> None:
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
    outputs.add_argument(
        "--emit-smt2",
        nargs="?",
        const="-",
        metavar="PATH",
        help="write the goal path's constraints as SMT-LIB (to stdout without PATH)",
    )
    native = solve.add_argument_group("native verification (runs the target; off by default)")
    native.add_argument(
        "--verify",
        action="store_true",
        help="also run each solution in a locked-down container (no network, read-only)",
    )
    native.add_argument("--sandbox-runtime", type=Path, metavar="PATH", help="docker or podman")
    native.add_argument(
        "--sandbox-image",
        default=DEFAULT_IMAGE,
        metavar="IMAGE",
        help=f"local image providing the C library (default {DEFAULT_IMAGE}; never pulled)",
    )
    search = solve.add_argument_group("search")
    search.add_argument(
        "--strategy",
        choices=[strategy.value for strategy in Strategy],
        default=Strategy.AUTO.value,
        help="symbolic search, concolic search, or symbolic then concolic (default auto)",
    )
    search.add_argument("--seed", metavar="TEXT", help="the first input concolic search follows")
    limits = solve.add_argument_group("limits")
    limits.add_argument("--timeout", type=float, default=600.0, metavar="SECONDS")
    limits.add_argument("--max-states", type=int, default=20_000)


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
