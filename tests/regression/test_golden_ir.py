"""Golden RevIR for a trimmed real Ghidra export of tests/fixtures/src/xor_check.c (gcc -O0).

Set PPY_REV_UPDATE_GOLDEN=1 to rewrite the expected text after an intentional change.
"""

import os
from pathlib import Path

import pytest

from ppy_rev.ghidra.schema import load_export
from ppy_rev.ir.model import Module
from ppy_rev.ir.text import format_module
from ppy_rev.ir.validate import validate_module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.simplify.pipeline import simplify_module

DATA = Path(__file__).parent / "data"


def _check_golden(module: Module, name: str) -> None:
    assert validate_module(module) == []
    text = format_module(module)
    golden = DATA / name
    if os.environ.get("PPY_REV_UPDATE_GOLDEN") == "1":
        golden.write_text(text, encoding="utf-8")
    assert text == golden.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lifted() -> Module:
    result = lift_export(load_export(DATA / "xor_check_gcc_O0.export.json"))
    assert result.diagnostics == ()
    return result.module


def test_xor_check_lifts_to_golden_ir(lifted: Module) -> None:
    _check_golden(lifted, "xor_check_gcc_O0.revir")


def test_xor_check_simplifies_to_golden_ir(lifted: Module) -> None:
    _check_golden(simplify_module(lifted), "xor_check_gcc_O0.simplified.revir")
