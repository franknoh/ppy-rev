"""Golden RevIR for a trimmed real Ghidra export of tests/fixtures/src/xor_check.c (gcc -O0).

Set PPY_REV_UPDATE_GOLDEN=1 to rewrite the expected text after an intentional change.
"""

import os
from pathlib import Path

from ppy_rev.ghidra.schema import load_export
from ppy_rev.ir.text import format_module
from ppy_rev.ir.validate import validate_module
from ppy_rev.lift.lifter import lift_export

DATA = Path(__file__).parent / "data"


def test_xor_check_lifts_to_golden_ir() -> None:
    result = lift_export(load_export(DATA / "xor_check_gcc_O0.export.json"))
    assert result.diagnostics == ()
    assert validate_module(result.module) == []
    text = format_module(result.module)
    golden = DATA / "xor_check_gcc_O0.revir"
    if os.environ.get("PPY_REV_UPDATE_GOLDEN") == "1":
        golden.write_text(text, encoding="utf-8")
    assert text == golden.read_text(encoding="utf-8")
