import pytest

from conftest import FixtureCompiler
from ppy_rev import Analyzer
from ppy_rev.diagnostics import Severity
from ppy_rev.ir.text import format_module
from ppy_rev.ir.validate import validate_module
from ppy_rev.lift.lifter import lift_export

pytestmark = pytest.mark.ghidra

VARIANTS = [
    (compiler, level) for compiler in ("gcc", "clang") for level in ("O0", "O1", "O2", "O3")
]


@pytest.mark.parametrize(("compiler", "optimization"), VARIANTS)
def test_fixture_lifts_to_valid_deterministic_ir(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    compiler: str,
    optimization: str,
) -> None:
    export = analyzer.export(compile_fixture.build("xor_check", compiler, optimization))
    result = lift_export(export)
    assert validate_module(result.module) == []
    names = {function.name for function in result.module.functions}
    assert "main" in names
    errors = [
        diagnostic
        for diagnostic in result.diagnostics
        if diagnostic.severity is Severity.ERROR and diagnostic.location.function == "main"
    ]
    assert errors == []
    assert format_module(result.module) == format_module(lift_export(export).module)
