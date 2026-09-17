from collections import Counter

import pytest

from conftest import FixtureCompiler
from ppy_rev import Analyzer
from ppy_rev.ghidra.schema import GhidraExport

pytestmark = pytest.mark.ghidra


def _function_opcodes(export: GhidraExport, name: str) -> Counter[str]:
    function = next(function for function in export.functions if function.name == name)
    opcodes: Counter[str] = Counter()
    for instruction in export.instructions:
        if any(start <= instruction.address <= end for start, end in function.body):
            opcodes.update(op.opcode for op in instruction.pcode)
    return opcodes


@pytest.fixture(scope="module")
def xor_export(analyzer: Analyzer, compile_fixture: type[FixtureCompiler]) -> GhidraExport:
    return analyzer.export(compile_fixture.build("xor_check"))


def test_raw_pcode_of_check_contains_expected_operation_classes(xor_export: GhidraExport) -> None:
    opcodes = _function_opcodes(xor_export, "check")
    for expected in ("INT_XOR", "LOAD", "STORE", "CBRANCH", "CALL", "INT_ADD", "RETURN"):
        assert opcodes[expected] > 0, expected


def test_high_pcode_is_exported_in_ssa_form(xor_export: GhidraExport) -> None:
    check = next(function for function in xor_export.functions if function.name == "check")
    assert check.high is not None and check.high.status == "ok"
    high_opcodes = {op.opcode for block in check.high.blocks for op in block.ops}
    assert {"MULTIEQUAL", "CBRANCH", "INT_XOR"} <= high_opcodes
    assert check.high.prototype is not None
    assert len(check.high.prototype.parameters) == 1


def test_plt_thunks_resolve_to_externals(xor_export: GhidraExport) -> None:
    thunks = {
        function.name: function.thunk_target
        for function in xor_export.functions
        if function.thunk_target is not None and function.thunk_target.external
    }
    assert {"puts", "strlen"} <= thunks.keys()


def test_string_references_point_into_main(xor_export: GhidraExport) -> None:
    main = next(function for function in xor_export.functions if function.name == "main")
    correct = next(string for string in xor_export.strings if string.value == "Correct!")
    assert any(
        start <= reference.source <= end
        for reference in correct.references
        for start, end in main.body
    )


def test_info_reports_architecture_entry_sections_and_functions(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler]
) -> None:
    info = analyzer.info(compile_fixture.build("xor_check"))
    assert info.architecture == "x86-64"
    assert info.bits == 64
    assert info.entry_symbol == "_start"
    assert {".text", ".rodata", ".data"} <= {section.name for section in info.sections}
    assert {"main", "check"} <= {function.name for function in info.functions}
    assert "puts" in info.imports
