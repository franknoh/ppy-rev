from __future__ import annotations

import copy
import gzip
import json
from pathlib import Path

import pytest

from ppy_rev._json import JsonObject, JsonValue
from ppy_rev.diagnostics import ExportFormatError
from ppy_rev.ghidra.schema import SCHEMA_VERSION, Varnode, load_export, parse_export

MINIMAL: dict[str, JsonValue] = {
    "schema_version": SCHEMA_VERSION,
    "producer": {"ghidra_version": "12.1.3", "decompiled": False},
    "binary": {
        "name": "chall",
        "format": "Executable and Linking Format (ELF)",
        "sha256": "00",
        "language": "x86:LE:64:default",
        "processor": "x86",
        "endianness": "little",
        "pointer_size": 8,
        "compiler_spec": "gcc",
        "image_base": "0x400000",
        "program_counter": "RIP",
        "stack_pointer": "RSP",
        "entry_points": ["0x401000"],
    },
    "address_spaces": [{"name": "ram", "kind": "ram", "size": 8, "word_size": 1}],
    "registers": [{"name": "RAX", "offset": "0x0", "size": 8, "base": "RAX"}],
    "user_ops": ["syscall"],
    "memory_blocks": [
        {
            "name": ".text",
            "space": "ram",
            "start": "0x401000",
            "size": 2,
            "read": True,
            "write": False,
            "execute": True,
            "initialized": True,
            "loaded": True,
            "external": False,
            "artificial": False,
            "bytes": "kMM=",
        }
    ],
    "symbols": [],
    "strings": [],
    "external_functions": [],
    "functions": [],
    "instructions": [
        {
            "address": "0x401000",
            "length": 1,
            "bytes": "90",
            "mnemonic": "NOP",
            "text": "NOP",
            "flow": "FALL_THROUGH",
            "fallthrough": "0x401001",
            "flows": [],
            "references": [],
            "pcode": [
                {
                    "opcode": "INT_ADD",
                    "inputs": [["register", "0x0", 8], ["const", "0xffffffffffffffff", 8]],
                    "output": ["register", "0x0", 8],
                },
                {"opcode": "RETURN", "inputs": [["register", "0x288", 8]], "output": None},
            ],
        }
    ],
}


def test_parses_minimal_export() -> None:
    export = parse_export(JsonObject(MINIMAL, "$"))
    assert export.binary.image_base == 0x400000
    assert export.memory_blocks[0].data == b"\x90\xc3"
    add, ret = export.instructions[0].pcode
    assert add.inputs[1] == Varnode("const", 0xFFFFFFFFFFFFFFFF, 8)
    assert add.output == Varnode("register", 0, 8)
    assert ret.output is None


def test_rejects_other_schema_versions() -> None:
    document = copy.deepcopy(MINIMAL)
    document["schema_version"] = SCHEMA_VERSION + 1
    with pytest.raises(ExportFormatError, match="unsupported export schema version"):
        parse_export(JsonObject(document, "$"))


def test_reports_path_of_malformed_field() -> None:
    document = copy.deepcopy(MINIMAL)
    binary = document["binary"]
    assert isinstance(binary, dict)
    binary["image_base"] = "400000"
    with pytest.raises(ExportFormatError, match=r"\$\.binary\.image_base"):
        parse_export(JsonObject(document, "$"))


def test_rejects_block_bytes_of_wrong_length() -> None:
    document = copy.deepcopy(MINIMAL)
    blocks = document["memory_blocks"]
    assert isinstance(blocks, list)
    block = blocks[0]
    assert isinstance(block, dict)
    block["size"] = 3
    with pytest.raises(ExportFormatError, match="2 bytes for a block of 3"):
        parse_export(JsonObject(document, "$"))


def test_loads_gzip_export(tmp_path: Path) -> None:
    path = tmp_path / "export.json.gz"
    path.write_bytes(gzip.compress(json.dumps(MINIMAL).encode()))
    assert load_export(path).user_ops == ("syscall",)


def test_unreadable_export_is_a_format_error(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text("{not json")
    with pytest.raises(ExportFormatError, match="cannot read Ghidra export"):
        load_export(path)
