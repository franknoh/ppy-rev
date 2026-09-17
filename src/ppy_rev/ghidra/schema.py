"""The versioned Ghidra export schema and its validating parser.

These types describe what the bridge extracted, in Ghidra's vocabulary (spaces, varnodes,
p-code mnemonics). Normalization into RevIR happens in `ppy_rev.lift`; nothing outside the
lifter and `ppy_rev.ghidra` should depend on this module.
"""

from __future__ import annotations

import base64
import binascii
import gzip
from dataclasses import dataclass
from pathlib import Path

from ppy_rev._json import JsonArray, JsonObject, parse, parse_hex
from ppy_rev.diagnostics import ExportFormatError

SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class Varnode:
    space: str
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class PcodeOp:
    opcode: str
    inputs: tuple[Varnode, ...]
    output: Varnode | None
    memory_space: str | None
    user_op: str | None


@dataclass(frozen=True, slots=True)
class Reference:
    to_space: str
    to: int
    type: str
    operand: int


@dataclass(frozen=True, slots=True)
class Instruction:
    address: int
    length: int
    data: bytes
    mnemonic: str
    text: str
    flow: str
    fallthrough: int | None
    flows: tuple[int, ...]
    references: tuple[Reference, ...]
    pcode: tuple[PcodeOp, ...]


@dataclass(frozen=True, slots=True)
class HighVarnode:
    id: int
    space: str
    offset: int
    size: int
    variable: str | None


@dataclass(frozen=True, slots=True)
class HighOp:
    address: int
    order: int
    opcode: str
    inputs: tuple[HighVarnode, ...]
    output: HighVarnode | None
    memory_space: str | None
    user_op: str | None


@dataclass(frozen=True, slots=True)
class HighBlock:
    index: int
    start: int
    stop: int
    predecessors: tuple[int, ...]
    successors: tuple[int, ...]
    ops: tuple[HighOp, ...]


@dataclass(frozen=True, slots=True)
class HighSymbol:
    name: str
    type: str
    size: int
    parameter: bool
    storage: tuple[Varnode, ...]


@dataclass(frozen=True, slots=True)
class HighPrototype:
    model: str | None
    return_type: str
    return_storage: tuple[Varnode, ...]
    varargs: bool
    no_return: bool
    parameters: tuple[HighSymbol, ...]


@dataclass(frozen=True, slots=True)
class JumpTable:
    switch: int
    cases: tuple[int, ...]
    labels: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class HighFunction:
    status: str
    error: str | None
    prototype: HighPrototype | None
    symbols: tuple[HighSymbol, ...]
    jump_tables: tuple[JumpTable, ...]
    blocks: tuple[HighBlock, ...]


@dataclass(frozen=True, slots=True)
class Parameter:
    name: str
    ordinal: int
    type: str
    size: int
    storage: tuple[Varnode, ...]


@dataclass(frozen=True, slots=True)
class ReturnValue:
    type: str
    size: int
    storage: tuple[Varnode, ...]


@dataclass(frozen=True, slots=True)
class ThunkTarget:
    name: str
    external: bool
    address: int


@dataclass(frozen=True, slots=True)
class Block:
    start: int
    end: int
    successors: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Function:
    name: str
    entry: int
    no_return: bool
    calling_convention: str
    signature: str
    signature_source: str
    varargs: bool
    thunk_target: ThunkTarget | None
    parameters: tuple[Parameter, ...]
    returns: ReturnValue
    body: tuple[tuple[int, int], ...]
    blocks: tuple[Block, ...]
    high: HighFunction | None


@dataclass(frozen=True, slots=True)
class ExternalFunction:
    name: str
    external_address: int
    library: str | None
    original_name: str | None
    no_return: bool
    signature: str


@dataclass(frozen=True, slots=True)
class DataReference:
    source: int
    type: str


@dataclass(frozen=True, slots=True)
class DefinedString:
    address: int
    length: int
    value: str | None
    charset: str | None
    data: bytes
    references: tuple[DataReference, ...]


@dataclass(frozen=True, slots=True)
class Symbol:
    name: str
    qualified_name: str
    kind: str
    source: str
    external: bool
    primary: bool
    entry_point: bool
    address: int | None


@dataclass(frozen=True, slots=True)
class MemoryBlock:
    name: str
    space: str
    start: int
    size: int
    read: bool
    write: bool
    execute: bool
    initialized: bool
    loaded: bool
    external: bool
    artificial: bool
    data: bytes | None

    @property
    def end(self) -> int:
        """Exclusive end address."""
        return self.start + self.size


@dataclass(frozen=True, slots=True)
class Register:
    name: str
    offset: int
    size: int
    base: str


@dataclass(frozen=True, slots=True)
class AddressSpace:
    name: str
    kind: str
    size: int
    word_size: int


@dataclass(frozen=True, slots=True)
class BinaryInfo:
    name: str
    format: str | None
    sha256: str | None
    language: str
    processor: str
    endianness: str
    pointer_size: int
    compiler_spec: str
    image_base: int
    program_counter: str
    stack_pointer: str
    entry_points: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Producer:
    ghidra_version: str
    decompiled: bool


@dataclass(frozen=True, slots=True)
class GhidraExport:
    schema_version: int
    producer: Producer
    binary: BinaryInfo
    address_spaces: tuple[AddressSpace, ...]
    registers: tuple[Register, ...]
    user_ops: tuple[str, ...]
    memory_blocks: tuple[MemoryBlock, ...]
    symbols: tuple[Symbol, ...]
    strings: tuple[DefinedString, ...]
    external_functions: tuple[ExternalFunction, ...]
    functions: tuple[Function, ...]
    instructions: tuple[Instruction, ...]


def load_export(path: Path) -> GhidraExport:
    """Read and validate an export written by the bridge (optionally gzip-compressed)."""
    try:
        data = path.read_bytes()
        document = parse(gzip.decompress(data) if path.suffix == ".gz" else data)
    except (OSError, ValueError) as error:
        raise ExportFormatError(f"cannot read Ghidra export {path}: {error}") from error
    return parse_export(JsonObject(document, "$"))


def parse_export(root: JsonObject) -> GhidraExport:
    version = root.integer("schema_version")
    if version != SCHEMA_VERSION:
        raise ExportFormatError(
            f"unsupported export schema version {version} (this ppy-rev reads version "
            f"{SCHEMA_VERSION}); re-export with the matching bridge"
        )
    producer = root.object("producer")
    return GhidraExport(
        schema_version=version,
        producer=Producer(
            ghidra_version=producer.string("ghidra_version"),
            decompiled=producer.boolean("decompiled"),
        ),
        binary=_binary(root.object("binary")),
        address_spaces=root.array("address_spaces").map_objects(_address_space),
        registers=root.array("registers").map_objects(_register),
        user_ops=root.array("user_ops").strings(),
        memory_blocks=root.array("memory_blocks").map_objects(_memory_block),
        symbols=root.array("symbols").map_objects(_symbol),
        strings=root.array("strings").map_objects(_string),
        external_functions=root.array("external_functions").map_objects(_external_function),
        functions=root.array("functions").map_objects(_function),
        instructions=root.array("instructions").map_objects(_instruction),
    )


def _bytes_hex(item: JsonObject, key: str) -> bytes:
    try:
        return bytes.fromhex(item.string(key))
    except ValueError:
        raise ExportFormatError(f"{item.path}.{key}: invalid hex bytes") from None


def _varnode(array: JsonArray) -> Varnode:
    if len(array) != 3:
        raise ExportFormatError(f"{array.path}: expected [space, offset, size]")
    return Varnode(
        space=array.string(0),
        offset=parse_hex(array.string(1), f"{array.path}[1]"),
        size=array.integer(2),
    )


def _varnodes(array: JsonArray) -> tuple[Varnode, ...]:
    return tuple(_varnode(item) for item in array.arrays())


def _binary(item: JsonObject) -> BinaryInfo:
    return BinaryInfo(
        name=item.string("name"),
        format=item.optional_string("format"),
        sha256=item.optional_string("sha256"),
        language=item.string("language"),
        processor=item.string("processor"),
        endianness=item.string("endianness"),
        pointer_size=item.integer("pointer_size"),
        compiler_spec=item.string("compiler_spec"),
        image_base=item.hex("image_base"),
        program_counter=item.string("program_counter"),
        stack_pointer=item.string("stack_pointer"),
        entry_points=item.array("entry_points").hexes(),
    )


def _address_space(item: JsonObject) -> AddressSpace:
    return AddressSpace(
        name=item.string("name"),
        kind=item.string("kind"),
        size=item.integer("size"),
        word_size=item.integer("word_size"),
    )


def _register(item: JsonObject) -> Register:
    return Register(
        name=item.string("name"),
        offset=item.hex("offset"),
        size=item.integer("size"),
        base=item.string("base"),
    )


def _memory_block(item: JsonObject) -> MemoryBlock:
    encoded = item.optional_string("bytes")
    data: bytes | None = None
    if encoded is not None:
        try:
            data = base64.b64decode(encoded, validate=True)
        except binascii.Error:
            raise ExportFormatError(f"{item.path}.bytes: invalid base64") from None
    block = MemoryBlock(
        name=item.string("name"),
        space=item.string("space"),
        start=item.hex("start"),
        size=item.integer("size"),
        read=item.boolean("read"),
        write=item.boolean("write"),
        execute=item.boolean("execute"),
        initialized=item.boolean("initialized"),
        loaded=item.boolean("loaded"),
        external=item.boolean("external"),
        artificial=item.boolean("artificial"),
        data=data,
    )
    if data is not None and len(data) != block.size:
        raise ExportFormatError(f"{item.path}: {len(data)} bytes for a block of {block.size}")
    return block


def _symbol(item: JsonObject) -> Symbol:
    return Symbol(
        name=item.string("name"),
        qualified_name=item.string("qualified_name"),
        kind=item.string("kind"),
        source=item.string("source"),
        external=item.boolean("external"),
        primary=item.boolean("primary"),
        entry_point=item.boolean("entry_point"),
        address=item.optional_hex("address"),
    )


def _string(item: JsonObject) -> DefinedString:
    return DefinedString(
        address=item.hex("address"),
        length=item.integer("length"),
        value=item.optional_string("value"),
        charset=item.optional_string("charset"),
        data=_bytes_hex(item, "bytes"),
        references=item.array("references").map_objects(
            lambda reference: DataReference(
                source=reference.hex("from"), type=reference.string("type")
            )
        ),
    )


def _external_function(item: JsonObject) -> ExternalFunction:
    return ExternalFunction(
        name=item.string("name"),
        external_address=item.hex("external_address"),
        library=item.optional_string("library"),
        original_name=item.optional_string("original_name"),
        no_return=item.boolean("no_return"),
        signature=item.string("signature"),
    )


def _function(item: JsonObject) -> Function:
    thunk = item.optional_object("thunk_target")
    returns = item.object("return")
    high = item.optional_object("high")
    return Function(
        name=item.string("name"),
        entry=item.hex("entry"),
        no_return=item.boolean("no_return"),
        calling_convention=item.string("calling_convention"),
        signature=item.string("signature"),
        signature_source=item.string("signature_source"),
        varargs=item.boolean("varargs"),
        thunk_target=None
        if thunk is None
        else ThunkTarget(
            name=thunk.string("name"),
            external=thunk.boolean("external"),
            address=thunk.hex("address"),
        ),
        parameters=item.array("parameters").map_objects(
            lambda parameter: Parameter(
                name=parameter.string("name"),
                ordinal=parameter.integer("ordinal"),
                type=parameter.string("type"),
                size=parameter.integer("size"),
                storage=_varnodes(parameter.array("storage")),
            )
        ),
        returns=ReturnValue(
            type=returns.string("type"),
            size=returns.integer("size"),
            storage=_varnodes(returns.array("storage")),
        ),
        body=tuple(_range(entry) for entry in item.array("body").arrays()),
        blocks=item.array("blocks").map_objects(
            lambda block: Block(
                start=block.hex("start"),
                end=block.hex("end"),
                successors=block.array("successors").hexes(),
            )
        ),
        high=None if high is None else _high_function(high),
    )


def _range(array: JsonArray) -> tuple[int, int]:
    if len(array) != 2:
        raise ExportFormatError(f"{array.path}: expected [start, end]")
    return (
        parse_hex(array.string(0), f"{array.path}[0]"),
        parse_hex(array.string(1), f"{array.path}[1]"),
    )


def _high_symbol(item: JsonObject) -> HighSymbol:
    return HighSymbol(
        name=item.string("name"),
        type=item.string("type"),
        size=item.integer("size"),
        parameter=item.boolean("parameter"),
        storage=_varnodes(item.array("storage")),
    )


def _high_varnode(item: JsonObject) -> HighVarnode:
    return HighVarnode(
        id=item.integer("id"),
        space=item.string("space"),
        offset=item.hex("offset"),
        size=item.integer("size"),
        variable=item.optional_string("variable"),
    )


def _high_function(item: JsonObject) -> HighFunction:
    status = item.string("status")
    if status != "ok":
        return HighFunction(
            status=status,
            error=item.optional_string("error"),
            prototype=None,
            symbols=(),
            jump_tables=(),
            blocks=(),
        )
    prototype = item.object("prototype")
    return HighFunction(
        status=status,
        error=None,
        prototype=HighPrototype(
            model=prototype.optional_string("model"),
            return_type=prototype.string("return_type"),
            return_storage=_varnodes(prototype.array("return_storage")),
            varargs=prototype.boolean("varargs"),
            no_return=prototype.boolean("no_return"),
            parameters=prototype.array("parameters").map_objects(_high_symbol),
        ),
        symbols=item.array("symbols").map_objects(_high_symbol),
        jump_tables=item.array("jump_tables").map_objects(
            lambda table: JumpTable(
                switch=table.hex("switch"),
                cases=table.array("cases").hexes(),
                labels=table.array("labels").integers(),
            )
        ),
        blocks=item.array("blocks").map_objects(_high_block),
    )


def _high_block(item: JsonObject) -> HighBlock:
    return HighBlock(
        index=item.integer("index"),
        start=item.hex("start"),
        stop=item.hex("stop"),
        predecessors=item.array("predecessors").integers(),
        successors=item.array("successors").integers(),
        ops=item.array("ops").map_objects(_high_op),
    )


def _high_op(item: JsonObject) -> HighOp:
    output = item.optional_object("output")
    return HighOp(
        address=item.hex("address"),
        order=item.integer("order"),
        opcode=item.string("opcode"),
        inputs=item.array("inputs").map_objects(_high_varnode),
        output=None if output is None else _high_varnode(output),
        memory_space=item.optional_string("memory_space"),
        user_op=item.optional_string("user_op"),
    )


def _instruction(item: JsonObject) -> Instruction:
    return Instruction(
        address=item.hex("address"),
        length=item.integer("length"),
        data=_bytes_hex(item, "bytes"),
        mnemonic=item.string("mnemonic"),
        text=item.string("text"),
        flow=item.string("flow"),
        fallthrough=item.optional_hex("fallthrough"),
        flows=item.array("flows").hexes(),
        references=item.array("references").map_objects(
            lambda reference: Reference(
                to_space=reference.string("to_space"),
                to=reference.hex("to"),
                type=reference.string("type"),
                operand=reference.integer("operand"),
            )
        ),
        pcode=item.array("pcode").map_objects(_pcode_op),
    )


def _pcode_op(item: JsonObject) -> PcodeOp:
    output = item.optional_array("output")
    return PcodeOp(
        opcode=item.string("opcode"),
        inputs=_varnodes(item.array("inputs")),
        output=None if output is None else _varnode(output),
        memory_space=item.optional_string("memory_space"),
        user_op=item.optional_string("user_op"),
    )
