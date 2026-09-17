"""Copy-on-write symbolic memory over the concrete program image.

Bytes are expressions. Forking a state is O(1): both children share the parent's written
bytes as an immutable layer and record their own writes in a fresh layer on top.
Mappings and permissions come from the concrete image; access outside them faults.
"""

from __future__ import annotations

from ppy_rev.execution.memory import ConcreteMemory, Mapping, MemoryFaultError
from ppy_rev.ir.model import Endianness
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.expr import Expr

_FLATTEN_DEPTH = 48


class _Layer:
    __slots__ = ("cells", "depth", "parent")

    def __init__(self, parent: _Layer | None) -> None:
        self.parent = parent
        self.cells: dict[int, Expr] = {}
        self.depth: int = 0 if parent is None else parent.depth + 1


class SymbolicMemory:
    def __init__(self, image: ConcreteMemory, layer: _Layer | None = None) -> None:
        if image.endianness is not Endianness.LITTLE:
            raise ValueError("symbolic memory models little-endian targets")
        self.image = image
        self._layer = layer if layer is not None else _Layer(None)

    def fork(self) -> SymbolicMemory:
        shared = self._layer
        self._layer = _Layer(shared)
        return SymbolicMemory(self.image, _Layer(shared))

    def checkpoint(self) -> object:
        """A marker for `written_since`: later writes, in this memory or its forks, go above it."""
        shared = self._layer
        self._layer = _Layer(shared)
        return shared

    def written_since(self, checkpoint: object) -> set[int]:
        """Addresses possibly written after `checkpoint`.

        Once layers have been flattened the marker is gone, and every address this memory
        has ever written is returned instead: a superset, never an omission.
        """
        written: set[int] = set()
        layer: _Layer | None = self._layer
        while layer is not None and layer is not checkpoint:
            written.update(layer.cells)
            layer = layer.parent
        return written

    def mapping_at(self, address: int) -> Mapping | None:
        return self.image.mapping_at(address)

    def accessible(self, address: int, size: int, write: bool) -> bool:
        mapping = self.image.mapping_at(address)
        if mapping is None or address + size > mapping.end:
            return False
        return mapping.writable if write else mapping.readable

    def _require(self, address: int, size: int, write: bool) -> Mapping:
        mapping = self.image.mapping_at(address)
        if not self.accessible(address, size, write) or mapping is None:
            raise MemoryFaultError(address, size, "write" if write else "read")
        return mapping

    def read_byte(self, address: int) -> Expr:
        layer: _Layer | None = self._layer
        while layer is not None:
            found = layer.cells.get(address)
            if found is not None:
                return found
            layer = layer.parent
        mapping = self.image.mapping_at(address)
        if mapping is None or not mapping.readable:
            return sx.const(0, 8)
        # The concrete image includes anything written while the process was set up.
        return sx.const(self.image.read(address, 1)[0], 8)

    def write_byte(self, address: int, value: Expr) -> None:
        self._layer.cells[address] = value
        if self._layer.depth > _FLATTEN_DEPTH:
            self._flatten()

    def load(self, address: int, width: int) -> Expr:
        size = width // 8
        self._require(address, size, write=False)
        value = self.read_byte(address)
        for index in range(1, size):
            value = sx.concat(self.read_byte(address + index), value)
        return value

    def store(self, address: int, value: Expr) -> None:
        size = value.width // 8
        self._require(address, size, write=True)
        for index in range(size):
            self.write_byte(address + index, sx.extract(value, index * 8, 8))

    def load_concrete(self, address: int, size: int) -> bytes | None:
        """The bytes at `address` if every one of them is a known constant."""
        self._require(address, size, write=False)
        result = bytearray()
        for index in range(size):
            byte = self.read_byte(address + index)
            if not byte.is_const:
                return None
            result.append(byte.value)
        return bytes(result)

    def _flatten(self) -> None:
        chain: list[_Layer] = []
        layer: _Layer | None = self._layer
        while layer is not None:
            chain.append(layer)
            layer = layer.parent
        merged = _Layer(None)
        for part in reversed(chain):
            merged.cells.update(part.cells)
        self._layer = merged
