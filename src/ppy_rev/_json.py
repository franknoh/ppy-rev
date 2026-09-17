"""Typed access to parsed JSON documents.

`json.load` returns an untyped value; this module is the single place where that value
enters the typed world. Every accessor validates the shape it promises and reports the
JSON path of anything unexpected.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path

from ppy_rev.diagnostics import ExportFormatError

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None


def parse(data: bytes | str) -> JsonValue:
    document: JsonValue = json.loads(data)
    return document


def dump(value: JsonValue, path: Path) -> None:
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


class JsonObject:
    """A JSON object together with its path, for error reporting."""

    __slots__ = ("_items", "path")

    def __init__(self, value: JsonValue, path: str) -> None:
        if not isinstance(value, dict):
            raise ExportFormatError(f"{path}: expected an object")
        self._items = value
        self.path = path

    def _get(self, key: str) -> JsonValue:
        if key not in self._items:
            raise ExportFormatError(f"{self.path}: missing field {key!r}")
        return self._items[key]

    def has(self, key: str) -> bool:
        return key in self._items

    def string(self, key: str) -> str:
        value = self._get(key)
        if not isinstance(value, str):
            raise ExportFormatError(f"{self.path}.{key}: expected a string")
        return value

    def optional_string(self, key: str) -> str | None:
        value = self._items.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ExportFormatError(f"{self.path}.{key}: expected a string or null")
        return value

    def integer(self, key: str) -> int:
        value = self._get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ExportFormatError(f"{self.path}.{key}: expected an integer")
        return value

    def boolean(self, key: str) -> bool:
        value = self._get(key)
        if not isinstance(value, bool):
            raise ExportFormatError(f"{self.path}.{key}: expected a boolean")
        return value

    def hex(self, key: str) -> int:
        return parse_hex(self.string(key), f"{self.path}.{key}")

    def optional_hex(self, key: str) -> int | None:
        text = self.optional_string(key)
        return None if text is None else parse_hex(text, f"{self.path}.{key}")

    def object(self, key: str) -> JsonObject:
        return JsonObject(self._get(key), f"{self.path}.{key}")

    def optional_object(self, key: str) -> JsonObject | None:
        value = self._items.get(key)
        return None if value is None else JsonObject(value, f"{self.path}.{key}")

    def array(self, key: str) -> JsonArray:
        return JsonArray(self._get(key), f"{self.path}.{key}")

    def optional_array(self, key: str) -> JsonArray | None:
        value = self._items.get(key)
        return None if value is None else JsonArray(value, f"{self.path}.{key}")


class JsonArray:
    __slots__ = ("_items", "path")

    def __init__(self, value: JsonValue, path: str) -> None:
        if not isinstance(value, list):
            raise ExportFormatError(f"{path}: expected an array")
        self._items = value
        self.path = path

    def __len__(self) -> int:
        return len(self._items)

    def raw(self, index: int) -> JsonValue:
        return self._items[index]

    def objects(self) -> Iterator[JsonObject]:
        for index, item in enumerate(self._items):
            yield JsonObject(item, f"{self.path}[{index}]")

    def arrays(self) -> Iterator[JsonArray]:
        for index, item in enumerate(self._items):
            yield JsonArray(item, f"{self.path}[{index}]")

    def strings(self) -> tuple[str, ...]:
        return tuple(self.string(index) for index in range(len(self._items)))

    def integers(self) -> tuple[int, ...]:
        return tuple(self.integer(index) for index in range(len(self._items)))

    def hexes(self) -> tuple[int, ...]:
        return tuple(
            parse_hex(self.string(index), f"{self.path}[{index}]")
            for index in range(len(self._items))
        )

    def string(self, index: int) -> str:
        value = self._items[index]
        if not isinstance(value, str):
            raise ExportFormatError(f"{self.path}[{index}]: expected a string")
        return value

    def integer(self, index: int) -> int:
        value = self._items[index]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ExportFormatError(f"{self.path}[{index}]: expected an integer")
        return value

    def map_objects[T](self, convert: Callable[[JsonObject], T]) -> tuple[T, ...]:
        return tuple(convert(item) for item in self.objects())


def parse_hex(text: str, path: str) -> int:
    if not text.startswith("0x"):
        raise ExportFormatError(f"{path}: expected a 0x-prefixed hex string, got {text!r}")
    try:
        return int(text, 16)
    except ValueError:
        raise ExportFormatError(f"{path}: invalid hex string {text!r}") from None
