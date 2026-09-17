"""Content-addressed cache of validated Ghidra exports."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from ppy_rev._version import __version__
from ppy_rev.config import GhidraOptions
from ppy_rev.ghidra.schema import SCHEMA_VERSION


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def export_cache_key(
    binary_sha256: str, ghidra_version: str, bridge_digest: str, options: GhidraOptions
) -> str:
    """Everything that can change the export must be part of the key."""
    fields = {
        "binary_sha256": binary_sha256,
        "bridge": bridge_digest,
        "decompile": options.decompile,
        "decompile_timeout": options.decompile_timeout_seconds,
        "ghidra_version": ghidra_version,
        "ppy_rev_version": __version__,
        "schema_version": SCHEMA_VERSION,
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class ExportCache:
    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def exports(self) -> Path:
        return self.root / "exports"

    def path_for(self, key: str) -> Path:
        return self.exports / f"{key}.json.gz"

    def lookup(self, key: str) -> Path | None:
        path = self.path_for(key)
        return path if path.is_file() else None

    def store(self, key: str, export_json: Path) -> Path:
        """Compress an export into the cache atomically."""
        self.exports.mkdir(parents=True, exist_ok=True)
        destination = self.path_for(key)
        descriptor, temporary_name = tempfile.mkstemp(dir=self.exports, suffix=".partial")
        try:
            with (
                os.fdopen(descriptor, "wb") as raw,
                gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed,
                export_json.open("rb") as source,
            ):
                shutil.copyfileobj(source, compressed)
            Path(temporary_name).replace(destination)
        except BaseException:
            Path(temporary_name).unlink(missing_ok=True)
            raise
        return destination

    def clear(self) -> int:
        if not self.exports.is_dir():
            return 0
        removed = 0
        for entry in self.exports.iterdir():
            if entry.is_file():
                entry.unlink()
                removed += 1
        return removed
