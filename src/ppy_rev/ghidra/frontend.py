"""Binary → validated Ghidra export, with caching."""

from __future__ import annotations

import tempfile
from pathlib import Path

from ppy_rev.config import AnalyzerConfig
from ppy_rev.diagnostics import UnsupportedBinaryError
from ppy_rev.elf import read_elf_header
from ppy_rev.ghidra.cache import ExportCache, export_cache_key, file_sha256
from ppy_rev.ghidra.headless import bridge_digest, locate_ghidra, run_export
from ppy_rev.ghidra.schema import GhidraExport, load_export


def export_binary(binary: Path, config: AnalyzerConfig) -> GhidraExport:
    if not binary.is_file():
        raise UnsupportedBinaryError(f"{binary} is not a regular file")
    read_elf_header(binary)
    installation = locate_ghidra(config.ghidra.home)
    key = export_cache_key(
        file_sha256(binary), installation.version, bridge_digest(), config.ghidra
    )
    cache = ExportCache(config.cache.resolve_directory()) if config.cache.enabled else None
    if cache is not None and (cached := cache.lookup(key)) is not None:
        return load_export(cached)
    with tempfile.TemporaryDirectory(prefix="ppy-rev-export-") as scratch:
        output = Path(scratch) / "export.json"
        run_export(installation, binary.resolve(), output, config.ghidra)
        export = load_export(output)
        if cache is not None:
            cache.store(key, output)
    return export
