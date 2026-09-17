"""Flag shapes a binary mentions, for the hint `solve` gives when an answer is not one."""

from __future__ import annotations

import re
from collections import Counter

from ppy_rev.analysis.program import read_c_string
from ppy_rev.ir.model import Module

_FLAG = re.compile(rb"(?:^|[^A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]{1,15}\{)")
_LIMIT = 4096


def flag_prefixes(module: Module) -> list[str]:
    """Prefixes such as `actf{` that appear in the program's readable data, most common first."""
    counts: Counter[str] = Counter()
    for region in module.memory:
        if region.data is None or region.executable or not region.readable:
            continue
        for match in _FLAG.finditer(region.data):
            text = read_c_string(module, region.start + match.start(1), _LIMIT)
            if text is not None and match.group(1) in text:
                counts[match.group(1).decode("latin-1")] += 1
    return [prefix for prefix, _ in counts.most_common()]
