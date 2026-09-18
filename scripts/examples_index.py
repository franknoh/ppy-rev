"""Rebuild examples/README.md from the per-example READMEs.

    uv run scripts/examples_index.py [check.sh output]

Times come from the output of `examples/check.sh`, if given; otherwise the ones already in
the index are kept, so the table can be refreshed after editing an example.
"""

from __future__ import annotations

import pathlib
import re
import sys

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"
_ROW = re.compile(r"^\| \[(\S+?)\]\(\S+?\) \|.*\| (\d+) s \|$", flags=re.MULTILINE)
_MEASURED = re.compile(r"^(?:ok|FAIL)\s+(\S+)\s+(\d+)s")
_FIELD = re.compile(r"^\| (\w[\w ]*) \| (.*?) \|$", flags=re.MULTILINE)

HEADER = """# Examples

{count} reversing challenges from past CTFs that `ppy-rev solve` answers, most of them with no
hints at all. Each directory has a walkthrough: what the binary checks, the command, the
output, and how the answer is found.

The binaries are other people's challenges, so they are not stored here. `fetch.sh` downloads
each one from a public archive at a pinned commit and checks its SHA-256; nothing it downloads
is run. `check.sh` then solves every example with the command its README documents and compares
the answer. With `VERIFY=1` it also runs each answer on the real binary, in the sandbox.

```bash
examples/fetch.sh
uv run ppy-rev solve examples/ais3_crackme/ais3_crackme
examples/check.sh                     # all of them, about ten minutes
VERIFY=1 examples/check.sh            # and check each answer against the binary itself
```

| Example | Event | Input | Hints | Answer | Time |
|---|---|---|---|---|---|
"""

FOOTER = """
Any of them can also be lifted to PPy and run again from there, as
[ais3_crackme](ais3_crackme/README.md) shows.

Times are with the Ghidra analysis already cached; the first run of a binary adds about five
seconds for it. Answers that are not flags are passwords the program turns into one, or the
number it asks for. This table is generated from the example READMEs by
`scripts/examples_index.py`. One binary, [crewctf_ez_rev](crewctf_ez_rev/README.md), rejects
every input on any glibc but the author's, and its README says so.
"""


def _times() -> dict[str, int]:
    index = EXAMPLES / "README.md"
    known = {name: int(seconds) for name, seconds in _ROW.findall(index.read_text())}
    if len(sys.argv) > 1:
        for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
            measured = _MEASURED.match(line)
            if measured is not None:
                known[measured.group(1)] = int(measured.group(2))
    return known


def main() -> None:
    times = _times()
    rows: list[tuple[int, str]] = []
    for readme in sorted(EXAMPLES.glob("*/README.md")):
        name = readme.parent.name
        fields = dict(_FIELD.findall(readme.read_text()))
        event = fields["Origin"].split(" ([files]")[0].split(",")[0]
        kind = "argv[1]" if "argv" in fields["Input"] else "stdin"
        seconds = times.get(name)
        rows.append(
            (
                seconds if seconds is not None else 10**6,
                f"| [{name}]({name}/README.md) | {event} | {kind} | {fields['Hints needed']} | "
                f"{fields['Answer']} | {'?' if seconds is None else f'{seconds} s'} |",
            )
        )
    body = "\n".join(row for _, row in sorted(rows))
    (EXAMPLES / "README.md").write_text(HEADER.format(count=len(rows)) + body + FOOTER)
    missing = sum(1 for seconds, _ in rows if seconds == 10**6)
    print(f"{len(rows)} examples, {missing} without a time")


if __name__ == "__main__":
    main()
