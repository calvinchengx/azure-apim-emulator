#!/usr/bin/env python3
"""Every statement is covered, and the total is not allowed to round it away.

    scripts/check_coverage.py cover.out

WHY THIS REPLACED THE AWK ONE-LINER. The gate was:

    go tool cover -func=cover.out | awk '/^total:/ { if ($3 != "100.0%") exit 1 }'

`go tool cover` prints the total to one decimal place, so it rounds. This
repository has roughly five thousand statements; six uncovered ones are 99.88%,
which prints as `100.0%` and passes. That is not a hypothetical rounding
argument: on 2026-09-05 the gate was green with SIX uncovered statements across
five files, found only because a coverage question about an unrelated change
sent someone to read the profile directly.

A gate that cannot distinguish "all covered" from "nearly all covered" is worse
than no gate, because the number it prints is the reason nobody looks.

So this reads the profile rather than the summary, and fails on any block whose
execution count is zero, naming the file, the lines and the source. The total is
still printed, at three decimals, because a figure that cannot round to 100 is
the point.
"""

from __future__ import annotations

import pathlib
import re
import sys

# `file.go:startLine.startCol,endLine.endCol numberOfStatements executionCount`
BLOCK = re.compile(r"^(?P<file>.+\.go):(?P<start>\d+)\.\d+,(?P<end>\d+)\.\d+ (?P<statements>\d+) (?P<count>\d+)$")


def source_line(path: str, line: int) -> str:
    """The offending line, so the failure is readable without opening an editor."""
    # The profile names packages by import path; the file sits under the module
    # root at whatever follows the module name.
    relative = path.split("azure-apim-emulator/")[-1]
    try:
        return pathlib.Path(relative).read_text(encoding="utf-8").split("\n")[line - 1].strip()
    except (OSError, IndexError):
        return ""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_coverage.py <cover.out>", file=sys.stderr)
        return 2
    profile = pathlib.Path(sys.argv[1])
    if not profile.is_file():
        print(f"FAIL: {profile} does not exist. Run the coverage step first.", file=sys.stderr)
        return 1

    total = covered = 0
    uncovered: list[tuple[str, int, int, int]] = []
    for line in profile.read_text(encoding="utf-8").splitlines():
        match = BLOCK.match(line.strip())
        if not match:
            continue  # the `mode:` header
        statements = int(match["statements"])
        total += statements
        if int(match["count"]) > 0:
            covered += statements
            continue
        uncovered.append((match["file"], int(match["start"]), int(match["end"]), statements))

    # A profile that parsed nothing would report a clean 0/0 run, which is the
    # shape of a checker that has stopped matching its input.
    if total == 0:
        print(f"FAIL: no coverage blocks parsed from {profile}. The format has changed, "
              f"so this check is guarding nothing.", file=sys.stderr)
        return 1

    if uncovered:
        missing = sum(block[3] for block in uncovered)
        print(f"FAIL: {missing} statement(s) in {len(uncovered)} block(s) are never executed.",
              file=sys.stderr)
        for path, start, end, statements in sorted(uncovered):
            relative = path.split("azure-apim-emulator/")[-1]
            where = f"{relative}:{start}" if start == end else f"{relative}:{start}-{end}"
            print(f"  {where}  ({statements} statement(s))  {source_line(path, start)}",
                  file=sys.stderr)
        print(f"\n  covered {covered}/{total} = {100 * covered / total:.3f}%. The old gate read "
              f"this as 100.0%.", file=sys.stderr)
        return 1

    print(f"coverage: {covered}/{total} statements, {100 * covered / total:.3f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
