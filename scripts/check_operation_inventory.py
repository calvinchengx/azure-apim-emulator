#!/usr/bin/env python3
"""Bind the operation inventory, the coverage report, and the parity ledger.

Three artefacts can disagree, and each disagreement is silent in a different
way:

1. The coverage report can drift from the inventory, so operations added by a
   spec bump are never probed and coverage rises because the denominator moved.
2. The report's own summary can disagree with its rows, which is what a
   hand-edited "fix" to a failing number looks like.
3. The parity ledger can quote a figure nobody measured. That is the one this
   project has been bitten by before, and it is the reason the numbers in the
   ledger row are parsed here rather than trusted.

Run with --strict in CI.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
API_VERSION = "2024-05-01"
INVENTORY = REPO / "docs" / "generated" / f"operations-{API_VERSION}.json"
COVERAGE = REPO / "docs" / "generated" / f"operation-coverage-{API_VERSION}.json"
PARITY = REPO / "docs" / "parity.md"
VERDICTS = {"routed", "absent", "unmeasured"}


def failures() -> list[str]:
    problems: list[str] = []
    inventory = json.loads(INVENTORY.read_text())
    coverage = json.loads(COVERAGE.read_text())

    operations = inventory["operations"]
    if len(operations) != inventory["operationCount"]:
        problems.append(
            f"inventory says {inventory['operationCount']} operations but lists {len(operations)}"
        )

    if inventory["specCommit"] != coverage["specCommit"]:
        problems.append(
            "coverage was measured against spec commit "
            f"{coverage['specCommit'][:12]} but the inventory is pinned to "
            f"{inventory['specCommit'][:12]}; re-run the probe"
        )

    published = {(row["operationId"], row["method"]) for row in operations}
    measured = {(row["operationId"], row["method"]) for row in coverage["operations"]}
    for missing in sorted(published - measured):
        problems.append(f"never probed: {missing[1]} {missing[0]}")
    for extra in sorted(measured - published):
        problems.append(f"probed but not published: {extra[1]} {extra[0]}")

    counts = {name: 0 for name in VERDICTS}
    for row in coverage["operations"]:
        verdict = row["verdict"]
        if verdict not in VERDICTS:
            problems.append(f"{row['operationId']}: unknown verdict {verdict!r}")
            continue
        counts[verdict] += 1

    summary = coverage["summary"]
    for name in sorted(VERDICTS):
        if summary[name] != counts[name]:
            problems.append(
                f"summary claims {summary[name]} {name} but the rows hold {counts[name]}"
            )
    if summary["total"] != len(coverage["operations"]):
        problems.append(
            f"summary total {summary['total']} does not match {len(coverage['operations'])} rows"
        )

    problems.extend(parity_failures(summary))
    return problems


def parity_failures(summary: dict) -> list[str]:
    """The ledger must quote the measured figures, not remembered ones.

    Each number is matched NEXT TO ITS LABEL. An earlier version only asked
    whether the value appeared somewhere in the row, which a prose mention of
    the same figure satisfied: changing `**294 routed**` to `**300 routed**`
    left the check green because the row said "any of the 294" further along.
    A gate that passes while the sentence it guards is wrong is worse than none.
    """
    text = PARITY.read_text()
    row = [line for line in text.splitlines() if "stable `2024-05-01` operation inventory" in line]
    if not row:
        return ["docs/parity.md has no `stable 2024-05-01 operation inventory` row"]
    line = row[0]
    problems = []
    for name in ("routed", "absent", "unmeasured"):
        found = {int(value) for value in re.findall(rf"\*\*(\d+) {name}\*\*", line)}
        if not found:
            problems.append(f"docs/parity.md does not state a **N {name}** figure")
        elif summary[name] not in found:
            problems.append(
                f"docs/parity.md says **{sorted(found)[0]} {name}** but the probe measured "
                f"{summary[name]}"
            )
    total = {int(value) for value in re.findall(r"\*\*(\d+)\*\*", line)}
    if summary["total"] not in total:
        problems.append(
            f"docs/parity.md does not state the measured total (**{summary['total']}**)"
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="exit non-zero on any problem")
    arguments = parser.parse_args()

    problems = failures()
    for problem in problems:
        print(f"operation-inventory: {problem}")
    if problems and arguments.strict:
        return 1
    if not problems:
        coverage = json.loads(COVERAGE.read_text())["summary"]
        print(
            "operation-inventory: {routed} routed, {absent} absent, "
            "{unmeasured} unmeasured of {total}".format(**coverage)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
