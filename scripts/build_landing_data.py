#!/usr/bin/env python3
"""Assemble the landing page's data, and refuse a page that hardcodes a number.

The landing page states five totals. Every one of them is a number that moves,
and a number typed into a page has no idea a witness was added: the sibling
repo found four stale copies of one count, two of them inside the sentence
arguing that a witness count is a better claim than a coverage percentage.

So the page reads these at run time from JSON copied beside it, and this script
FAILS when the page carries a literal where a placeholder belongs. The check is
the point; copying the files is the easy half.

    ./scripts/build_landing_data.py --out _site --landing site/index.html
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
GENERATED = ROOT / "docs" / "generated"
WITNESSES = ROOT / "docs" / "witnesses.json"
LEDGER = ROOT / "docs" / "parity.md"

# Each is (id the page fills, the file it reads). A page that stops reading one
# of these shows a dash forever, which is worse than a wrong number because
# nothing looks broken.
BINDINGS = {
    "witness-count": "witnesses-manifest.json",
    "policy-implemented": "policy-inventory.json",
    "expr-bound": "expression-members.json",
    "corpus-parsed": "policy-corpus.json",
    "verified-count": "parity-summary.json",
}

# A literal where a placeholder belongs. Matched against the stat tiles only,
# which is where a total is stated as a headline.
HARDCODED = re.compile(r'<b[^>]*>(\d[\d,]*)</b>\s*<span>(?:witnesses|rows verified)')


def parity_summary() -> dict:
    """Count the ledger's states, so the page can say how many are verified."""
    states: dict[str, int] = {}
    for line in LEDGER.read_text().splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) < 4 or cells[1] in ("", "Capability track") or set(cells[1]) <= set("-"):
            continue
        states[cells[2]] = states.get(cells[2], 0) + 1
    if not states:
        raise SystemExit(f"FAIL: no ledger rows parsed from {LEDGER.relative_to(ROOT)}")
    # `verified` is absent from the ledger today, and 0 is the honest answer
    # rather than a missing key the page would render as a dash.
    states.setdefault("verified", 0)
    return states


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--landing", required=True)
    args = parser.parse_args()

    page = pathlib.Path(args.landing)
    if not page.exists():
        print(f"FAIL: {page} does not exist.")
        return 1
    text = page.read_text()

    hardcoded = HARDCODED.search(text)
    if hardcoded:
        print(
            f"FAIL: {page} hardcodes {hardcoded.group(1)} in a stat tile. The page reads "
            f"its totals at run time; a typed number goes stale the day the count moves."
        )
        return 1

    for element, source in BINDINGS.items():
        if f'id="{element}"' not in text:
            print(f"FAIL: {page} no longer has #{element}, so a headline number would never fill.")
            return 1
        if source not in text:
            print(f"FAIL: {page} no longer reads {source}, so #{element} would show a dash forever.")
            return 1

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "witnesses-manifest.json").write_text(WITNESSES.read_text())
    for name in ("policy-inventory.json", "expression-members.json", "policy-corpus.json"):
        source = GENERATED / name
        if not source.exists():
            print(f"FAIL: {source.relative_to(ROOT)} does not exist.")
            return 1
        (out / name).write_text(source.read_text())
    summary = parity_summary()
    (out / "parity-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    print(
        "landing data: "
        + ", ".join(f"{state} {count}" for state, count in sorted(summary.items()))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
