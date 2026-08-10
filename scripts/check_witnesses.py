#!/usr/bin/env python3
"""Does every green parity claim name a witness that still exists?

The ledger (docs/parity.md) grades each capability track. A row graded
`implemented` or `sdk-verified` is a CLAIM about behavior, and a claim whose
evidence has quietly disappeared — a renamed test, a deleted CI job — is worse
than no claim, because the reader cannot see it rotted. This binds the two:

  * every green ledger row must appear in docs/witnesses.json;
  * every witness it names must still exist in the tree.

Witness kinds are ranked, because they are not equal evidence:

  ci:<job>    a CI job driving a packaged external client over a network
  sdk:<Test>  a Go test in which MICROSOFT'S OWN client does the talking —
              armapimanagement over ARM's wire — third-party evidence, but
              in-process, so it ranks below ci:
  go:<Test>   a Go test using our own client: our reading of the contract on
              both ends of the wire

Rows graded `partial` or `planned` claim nothing yet and are exempt — the
point is to hold the green rows to account, not to demand evidence for work
that is honestly labelled unfinished.

    ./scripts/check_witnesses.py            exit non-zero on any unbacked claim
    ./scripts/check_witnesses.py --strict   also fail on manifest entries that
                                            no longer match a ledger row
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "parity.md"
MANIFEST = ROOT / "docs" / "witnesses.json"
GREEN = {"implemented", "sdk-verified"}


def ledger_rows():
    """(capability, state) for every data row of the ledger's table."""
    rows = []
    for line in LEDGER.read_text().splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3 or set(cells[0]) <= {"-", ":"} or cells[1] == "State":
            continue
        rows.append((cells[0], cells[1]))
    return rows


def go_tests():
    """Every runnable test name, top-level and subtest.

    Subtests count as names in their own right, and deliberately so: one
    thousand-line test driving twenty resource families is a single witness
    covering twenty claims, which is exactly the bundling this checker exists
    to expose. Naming `TestX/tag` binds the tag claim to the block that
    actually asserts tag behavior, and `go test -run 'TestX/tag'` runs it.
    """
    names = set()
    for path in ROOT.rglob("*_test.go"):
        if "node_modules" in path.parts or "/build/" in str(path):
            continue
        parent = None
        for line in path.read_text().splitlines():
            top = re.match(r"^func (Test[A-Za-z0-9_]+)", line)
            if top:
                parent = top.group(1)
                names.add(parent)
                continue
            sub = re.search(r"""\bt\.Run\(["`]([^"`]+)["`]""", line)
            if sub and parent:
                # go test rewrites spaces to underscores when it names a
                # subtest, so the manifest must cite the rewritten form.
                names.add(f"{parent}/{sub.group(1).replace(' ', '_')}")
    return names


def ci_jobs():
    jobs = set()
    for path in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = path.read_text()
        in_jobs = False
        for line in text.splitlines():
            if re.match(r"^jobs:\s*$", line):
                in_jobs = True
                continue
            if in_jobs:
                if line and not line[0].isspace():
                    in_jobs = False
                    continue
                m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
                if m:
                    jobs.add(m.group(1))
    return jobs


def main():
    strict = "--strict" in sys.argv
    manifest = json.loads(MANIFEST.read_text())["claims"]
    tests, jobs = go_tests(), ci_jobs()
    rows = ledger_rows()
    green = [c for c, s in rows if s in GREEN]

    errors = []
    for cap in green:
        witnesses = manifest.get(cap)
        if not witnesses:
            errors.append(f"{cap!r} is graded green but names no witness in witnesses.json")
            continue
        for w in witnesses:
            kind, _, name = w.partition(":")
            if kind in ("go", "sdk") and name not in tests:
                errors.append(f"{cap!r} -> {w} (no such Go test)")
            elif kind == "ci" and name not in jobs:
                errors.append(f"{cap!r} -> {w} (no such CI job)")
            elif kind not in ("go", "sdk", "ci"):
                errors.append(f"{cap!r} -> {w} (unknown witness kind {kind!r})")

    known = {c for c, _ in rows}
    dangling = [c for c in manifest if c not in known]

    print(f"green claims: {len(green)}")
    print(f"  witnessed        : {len(green) - len([e for e in errors if 'names no witness' in e])}")
    print(f"  sdk: witnesses   : {sum(1 for ws in manifest.values() for w in ws if w.startswith('sdk:'))}")
    print(f"  go: witnesses    : {sum(1 for ws in manifest.values() for w in ws if w.startswith('go:'))}")
    print(f"  ci: witnesses    : {sum(1 for ws in manifest.values() for w in ws if w.startswith('ci:'))}")
    print(f"  partial/planned  : {len(rows) - len(green)} (exempt — they claim nothing yet)")

    # A witness carrying many claims is where over-crediting hides: the name
    # looks like evidence for each row, but one failure mode inside it is all
    # that any of them really proves. Surfaced, not failed, because a genuinely
    # broad witness (a CI job running four SDK suites) is legitimate.
    carrying = {}
    for cap in green:
        for w in manifest.get(cap, []):
            carrying.setdefault(w, []).append(cap)
    heavy = sorted(((w, c) for w, c in carrying.items() if len(c) > 3), key=lambda x: -len(x[1]))
    if heavy:
        print("\nWitnesses carrying many claims (check none is over-credited):")
        for w, covered in heavy:
            print(f"  {w}: {len(covered)} claims")

    if dangling:
        print("\nManifest entries matching no ledger row:")
        for d in dangling:
            print(f"  {d}")
        if strict:
            errors.extend(f"{d!r} is in witnesses.json but not in the ledger" for d in dangling)

    if errors:
        print("\nUnbacked claims:")
        for e in errors:
            print(f"  {e}")
        print(f"\nFAIL: {len(errors)} problem(s). Every green claim needs a witness that exists.")
        return 1
    print("\nEvery green claim names a witness that exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
