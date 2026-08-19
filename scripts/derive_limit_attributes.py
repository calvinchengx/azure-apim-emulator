#!/usr/bin/env python3
"""Derive the documented attribute surface of the four limit policies.

The rate-limit and quota families differ from each other attribute by attribute
in ways that are easy to get wrong by hand: `bandwidth` is documented on the
quota pair only, `counter-key` and `increment-*` on the by-key pair only, and
the five response/variable attributes on the rate-limit pair only. Transcribing
that table is how the emulator came to accept `counter-key` on `<rate-limit>`,
which Azure rejects.

So it is read out of the vendored reference pages instead. The compiler embeds
the result and rejects anything absent from it, so the accepted surface is the
derived one rather than a second hand-maintained copy of it.

    ./scripts/derive_limit_attributes.py           rewrite the generated record
    ./scripts/derive_limit_attributes.py --check   fail if it is out of date
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "third_party" / "microsoft" / "policy-reference"
OUTPUT = ROOT / "internal" / "policy" / "limit_attributes.json"
COMMIT = "f31ac8723a622ba3950df57ba0389d8347f546ab"

# Which sections each page must yield. Stated rather than discovered, so a page
# that is restructured upstream fails loudly instead of deriving a short table
# that every later check would then agree with.
EXPECTED = {
    "rate-limit": ("attributes", "api", "operation"),
    "quota": ("attributes", "api", "operation"),
    "rate-limit-by-key": ("attributes",),
    "quota-by-key": ("attributes",),
}

HEADING = re.compile(r"^#{2,4}\s+(.+?)\s*$")
SECTION = re.compile(r"^(?:(api|operation)\s+)?attributes$", re.IGNORECASE)


def tables(text):
    """Map section key -> attribute names, for every '## ... attributes' heading."""
    found = {}
    current = None
    rows = []

    def flush():
        if current and rows:
            found.setdefault(current, []).extend(rows)

    for line in text.splitlines():
        heading = HEADING.match(line)
        if heading:
            flush()
            rows = []
            match = SECTION.match(heading.group(1).strip())
            current = (match.group(1) or "attributes").lower() if match else None
            continue
        if current is None or not line.startswith("|"):
            continue
        cell = line.split("|")[1].strip()
        # Skip the header row and the |---| separator.
        if not cell or cell.lower() == "attribute" or set(cell) <= set("- :"):
            continue
        rows.append(cell)
    flush()
    return {key: sorted(set(value)) for key, value in found.items()}


def derive():
    policies = {}
    for name, expected in EXPECTED.items():
        page = SOURCE / f"{name}-policy.md"
        if not page.exists():
            raise SystemExit(f"missing vendored reference: {page}")
        found = tables(page.read_text())
        if tuple(sorted(found)) != tuple(sorted(expected)):
            raise SystemExit(
                f"{page.name}: derived sections {sorted(found)}, expected {sorted(expected)}"
            )
        for key, attributes in found.items():
            if not attributes:
                raise SystemExit(f"{page.name}: section {key!r} derived no attributes")
        policies[name] = found
    return {"source": "MicrosoftDocs/azure-docs articles/api-management", "commit": COMMIT, "policies": policies}


def main():
    derived = derive()
    rendered = json.dumps(derived, indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            raise SystemExit(
                f"{OUTPUT.relative_to(ROOT)} is out of date; run ./scripts/derive_limit_attributes.py"
            )
        print(f"limit attribute surface matches {OUTPUT.relative_to(ROOT)}")
        return
    OUTPUT.write_text(rendered)
    for name, sections in derived["policies"].items():
        print(f"{name}: " + ", ".join(f"{k}={len(v)}" for k, v in sorted(sections.items())))


if __name__ == "__main__":
    main()
