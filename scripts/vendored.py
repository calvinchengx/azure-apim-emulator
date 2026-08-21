"""The commit each vendored Microsoft source is pinned at.

third_party/microsoft/README.md carries the pin table, and it is the record a
reader consults and a re-vendor edits. Every derived record also states the
commit it was read from, so before this module the same pin was a literal in the
README and again in each script that derives from it.

Each `--check` compares a record against its own output, so three copies of one
pin could never disagree loudly: a re-vendor that updated the README and one
script left the other deriving from the new pages while stating the old commit,
and both checks stayed green. The provenance field exists to bound what the
derivation proves, so a wrong one is worse than an absent one.

So the table is read rather than transcribed. `pin()` fails on an unknown or
ambiguous pattern instead of returning a default, because a silently missing pin
is the failure this module exists to prevent.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "third_party" / "microsoft" / "README.md"

# | `file pattern` | source | `commit` | licence |
ROW = re.compile(r"^\|\s*`(?P<file>[^`]+)`\s*\|(?P<source>[^|]*)\|\s*`(?P<commit>[0-9a-f]{40})`\s*\|")


def pins():
    """Every (file pattern, commit) row of the vendored pin table."""
    found = {}
    for line in README.read_text().splitlines():
        match = ROW.match(line)
        if match:
            found[match.group("file")] = match.group("commit")
    if not found:
        raise SystemExit(f"{README.relative_to(ROOT)} carries no vendored pin table")
    return found


def pin(pattern):
    """The commit `pattern` is vendored at, as the README table spells it."""
    table = pins()
    if pattern not in table:
        raise SystemExit(
            f"{README.relative_to(ROOT)} has no pin for {pattern!r}; it lists {sorted(table)}"
        )
    return table[pattern]
