#!/usr/bin/env python3
"""Fail if the policy inventory has unclassified or compiler-mismatched entries.

The inventory (docs/generated/policy-inventory.json) is the classified Microsoft
Learn catalog plus emulator-only composition names. A stable policy with status
`unclassified` is a hole in the P2 exit criterion. A compiler-recognized name
that is not `implemented` or `partial`, or an `implemented`/`partial` name the
compiler does not recognize, means the ledger drifted from the switch.

    ./scripts/check_policy_inventory.py            report and exit non-zero on errors
    ./scripts/check_policy_inventory.py --strict   same, and require sections/gateways/
                                                   expression_fields on every entry
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "docs" / "generated" / "policy-inventory.json"
POLICY_GO = ROOT / "internal" / "policy" / "policy.go"
ALLOWED = {"implemented", "partial", "unsupported", "unclassified", "external-adapter"}
COMPILER_STATUSES = {"implemented", "partial"}
IGNORE_CASES = {
    "inbound",
    "backend",
    "outbound",
    "on-error",
    "when",
    "otherwise",
    "set-url",
    "append",
    "skip",
    "delete",
    "example",
    "schema",
}
CASE_RE = re.compile(r'case\s+((?:"[^"]+"\s*,\s*)*"[^"]+")')


def compiler_policies():
    text = POLICY_GO.read_text()
    start = text.find("func compileNode(")
    end = text.find("\nfunc compileLimit(", start)
    if start < 0 or end < 0:
        raise SystemExit("could not locate compileNode in internal/policy/policy.go")
    names = set()
    for match in CASE_RE.finditer(text[start:end]):
        for raw in match.group(1).split(","):
            name = raw.strip().strip('"')
            if name and name not in IGNORE_CASES:
                names.add(name)
    if "include-fragment" in text:
        names.add("include-fragment")
    return names


def main():
    strict = "--strict" in sys.argv
    document = json.loads(INVENTORY.read_text())
    policies = document.get("policies")
    errors = []
    if not isinstance(policies, list) or not policies:
        errors.append("inventory policies list is missing or empty")
        print("\n".join(errors))
        return 1

    seen = {}
    for index, item in enumerate(policies):
        prefix = f"policies[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} is not an object")
            continue
        name = item.get("name")
        status = item.get("status")
        if not name:
            errors.append(f"{prefix} is missing name")
            continue
        if name in seen:
            errors.append(f"{name!r} is listed more than once")
        seen[name] = status
        if status not in ALLOWED:
            errors.append(f"{name!r} has unknown status {status!r}")
        if status == "unclassified":
            errors.append(f"{name!r} is unclassified")
        if strict:
            for field in ("sections", "gateways", "expression_fields"):
                value = item.get(field)
                if not isinstance(value, list):
                    errors.append(f"{name!r} is missing {field} list")

    compiled = compiler_policies()
    for name in sorted(compiled):
        status = seen.get(name)
        if status is None:
            errors.append(f"compiler recognizes {name!r} but inventory omits it")
        elif status not in COMPILER_STATUSES:
            errors.append(f"compiler recognizes {name!r} but inventory grades it {status!r}")
    for name, status in sorted(seen.items()):
        if status in COMPILER_STATUSES and name not in compiled:
            errors.append(f"inventory grades {name!r} {status} but the compiler does not recognize it")

    print(f"policy inventory: {len(seen)} entries")
    print(f"  implemented    : {sum(1 for status in seen.values() if status == 'implemented')}")
    print(f"  partial        : {sum(1 for status in seen.values() if status == 'partial')}")
    print(f"  unsupported    : {sum(1 for status in seen.values() if status == 'unsupported')}")
    print(f"  external-adapter: {sum(1 for status in seen.values() if status == 'external-adapter')}")
    print(f"  compiler names : {len(compiled)}")
    if errors:
        print("policy inventory errors:")
        print("\n".join(f"  {error}" for error in errors))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
