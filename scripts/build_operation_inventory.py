#!/usr/bin/env python3
"""Regenerate the stable operation inventory from Microsoft's published spec.

The inventory is the DENOMINATOR for parity. Every other number in
`docs/parity.md` is a fraction of a surface we chose to describe; this one is a
fraction of the surface Azure actually publishes, which is the only figure that
can say how much is left.

Network is needed only to REGENERATE. The generated JSON is committed, so CI
and `make verify` read it offline. Regenerate with:

    uv run python scripts/build_operation_inventory.py

The spec is pinned to a commit rather than tracked from `main`, because an
inventory that silently changes underneath a coverage report turns a regression
into a rounding difference nobody reads.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

# Optional local checkout of the pinned spec directory, so a regeneration can
# run offline. The pin is still what the output records: reading local files
# does not change which commit the inventory claims to describe, so point this
# at that commit's files or not at all.
SPEC_DIR_LOCAL = os.environ.get("APIM_SPEC_DIR", "")

# Pinned 2026-08-17. Bump deliberately: a new pin can only be reviewed if the
# resulting inventory diff is in the same commit as the pin change.
SPEC_COMMIT = "8e3e3baa2523e17becb3d7032eb909aba12b7f2c"
SPEC_DIR = (
    "specification/apimanagement/resource-manager/Microsoft.ApiManagement"
    "/ApiManagement/stable/2024-05-01"
)
API_VERSION = "2024-05-01"
HTTP_METHODS = ("get", "put", "post", "patch", "delete", "head")

REPO = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = REPO / "docs" / "generated" / f"operations-{API_VERSION}.json"


def fetch(path: str) -> bytes:
    """Read one spec file through `gh`, which is authenticated.

    Unauthenticated raw.githubusercontent fetches are rate limited, and the
    limit does not fail loudly: it returns 200 with a 199-byte HTML body that
    parses as neither JSON nor an error. Going through `gh api` avoids it, and
    the JSON parse below is what catches it if it ever returns anyway.

    Retries because a single transient failure in a 60-file walk would
    otherwise produce a SHORTER inventory rather than an error, and a shrinking
    denominator flatters coverage exactly when something is wrong.
    """
    if SPEC_DIR_LOCAL:
        return (pathlib.Path(SPEC_DIR_LOCAL) / pathlib.Path(path).name).read_bytes()
    last = ""
    for attempt in range(4):
        result = subprocess.run(
            [
                "gh",
                "api",
                "-H",
                "Accept: application/vnd.github.raw",
                f"/repos/Azure/azure-rest-api-specs/contents/{path}?ref={SPEC_COMMIT}",
            ],
            capture_output=True,
        )
        if result.returncode == 0:
            return result.stdout
        last = result.stderr.decode()[:200]
        time.sleep(2 * (attempt + 1))
    raise SystemExit(f"cannot fetch {path}: {last}")


def spec_files() -> list[str]:
    if SPEC_DIR_LOCAL:
        return sorted(p.name for p in pathlib.Path(SPEC_DIR_LOCAL).glob("*.json"))
    listing = json.loads(fetch(SPEC_DIR))
    return sorted(
        entry["name"] for entry in listing if entry["name"].endswith(".json")
    )


def global_path_enums(documents: dict[str, dict]) -> dict[str, str]:
    """Fixed values the spec declares for path parameters, across all files.

    Several APIM path segments are not resource names at all: `{policyId}` is
    always `policy`, `{settingsType}` is always `public`. Probing them with a
    synthesised name asks for an address that cannot exist, and then reads the
    resulting 404 as though it said something about the route. Taking the value
    from the spec is the difference between measuring the surface and measuring
    our own guess at it.

    Collected globally because these parameters are declared once and `$ref`'d
    from the files that use them, so a per-file lookup finds nothing. The
    parameter names are unique across APIM, which is what makes one flat map
    safe here.
    """
    values: dict[str, str] = {}
    for document in documents.values():
        candidates: list[dict] = list(document.get("parameters", {}).values())
        for item in document.get("paths", {}).values():
            candidates.extend(item.get("parameters", []))
            for operation in item.values():
                if isinstance(operation, dict):
                    candidates.extend(operation.get("parameters", []))
        for parameter in candidates:
            if not isinstance(parameter, dict):
                continue
            if parameter.get("in") == "path" and parameter.get("enum"):
                values.setdefault(parameter["name"], sorted(parameter["enum"])[0])
    return values


def collect() -> list[dict]:
    documents = {name: json.loads(fetch(f"{SPEC_DIR}/{name}")) for name in spec_files()}
    fixed_values = global_path_enums(documents)
    operations: list[dict] = []
    for name, document in documents.items():
        for path, item in document.get("paths", {}).items():
            for method, operation in item.items():
                if method.lower() not in HTTP_METHODS:
                    continue
                operation_id = operation.get("operationId")
                if not operation_id:
                    # Every APIM operation carries one; a missing id means the
                    # shape changed and the inventory would silently lose a row.
                    raise SystemExit(f"{name}: {method.upper()} {path} has no operationId")
                row = {
                    "operationId": operation_id,
                    "group": operation_id.split("_")[0],
                    "method": method.upper(),
                    "path": path,
                    "specFile": name,
                }
                present = {
                    name: value
                    for name, value in fixed_values.items()
                    if "{" + name + "}" in path
                }
                if present:
                    row["pathEnums"] = dict(sorted(present.items()))
                operations.append(row)
    operations.sort(key=lambda row: (row["operationId"], row["method"], row["path"]))
    return operations


def main() -> int:
    operations = collect()
    if not operations:
        raise SystemExit("no operations found; the spec layout probably changed")
    document = {
        "$comment": [
            "GENERATED by scripts/build_operation_inventory.py. Do not hand-edit.",
            "The complete operation surface Microsoft publishes for the stable",
            f"{API_VERSION} management API, used as the parity denominator.",
            "Coverage against it is measured by e2e/inventory and recorded in",
            f"operation-coverage-{API_VERSION}.json.",
        ],
        "apiVersion": API_VERSION,
        "specCommit": SPEC_COMMIT,
        "specDir": SPEC_DIR,
        "operationCount": len(operations),
        "operations": operations,
    }
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n")
    groups = len({row["group"] for row in operations})
    print(f"{OUTPUT.relative_to(REPO)}: {len(operations)} operations, {groups} groups")
    return 0


if __name__ == "__main__":
    sys.exit(main())
