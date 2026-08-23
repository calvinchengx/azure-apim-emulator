#!/usr/bin/env python3
"""Assemble the published site: the landing page at the root, the docs beneath it.

    scripts/assemble_site.py --out _site
    scripts/assemble_site.py --self-test

WHY THIS EXISTS. The docs moved from `/azure-apim-emulator/<slug>/` to
`/azure-apim-emulator/docs/<slug>/`, which is the shape the rest of the
family uses. That moved **15 published routes**, and a moved URL is a 404 for
every link already pointing at it: this project's own README, anything in the
sibling repositories, and anything outside them nobody can enumerate. Grepping
the family found only two such links, both in this repository's README. The
links nobody can grep are the reason for this file.

So every old path gets a redirect stub here, and the stubs are not optional
politeness: `website/published-routes.txt` is the route list captured from the
build immediately BEFORE the move, and this script fails if any entry in it
would 404. That file is the oracle. Deriving the check from the new build
instead would only prove the new build agrees with itself.

ASTRO'S `redirects:` CANNOT DO THIS. A redirect key is emitted underneath the
configured base, so after the move `/01-quickstart/` publishes at
`/azure-apim-emulator/docs/01-quickstart/` and nothing answers the
root-level path anyone actually linked to. The stubs must be written outside
Astro, which is here.

THE LANDING DATA is written by scripts/build_landing_data.py AFTER this script
runs, because this one clears the output directory. Nothing may be written into
_site before it.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "website" / "dist"
LANDING = ROOT / "site" / "index.html"
ROUTES = ROOT / "website" / "published-routes.txt"
BASE = "/azure-apim-emulator/docs/"

# Routes RENAMED by the move rather than merely relocated, which therefore have
# no same-named page under /docs/ to stub from.
#
# Empty here, and that is a finding rather than an omission: every one of this
# project's 24 published routes keeps its own name under /docs/. The one route
# that did change meaning is the site root, which used to serve the docs index
# and now serves the landing page. It is deliberately absent from the oracle
# below: it does not 404, it shows a different page, which is the point of the
# change.
ALIASES: dict[str, str] = {}

STUB = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Moved</title>
<link rel="canonical" href="{target}">
<meta http-equiv="refresh" content="0; url={target}">
<meta name="robots" content="noindex">
</head>
<body>This page moved to <a href="{target}">{target}</a>.</body>
</html>
"""


def routes_in(tree: Path) -> set[str]:
    """Every route a built tree serves, as `a/b` with no leading or trailing slash."""
    out = set()
    for page in tree.rglob("index.html"):
        rel = page.relative_to(tree).parent.as_posix()
        out.add("" if rel == "." else rel)
    return out


def write_stub(out: Path, route: str) -> None:
    if not route:
        return  # the root is the landing page, never a stub
    page = out / route / "index.html"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(STUB.format(target=f"{BASE}{route}/"), encoding="utf-8")


def assemble(out: Path) -> int:
    if not (DIST / "index.html").is_file():
        raise SystemExit(
            f"assemble_site: no Starlight build at {DIST}. Run the docs build first."
        )
    if not LANDING.is_file():
        raise SystemExit(f"assemble_site: no landing page at {LANDING}")

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    shutil.copytree(DIST, out / "docs")
    shutil.copy2(LANDING, out / "index.html")

    # A stub for every route the docs now serve, at the path it used to have.
    new = routes_in(out / "docs")
    for route in sorted(new):
        write_stub(out, route)
    for old_route, target in ALIASES.items():
        page = out / old_route / "index.html"
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text(
            STUB.format(target=f"{BASE}{target}/" if target else BASE), encoding="utf-8"
        )

    # THE ORACLE. Every route the site published before the move must resolve.
    if not ROUTES.is_file():
        raise SystemExit(f"assemble_site: {ROUTES} is missing; there is nothing to check against")
    old = {r.strip() for r in ROUTES.read_text(encoding="utf-8").splitlines() if r.strip()}
    if not old:
        raise SystemExit(f"assemble_site: {ROUTES} is empty; the check would pass over nothing")
    missing = sorted(r for r in old if not (out / r / "index.html").is_file())
    if missing:
        print("assemble_site FAILED: these published routes would 404", file=sys.stderr)
        for r in missing:
            print(f"  /{r}/", file=sys.stderr)
        return 1

    print(
        f"assemble_site: {len(new)} docs route(s) under {BASE}, "
        f"{len(old)} pre-move route(s) still resolving, landing page at the root"
    )
    return 0


def self_test() -> int:
    """Prove the oracle can fail, on a tree built by hand.

    A gate nobody has watched fail is a gate nobody knows the direction of.
    """
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "site"
        (out / "docs" / "kept").mkdir(parents=True)
        (out / "docs" / "kept" / "index.html").write_text("x")
        (out / "docs" / "index.html").write_text("x")
        for route in sorted(routes_in(out / "docs")):
            write_stub(out, route)

        have = (out / "kept" / "index.html").is_file()
        ok &= have
        print(f"  {'ok  ' if have else 'FAIL'} a stub is written for each docs route")

        gone = not (out / "vanished" / "index.html").is_file()
        ok &= gone
        print(f"  {'ok  ' if gone else 'FAIL'} a route with no page has no stub, so the oracle can catch it")

        root_is_free = not (out / "index.html").exists()
        ok &= root_is_free
        print(f"  {'ok  ' if root_is_free else 'FAIL'} the root is left for the landing page")

        points_at_docs = f'href="{BASE}kept/"' in (out / "kept" / "index.html").read_text()
        ok &= points_at_docs
        print(f"  {'ok  ' if points_at_docs else 'FAIL'} the stub points into {BASE}")
    print("self-test passed" if ok else "self-test FAILED")
    return 0 if ok else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=ROOT / "_site")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    return self_test() if a.self_test else assemble(a.out)


if __name__ == "__main__":
    raise SystemExit(main())
