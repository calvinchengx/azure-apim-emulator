#!/usr/bin/env python3
"""Keep the documentation navigable: no broken links, no unreachable pages.

Two failures this catches, both of which happened by hand before it existed:

1. **A link to a page that is not there.** Renumbering the chapters rewrites
   every filename, and the Astro build does NOT fail on a dangling intra-doc
   link — it exits 0 and publishes a 404. Measured, not assumed.
2. **A page missing from the sidebar.** The site builds it, the search finds
   it, and nobody browsing ever sees it. A page nobody can reach is barely
   different from one that does not exist.

Run with --strict in CI.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
CONFIG = REPO / "website" / "astro.config.mjs"

# `](00-slug.md)`, `](./00-slug.md#anchor)`, `](parity.md)`, `](generated/x.md)`
DOC_LINK = re.compile(r"\]\((?:\./)?((?:generated/)?[a-z0-9][a-z0-9-]*\.md)(#[^)]*)?\)")
README_LINK = re.compile(r"\]\(docs/((?:generated/)?[a-z0-9][a-z0-9-]*\.md)(#[^)]*)?\)")
SIDEBAR_SLUG = re.compile(r"slug:\s*'([^']+)'")
# Chapters are numbered; index and parity are not, and neither is generated/.
CHAPTER = re.compile(r"^\d{2}-[a-z0-9-]+\.md$")


def problems() -> list[str]:
    found: list[str] = []

    for page in sorted(DOCS.glob("*.md")):
        for match in DOC_LINK.finditer(page.read_text()):
            target = DOCS / match.group(1)
            if not target.exists():
                found.append(f"{page.name} links to {match.group(1)}, which does not exist")

    readme = REPO / "README.md"
    for match in README_LINK.finditer(readme.read_text()):
        if not (DOCS / match.group(1)).exists():
            found.append(f"README.md links to docs/{match.group(1)}, which does not exist")

    config = CONFIG.read_text()
    slugs = set(SIDEBAR_SLUG.findall(config))
    for slug in sorted(slugs):
        if slug == "index":
            continue
        if not (DOCS / f"{slug}.md").exists():
            found.append(f"the sidebar lists {slug}, which has no page")

    for page in sorted(DOCS.glob("*.md")):
        if page.name in {"index.md", "parity.md"} or not CHAPTER.match(page.name):
            continue
        if page.stem not in slugs:
            found.append(
                f"{page.name} is not in the sidebar, so nothing on the site links to it"
            )

    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="exit non-zero on any problem")
    arguments = parser.parse_args()
    found = problems()
    for problem in found:
        print(f"docs-links: {problem}")
    if found and arguments.strict:
        return 1
    if not found:
        chapters = len([p for p in DOCS.glob("*.md") if CHAPTER.match(p.name)])
        print(f"docs-links: {chapters} chapters, every link resolves and every page is reachable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
