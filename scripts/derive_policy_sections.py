#!/usr/bin/env python3
"""Derive which policy sections each policy is documented in.

Every Microsoft policy reference page carries a "Policy sections:" line under
`## Usage` naming the sections the policy may appear in. `<rate-limit>` in
`<outbound>` and `<rate-limit-by-key>` in `<on-error>` are rejected by Azure and
compiled happily here, because the compiler never had that line.

The inventory used to carry a hand-written `sections` field instead. It was
wrong for all four limit policies -- the only four anyone had checked -- so the
table is read out of the vendored pages rather than transcribed, the same way
scripts/derive_limit_attributes.py reads the attribute tables.

The pages are not read alone. Microsoft's published policy snippets are a second
source, and they disagree: `Log_errors_to_Stackify.policy.xml` puts `<trace>` in
`<on-error>`, which trace-policy.md's line omits. Enforcing one source would
reject a document Microsoft tells people to write, so every snippet section is
scanned and a pair the pages do not carry has to be classified here before this
script will run.

Two records come out of one derivation, so they cannot disagree:
internal/policy/policy_sections.json, which the compiler embeds and enforces,
and the `sections` field of docs/generated/policy-inventory.json, which the
ledger publishes.

    ./scripts/derive_policy_sections.py           rewrite both records
    ./scripts/derive_policy_sections.py --check   fail if either is out of date
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "third_party" / "microsoft" / "policy-reference"
INCLUDES = SOURCE / "includes"
SNIPPETS = ROOT / "third_party" / "microsoft" / "policy-snippets"
OUTPUT = ROOT / "internal" / "policy" / "policy_sections.json"
INVENTORY = ROOT / "docs" / "generated" / "policy-inventory.json"
COMMIT = "f31ac8723a622ba3950df57ba0389d8347f546ab"
SNIPPETS_COMMIT = "87225c2090e45add095919e8767c37d9ece42e0c"

# The four sections `compileRoot` knows. A page naming anything else is not
# naming policy sections, and is handled as SECTIONLESS below.
SECTIONS = ("inbound", "backend", "outbound", "on-error")

# Names the compiler accepts that Microsoft's catalog has no page for. Stated,
# because "no page" and "page we forgot to vendor" look identical otherwise, and
# the second one would silently leave a policy unenforced.
NO_REFERENCE_PAGE = {
    # <base /> is a composition construct documented in the policy how-to, not a
    # policy with a reference page. It is valid in every section.
    "base",
    # An emulator-only name; the catalog has authentication-basic, -certificate
    # and -managed-identity, and no authentication-oauth2.
    "authentication-oauth2",
}

# Retired names the compiler still accepts, and the page each one's content now
# lives on. Microsoft redirects the azure-openai-* pages to their llm-*
# successors, so vendoring both would vendor one page twice.
ALIASES = {
    "azure-openai-token-limit": "llm-token-limit",
    "azure-openai-emit-token-metric": "llm-emit-token-metric",
}

# Pages that document no policy section, because the policy is not configured in
# one. All four are GraphQL resolver policies. Stated rather than inferred from a
# failed parse: a page that stops carrying its sections line would otherwise land
# here silently, and land the policy outside enforcement with it.
SECTIONLESS = {
    "sql-data-source",
    "cosmosdb-data-source",
    "http-data-source",
    # Names a place rather than a section: "`http-response` element in
    # `http-data-source` resolver".
    "publish-event",
}

# Pairs Microsoft's published snippets use that the reference pages do not
# document, each with the snippet that uses it. Read by eye once, then held to
# both halves of its claim below, so a page that starts documenting the section
# or a corpus refresh that drops the snippet fails here rather than leaving a
# widening nobody can still justify.
CORPUS_WIDENS = {
    # <trace source="OnError"> is the first element of the on-error section,
    # which trace-policy.md's line omits.
    ("trace", "on-error"): "Log_errors_to_Stackify.policy.xml",
}

# Pairs the corpus scan reports that are not section-level uses at all: the
# element is nested inside another policy. The snippets are not parseable XML --
# expressions carry bare `<` and `&` -- so the scan is textual and cannot see
# that nesting.
CORPUS_NESTED = {
    # Under <return-response> and <send-one-way-request>.
    ("set-body", "on-error"),
    # Under <send-request>.
    ("set-method", "outbound"),
}

# Both orders Microsoft writes the line in: the bold inside the link, and the
# link inside the bold.
LINE = re.compile(r"^\s*-\s*\**\[\**Policy sections:\**\]\([^)]*\)\**\s*(?P<value>.*?)\s*$")
INCLUDE = re.compile(r"\[!INCLUDE\s*\[[^\]]*\]\(([^)]*)\)\]")
SPAN = re.compile(r"<(inbound|backend|outbound|on-error)>(.*?)</\1>", re.S)
ELEMENT = re.compile(r"<([a-z][a-z0-9-]*)[\s/>]")


def sections_line(page):
    """The 'Policy sections:' values on a page, following vendored includes.

    llm-semantic-cache-lookup's whole Usage block lives in an include, so a page
    without the line is not yet a page without sections.
    """
    text = page.read_text()
    values = [match.group("value") for match in map(LINE.match, text.splitlines()) if match]
    if values:
        return values
    for target in INCLUDE.findall(text):
        included = INCLUDES / pathlib.PurePosixPath(target).name
        if not included.exists():
            continue
        values.extend(
            match.group("value") for match in map(LINE.match, included.read_text().splitlines()) if match
        )
    return values


def page_sections(page):
    """The sections a page documents, or None when it documents none."""
    values = sections_line(page)
    if len(values) > 1:
        raise SystemExit(f"{page.name}: {len(values)} 'Policy sections:' lines, expected one")
    if not values:
        return None
    named = [item.strip().strip("`") for item in values[0].split(",")]
    if not set(named) <= set(SECTIONS):
        return None
    return [section for section in SECTIONS if section in named]


def corpus_pairs():
    """Every (policy, section) pair Microsoft's published snippets contain."""
    pairs = {}
    for snippet in sorted(SNIPPETS.glob("*.xml")):
        text = snippet.read_text()
        for section, body in SPAN.findall(text):
            for name in set(ELEMENT.findall(body)):
                pairs.setdefault((name, section), []).append(snippet.name)
    return pairs


def widen(derived):
    """Add the sections the corpus uses and the pages omit.

    Every conflict has to be classified, so a corpus or reference refresh that
    introduces one stops here instead of being decided by whichever source the
    script happens to read second.
    """
    widened = {}
    classified = set()
    for (name, section), snippets in sorted(corpus_pairs().items()):
        documented = derived.get(name)
        if not documented or section in documented:
            continue
        if (name, section) in CORPUS_NESTED:
            classified.add((name, section))
            continue
        witness = CORPUS_WIDENS.get((name, section))
        if witness is None:
            raise SystemExit(
                f"the snippet corpus puts <{name}> in <{section}>, which {name}-policy.md "
                f"does not document: classify it in CORPUS_WIDENS or CORPUS_NESTED {snippets}"
            )
        if witness not in snippets:
            raise SystemExit(
                f"CORPUS_WIDENS names {witness} for <{name}> in <{section}>, but the corpus "
                f"uses it in {snippets}"
            )
        classified.add((name, section))
        derived[name] = [
            item for item in SECTIONS if item in set(documented) | {section}
        ]
        widened[name] = sorted(widened.get(name, []) + [section], key=SECTIONS.index)
    stale = (set(CORPUS_WIDENS) | CORPUS_NESTED) - classified
    if stale:
        raise SystemExit(
            f"CORPUS_WIDENS/CORPUS_NESTED classify pairs the corpus and the pages no longer "
            f"disagree about: {sorted(stale)}"
        )
    return widened


def derive():
    inventory = json.loads(INVENTORY.read_text())
    names = [item["name"] for item in inventory["policies"]]

    # The vendored corpus and the ledger must name the same policies. Otherwise a
    # new inventory entry arrives with no page to derive from, and inherits no
    # enforcement, which is the state this script exists to end.
    expected = {ALIASES.get(name, name) for name in names} - NO_REFERENCE_PAGE
    vendored = {page.name[: -len("-policy.md")] for page in SOURCE.glob("*-policy.md")}
    if vendored != expected:
        missing = sorted(expected - vendored)
        extra = sorted(vendored - expected)
        raise SystemExit(
            f"vendored pages do not match the inventory: missing {missing}, unexpected {extra}"
        )

    derived = {}
    for name in sorted(vendored):
        found = page_sections(SOURCE / f"{name}-policy.md")
        if (found is None) != (name in SECTIONLESS):
            raise SystemExit(
                f"{name}-policy.md: derived {found!r}, but SECTIONLESS says "
                f"{'no sections' if name in SECTIONLESS else 'a section list'}"
            )
        derived[name] = found or []
    widened = widen(derived)
    for alias, page in ALIASES.items():
        derived[alias] = derived[page]
    return inventory, {
        "source": "MicrosoftDocs/azure-docs articles/api-management",
        "commit": COMMIT,
        "snippets": {
            "source": "Azure/api-management-policy-snippets",
            "commit": SNIPPETS_COMMIT,
            "widens": widened,
        },
        "policies": derived,
    }


def rendered(inventory, record):
    for item in inventory["policies"]:
        if item["name"] in record["policies"]:
            item["sections"] = record["policies"][item["name"]]
    return (
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        json.dumps(inventory, indent=2) + "\n",
    )


def main():
    inventory, record = derive()
    surface, ledger = rendered(inventory, record)
    if "--check" in sys.argv:
        for path, want in ((OUTPUT, surface), (INVENTORY, ledger)):
            if not path.exists() or path.read_text() != want:
                raise SystemExit(
                    f"{path.relative_to(ROOT)} is out of date; run ./scripts/derive_policy_sections.py"
                )
        print(f"policy sections match {OUTPUT.relative_to(ROOT)} and {INVENTORY.relative_to(ROOT)}")
        return
    OUTPUT.write_text(surface)
    INVENTORY.write_text(ledger)
    enforced = sum(1 for sections in record["policies"].values() if sections)
    print(f"{len(record['policies'])} policies derived, {enforced} with a documented section")
    for name, sections in sorted(record["policies"].items()):
        print(f"  {name}: {', '.join(sections) or '(no section)'}")


if __name__ == "__main__":
    main()
