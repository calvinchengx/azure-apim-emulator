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
ledger publishes. Every policy the ledger names appears in both, including the
two the catalog has no page for -- a policy left out of the derivation kept the
hand-written value in the ledger and no value at all in the compiler, which is
three answers for one policy with nothing to catch it.

    ./scripts/derive_policy_sections.py           rewrite both records
    ./scripts/derive_policy_sections.py --check   fail if either is out of date
"""

import json
import pathlib
import re
import sys

import vendored

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "third_party" / "microsoft" / "policy-reference"
INCLUDES = SOURCE / "includes"
SNIPPETS = ROOT / "third_party" / "microsoft" / "policy-snippets"
OUTPUT = ROOT / "internal" / "policy" / "policy_sections.json"
INVENTORY = ROOT / "docs" / "generated" / "policy-inventory.json"
COMMIT = vendored.pin("policy-reference/*.md")
SNIPPETS_COMMIT = vendored.pin("policy-snippets/*.xml")

# The four sections `compileRoot` knows. A page naming anything else is not
# naming policy sections, and is handled as SECTIONLESS below.
SECTIONS = ("inbound", "backend", "outbound", "on-error")

# Names the compiler accepts that Microsoft's catalog has no page for, each with
# the sections it is held to. Stated, because "no page" and "page we forgot to
# vendor" look identical otherwise, and the second one would silently leave a
# policy unenforced.
#
# The sections are stated too, rather than left out of the derived record. A name
# absent from the record is held to no section by the compiler, while the ledger
# went on publishing whatever had been hand-written for it -- which for
# authentication-oauth2 was `backend`, a section its own family is not valid in.
NO_REFERENCE_PAGE = {
    # <base /> is a composition construct documented in the policy how-to, not a
    # policy with a reference page. It is valid in every section, and holding it
    # to anything less stops every inherited document compiling.
    "base": list(SECTIONS),
    # An emulator-only name; the catalog has authentication-basic, -certificate
    # and -managed-identity, and no authentication-oauth2. There is no page to
    # derive from, so it follows the family it is modelled on, all of which is
    # inbound-only.
    "authentication-oauth2": ["inbound"],
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

# Pairs Microsoft's published snippets use at SECTION LEVEL that the reference
# pages do not document, each with the snippet that uses it. Read by eye once,
# then held to both halves of its claim below, so a page that starts documenting
# the section or a corpus refresh that drops the snippet fails here rather than
# leaving a widening nobody can still justify.
CORPUS_WIDENS = {
    # <trace source="OnError"> is the first element of the on-error section,
    # which trace-policy.md's line omits.
    ("trace", "on-error"): "Log_errors_to_Stackify.policy.xml",
}

# The constructs a section passes through unchanged: the compiler compiles their
# children AGAINST the enclosing section (every compileNodes call in
# internal/policy/policy.go), because a <rate-limit> inside a <choose> in
# <outbound> still runs outbound.
#
# Everything else that holds policy-shaped children -- <send-request>,
# <send-one-way-request>, <return-response> -- compiles them itself and never
# holds them to a section, so an element under one of those is not a section-level
# use at all. `Log_errors_to_Stackify.policy.xml` puts <set-body> under
# <send-one-way-request> under <on-error>, and set-body is not valid in on-error.
#
# This used to be a hand-listed set of (policy, section) pairs to excuse, because
# the scan was flat text and could not see nesting. Keyed by pair, one excuse
# covered every future occurrence: a snippet that later put <set-body> DIRECTLY in
# <on-error> was answered by the same entry and never reached the classifier,
# which is the widening this file exists to force someone to look at.
TRANSPARENT = frozenset({"choose", "when", "otherwise", "retry", "wait", "limit-concurrency"})

# Elements that are not policies but hold policy-shaped children. Named so they
# reach the stack: everything outside the vocabulary is skipped rather than
# nested, and an opaque container the vocabulary does not carry would let its
# children read as children of the enclosing section. Every other opaque
# container -- <send-request>, <send-one-way-request>, <return-response>, the
# resolver data sources -- is itself a policy name, and is in the vocabulary
# already.
CONTAINERS = frozenset({"http-request", "http-response"})

# Both orders Microsoft writes the line in: the bold inside the link, and the
# link inside the bold.
LINE = re.compile(r"^\s*-\s*\**\[\**Policy sections:\**\]\([^)]*\)\**\s*(?P<value>.*?)\s*$")
INCLUDE = re.compile(r"\[!INCLUDE\s*\[[^\]]*\]\(([^)]*)\)\]")
COMMENT = re.compile(r"<!--.*?-->", re.S)
# One XML tag. The attribute alternation lets a quoted value hold a `>`, which
# the expressions in this corpus do. The snippets are not well-formed XML -- an
# expression carries bare `<` and `&`, and an interpolated string carries a `"`
# inside a `"`-delimited attribute -- so they are read as a tag stream held to a
# known vocabulary rather than parsed. An expression that reads `List<string>`
# yields a `<string>` tag that no vocabulary contains, and is skipped.
TAG = re.compile(
    r"<(?P<close>/?)(?P<name>[a-z][a-z0-9-]*)"
    r"(?:[^>\"']|\"[^\"]*\"|'[^']*')*?(?P<empty>/?)>",
    re.S,
)


def ordered(sections):
    """`sections` in the order the four are written, which is the order they run."""
    return [section for section in SECTIONS if section in set(sections)]


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
    return ordered(named)


def snippet_elements(text, vocabulary):
    """Every (element, ancestors) in one snippet, for elements in `vocabulary`.

    Elements outside the vocabulary are skipped rather than stacked, which is what
    keeps an expression's `<string>` or `<jobject>` out of the nesting. A tag the
    stream cannot balance is an error: the corpus is pinned and balances today, so
    a refresh that stops balancing has to be looked at rather than read crooked.
    """
    found = []
    stack = []
    for match in TAG.finditer(COMMENT.sub(" ", text)):
        name = match.group("name")
        if name not in vocabulary:
            continue
        if match.group("close"):
            if name not in stack:
                raise SystemExit(f"</{name}> closes nothing; the snippet corpus does not balance")
            # Pop back to the name being closed rather than demanding it be on
            # top. Some snippets are not well-formed even as a tag stream:
            # Set_cache_duration_using_response_cache_control_header.policy.xml
            # writes `duration="@{... Groups["maxAge"] ...}"`, a `"` inside a
            # `"`-delimited attribute, so the tag ends early and <cache-store>
            # never sees its own closer. Recovering at the enclosing </outbound>
            # is what a reader does with that file too.
            while stack.pop() != name:
                pass
            continue
        found.append((name, tuple(stack)))
        if not match.group("empty"):
            stack.append(name)
    if stack:
        raise SystemExit(f"{stack} left open; the snippet corpus does not balance")
    return found


def section_uses(text, names):
    """The (policy, section) pairs one document uses AT SECTION LEVEL.

    A policy is in a section when every element between the two passes the section
    through. Under anything else it is a child of that policy, not of the section.
    """
    vocabulary = (
        set(names) | set(SECTIONS) | set(TRANSPARENT) | set(CONTAINERS) | {"policies", "fragment"}
    )
    used = set()
    for name, ancestors in snippet_elements(text, vocabulary):
        if name not in names:
            continue
        for depth, ancestor in enumerate(ancestors):
            if ancestor not in SECTIONS:
                continue
            if all(item in TRANSPARENT for item in ancestors[depth + 1:]):
                used.add((name, ancestor))
            break
    return used


def corpus_pairs(names):
    """Every section-level (policy, section) pair the published snippets use."""
    pairs = {}
    for snippet in sorted(SNIPPETS.glob("*.xml")):
        for pair in section_uses(snippet.read_text(), names):
            pairs.setdefault(pair, []).append(snippet.name)
    return pairs


def widen(derived):
    """Add the sections the corpus uses and the pages omit.

    Every conflict has to be classified, so a corpus or reference refresh that
    introduces one stops here instead of being decided by whichever source the
    script happens to read second.
    """
    widened = {}
    classified = set()
    for (name, section), snippets in sorted(corpus_pairs(set(derived)).items()):
        documented = derived.get(name)
        if not documented or section in documented:
            continue
        witness = CORPUS_WIDENS.get((name, section))
        if witness is None:
            raise SystemExit(
                f"the snippet corpus puts <{name}> in <{section}>, which {name}-policy.md "
                f"does not document: classify it in CORPUS_WIDENS {snippets}"
            )
        if witness not in snippets:
            raise SystemExit(
                f"CORPUS_WIDENS names {witness} for <{name}> in <{section}>, but the corpus "
                f"uses it in {snippets}"
            )
        classified.add((name, section))
        derived[name] = ordered(set(documented) | {section})
        widened[name] = ordered(widened.get(name, []) + [section])
    stale = set(CORPUS_WIDENS) - classified
    if stale:
        raise SystemExit(
            f"CORPUS_WIDENS classifies pairs the corpus and the pages no longer "
            f"disagree about: {sorted(stale)}"
        )
    return widened


def derive():
    inventory = json.loads(INVENTORY.read_text())
    names = [item["name"] for item in inventory["policies"]]

    # The vendored corpus and the ledger must name the same policies. Otherwise a
    # new inventory entry arrives with no page to derive from, and inherits no
    # enforcement, which is the state this script exists to end.
    expected = {ALIASES.get(name, name) for name in names} - set(NO_REFERENCE_PAGE)
    vendored_pages = {page.name[: -len("-policy.md")] for page in SOURCE.glob("*-policy.md")}
    if vendored_pages != expected:
        missing = sorted(expected - vendored_pages)
        extra = sorted(vendored_pages - expected)
        raise SystemExit(
            f"vendored pages do not match the inventory: missing {missing}, unexpected {extra}"
        )

    derived = {}
    for name in sorted(vendored_pages):
        found = page_sections(SOURCE / f"{name}-policy.md")
        if (found is None) != (name in SECTIONLESS):
            raise SystemExit(
                f"{name}-policy.md: derived {found!r}, but SECTIONLESS says "
                f"{'no sections' if name in SECTIONLESS else 'a section list'}"
            )
        derived[name] = found or []
    # Before the corpus scan, so the pageless names are held to the same conflict
    # check as every other name rather than skipped by it.
    for name, sections in NO_REFERENCE_PAGE.items():
        derived[name] = ordered(sections)
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
    missing = [item["name"] for item in inventory["policies"] if item["name"] not in record["policies"]]
    if missing:
        raise SystemExit(f"the ledger names policies the derivation does not: {missing}")
    for item in inventory["policies"]:
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
