#!/usr/bin/env python3
"""Derive the documented APIM expression surface from vendored Microsoft sources.

WHY THIS EXISTS. The documented surface used to be a hand-written Go list. A
hand-copied record of what somebody else documents drifts silently: comparing it
against Microsoft's own sources found `LastError.Element`/`ElementPath`, which
Microsoft does not document, while `Path` and `PolicyId`, which it does, were
absent, and `context.Backend`, `context.Workspace` and
`Deployment.SustainabilityInfo` were missing outright.

So the surface is DERIVED, from two independent Microsoft sources vendored under
third_party/microsoft/ at pinned commits:

  * the published policy-expressions reference (broad, but prose-formatted), and
  * the policy toolkit's C# interfaces (precise, but narrower).

Neither alone is the oracle. Each member records which sources carry it, so a
member only one source knows about is visible rather than averaged away.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "third_party" / "microsoft"
OUTPUT = ROOT / "internal" / "expression" / "documented.json"

# Doc rows name the context types two ways: `context.Api` points at an `IApi`
# row that carries the members. The ledger uses the short name, so the interface
# rows fold onto it. Stated explicitly because it is the one judgement in this
# script that Microsoft's sources do not make for us.
INTERFACE_TO_TYPE = {
    "IApi": "Api",
    "IUrl": "Url",
    "IGroup": "Group",
    "IUserIdentity": "UserIdentity",
    "IMessageBody": "Body",
    "IPrivateEndpointConnection": "PrivateEndpointConnection",
    "ISubscriptionKeyParameterNames": "SubscriptionKeyParameterNames",
    "IGraphQLDataObject": "GraphQLDataObject",
    "IAzureVnetInfo": "AzureVnetInfo",
    "IExpressionContext": "context",
    "IContextApi": "Api",
    "IDeployment": "Deployment",
    "ILastError": "LastError",
    "IOperation": "Operation",
    "IProduct": "Product",
    "IRequest": "Request",
    "IResponse": "Response",
    "ISubscription": "Subscription",
    "IUser": "User",
}

IDENT = re.compile(r"^\**`?([A-Za-z_][A-Za-z0-9_]*)`?\**\s*(?::|$|<|\()")

# Rows whose first cell is a METHOD SIGNATURE document members too. Skipping
# them is how `Headers.GetValueOrDefault` -- which Microsoft documents, and which
# this emulator implements -- came to be classified as an undocumented helper.
SIGNATURE = re.compile(r"^[\w<>\[\]\.]+\s+([\w\.]+)(?:<[^>]*>)?\((.*)\)$")

# An extension method names its receiver as `input: this <TYPE>`, and the
# receiver is the type the member hangs off.
RECEIVER_TO_TYPE = {
    "string": "string",
    "byte[]": "byte[]",
    "System.Security.Cryptography.X509Certificates.X509Certificate2": "Certificate",
}


def canonical(name):
    return INTERFACE_TO_TYPE.get(name, name)


# A signature row spells its parameters, `(headerName: string, defaultValue:
# string)` or `(preserveContent = false)`. Those names are what a caller may use
# as a named argument, so they are derived here rather than listed by hand.
PARAMETER = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]")

parameter_names = set()


def parse_signature(head, surface):
    """Record a member documented as a method signature.

    `string context.Request.Headers.GetValueOrDefault(headerName: string, ...)`
    is a member of `Headers`; `BasicAuthCredentials AsBasic(input: this string)`
    is a member of `string`.
    """
    match = SIGNATURE.match(head)
    if not match:
        return
    qualified, arguments = match.group(1), match.group(2)
    for parameter in PARAMETER.findall(arguments):
        # `this` marks an extension method's receiver, not a parameter a caller
        # may name.
        if parameter != "this":
            parameter_names.add(parameter)
    name = qualified.split(".")[-1]
    # A method's declared type is its RETURN type, which is what a policy sees.
    returns = head.split(None, 1)[0]
    if "." in qualified:
        surface.setdefault(canonical(qualified.split(".")[-2]), {})[name] = returns
        return
    receiver = re.search(r":\s*this\s+([\w\.\[\]]+)", arguments)
    if receiver and receiver.group(1) in RECEIVER_TO_TYPE:
        surface.setdefault(RECEIVER_TO_TYPE[receiver.group(1)], {})[name] = returns


def parse_docs(path):
    """Read the reference table's context-graph rows."""
    surface = {}
    for line in path.read_text().splitlines():
        if not line.startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) < 3:
            continue
        head = re.sub(r"<a id=\"[^\"]*\"></a>", "", cells[1]).strip().strip("`")
        # Rows for allowed .NET types and for standalone method signatures are
        # not part of the context graph.
        if not re.fullmatch(r"(context(\.[A-Za-z][A-Za-z0-9_]*)*|I[A-Z][A-Za-z0-9_]*)", head):
            # A method-signature row documents a member of the type it hangs
            # off, so it is read rather than skipped.
            parse_signature(head, surface)
            continue
        typ = canonical(head.split(".")[-1])
        for fragment in re.split(r"<br\s*/?>", cells[2]):
            # A link INTO the table names a member's type and its text is the
            # member. A link OUT of the table is prose: `[Examples](configure-
            # graphql-resolver.md)` sits in the GraphQL row and is not a member.
            fragment = re.sub(r"\[([^\]]*)\]\(#ref-[^)]*\)", r"\1", fragment)
            fragment = re.sub(r"\[[^\]]*\]\([^)]*\)", "", fragment).strip()
            if not fragment:
                continue
            # Only the PARENTHESISED part of a member cell holds parameters:
            # `As<T>(preserveContent = false)` does, while `Elapsed: TimeSpan`
            # is a member and its type, and scanning the whole fragment
            # collected member names as though they were parameters.
            for call in re.findall(r"\(([^()]*)\)", fragment):
                for parameter in PARAMETER.findall(call):
                    if parameter != "this":
                        parameter_names.add(parameter)
            match = IDENT.match(fragment)
            # `IGraphQLDataObject` has a single cell reading "TBD": Microsoft
            # documents the type without documenting its members. Recording TBD
            # as a member would invent one.
            if match and match.group(1) != "TBD":
                surface.setdefault(typ, {})[match.group(1)] = declared_type(fragment)
    return surface


# `Id`: `string` -- and sometimes `Elapsed: `TimeSpan` - prose about it`, so the
# type is what sits between the colon and any trailing prose.
DECLARED = re.compile(r"^[^:]*:\s*`?([^`\n]+?)`?(?:\s+-\s.*)?$")


def declared_type(fragment):
    """The C# type a reference fragment declares, or "" when it names none."""
    match = DECLARED.match(fragment.strip())
    if not match:
        return ""
    return match.group(1).strip().strip("`").strip()


DOTTED_TYPE = re.compile(r"^(System|Newtonsoft)\.[A-Za-z0-9_.<>, \[\]]+$")


def parse_framework_types(path):
    """Read the allowed .NET types table.

    These are types a policy may USE but whose members Microsoft does not
    enumerate. `context.Request.Certificate` is an X509Certificate2, so the
    members this emulator answers on it are our reading of a .NET type rather
    than of an APIM document. Recording the TYPE keeps that distinction gateable:
    a member of a listed type is available in a real tenant, which a member
    nobody documents at all is not.
    """
    types = set()
    for line in path.read_text().splitlines():
        if not line.startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) < 2:
            continue
        head = cells[1].strip().strip("`")
        if DOTTED_TYPE.fullmatch(head):
            types.add(head)
    return sorted(types)


PROPERTY = re.compile(r"^\s*(?:public\s+)?([\w<>,\[\]\?\. ]+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*get;")


def parse_toolkit(directory):
    """Read property names off the toolkit's C# interface declarations."""
    surface = {}
    for path in sorted(directory.glob("*.cs")):
        declared = re.search(r"public\s+interface\s+([A-Za-z_][A-Za-z0-9_]*)", path.read_text())
        if not declared:
            continue
        typ = canonical(declared.group(1))
        for line in path.read_text().splitlines():
            match = PROPERTY.match(line)
            if match:
                surface.setdefault(typ, {})[match.group(2)] = match.group(1).strip()
    return surface


def main():
    docs = parse_docs(VENDOR / "policy-expressions.md")
    toolkit = parse_toolkit(VENDOR / "toolkit")
    members = []
    for typ in sorted(set(docs) | set(toolkit)):
        for name in sorted(set(docs.get(typ, {})) | set(toolkit.get(typ, {}))):
            sources, declared = [], {}
            for label, surface in (("reference", docs), ("toolkit", toolkit)):
                if name in surface.get(typ, {}):
                    sources.append(label)
                    # A source can name a member without naming its type, and an
                    # empty declaration is recorded as absent rather than as "".
                    if surface[typ][name]:
                        declared[label] = surface[typ][name]
            member = {"type": typ, "name": name, "sources": sources}
            if declared:
                member["declared"] = declared
            members.append(member)
    payload = {
        "note": "DERIVED by scripts/derive_expression_surface.py from third_party/microsoft/. Do not edit by hand.",
        "members": members,
        "frameworkTypes": parse_framework_types(VENDOR / "policy-expressions.md"),
        "parameterNames": sorted(parameter_names),
    }
    rendered = json.dumps(payload, indent=1) + "\n"
    if "--check" in sys.argv:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            print("documented.json is stale; run scripts/derive_expression_surface.py", file=sys.stderr)
            return 1
        print(f"documented.json matches the vendored sources ({len(members)} members)")
        return 0
    OUTPUT.write_text(rendered)
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(members)} members, "
          f"{len(payload['frameworkTypes'])} allowed .NET types")
    return 0


if __name__ == "__main__":
    sys.exit(main())
