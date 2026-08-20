# Vendored Microsoft sources

These files are Microsoft's, vendored at pinned commits so what this emulator
accepts is derived from them rather than transcribed by hand. Nothing here is
edited. `make check-inventory` runs every derivation with `--check` and fails
when a generated record and its source disagree.

| File | Source | Commit | Licence |
|---|---|---|---|
| `policy-expressions.md` | [MicrosoftDocs/azure-docs](https://github.com/MicrosoftDocs/azure-docs) `articles/api-management/api-management-policy-expressions.md` | `4a74bf2f66742c18e9cbe465af133be6f87c895b` | CC-BY-4.0 |
| `toolkit/*.cs` | [Azure/azure-api-management-policy-toolkit](https://github.com/Azure/azure-api-management-policy-toolkit) `src/Authoring/Expressions/` | `1989f9f1764e1560ba971c939983ccf59e154031` | MIT |
| `policy-snippets/*.xml` | [Azure/api-management-policy-snippets](https://github.com/Azure/api-management-policy-snippets) | `87225c2090e45add095919e8767c37d9ece42e0c` | MIT |
| `policy-reference/*.md` | [MicrosoftDocs/azure-docs](https://github.com/MicrosoftDocs/azure-docs) `articles/api-management/*-policy.md`, one page per policy in the inventory | `f31ac8723a622ba3950df57ba0389d8347f546ab` | CC-BY-4.0 |
| `policy-reference/includes/*.md` | [MicrosoftDocs/azure-docs](https://github.com/MicrosoftDocs/azure-docs) `includes/` | `f31ac8723a622ba3950df57ba0389d8347f546ab` | CC-BY-4.0 |

## The policy reference states behaviour, not just surface

`policy-reference/` carries the reference page for individual policies. Those
pages are the only place Microsoft states how a policy COUNTS, as opposed to
which attributes it takes, and the two limit families turned out to differ from
this emulator on exactly that. `rate-limit-policy.md` says the policy limits "on
a per subscription basis" and "is only applied when an API is accessed using a
subscription key"; both sentences were unimplemented, and neither is derivable
from a schema or an attribute table. Sentences like those are read by people, and
are vendored so a behavioural claim in a test can cite a pinned sentence instead
of a memory of the docs.

Two tables in them are read by scripts instead, because both had a hand-written
copy in this repo and both copies were wrong:

- the attribute tables feed `scripts/derive_limit_attributes.py` and
  `internal/policy/limit_attributes.json`;
- the `Policy sections:` line under `## Usage` feeds
  `scripts/derive_policy_sections.py`, `internal/policy/policy_sections.json` and
  the `sections` field of `docs/generated/policy-inventory.json`. The compiler
  rejects a policy in a section its page does not name, so this is the record
  that decides whether `<rate-limit>` compiles in `<outbound>`.

`includes/` holds the include files those tables live in when a page defers to
one: `llm-semantic-cache-lookup-policy.md` has no `## Usage` block of its own.

The sections derivation reads `policy-snippets/` as a second source, and the two
disagree: `Log_errors_to_Stackify.policy.xml` puts `<trace>` in `<on-error>`,
which `trace-policy.md` omits. Every such pair has to be classified in the script
before it will run, so a disagreement is decided once and in the open rather than
by whichever source the script read second.

## Why two sources

Neither is complete on its own, which is the reason to carry both.

The reference documents `context.Backend`, `context.Workspace`,
`Deployment.SustainabilityInfo` and the allowed .NET type list, none of which the
toolkit has. The toolkit documents `context.Product`, `context.Trace` and
`LastError.HttpErrorCode`, which the reference's own `context` row omits. They
also disagree outright: the reference says `Product.SubscriptionsLimit`, the
toolkit says `SubscriptionLimit`. Each member records which sources name it, so a
disagreement stays visible instead of being averaged into a single answer.

## The corpus measures a different thing

`policy-expressions.md` and `toolkit/` describe the SURFACE: which members exist
and what type each answers. `policy-snippets/` is 59 complete policy documents,
and it measures the LANGUAGE: whether this parser can read what Microsoft tells
people to write. A member inventory says nothing about that, because a policy is
an expression, not a member lookup.

There are TWO gates over it, because parsing is not working:
`TestCorpusParsesWhatItParsedBefore` reads the expressions, and
`TestCorpusEvaluatesWhatItEvaluatedBefore` runs them. A member that stops
resolving is invisible to the first and caught by the second.

`TestCorpusParsesWhatItParsedBefore` extracts every `@(...)` and `@{...}` from
them and parses each. The result is recorded in
`docs/generated/policy-corpus.json` and enforced as a RATCHET: an expression that
parses today must keep parsing, and a run that parses more must regenerate the
baseline. A percentage floor would not do -- it lets one expression regress while
another improves and reports the same number.

## Refreshing

Re-download at a newer commit, update the table above, then regenerate whichever
record the source feeds:

- the reference and the toolkit feed `scripts/derive_expression_surface.py`, and
  members Microsoft has added appear as `planned` in the ledger without anyone
  having to notice them;
- the snippets feed `APIM_UPDATE_CORPUS=1 go test ./internal/expression/`, and
  `corpusCommit` in `corpus_test.go` must be updated to match.
