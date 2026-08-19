# Vendored Microsoft sources

These files are Microsoft's, vendored at pinned commits so the expression
inventory is derived from them rather than transcribed by hand. Nothing here is
edited. `scripts/derive_expression_surface.py` reads them and writes
`internal/expression/documented.json`; `make check-expression-surface` fails when
the two disagree.

| File | Source | Commit | Licence |
|---|---|---|---|
| `policy-expressions.md` | [MicrosoftDocs/azure-docs](https://github.com/MicrosoftDocs/azure-docs) `articles/api-management/api-management-policy-expressions.md` | `4a74bf2f66742c18e9cbe465af133be6f87c895b` | CC-BY-4.0 |
| `toolkit/*.cs` | [Azure/azure-api-management-policy-toolkit](https://github.com/Azure/azure-api-management-policy-toolkit) `src/Authoring/Expressions/` | `1989f9f1764e1560ba971c939983ccf59e154031` | MIT |
| `policy-snippets/*.xml` | [Azure/api-management-policy-snippets](https://github.com/Azure/api-management-policy-snippets) | `87225c2090e45add095919e8767c37d9ece42e0c` | MIT |

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
