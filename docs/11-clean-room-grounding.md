# 11 - Clean-room grounding

## Rules

Implementation and compatibility claims may use only:

- public Microsoft specifications and documentation
- public Microsoft source repositories under their published licenses
- official public SDK source and behavior
- standards specifications
- black-box observations from Azure resources the project is authorized to use
- independently written fixtures and implementation code

Do not use leaked source, private Microsoft documentation, decompiled service
binaries, confidential support material, or observations lacking provenance.

## Initial pinned sources

Pins record the design baseline on 2026-07-30. Re-audits diff these commits and
classify changes in the parity ledger.

| Source | Commit | Purpose |
|---|---|---|
| `Azure/azure-rest-api-specs` | `b572ea521b022767cf0a4cbb161c3774d936300e` | APIM TypeSpec/OpenAPI and examples |
| `MicrosoftDocs/azure-docs` | `005b5c0248d19fef9af8e9f0ea78eacae83ccaa9` | APIM concepts, policies, tiers, gateways, portal, workspaces, networking, observability |
| `Azure/API-Management` | `02b1448d8646611d236ff6c5da8bfac03e280359` | public release notes, policy samples, guidance |
| `Azure/azure-api-management-policy-toolkit` | `09a81c26a4c042a9360a400d2d1a7003e740884a` | public policy authoring/testing model and fixtures |
| `Azure/api-management-developer-portal` | `a7466616eb2c1eb5c63b3a5c1ce0f8f1a1311119` | public portal architecture and interoperability |

## Version baseline

- stable management API: `2024-05-01`
- latest known preview: `2025-09-01-preview`
- APIM policy documentation is live rather than released as one versioned schema
- gateway capability tables and release notes are therefore separately pinned and audited

## Behavioral fixture provenance

Every Azure-derived fixture records:

- scenario and expected assertion
- request with secrets removed
- region, tier, gateway type, API version, and date
- source account alias and authorization statement in private CI metadata
- normalization rules
- hash of raw encrypted capture when retention is permitted
- related public documentation or issue

Sanitized fixtures may be committed. Credentials, subscription keys, tokens,
tenant identifiers, customer data, and private hostnames may not.

## Upstream audit

Before release:

1. Fetch current source heads and APIM release notes.
2. Diff operation directories, policy reference inventory, expression allowlist,
   capability tables, portal content contracts, workspace docs, and tier docs.
3. Add or update parity entries.
4. Run stable SDK and differential suites.
5. Publish the new grounding commits in the release parity snapshot.

