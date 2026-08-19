# 00 - Charter and parity definition

## Mission

`azure-apim-emulator` lets applications, deployment tools, API publishers, and
API consumers exercise Azure API Management workflows locally and in CI without
changing their production-facing code.

The project emulates contracts, not Azure datacenters. A behavior belongs in
scope when a user, SDK, CLI, template, portal client, gateway client, backend,
or telemetry consumer can observe it through a public interface.

## Full parity

Full parity is reached only when all of the following hold for stable public
features:

1. The documented request is accepted or rejected under the same conditions.
2. Status, headers, body shape, paging, ETags, LRO state, and errors match.
3. The resulting resource state and gateway behavior match.
4. Official SDKs complete the same workflow without emulator-specific branches.
5. A differential test against Azure agrees after documented normalization.
6. Tier, gateway, workspace, protocol, and policy applicability differences are honored.

Undocumented behavior discovered by black-box study is recorded as an observed
contract with the Azure region, tier, API version, date, and reproduction. It
does not silently override published documentation.

## Compatibility dimensions

Every parity entry is keyed by more than a feature name:

- management API version: stable and preview tracked independently
- service tier: Consumption, Developer, Basic, Standard, Premium, and v2 variants
- gateway: classic managed, v2 managed, consumption, workspace, self-hosted, and Arc-hosted
- scope: service, workspace, product, API, operation, and GraphQL resolver
- protocol: HTTP/REST, SOAP, GraphQL, WebSocket, SSE, gRPC, and MCP
- identity: administrator, service principal, managed identity, portal user, subscription
- deployment topology: public, custom-domain, private, multi-region, and local simulation

## Compatibility states

The parity ledger uses these states:

- `verified`: documented contract plus automated Azure differential coverage
- `sdk-verified`: official SDK workflow passes, but no Azure differential yet
- `implemented`: local contract tests pass
- `partial`: a documented subset works and omissions are enumerated
- `planned`: owned by a roadmap phase
- `unknown`: not yet researched
- `blocked-external`: requires an unavailable Azure service or permission to characterize

No feature is marked verified from a happy-path smoke test alone.

## Stable and preview policy

- Stable management baseline: `2024-05-01`.
- Older stable versions used by supported SDKs remain accepted and retain their wire differences.
- Latest known preview at project creation: `2025-09-01-preview`.
- Preview support is opt-in, labeled, and may change without preserving emulator compatibility.
- The release process audits upstream specs and documentation before each emulator release.

## Local substitutions

Some Azure infrastructure has a deterministic local substitute:

| Azure concept | Local implementation | Required parity |
|---|---|---|
| regional deployment | logical deployment record and deterministic LRO | management contract and state transitions |
| scale units | configured logical capacity | tier validation, limits, and observable headers |
| private endpoint | host/DNS/access policy | resource state and local reachability |
| Azure Monitor | local event store plus export adapters | schema, sampling, correlation, and queryable outcomes |
| managed identity | `entra-emulator` identity | token acquisition and policy behavior |
| Key Vault reference | `azure-keyvault-emulator` | resolution, refresh, versioning, and failure semantics |

Substitutions are documented in responses and the parity ledger. They must not
claim that local infrastructure is a security or availability boundary.

## Quality bars

- Race-clean Go tests and deterministic clocks.
- 100 percent aggregate statement coverage for committed Go code; critical policy and routing packages also require branch-oriented tests beyond the aggregate metric.
- No silent fallback for unsupported policies, expressions, protocols, or API versions.
- Bounded memory under streaming workloads; bodies are buffered only when policy semantics require it.
- Original policy and API documents remain retrievable byte-for-byte where Azure preserves them.
- Every bug fixed from an Azure comparison gains a permanent golden or differential fixture.
