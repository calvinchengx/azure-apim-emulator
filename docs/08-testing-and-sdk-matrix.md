# 08 - Testing and SDK matrix

## Test oracles

No single oracle proves APIM parity. The project combines:

1. Public OpenAPI/TypeSpec schemas for management wire shape.
2. Microsoft Learn policy and feature documentation for declared semantics.
3. Official SDKs as real client witnesses.
4. Microsoft open-source portal and policy projects for interoperable formats and workflows.
5. Differential tests against authorized Azure APIM instances for observable behavior.

Generated SDKs share a specification and therefore are not independent evidence
of runtime semantics. Passing them is necessary but not sufficient.

## Initial SDK witnesses

| Language | Package | Version at repository creation | Initial purpose |
|---|---|---:|---|
| Python | `azure-mgmt-apimanagement` | `5.0.0` | primary `2024-05-01` management witness |
| JavaScript | `@azure/arm-apimanagement` | `10.0.0` | portal/tooling ecosystem, named-value tag predicates, policy-fragment lifecycle, and filtered/ordered collection witness |
| .NET | `Azure.ResourceManager.ApiManagement` | `1.3.1` | ARM client and policy-tooling ecosystem witness |
| Go | `armapimanagement` | `v1.1.1` | older `2021-08-01` compatibility witness |

Versions are pinned in CI and audited periodically. New SDK versions are added
before old witnesses are removed. The first implementation spike proves custom
endpoint and `entra-emulator` authentication for all four.

## Test layers

### Unit

Pure tests for version projections, presence/null semantics, ETags, paging,
routing, policy compilation, expressions, protocol parsers, capability rules,
and error mapping. Table tests are generated from operation and policy inventories.

### Integration

Start the complete handler stack with temporary SQLite, deterministic clock,
TLS, and fixture backends. Verify management writes atomically change gateway
behavior and failed compiles leave the previous snapshot active.

### SDK end-to-end

Each SDK provisions a logical service, imports APIs, creates products and
subscriptions, uploads policies, calls the gateway, rotates keys, pages lists,
handles LROs, and tears resources down without emulator-specific request code.
The Go witness also reads APIM entity tags, performs wildcard updates, and
asserts the structured `412 PreconditionFailed` response for a stale update. It
uses an official filtered pager across multiple `$top=1` pages and verifies the
total count and terminal `nextLink` behavior.

### Protocol end-to-end

Use real clients for HTTP, SOAP, GraphQL, WebSocket, gRPC, portal OAuth console,
and MCP/model traffic. Backends record exact method, URL, headers, body, TLS
identity, timing, cancellation, and connection behavior.

### Differential

The same declarative scenario runs against emulator and Azure. Capture:

- management request/response transcript and final resource state
- gateway response and backend-observed request
- traces, errors, rate/quota/cache state, and telemetry
- portal-visible content and workflow outcomes

Normalize only declared nondeterminism: request IDs, dates, generated secrets,
regional hostnames, asynchronous timing, and explicitly unordered collections.
Every normalization rule is reviewed and tested so it cannot hide a semantic difference.

### Fuzz and load

Fuzz management JSON, XML policies, expressions, route templates, OpenAPI/WSDL,
GraphQL, protobuf, headers, and chunked bodies. Load tests enforce bounded memory,
snapshot swap behavior, rate/quota atomicity, streaming, cancellation, and leak freedom.

## Azure fixture matrix

Differential fixtures record:

- Azure subscription and region alias, never credentials
- tier and gateway type
- management API version
- gateway build/version where observable
- feature flags and workspace topology
- date, request transcript hashes, and documentation/spec grounding commit

Tests that incur cost or require scarce tiers are scheduled, budgeted, and kept
outside ordinary pull-request CI. Sanitized golden outputs remain in the repository.

The P0 service differential is non-destructive. Set
`APIM_AZURE_SERVICE_URL` to an existing service resource URL and
`APIM_AZURE_BEARER_TOKEN` to an authorized ARM token, then run
`make test-differential`. The test reads Azure, checks the dated schema
inventory, replays that document into an isolated emulator, and compares the
writable projection without changing Azure.

Declarative replay scenarios live under `e2e/differential/testdata/` and are
listed in `fixture-manifest.json`. Each implemented scenario defines ordered
management or gateway steps, fixture-backed request bodies, expected status
codes, and a golden response projection. The same runner is intended for
local replay and authorized Azure witnesses. Normalization is recursive and
explicitly limited to the manifest rules for generated IDs, timestamps,
secrets, regional hostnames, and unordered collections; it does not normalize
arbitrary response differences.

## Deterministic controls

`/_emulator` supports:

- freeze/advance/reset clock
- fail or delay the next N management/backend/configuration requests
- force 429/5xx, disconnect, malformed backend response, and TLS failures
- inspect active snapshots and compilation diagnostics
- reset service or whole-emulator state
- export/import sanitized test state
- capture parity transcripts

These routes are local tooling and never impersonate Azure APIs.

## Coverage gates

- 100 percent aggregate statement coverage for committed Go code
- 100 percent operation inventory classification
- 100 percent policy inventory classification
- every `verified` parity item links to an automated differential fixture
- race detector on core packages
- cross-platform build and smoke tests
- portal Playwright tests at desktop and mobile widths
