# 03 - System architecture

## Shape

One Go process hosts multiple logical APIM services and exposes separate public
surfaces:

```text
 Microsoft SDK / ARM client             API consumer / portal user
              |                                      |
     management.azure.localhost              *.azure-api.localhost
              |                                      |
        Management API                         Gateway ingress
              |                                      |
        Resource store ---- compile ----> immutable runtime snapshot
              |                                      |
        Portal content                         policy pipeline
              |                                      |
        Emulator control                    backend transport
                                                     |
                                            protected backend APIs
```

## Process boundaries

The default distribution is a single binary. Optional integrations run out of
process only when their native runtime or security boundary justifies it:

- a future exact .NET expression worker is optional and never required by default
- external telemetry collectors remain external
- self-hosted gateway nodes may run as separate instances of the same Go binary
- portal assets are built ahead of time and embedded with `go:embed`

## Planned Go packages

```text
cmd/azure-apim-emulator        process entry point
pkg/emulator                   embeddable test API
internal/config                flags, environment, validation
internal/clock                 real and controllable clocks
internal/arm                   ARM routing, auth, errors, paging, LROs
internal/model                 canonical resource and API document models
internal/store                 SQLite repositories and migrations
internal/compiler              resource graph to runtime snapshot
internal/gateway               ingress, route selection, pipeline, transport
internal/policy                XML model, inheritance, compilation, policies
internal/expression            lexer, parser, binder, evaluator, APIM type model
internal/protocol              REST, SOAP, GraphQL, WebSocket, gRPC, SSE, MCP
internal/portal                portal data, content, revisions, publishing, auth
internal/workspace             isolation, references, gateways, governance
internal/identity              ARM auth, JWT, subscriptions, users, managed identity
internal/network               hostnames, TLS, reachability, private simulation
internal/telemetry             traces, logs, metrics, analytics, exporters
internal/operator              /_emulator controls and diagnostic portal API
internal/parity                fixture normalization and comparison helpers
portal/                        embedded operator portal
developer-portal/              APIM-compatible developer portal assets and adapters
e2e/                           official SDK and product workflow suites
```

Package ownership follows behavior, not REST file layout. Generated schema
types may live under `internal/arm/spec`, but generated code never owns runtime
semantics.

## Runtime snapshots

Management writes use SQLite transactions. A successful write triggers a
configuration compile:

1. Read the affected service/workspace resource graph.
2. Validate references and tier applicability.
3. Expand policy scope and `<base />` inheritance.
4. Compile routes, policies, expressions, backends, certificates, and limits.
5. If compilation fails, keep the prior active snapshot and return the matching management error.
6. Atomically publish an immutable snapshot with a monotonically increasing revision.
7. Existing requests finish on their captured snapshot; new requests use the new one.

This isolates management concurrency from the hot request path and prevents
partially applied policy state.

## Storage

Use `modernc.org/sqlite` to keep the binary CGO-free. Separate tables hold:

- ARM resource envelopes and version-specific projections
- canonical APIs, operations, schemas, products, users, groups, and subscriptions
- original API definitions and policy XML
- named values, backends, certificates, identity and authorization configuration
- portal draft content, media metadata, revisions, and published snapshots
- workspace ownership and gateway associations
- LRO records, deployment state, and ETags
- rate, quota, cache, session, trace, analytics, and fault-injection state

Secrets are encrypted-at-rest only as a local safety feature, never presented as
an HSM or Azure security boundary. Tests can select an in-memory store.

## Determinism

A shared clock drives LRO progression, subscription expiry, token validation,
cache expiry, retry windows, rate and quota periods, certificate lifetime,
portal reports, and telemetry timestamps. The operator API can freeze, advance,
or reset it. Stable seeded IDs and keys make CI output reproducible.

## Configuration surfaces

- environment variables and flags for process concerns
- ARM resources for Azure-compatible service configuration
- `/_emulator` for test-only clock, faults, snapshots, reset, inspection, and parity capture
- no emulator-only fields are inserted into Azure resource representations

## Distribution targets

- native Linux, macOS, and Windows binaries for amd64 and arm64
- distroless container image
- Homebrew, winget, and `go install`
- Docker Compose with companion emulators and representative backends
- embeddable Go package that allocates ports and cleans up with `testing.T`

