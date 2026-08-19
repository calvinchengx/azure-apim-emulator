# 12 - Risk register

## R1 - Scope and moving target

**Risk:** APIM spans many tiers, gateways, protocols, portals, integrations, and
fast-moving AI features.

**Response:** generated inventories, dated parity snapshots, stable/preview
separation, phased releases, and no undated blanket parity claim.

## R2 - Undocumented runtime semantics

**Risk:** specs describe shapes better than policy ordering, errors, routing,
timeouts, and edge behavior.

**Response:** authorized Azure differential harness, backend recorder, trace
capture, regional/tier metadata, and permanent fixtures for every discovery.

## R3 - C#/.NET expression fidelity in Go

**Risk:** parsing is easier than reproducing .NET conversions, exceptions,
collections, regex, JSON/XML, crypto, and date behavior.

**Response:** project-owned typed AST, member-level inventory, golden vectors
executed in .NET and Azure, differential fuzzing, explicit unsupported nodes,
and an optional sandboxed reference worker for diagnosis.

## R4 - SDK endpoint rigidity

**Risk:** generated clients may hard-code ARM hosts, audiences, API versions, or
polling behavior differently by language/version.

**Response:** P0 four-SDK spike before broad implementation, pinned versions,
documented endpoint injection, and older API projections rather than query-version aliasing.

## R5 - Memory growth

**Risk:** buffering, policy caches, portal assets, analytics, GraphQL, gRPC, and
many services can erase Go's memory advantage.

**Response:** streaming by default, bounded body stores, immutable snapshot
sharing, LRU caches, retention limits, heap benchmarks, and release memory budgets.

## R6 - Concurrency and state consistency

**Risk:** management writes race with requests, rate limits, quota, cache, portal
publishing, and distributed gateway configuration.

**Response:** transactional writes, compile-before-publish, immutable snapshots,
atomic counters/SQLite transactions, revisioned config, race tests, and failure injection.

## R7 - Protocol and parser security

**Risk:** XML, WSDL, GraphQL, protobuf, OpenAPI, C# expressions, portal content,
and linked imports expose denial-of-service and injection paths.

**Response:** depth/size/time limits, disabled external XML entities, controlled
fetcher, CSP/sanitization, fuzzing, loopback default, secret redaction, and helper isolation.

## R8 - Portal compatibility

**Risk:** the open-source portal evolves independently and contains a large UI,
content format, publishing workflow, and authentication surface.

**Response:** pin upstream commits, separate content/runtime contracts from UI,
test self-hosted interoperability, use Playwright visual/workflow fixtures, and
review license implications before code reuse.

## R9 - Azure test cost and availability

**Risk:** Premium/v2, workspaces, regions, networking, and AI integrations cost
money or require scarce permissions.

**Response:** scheduled budgeted suites, reusable fixtures, sanitized goldens,
tier-specific test subscriptions, cleanup audits, and `blocked-external` parity state.

## R10 - Clean-room contamination

**Risk:** accidental use of non-public Microsoft implementation details would
undermine the project.

**Response:** grounding manifest, public-source citations, fixture provenance,
contributor rules, no leaked/internal artifacts, and review of every behavioral
claim that is not directly documented.

## R11 - Local substitutions overclaim fidelity

**Risk:** network, scale, region, monitoring, and availability simulations could
be mistaken for real infrastructure guarantees.

**Response:** distinguish wire/state parity from physical implementation,
document substitutions, expose local topology, and never market the emulator as
a security, performance, resilience, or billing simulator.

