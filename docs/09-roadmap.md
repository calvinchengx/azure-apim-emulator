# 09 - Implementation roadmap

Each phase is independently useful, SDK-witnessed, documented, and reflected in
the parity ledger. Full parity is a moving target; upstream audits append work
without erasing completed evidence.

## P0 - Contract spike and foundations

Goal: prove the architecture before broad resource work.

- [x] Go module, command, config, controllable clock, request IDs, SQLite migrations, TLS, and host routing.
- [x] Embeddable `pkg/emulator` test fixture with isolated state, HTTP/TLS modes, trusted client, lifecycle cleanup, and configuration options.
- [x] ARM auth against `entra-emulator` and canonical ARM errors for the implemented resources.
- [ ] Pre-seeded service plus full service GET/PUT/PATCH/DELETE/list semantics. Core publisher/SKU fields, resource-group/subscription lists, idempotent deletion, create/update status, body ETags, and deterministic LRO polling are working; the complete service schema and Azure differential fixtures remain.
- [x] Minimal API, operation, policy, product, product/API link, and subscription resources.
- [x] Four-SDK custom-endpoint spike: Go `armapimanagement v1.1.1`, JavaScript `@azure/arm-apimanagement 10.0.0`, Python `azure-mgmt-apimanagement 5.0.0`, and .NET `Azure.ResourceManager.ApiManagement 1.3.1`.
- [x] HTTP route to fixture backend, subscription-key validation, `forward-request`, `set-header`, and `return-response`.
- [x] Policy XML round-trip, immutable snapshot compiler, last-known-good failed-compile protection, and bounded structured gateway traces.
- [x] CI, 100% coverage gate, GoReleaser skeleton, non-root distroless container, Compose, and initial MkDocs site.

Exit: every SDK creates/configures a service and a subscription-protected API,
then calls it through the gateway with Entra-authenticated management.

## P1 - Core management and HTTP gateway

- APIs, revisions, releases, versions, operations, schemas, tags, products,
  groups, users, subscriptions, named values, backends, certificates, fragments,
  loggers, and diagnostics for stable API versions.
- OpenAPI import/export and linked imports.
- Complete ARM common semantics: ETags, paging, filters, patch, LROs, errors, and secret operations.
- HTTP routing edge cases, custom domains, backend TLS, pools, retries, circuit breakers, streaming, SSE, and WebSocket.
- Entra JWT, managed identity, OAuth/OIDC, client certificates, and Key Vault-backed named values.
- Core policy families: routing, mutation, control flow, auth, limits, cache, validation, send-request, transforms, and tracing.
- Operator portal for resources, snapshots, traces, clock, faults, and parity.

Exit: common APIM application-development and CI workflows run offline with
official SDKs and documented policies.

## P2 - Expression completeness and policy inventory

- Full documented C# 7 expression grammar used by APIM.
- Complete APIM context object and documented allowed .NET type/member surface in pure Go.
- Multi-statement blocks, lambdas/LINQ, JSON/XML/JWT/crypto semantics, and exception behavior.
- Every policy-reference entry implemented or carrying an explicit external dependency adapter.
- Scope inheritance across service, product, API, operation, fragments, and workspace governance.
- Generated member- and policy-level compatibility documentation.
- Large Azure differential corpus for error paths and edge semantics.

Exit: policy and expression inventories contain no unclassified stable entries.

## P3 - Developer portal

- Portal content/item APIs, draft model, publishing, revisions, reset, and media.
- APIM-compatible consumer portal with API/product docs, search, visibility, subscriptions, profile, and reports.
- Basic, Entra, external identity, invitation, password reset, and delegated authentication flows.
- Interactive REST/SOAP/GraphQL/WebSocket console with subscription and OAuth support.
- Administrative editor, styles, layouts, widgets, custom widgets, CSP, localization, accessibility, and custom domains.
- Self-hosted portal interoperability and published content export/import.

Exit: publisher and consumer portal journeys match Azure fixtures and use the
same underlying APIM resources as the gateway.

## P4 - Workspaces and distributed gateways

- Workspace resource hierarchy, uniqueness, references, RBAC, deletion, and service governance.
- Dedicated/shared/default workspace gateway association and runtime isolation.
- Separate-process self-hosted gateways, configuration sync, auth/token rotation,
  backup, last-known-good, heartbeat, metrics, disconnected and fail-static behavior.
- Gateway capability/version matrix and Arc-visible management contracts.
- Federated workspace diagnostics and unified developer portal discovery.

Exit: multi-team workspace and hybrid gateway scenarios pass SDK, failure, and differential suites.

## P5 - SOAP, GraphQL, gRPC, and advanced protocols

- WSDL/SOAP import, pass-through, transformations, SOAP actions, and faults.
- Pass-through and synthetic GraphQL, resolver policies, validation, limits, and introspection.
- gRPC unary/streaming, protobuf imports, metadata, status/trailers, deadlines, and tier constraints.
- Complete WebSocket/SSE behavior and protocol-specific telemetry.
- OData/WADL compatibility retained where publicly supported.

Exit: each documented protocol has real-client witnesses and Azure differential fixtures.

## P6 - Networking, tiers, regions, and platform lifecycle

- All current tiers/SKUs and capability validation.
- Classic/v2 networking, public access, inbound private endpoints, outbound
  integration/injection, DNS, IP state, proxy, zones, regions, and multi-region routing.
- Custom hostname/certificate lifecycle for gateway, portal, management, SCM, and configuration endpoints.
- Backup/restore, deleted services, upgrades/migrations, scaling, deployment state, and long infrastructure LRO simulation.
- Local topology profiles that make network state behaviorally testable.

Exit: stable infrastructure-facing management contracts and locally observable
network outcomes are parity-classified and differential-tested.

## P7 - Observability, authorizations, and ecosystem integrations

- Azure Monitor schema, diagnostics settings, resource logs, metrics, analytics, and reports.
- Application Insights and OpenTelemetry correlations, sampling, masking, and exporters.
- Authorization providers, credential manager, Service Bus, Event Hub-style logging,
  Dapr, Service Fabric, external cache, and documented backend integrations.
- Notifications, email templates, issues/comments, tenant settings, reports, and remaining platform resources.

Exit: the stable management operation inventory is fully verified or has an
explicit external-adapter test fixture.

## P8 - AI gateway, MCP, and current previews

- Model APIs and provider adapters, load balancing, token limits, semantic cache,
  content safety, prompt controls, logging, and model telemetry.
- MCP-related import, exposure, governance, authentication, policy, and portal behavior.
- Deterministic fake providers plus opt-in Azure/OpenAI/provider differential suites.
- Promote supported preview contracts only after stable tracks remain green.

Exit: all publicly documented stable AI/MCP capabilities are parity-classified;
previews have isolated versioned coverage.

## P9 - Full-parity audit and continuous maintenance

- Zero unknown stable operations, policies, expression members, portal workflows,
  gateway capabilities, or tier rows.
- Cross-region/tier differential sweep and reproducible parity release snapshot.
- Performance and memory budgets published for idle, routing, policies, portal,
  self-hosted gateway, and load scenarios.
- Automated upstream spec/docs/release-note diff opens parity work items.
- Deprecation policy and compatibility windows for older SDK/API versions.

Exit: a release may claim full parity only for the exact dated compatibility
snapshot whose evidence is published. Later upstream changes reopen the ledger.
