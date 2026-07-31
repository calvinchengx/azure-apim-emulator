# 04 - Gateway and protocol runtime

## Addressing

Default local endpoints are:

```text
https://{service}.azure-api.localhost:{port}       managed gateway
https://{gateway}.gateway.azure-api.localhost:{port} self-hosted/workspace gateway
https://{service}.portal.azure-api.localhost:{port} developer portal
https://management.azure.localhost:{port}          ARM management
```

Compatibility mode accepts DNS-pinned Azure hostnames such as
`{service}.azure-api.net`. Certificates cover local wildcard forms. Host header
validation and configured custom domains follow tier-specific rules.

## Request lifecycle

1. Resolve service from a configured custom hostname or the standard host suffix, then resolve gateway and workspace.
2. Capture the active immutable snapshot.
3. Match API and operation using protocol-specific routing and revision/version rules.
4. Resolve subscription key and caller context.
5. Execute effective inbound policies from broadest to narrowest scope.
6. Select and call the backend through the backend policy section, honoring backend TLS chain-validation settings, client certificates, and compiled retry policies.
7. Execute outbound policies in the documented order.
8. On failure, create `LastError` and run applicable `on-error` policies.
9. Emit response, trace, metrics, logs, analytics, and quota effects.

Each stage records a structured trace when tracing is authorized. No diagnostic
mode changes request semantics.

## HTTP transport

Build on `net/http` with a gateway-owned transport rather than exposing
`httputil.ReverseProxy` behavior as the contract. Requirements include:

- streaming and cancellation in both directions
- hop-by-hop header removal and documented APIM forwarding headers
- raw path, escaped path, query ordering, duplicate header, and trailer correctness
- HTTP/1.1 and HTTP/2 first; documented HTTP/3 behavior when the Go stack permits
- backend connection pooling, proxy settings, client certificates, SNI, TLS validation, and custom CAs
- timeout, circuit-breaker, pool, and load-balancing semantics; retry execution is implemented for transient failures and status predicates
- bounded request/response buffering activated only by policies that inspect bodies
- body replay rules for retries and `send-request`
- request size, decompression, encoding, chunking, and malformed-message behavior

Memory and leak benchmarks are release gates for streaming and buffered paths.

## Route compilation

Compile path templates into a deterministic matcher preserving APIM precedence:

- service hostname and gateway association
- API path and protocol
- revision and version selection
- operation method and URL template
- wildcard and parameter matching
- query-template discrimination where supported

Ambiguity, duplicate operations, case behavior, encoded separators, and unmatched
requests are characterized against Azure and captured as golden fixtures.

## Protocol tracks

### REST and generic HTTP

The foundational runtime. Preserve arbitrary media types and streaming bodies;
OpenAPI enriches validation and portal documentation but is not required to proxy.

### SOAP

Support SOAP pass-through, WSDL import, SOAP action routing, REST-to-SOAP and
SOAP-to-REST transformations, XML policies, fault envelopes, and content types.

### GraphQL

Support pass-through and synthetic GraphQL APIs, schema validation, operation
limits, field resolver policy scopes, resolver backends, variables, fragments,
introspection behavior, and GraphQL-specific errors.

### WebSocket and SSE

Support upgrade routing, long-lived connections, handshake policies, connection
limits, cancellation, and streaming telemetry without buffering event streams.

### gRPC

Support pass-through where the selected gateway/tier permits it, protobuf
imports, HTTP/2 requirements, metadata forwarding, status/trailers, deadlines,
streaming modes, and documented transcoding if exposed publicly.

### MCP and AI gateway traffic

Track APIM's public MCP and model gateway contracts as versioned protocol and
policy capabilities. AI-specific token accounting, model routing, semantic
caching, safety, and provider integrations use adapters with deterministic fake
providers for local tests and opt-in real-provider differential suites.

## Self-hosted gateway

The emulator supports two modes:

- same-process logical gateways for fast tests
- separate gateway processes that fetch configuration, retain last-known-good
  state, report heartbeat/telemetry, and demonstrate disconnected operation

The public deployment/configuration protocol is characterized independently.
Configuration backup, token rotation, fail-static behavior, gateway version
capabilities, and unsupported-policy handling are first-class parity entries.
