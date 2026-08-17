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

**Implemented: pass-through.** A WSDL is imported through `format: "wsdl"` or
`"wsdl-link"` on the API itself, not through a schema sub-resource, because that
is where Azure puts it; following the same shape is what keeps an import script
portable. The import derives one APIM operation per WSDL operation and stamps
`apiType: soap`, which is what puts the API on this path.

Every SOAP operation is a POST to the same URL, so operations are not chosen by
path. The gateway resolves them by SOAPAction first, then by the local name of
the first element inside the envelope Body. The fallback is not a nicety: SOAP
1.2 carries the action as a content-type parameter rather than a header, and
WS-I Basic Profile permits an empty SOAPAction, so an action-only gateway would
reject perfectly valid callers.

Only requests whose content type is `text/xml`, `application/soap+xml` or
`application/xml` take this path. A SOAP API's WSDL is fetched with a plain GET,
and answering that with a fault would be nonsense.

The envelope is forwarded **byte for byte**. Re-serialising the parsed document
would change whitespace, prefixes and attribute order, and a WS-Security signed
envelope would stop verifying.

An operation the WSDL does not define is refused at the gateway as a SOAP
**fault**, not a bare HTTP error, because a fault is what a client's stack
decodes into an exception; an HTTP error surfaces as a transport failure
instead, and the two are not interchangeable to anyone debugging. The fault is
shaped for the caller's version: SOAP 1.1 uses `faultcode`/`faultstring`, SOAP
1.2 restructured them into `Code`/`Value` and `Reason`/`Text`, so answering a
1.2 caller with a 1.1 body produces something their library cannot decode. The
message is XML-escaped, since it carries a caller-supplied operation name and an
unescaped `<` would turn a clear refusal into a parse error.

**Pending.** SOAP-to-REST transformation, serving the WSDL at `?wsdl`,
`wsdlSelector` service and endpoint filtering, and XSD-level request validation.

### GraphQL

Support pass-through and synthetic GraphQL APIs, schema validation, operation
limits, field resolver policy scopes, resolver backends, variables, fragments,
introspection behavior, and GraphQL-specific errors.

**Implemented: pass-through.** An API is GraphQL when `properties.apiType` is
`graphql` *and* it carries a schema resource with content type
`application/vnd.ms-azure-apim.graphql.schema`. Both signals are required: an
apiType with no schema describes nothing servable, and a schema on a REST API is
a document the gateway must not act on. A GraphQL API with no schema **yet** is
not an error, because ARM creates the API and its schema as separate resources,
so every import passes through that state.

Requests arrive as a JSON POST, an `application/graphql` POST, or a GET with
`?query=`. A GET is re-encoded as a JSON POST when forwarded, since GraphQL
backends accept POST; a POST body is replayed byte for byte, so members the
gateway has no business editing (`extensions`, where Apollo puts persisted-query
hashes) survive the hop.

Operations are validated against the schema **at the gateway**, so the backend
never sees a request it would have to reject and the caller gets the same error
whichever backend is behind it. A request error is a 4xx carrying
`{"errors":[...]}`, which is the GraphQL-over-HTTP pairing for "execution never
began"; the 200-with-errors shape means execution ran and some fields failed,
and returning it for a malformed request would tell a client its query was
accepted.

Introspection is answered from the stored schema and never forwarded, so an API
stays discoverable through the gateway even when its backend has introspection
disabled. Two details a client depends on: the response is projected to exactly
the fields selected, and types are listed in schema-declaration order, because
every tool that prints a schema back from introspection reproduces that order.
The gateway advertises only directives it honours, so the parser's own
`@defer` is filtered out rather than promising incremental delivery.

**Synthetic GraphQL** has no backend at all: each field is produced by a
resolver. A resolver is an ARM resource at `/apis/{id}/resolvers/{name}` whose
`path` is the schema coordinate it binds (`Query/orders`, `Order/customer`), and
whose policy at `.../resolvers/{name}/policies/policy` is an
`<http-data-source>` rather than a `<policies>` document. The coordinate is
checked against the schema on import, because a resolver bound to a field the
schema does not define can never run, and a field that is silently always null
is far harder to diagnose than a rejected import.

Inside a resolver, `context.GraphQL.Arguments` holds the field's arguments with
variables already substituted and schema defaults applied, and
`context.GraphQL.Parent` holds the object the field is being resolved on, null
at the root. Both are bound only while a resolver runs; `context.GraphQL` is
null everywhere else, so an inbound policy cannot read an empty argument set and
mistake it for "the caller passed nothing". Each field gets its own evaluation
state, so one field's arguments can never appear in another field's request.

A field with no resolver is served from its parent's payload, which is how a
single resolver returning a whole object satisfies an entire subtree without one
HTTP call per leaf. A failing resolver follows GraphQL's partial-failure
contract: that field becomes null and gains an entry in `errors` carrying its
path, the response is still 200 because execution ran, and every sibling still
resolves.

**Pending.** Resolver `<http-response>` mapping is refused rather than ignored,
since dropping it would return the backend's raw shape while the author believes
it was transformed. `validate-graphql-request` depth and size limits, and the
Azure SQL and Cosmos DB data sources, are not implemented.

### WebSocket and SSE

Support upgrade routing, long-lived connections, handshake policies, connection
limits, cancellation, and streaming telemetry without buffering event streams.

### gRPC

Support pass-through where the selected gateway/tier permits it, protobuf
imports, HTTP/2 requirements, metadata forwarding, status/trailers, deadlines,
streaming modes, and documented transcoding if exposed publicly.

**Implemented: pass-through.** An API is gRPC when `properties.apiType` is
`grpc` *and* it carries a schema resource with content type
`application/vnd.ms-azure-apim.grpc.schema`. Only requests whose content type
begins `application/grpc` take the gRPC path, so an ordinary HTTP probe to the
same API is not framed as a gRPC response.

Calls route by their `/package.Service/Method` path. A method the schema does
not define is refused at the gateway with `UNIMPLEMENTED` and never reaches the
backend, which is the same bargain the GraphQL schema makes: the caller gets one
answer regardless of which backend is behind the API.

**HTTP/2 is not optional, and it was not previously enabled.** gRPC is defined
over HTTP/2 and puts the call status in TRAILERS, which an HTTP/1.1 response
cannot carry. Two changes were needed:

- **Inbound.** The TLS listener now advertises `h2` in ALPN, and the handler is
  wrapped in `h2c` so cleartext callers can use HTTP/2 as well. Without ALPN the
  handshake settled on HTTP/1.1 no matter what the client offered.
- **Outbound.** Go's default transport negotiates HTTP/2 only over TLS, so a
  cleartext gRPC backend received an HTTP/1.1 request and replied with HTTP/2
  frames the transport reported as a malformed response. gRPC forwarding uses an
  explicit HTTP/2 transport, with the h2c prior-knowledge handshake for `http://`
  backends. A transport the caller already configured keeps its TLS settings, so
  a backend requiring mutual TLS still works.

A call arriving over HTTP/1.1 is refused with a status rather than proxied,
because its result could never be delivered. Bodies are streamed rather than
buffered and flushed per chunk, so a server-streaming call delivers messages as
they arrive. Trailers are announced before the body is written, since there is
no way to add one afterwards, and `grpc-status` is announced even when the
backend omits it so a client is never left waiting on a status that was dropped.

**Pending.** Client-streaming and bidirectional streaming are unproven; the
witness covers unary and server streaming. Deadline propagation, gRPC-Web
transcoding, and tier constraints are not implemented.

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

## API type is read under two names

Azure's REST contract carries an API's type as `properties.type`; Microsoft's
own SDKs expose it client-side as `apiType` and serialize it to `type`. Raw ARM
callers, and this emulator's WSDL import, have historically written `apiType`.

`apiTypeOf` in `internal/gateway/mcp.go` reads `type` first and falls back to
`apiType`, and every protocol family goes through it. Reading only `apiType` --
which all of them did until an MCP witness first created a typed API through the
official SDK -- means an API created by that SDK is stored, echoed back on GET
looking perfectly correct, and then served as though it had no type at all. The
round-trip is lossless and only the behaviour is missing, so there is no local
symptom to investigate.

