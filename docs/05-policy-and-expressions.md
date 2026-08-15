# 05 - Policy and expression engine

## Source form

APIM policy documents are XML with four ordered sections:

```xml
<policies>
  <inbound><base /></inbound>
  <backend><base /><forward-request /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
```

The emulator stores the submitted representation and compiles a semantic tree.
Formatting preservation, `rawxml` versus `xml`, entity handling, comments,
encoding, linked documents, and management validation are compatibility tests.

## Scope and inheritance

Policies may apply at global/service, workspace governance, product, API,
operation, and resolver scopes. Compilation must reproduce:

- `<base />` insertion at its exact location
- section-specific parent selection
- product association and subscription-dependent scope
- workspace isolation and service-level governance
- API revision/release selection
- policy fragments and named-value expansion
- restrictions by tier and gateway type

The compiler emits source maps from executable nodes back to resource ID, XML
line/column, scope, section, and policy ID for `LastError` and tracing.

## Execution model

```go
type Policy interface {
    Execute(*GatewayContext) PolicyResult
}

type PolicyResult struct {
    Flow  FlowAction // continue, respond, retry, jump-to-error
    Error *PolicyError
}
```

`GatewayContext` exposes request, response, deployment, API, operation, product,
subscription, user, variables, trace, and last-error objects with APIM-compatible
mutability and lifetime. Policies never receive the storage layer directly.

## Policy inventory

All policies in Microsoft's live policy reference are imported into a generated
inventory containing XML schema, section/scope applicability, gateway support,
expression-bearing fields, dependencies, roadmap owner, and parity state.

Implementation tracks include:

- routing and forwarding
- request/response mutation and transformation
- control flow, variables, fragments, and return behavior
- JWT, Entra, certificates, managed identity, Basic, Digest, and authorization context
- subscription, IP filtering, CORS, validation, and content safety
- rate limits, quotas, concurrency, cache, and external cache
- standalone `set-status`, empty-body `mock-response`, compile-time `include-fragment` expansion, Adobe `cross-domain` XML, and gateway/backend `redirect-content-urls`
- retry, send-request, fire-and-forget one-way request, configured-validator `validate-azure-ad-token`, log/event, and metrics
- backend pools, load balancing, circuit breakers, Service Fabric, Dapr, and Service Bus
- GraphQL resolver and validation policies
- SOAP/XML/JSON/Liquid transformations
- AI/model routing, token limits, semantic cache, safety, and prompt policies

Unsupported policy elements are never skipped silently. The default mode accepts
and stores Azure-valid XML, marks the compiled node unsupported, and produces an
APIM-shaped runtime failure only when execution reaches it. Strict mode rejects
such a policy during upload.

## Expression syntax

APIM expressions use C# 7-style forms:

- `@(expression)` for a single expression
- `@{ statements; return value; }` for a multi-statement block

The lexer tokenizes `@(expression)` and `@{ statements }` wrappers, C# literals
(including APIM-policy single-quoted strings), identifiers, comments, and the
phase-1 operator set. The evaluator runs context-free expressions and binds
`context` for `choose` conditions: request method/URL/headers/IP, policy
variables, member access, indexing, and calls (`ToString`, `Length`,
`GetValueOrDefault`, `ContainsKey`). Statement blocks, the remaining context
members, mutation-policy evaluation, and the public allowlist remain open.

The pure-Go engine has these stages:

```text
source -> lexer -> C# subset parser -> AST -> APIM binder/type checker
       -> allowlist validator -> compiled expression -> evaluator
```

Parsing may use a generated ANTLR C# grammar initially, but the bound AST and
runtime are project-owned so grammar breadth cannot accidentally enable
unsupported semantics.

## Expression compatibility phases

1. Literals, interpolation boundaries, arithmetic, comparisons, boolean logic,
   null, conditional expressions, casts, indexing, member access, and calls.
2. `context` request/response/variables/deployment/API/operation/product/subscription/user members.
3. Documented string, numeric, collection, URI, encoding, hash, HMAC, GUID,
   date/time, regex, JSON, XML, and JWT types/members.
4. Lambdas and allowed LINQ operations.
5. Multi-statement blocks, local variables, branches, loops where allowed,
   exception behavior, and all documented language constructs.

The compatibility table is generated at the type/member level from the public
allowlist and linked to tests. Similar-looking Go behavior is not accepted when
.NET semantics differ; edge cases receive explicit compatibility implementations.

## Optional exact engine

Keep an engine interface that can call a sandboxed external .NET worker in the
future. It is optional, lazily started, separately memory-limited, denied network
and filesystem access, time-bounded, and never loaded into the Go process. The
pure-Go engine remains the required route to default full parity.

## Compilation and caching

Cache expressions by source, compatibility profile, named-value dependencies,
and type-model version. Cache policy plans by resource ETag and parent scope
revision. Invalidations occur during snapshot compilation, never in the request
hot path.

