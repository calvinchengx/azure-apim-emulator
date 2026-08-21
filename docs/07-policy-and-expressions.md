# 07 - Policy and expression engine

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
operation, and resolver scopes. ARM GET/PUT now persist service, API,
operation, and product policy documents; product subscription composition
uses the matching operation plan rather than the first map entry.
Compilation must reproduce:

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

All policies in Microsoft's live policy reference are classified in the checked-in
inventory (`docs/generated/policy-inventory.json`) with status, the sections the
policy is valid in, gateway support, and known expression-bearing fields.
`scripts/check_policy_inventory.py --strict` fails CI when any stable name is
`unclassified` or when compiler recognition drifts from `implemented`/`partial`.
XML schema, remaining expression-bearing fields, dependencies, and roadmap owner
columns remain open.

The `sections` field is DERIVED, not written. Every policy reference page carries
a `Policy sections:` line naming where that policy may appear, and Azure rejects a
document that puts one anywhere else. The hand-written field was wrong for all
four limit policies -- the only four anyone had checked -- so
`scripts/derive_policy_sections.py` reads the line out of the vendored pages and
writes both the ledger's field and `internal/policy/policy_sections.json`, which
the compiler embeds. A policy in a section its page does not name is REJECTED at
compile, in every mode: the document is one Azure answers 400 at deploy, so it is
refused at upload here too rather than stored and failed per request. `<base/>` is
valid in every section, and the GraphQL resolver policies are configured in a
resolver rather than a section, so neither is ever rejected for where it appears.

That fault is reported apart from an unsupported one, because the two ask
opposite things of the reader. `policy.ErrWrongSection` says the document is
invalid and needs editing; `policy.ErrUnsupported` says the document is fine and
this emulator does not run that policy yet.

Gateway support is still hand-written, and unverified in the same way the sections
were.

Implementation tracks include:

- routing and forwarding
- request/response mutation and transformation
- control flow, variables, fragments, and return behavior
- JWT and Entra validation (audience/issuer/required-claim and client-application-id payload checks; `openid-config` and inline `token-value` remain unsupported), certificates, managed identity, Basic, Digest, and authorization context
- subscription, IP filtering, CORS, validation, and content safety
- rate limits, quotas (including nested `api`/`operation` children and quota `bandwidth`), concurrency, first-class sequential `wait` (`for=all|any|self` over `send-request`/`cache-lookup-value`/`choose`), cache, and external cache
- standalone `set-status`, `mock-response` including example bodies (schema bodies remain unsupported), compile-time `include-fragment` expansion, Adobe `cross-domain` XML, and gateway/backend `redirect-content-urls`
- retry, send-request, fire-and-forget one-way request, configured-validator `validate-azure-ad-token`, log/event, and metrics
- backend pools, load balancing, circuit breakers, Service Fabric, Dapr, and Service Bus
- GraphQL resolver and validation policies
- SOAP/XML/JSON/Liquid transformations
- AI/model routing, token limits, semantic cache, safety, and prompt policies

Unsupported policy elements are never skipped silently. The default mode accepts
and stores Azure-valid XML, marks the compiled node unsupported, and produces an
APIM-shaped runtime failure only when execution reaches it. Strict mode rejects
such a policy during upload.

Strict mode governs what this emulator RUNS, so it does not reach XML that is not
Azure-valid in the first place. A policy in a section its page does not document
is rejected at upload in both modes.

A document the store already holds is treated differently again. Tightening the
compiler can turn a document an earlier build accepted into one this build
rejects, and startup does not refuse to serve over it: the document is activated
as an invalid plan, reported on stderr, and reports its compile error on every
request that reaches it, so the ARM API stays available to replace it. Activation
after a write still rejects a document that write introduced.

## Expression syntax

APIM expressions use C# 7-style forms:

- `@(expression)` for a single expression
- `@{ statements; return value; }` for a multi-statement block

The lexer tokenizes `@(expression)` and `@{ statements }` wrappers, C# literals
(including APIM-policy single-quoted strings), identifiers, comments, and the
phase-1 operator set. The evaluator runs context-free expressions and binds
`context` for `choose`, mutation policies, and retry conditions: request
method/URL/headers/IP, response status/headers, last-error message, policy
variables, member access, indexing, and calls (`ToString`, `Length`,
`GetValueOrDefault`, `Get`, `ContainsKey`). `Url.Port`, `LastError.Message`,
and request/response `Body.As<string>()` (with body capture/replay) are bound
for `choose`/on-error through `stateEnv` the same way retry already
binds last-error. `context.Api` (`Id`/`Name`/`Path`), `Operation`
(`Id`/`Name`/`Method`/`UrlTemplate`), `Product`/`Subscription`/`User`
(`Id`/`Name`), and `Deployment` (`ServiceName`/`Region`) are bound from the
activated snapshot; missing scopes are null. Other identity members,
`AsJObject`/`AsJson` remain unknown. Statement blocks may declare
expression-scoped `var` locals, `if`/`else` with a `return` on every path,
and must `return`; `new`/loops stay rejected. Statement blocks and
runtime evaluation of `set-header`, `set-query-parameter`, `set-variable`,
`set-body`, `set-method`, `return-response` children, `send-request` /
`send-one-way-request` url/method/header/body/mode/timeout, `set-backend-service`,
`rewrite-uri`, `find-and-replace` from/to, value-cache key/value fields,
`cache-lookup-value` variable-name, CORS allowed-origins/allowed-methods/
allowed-headers/expose-headers/max-age,
`check-header` name/values/error message, `limit-concurrency` key,
rate-limit/quota `counter-key`, authentication-basic /
managed-identity / oauth2 / certificate attributes, `set-status`
code/reason, `mock-response` status-code/content-type, `json-to-xml`
root-element-name, `jsonp` callback-parameter-name, and
`validate-azure-ad-token` tenant-id/header-name/query-parameter-name/
failed-validation-httpcode/failed-validation-error-message are implemented;
other statements, remaining context members, and other expression-bearing
fields remain open. The binder publishes a checked-in type/member allowlist
(`docs/generated/expression-members.json`); unknown members still fail at
runtime, and documented-but-unbound names stay `planned` until implemented.

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

