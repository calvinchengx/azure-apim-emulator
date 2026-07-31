# 03 - Management plane and resource model

## Contract source

The canonical contract is the public `Microsoft.ApiManagement` specification in
`Azure/azure-rest-api-specs`. Stable `2024-05-01` is implemented first, while
the service accepts older versions required by supported SDKs. Preview versions
live behind explicit compatibility flags.

## ARM routing

Support resource IDs under:

```text
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/
  providers/Microsoft.ApiManagement/service/{serviceName}/...
```

Subscription IDs and resource groups are logical namespaces. The emulator does
not require a separate Resource Manager emulator, but implements the APIM
provider paths, provider metadata needed by clients, standard ARM headers, and
APIM operations reached by official SDKs.

## Service lifecycle decision

- Seed a configurable default service at startup for immediate local use.
- `PUT` creates or updates services through a deterministic asynchronous operation.
- `GET`, `PATCH`, `DELETE`, list, check-name, locations, SKUs, and deleted-service workflows follow their documented contracts.
- LROs honor `Azure-AsyncOperation`, `Location`, `Retry-After`, terminal states, error bodies, cancellation where documented, and the controllable clock.
- Infrastructure-heavy properties are validated and persisted; their local behavioral effect is owned by networking, tier, or gateway modules.
- A missing service is never created by `GET`. Optional lazy creation occurs only on a child write when explicitly enabled for developer convenience.

## Resource coverage

The canonical model must cover every stable APIM resource family, including:

- services, locations, regions, SKUs, certificates, hostname configurations, identities, private endpoints, and network status
- APIs, revisions, releases, versions, version sets, operations, policies, schemas, tags, and documentation
- products, groups, users, subscriptions, client applications, and product/API/group links
- named values, backends, backend pools, caches, loggers, diagnostics, and policy fragments
- OAuth authorization servers, OpenID Connect providers, identity providers, authorization providers, authorizations, and access policies
- gateways, gateway APIs, hostname bindings, certificate authorities, configuration connections, and workspace gateways
- workspaces and all workspace-scoped child resources
- portal content types/items, revisions, configuration, delegation, sign-in, and sign-up settings
- notifications, email templates, issues, comments, attachments, reports, tenant access, and miscellaneous documented tools

The parity ledger is generated from the specification operation inventory so a
new upstream operation appears as a failing audit rather than an unnoticed gap.

## Canonical model and API projections

Store one canonical resource model and implement explicit version projections:

```text
wire request -> version decoder -> canonical command -> domain/store
domain result -> version encoder -> wire response
```

Unknown JSON properties are preserved where ARM round-trips them. Read-only
properties supplied by clients are ignored or rejected exactly as Azure does.
Null, omitted, and empty values remain distinct where the specification or
observed behavior distinguishes them.

API resources now retain their canonical ARM document in a migration-safe
companion table. PUT replaces that document, PATCH recursively merges it with
explicit `null` deletion, imports strip input-only `format`/`value`, and cloned
revisions inherit the source document before applying clone overrides. GET and
list responses project authoritative relational fields over the retained
document. The official Go SDK witness round-trips and patches `description`, a
field intentionally outside the gateway's minimal routing model. This pattern
is being extended to each remaining resource family.

API operations use the same companion-document model. Direct PUT replaces,
PATCH recursively merges, API import creates document rows transactionally, and
revision cloning copies them with the operation. Request/response contracts,
template parameters, descriptions, and other non-routing properties therefore
survive GET and list projections while method and URL template remain indexed
for gateway compilation.

Products also retain canonical documents, including description, terms,
subscription requirements, and subscription limits. New products default to
the stable contract's `notPublished` state. Indexed display/state/approval
fields remain authoritative while PUT/PATCH preserve the complete SDK-visible
contract.

Groups retain canonical documents across direct GET/list and product/user
association projections. PUT replaces unknown metadata, PATCH recursively
merges it with explicit nullable-field clearing, and the indexed identity,
display, type, external-directory, and built-in fields remain authoritative.
Companion-document writes are transactional with the group row.

## Common ARM semantics

Implement centrally and test across resources:

- case rules for resource groups, service names, IDs, and child names
- resource ID normalization without corrupting user-visible IDs
- `ETag`, `If-Match`, `If-None-Match`, wildcard preconditions, and conflicts
- OData `$filter`, `$top`, `$skip`, paging, stable ordering, `nextLink`, and count
- PUT replacement versus merge behavior and PATCH field presence
- standard ARM error envelopes, nested details, target fields, and request IDs
- LRO polling, deletion, retry headers, and idempotency
- import/export content formats, linked content retrieval, size limits, and validation
- secret-list operations that intentionally differ from ordinary GET

Conditional entity-tag handling is implemented centrally for every current
resource route. `GET` and `HEAD` honor strong `If-Match` and weak
`If-None-Match` comparisons, including comma-separated validators and `*`.
`PUT`, `PATCH`, and `DELETE` evaluate their preconditions while management
mutations are serialized, return `412 PreconditionFailed` on stale state, and
return `400 InvalidHeaderValue` for malformed entity tags. Endpoint-specific
rules that require `If-Match` even when the header is omitted remain part of
the generated operation-contract audit.

Current collection routes are normalized centrally to the APIM paged shape.
They validate int32 `$top` (`>= 1`) and `$skip` (`>= 0`), preserve stable store
ordering, return the filtered total in `count`, and emit an absolute `nextLink`
that retains the original query. `$filter` supports parentheses, `and`/`or`,
`eq`, `ne`, `gt`, `ge`, `lt`, `le`, boolean/number/null/string literals,
doubled-quote string escaping, and `contains`, `startswith`, `endswith`, and
`substringof`. The generated operation inventory will further constrain fields,
operators, and functions to each endpoint's documented matrix.

All current ARM failures include the canonical JSON error envelope and mirror
its code in `x-ms-error-code`, alongside the per-request request and correlation
IDs. Endpoint-specific nested `details` and `additionalInfo` payloads remain in
the generated error-contract audit.

## API import and export

Support OpenAPI 2/3/3.1 as documented, WSDL/SOAP, GraphQL schema, WADL where
still accepted, OData metadata, and protobuf/gRPC definitions. Import is a
compiler front end that produces APIs, operations, schemas, representations,
parameters, and protocol metadata transactionally. Original documents are
retained for matching export modes and forensic comparison.

Linked imports use a controlled HTTP fetcher with timeouts, size limits,
redirect policy, TLS configuration, and emulator SSRF warnings. Tests use local
fixture servers.

The current P1 implementation accepts OpenAPI 2.0 and 3.x JSON/YAML inline or
by HTTP(S) link, enforces a 4 MiB retrieval bound, and transactionally replaces
the API, generated operations, imported component schema, and retained source.
Exports regenerate canonical OpenAPI 3 YAML/JSON or Swagger 2 JSON and return a
signed link that expires after five minutes on the controllable clock. Deeper
OpenAPI semantic validation, imported representations and policies, redirect
and SSRF controls, and the non-OpenAPI formats remain tracked parity work.

## SDK endpoint and authentication

Management clients point to `https://management.azure.localhost:{port}` while
requesting the normal ARM audience. `entra-emulator` issues the token and the
management plane validates signature, issuer, audience, lifetime, and principal.

Default local authorization grants a valid ARM token full APIM access. Optional
RBAC mode evaluates built-in/custom role assignments at subscription, resource
group, service, and workspace scopes, including deny behavior observable by SDKs.
