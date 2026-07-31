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

API version sets retain canonical documents alongside indexed versioning
fields. PUT replacement and recursive PATCH preserve unknown metadata, support
explicit clearing of optional header/query/description fields, and project the
authoritative scheme fields on GET and list responses. The official Go SDK
witness verifies description persistence after update.

Tags retain canonical documents transactionally with their indexed display
name. Unknown metadata survives PUT, recursive PATCH, direct GET/list, and the
API, operation, and product association projections. The official Go SDK
witness covers the complete modeled tag lifecycle and every association type.

API schemas retain their canonical ARM envelopes separately from the nested
schema definition in `properties.document`. Unknown root and property metadata
survives PUT, GET, list, OpenAPI import, and API revision cloning while resource
identity, content type, and schema content remain authoritative. Companion
writes and imports are transactional, legacy rows receive an empty envelope,
and the official Go SDK witness verifies the typed components document.

Policy fragments retain canonical documents with PUT replacement semantics.
Unknown metadata survives GET/list while validated XML, description, requested
wire format, and provisioning state remain authoritative. The JavaScript SDK
witness covers create/get/list/reference/ETag/delete behavior, and document
writes are transactional with compiler-visible fragment state.

API releases retain canonical documents in the same transaction that records
the release and promotes its target revision. PUT replaces extension data,
PATCH recursively merges it with explicit note clearing, and resolved target
IDs plus server-managed creation/update timestamps remain authoritative. The
official Go SDK witness verifies update persistence with a subsequent GET.

Users retain canonical documents transactionally across direct, list, and
group-membership projections. PUT replaces extension data and PATCH recursively
merges it with nullable note/identity clearing. Password and primary/secondary
key fields are removed at both the handler and store boundaries and again from
wire projections; generated credentials remain only in secret columns used by
SSO and shared-access-token operations. The official Go SDK witness covers the
modeled lifecycle and verifies updated notes and identities with a subsequent
GET.

Subscriptions retain canonical documents transactionally while primary and
secondary gateway keys remain isolated in secret columns. PUT replacement and
recursive PATCH preserve extension data across management and gateway-runtime
scans; handler, store, and normal wire projections strip key fields. The
explicit `listSecrets` action remains the only management projection that
returns keys, and regeneration updates those indexed keys without altering the
canonical document. Official Go SDK evidence covers normal GET, secret listing,
rotation, and use of the rotated key at the gateway.

Named values retain canonical documents transactionally while their operational
value remains isolated in its indexed column. Handler, store, and ordinary wire
projections strip `value`; `listValue` is the explicit disclosure operation.
PUT replacement and recursive PATCH preserve extension data, tags, secret state,
and non-secret Key Vault reference metadata with explicit null clearing. The
official Go SDK witness verifies redacted GET, updated `listValue`, ETags, and
gateway policy substitution.

Backends retain canonical documents atomically in their primary resource row.
PUT replacement and recursive PATCH preserve credential, TLS, proxy, circuit
breaker, and extension structures consumed by gateway compilation; indexed
title/description/URL/protocol/resource fields remain authoritative and honor
explicit nulls. Legacy rows receive a canonical fallback before PATCH, malformed
documents fail rather than being silently discarded, and the official Go SDK
witness verifies credential IDs survive an update and subsequent GET.

Certificates retain canonical documents transactionally while inline PFX bytes
and passwords remain isolated in secret columns. Handler, store, and wire
boundaries strip `data`/`password`; client-supplied subject, thumbprint, and
expiration fields are discarded and projected only from parsed PFX state. PUT
replacement preserves extension and non-secret Key Vault reference metadata,
and refresh responses use the same redacted projection. Official Go SDK evidence
covers PFX create/get/list and Key Vault create/refresh/get workflows.

Loggers retain canonical documents while operational credentials remain in a
separate indexed field. Handler and store boundaries strip duplicate credential
fields from the canonical document, and ordinary create, GET, and list responses
replace raw values with deterministic `{{Logger-Credentials-...}}` references;
existing named-value references remain unchanged. The official Go SDK witness
verifies that the submitted instrumentation key is not returned. Exact Azure
reference naming remains assigned to the live differential fixture.

Service and API diagnostics retain canonical documents atomically with indexed
logger, sampling, client-IP, always-log, and verbosity fields. PATCH recursively
merges complex frontend/backend, correlation, and operation-name settings while
explicit nulls reset indexed optional fields to their stable defaults. Resource
identity is stripped before persistence and projected authoritatively at each
scope. The official Go SDK witness verifies correlation protocol, operation-name
format, pipeline settings, sampling, revision cloning, and ETags.

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
return `400 InvalidHeaderValue` for malformed entity tags. The stable
`2024-05-01` operation audit is enforced for implemented routes: entity PATCH
and DELETE operations return `400 MissingRequiredHeader` when `If-Match` is
absent, PUT keeps it optional, and association deletes do not acquire an entity
precondition. Exact live-Azure missing-header wording remains differential work.

Current collection routes are normalized centrally to the APIM paged shape.
They validate int32 `$top` (`>= 1`) and `$skip` (`>= 0`), preserve stable store
ordering, return the filtered total in `count`, and emit an absolute `nextLink`
that retains the original query. `$filter` supports parentheses, `and`/`or`,
`eq`, `ne`, `gt`, `ge`, `lt`, `le`, boolean/number/null/string literals,
doubled-quote string escaping, and `contains`, `startswith`, `endswith`, and
`substringof`. Undocumented OData options are rejected on collection operations.
The stable `2024-05-01` exception is implemented for policy fragments:
`$orderby=name` accepts `asc` or `desc`, applies stable ordering before paging,
and is exercised through the official JavaScript SDK. The generated operation
inventory now constrains scalar filter fields, comparison operators, and string
functions for every implemented collection shape. Named-value `tags/any(...)`
and `tags/all(...)` predicates support scalar lambda comparisons and string
functions, including correct empty-array behavior, and are exercised through
the official JavaScript SDK. Named selectors such as
`expandGroups`, `tags`, and `scope` also remain to be implemented.

The stable selector matrix is validated centrally: `tags` is accepted on API,
operation, and product collections, `scope` on tag collections, and the
documented expansion/Key Vault refresh booleans only on their declared
operations. Product `tags` performs association-backed filtering; expansion
projection now includes API version sets, API/operation tags, and product/user
groups. Tag `scope` and Key Vault refresh-failure projection remain pending.

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
