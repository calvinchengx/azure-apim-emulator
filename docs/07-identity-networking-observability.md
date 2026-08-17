# 07 - Identity, networking, and observability

## Identity domains

APIM uses identity in several distinct places:

- ARM callers managing the service
- service and workspace managed identities calling backends and Azure services
- API callers validated by gateway policies
- subscription holders and developer portal users
- self-hosted gateways authenticating to configuration endpoints
- OAuth/OIDC authorization servers and credential managers

### Credential manager (authorizationProviders)

**The direction is the thing to keep straight.** This is OUTBOUND
authentication: APIM acts as the OAuth2 **client** and token vault for calls to
a backend. It is not authenticating the caller of your API (that is
`validate-jwt`), and it is not the developer portal's sign-in (that is
`identityProviders` and `authorizationServers`). The names sit one word apart
and the resources are unrelated.

An `authorizationProvider` holds the OAuth2 app configuration for a SaaS. Under
it, each `authorization` is one stored credential, in one of two grants:

- **clientCredentials** is service-to-service and usable the moment it is
  configured.
- **authorizationCode** needs a person. It is created in `Error` status, and
  becomes `Connected` only after `getLoginLinks` hands back a URL someone
  visits and `confirmConsentCode` redeems what they came back with. The
  emulator never auto-consents: a flow that completed without anyone approving
  it would look finished here and stall in Azure.

`accessPolicies` name the principals permitted to use a credential. Deleting a
provider cascades, because withdrawing an integration must revoke what it
issued rather than orphan it.

A policy reaches the credential through `get-authorization-context`, which puts
it in a variable read as
`@(((Authorization)context.Variables["auth"]).AccessToken)`. By default a
credential that cannot be resolved stops the pipeline; `ignore-error="true"` is
the documented way to let the request proceed without it.

**What never leaves the emulator.** The client secret is not echoed by the
management plane, and the refresh token is not bound into the expression
context. A policy sees the access token and nothing else, because an expression
able to export a refresh token would export a long-lived grant, which is the
one thing a credential manager exists to prevent. The scope a policy may reach
comes from the route the request landed on, not from anything the policy names.

**Pending.** Managed-identity and JWT `identity-type`, per-caller access-policy
enforcement at request time, and the Azure-hosted providers (GitHub, Google,
Dropbox, MS Graph). Those last need registered OAuth apps and, for the
authorization-code grant, a human at a browser, so they belong in an opt-in
differential suite rather than CI.


Each is modeled separately even when all tokens come from `entra-emulator`.

## Entra integration

Use real OIDC discovery and JWKS validation against `entra-emulator`. Support
system- and user-assigned managed identities, ARM audience tokens, gateway
`validate-jwt` and `validate-azure-ad-token`, portal Entra signin, OAuth test
console flows, authorization providers, and managed-identity backend calls.

Production Azure authorities remain configurable for opt-in differential tests.
The emulator never accepts an unsigned or unverified token merely for convenience.

## Key Vault integration

Named values and certificates can reference `azure-keyvault-emulator` through
the same managed-identity and HTTPS flow used by Azure:

- versioned and versionless secret references resolved on PUT/PATCH/`refreshSecret`
- classified `lastStatus` codes and last-known-good values when retrieval fails
- `isKeyVaultRefreshFailed` collection projection from last status
- background refresh on the controllable clock
- identity selection and permission failures
- certificate rotation and hostname/backend TLS activation

Live retrieval of the secret payload is implemented. Challenge-based
managed-identity token acquisition against `entra-emulator` remains assigned
to the companion-auth slice.

Static local named values remain available without a companion emulator.

## Networking model

Networking has two layers:

1. ARM-visible topology and provisioning state.
2. Local reachability rules enforced by listeners and outbound transports.

Model public network access, inbound private endpoints, classic VNet modes, v2
outbound integration/injection, workspace gateway constraints, custom domains,
host validation, IP addresses, zones, regions, proxy settings, DNS overrides,
backend reachability, and service dependencies.

Local network profiles map Azure concepts to loopback addresses, container
networks, explicit CIDRs, and allow/deny rules. They are deterministic test
controls, not claims of network isolation.

## TLS and certificates

- Generate a local CA/leaf set covering default local wildcard hosts.
- Allow user-provided certificates and trust roots.
- Model gateway, portal, management, SCM, and configuration hostnames.
- Support SNI selection, wildcard precedence, client-certificate negotiation,
  backend client certificates, custom CAs, expiry, rotation, and chain errors.
- Integrate certificate state changes through atomic runtime snapshots.

## Observability pipeline

Every request emits one internal event stream from which adapters derive:

- gateway traces and `LastError`
- resource logs and diagnostic logs
- platform and custom metrics
- built-in analytics and portal reports
- Application Insights request/dependency/exception/trace telemetry
- Azure Monitor diagnostic-setting exports
- OpenTelemetry traces, metrics, and logs where publicly supported
- self-hosted gateway heartbeat and configuration status

Correlation IDs, sampling, body/header logging limits, masking, logger scopes,
workspace federation, retention, and timestamp behavior are contract-tested.

## Local sinks

The default sink is SQLite plus structured logs exposed through the operator
portal. Optional adapters export to OTLP, an Application Insights-compatible
collector, HTTP/Event Hub-style fixtures, and user-provided endpoints. Azure
credentials or network calls are never required for the standard test suite.

The current slice implements lossless logger and service/API diagnostic ARM
documents, logger credential isolation and reference projection, logger resource
reference protection, recursive diagnostic PATCH with indexed null/default
synchronization, revision cloning, fixed sampling, `allErrors` override behavior,
and local request events containing correlation, status, duration, method, path,
and optional client IP. Opt-in diagnostic header capture is persisted with
case-preserving multi-value headers and masks authorization, cookie, subscription
key, and API-key headers. Body limits, external adapters, analytics, and metrics
remain tracked parity work. Explicit `publicNetworkAccess=Disabled` now blocks
local gateway ingress with an APIM-shaped 403; private endpoint reachability and
custom-domain certificate lifecycle remain differential work.

## Security posture

This is local development software, not a security boundary. Even so:

- bind to loopback by default
- require explicit opt-in for remote listening
- redact secrets and subscription keys from logs and portal views
- bound body capture, parser depth, XML expansion, import fetches, and expression execution
- warn on policies capable of outbound requests or code-like evaluation
- isolate optional native/runtime helpers
- include fuzzing for HTTP, XML, C# expressions, GraphQL, WSDL, and imports
