# 07 - Identity, networking, and observability

## Identity domains

APIM uses identity in several distinct places:

- ARM callers managing the service
- service and workspace managed identities calling backends and Azure services
- API callers validated by gateway policies
- subscription holders and developer portal users
- self-hosted gateways authenticating to configuration endpoints
- OAuth/OIDC authorization servers and credential managers

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

- versioned and versionless secret references
- background refresh on the controllable clock
- last-known-good behavior and observable resolution errors
- identity selection and permission failures
- certificate rotation and hostname/backend TLS activation

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

## Security posture

This is local development software, not a security boundary. Even so:

- bind to loopback by default
- require explicit opt-in for remote listening
- redact secrets and subscription keys from logs and portal views
- bound body capture, parser depth, XML expansion, import fetches, and expression execution
- warn on policies capable of outbound requests or code-like evaluation
- isolate optional native/runtime helpers
- include fuzzing for HTTP, XML, C# expressions, GraphQL, WSDL, and imports

