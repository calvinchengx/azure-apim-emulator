# azure-apim-emulator

[![version](https://img.shields.io/github/v/release/calvinchengx/azure-apim-emulator?label=version)](https://github.com/calvinchengx/azure-apim-emulator/releases/latest)
[![CI](https://github.com/calvinchengx/azure-apim-emulator/actions/workflows/ci.yml/badge.svg)](https://github.com/calvinchengx/azure-apim-emulator/actions/workflows/ci.yml)
[![Docs](https://github.com/calvinchengx/azure-apim-emulator/actions/workflows/docs-site.yml/badge.svg)](https://calvinchengx.github.io/azure-apim-emulator/)
[![CodeQL](https://github.com/calvinchengx/azure-apim-emulator/actions/workflows/codeql.yml/badge.svg)](https://github.com/calvinchengx/azure-apim-emulator/actions/workflows/codeql.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A clean-room, local emulator of the complete publicly observable Azure API
Management product. The implementation will be a low-memory Go service with
an embedded portal, real integration with `entra-emulator` and
`azure-keyvault-emulator`, and compatibility verified through unmodified
Microsoft SDKs and differential tests against Azure APIM.

## Status

**P0 implementation is underway.** The first vertical slice is working:

- Go process, pure-Go SQLite, controllable clock, local TLS, and seeded service
- ARM token validation against `entra-emulator`
- lossless service GET/PUT/PATCH/DELETE/list with deterministic LRO polling
- API, operation, product, product/API link, subscription, and API-policy writes
- XML compilation for `base`, `set-header`, `set-backend-service`,
  `rewrite-uri`, `forward-request`, and `return-response`
- immutable gateway snapshots, operation routing, subscription keys, streaming
  backend forwarding, and APIM-shaped failures
- official Go APIM SDK `v1.1.1` against API `2021-08-01`, including a real
  `azidentity.ClientSecretCredential` flow through `entra-emulator`
- official Go `v1.1.1`, JavaScript `10.0.0`, Python `5.0.0`, and .NET `1.3.1`
  workflows that configure a service, protected API, operation, and subscription,
  then call the API through the gateway

The P0 Azure differential harness is ready; a live authorized Azure run remains
before the service lifecycle can be classified as externally verified. See the
live parity ledger.

## Development

```bash
APIM_DISABLE_AUTH=true go run ./cmd/azure-apim-emulator --disable-tls
go test ./...
make test-coverage
make setup-sdks test-sdks
make test-differential
```

The default listener is `http://localhost:8445` in this development mode. ARM
requests use `management.azure.localhost`; gateway requests use
`{service}.azure-api.localhost` or plain localhost for the seeded service.
Note: 8445 is also `arm-emulator`'s port in the family compose (see
[azure-emulators](https://github.com/calvinchengx/azure-emulators)), which is
why that compose maps this service to 8446 instead. Running this dev binary
next to a containerised `arm-emulator` will collide on 8445.
`make test-coverage` enforces 100% aggregate statement coverage across the
current Go implementation. Run the full build, race, coverage, and vet suite
with `make verify`.

## Compatibility target

Full parity means every stable, publicly documented or externally observable
APIM contract is eventually implemented and tested:

- ARM management plane and official Microsoft SDK workflows
- managed, workspace, and self-hosted gateway behavior
- policy XML, policy inheritance, and APIM C# policy expressions
- developer portal authoring, publishing, identity, subscriptions, and console
- workspaces and workspace gateways
- REST, SOAP, GraphQL, WebSocket, SSE, gRPC, and MCP-facing API behavior
- products, users, groups, subscriptions, authorizations, and identity providers
- diagnostics, analytics, Azure Monitor, Application Insights, and tracing
- custom domains, certificates, networking state, private access, tiers, and SKUs
- AI gateway policies and documented external-service integrations

Azure's private infrastructure is not reproduced. Infrastructure-facing
features expose compatible resource state and locally meaningful behavior. For
example, a private endpoint changes local reachability and DNS policy without
creating an Azure virtual network.

The first stable management baseline is `2024-05-01`. Preview
`2025-09-01-preview` is tracked separately and never silently mixed into the
stable contract.

## Decisions already made

- Go, standard-library HTTP where practical, pure-Go SQLite, and one distributable binary.
- A default APIM service is pre-seeded; SDK service CRUD is also supported through deterministic LROs.
- Policies are stored as original XML and compiled into immutable Go runtime snapshots.
- The default expression engine is pure Go and grows toward the documented APIM C# surface.
- Unsupported expressions are preserved by default and fail explicitly only if executed.
- Strict mode rejects policies containing unsupported executable behavior at upload time.
- A policy in a section its reference page does not document is rejected at upload in either mode, because that document is one Azure rejects too.
- Full product parity is the roadmap target; gaps are tracked, not hidden as permanent non-goals.

## Documentation

- [Quickstart](docs/01-quickstart.md) - publish an API and call it, in a minute
- [Installation](docs/02-installation.md) - container, binary, or the Entra pair
- [Configuration](docs/04-configuration.md) - every flag and variable
- [Charter and parity definition](docs/00-charter-and-parity.md)
- [System architecture](docs/03-architecture.md)
- [Management plane and resource model](docs/05-management-plane.md)
- [Gateway and protocol runtime](docs/06-gateway-and-protocols.md)
- [Policy and expression engine](docs/07-policy-and-expressions.md)
- [Portal, workspaces, and platform features](docs/08-portal-workspaces-platform.md)
- [Identity, networking, and observability](docs/09-identity-networking-observability.md)
- [Testing and SDK matrix](docs/10-testing-and-sdk-matrix.md)
- [Implementation roadmap](docs/11-roadmap.md)
- [Risk register](docs/12-risk-register.md)
- [Clean-room grounding](docs/13-clean-room-grounding.md)
- [Live parity ledger](docs/parity.md)

## Emulator family

- [`entra-emulator`](https://github.com/calvinchengx/entra-emulator) issues and validates the identities used
  by management, gateway, portal, and managed-identity flows.
- [`azure-keyvault-emulator`](https://github.com/calvinchengx/azure-keyvault-emulator) supplies Key Vault-backed
  named values and certificates.
- [`fabric-emulator`](https://github.com/calvinchengx/fabric-emulator) can be placed behind the gateway as a
  realistic protected backend.
- [`databricks-emulator`](https://github.com/calvinchengx/databricks-emulator) can sit behind it the same way;
  it is a sibling workspace emulator rather than a dependency of this one.
- [`arm-emulator`](https://github.com/calvinchengx/arm-emulator) is deliberately **not** a dependency: this
  emulator serves its own `Microsoft.ApiManagement` ARM surface rather than
  calling out to arm-emulator's.

To run them together, see [**azure-emulators**](https://github.com/calvinchengx/azure-emulators): a composition-only
repo holding the family `docker-compose.yml`, the shared issuer wiring, and the
pinned image versions the members are tested against.

## License intent

Apache-2.0, matching the emulator family. Implementation will be clean-room,
grounded only in public specifications, public Microsoft documentation,
open-source Microsoft projects, official SDK behavior, and black-box behavioral
study of services the project is authorized to test.
