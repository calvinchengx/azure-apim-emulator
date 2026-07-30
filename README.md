# azure-apim-emulator

A clean-room, local emulator of the complete publicly observable Azure API
Management product. The implementation will be a low-memory Go service with
an embedded portal, real integration with `entra-emulator` and
`azure-keyvault-emulator`, and compatibility verified through unmodified
Microsoft SDKs and differential tests against Azure APIM.

## Status

**Design phase.** This repository currently contains the implementation charter,
architecture, compatibility contract, subsystem plans, test strategy, parity
ledger, and delivery roadmap. No APIM endpoint is implemented yet.

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
- Full product parity is the roadmap target; gaps are tracked, not hidden as permanent non-goals.

## Documentation

- [Charter and parity definition](docs/01-charter-and-parity.md)
- [System architecture](docs/02-architecture.md)
- [Management plane and resource model](docs/03-management-plane.md)
- [Gateway and protocol runtime](docs/04-gateway-and-protocols.md)
- [Policy and expression engine](docs/05-policy-and-expressions.md)
- [Portal, workspaces, and platform features](docs/06-portal-workspaces-platform.md)
- [Identity, networking, and observability](docs/07-identity-networking-observability.md)
- [Testing and SDK matrix](docs/08-testing-and-sdk-matrix.md)
- [Implementation roadmap](docs/09-roadmap.md)
- [Risk register](docs/10-risk-register.md)
- [Clean-room grounding](docs/11-clean-room-grounding.md)
- [Live parity ledger](docs/parity.md)

## Emulator family

- `entra-emulator` issues and validates the identities used by management,
  gateway, portal, and managed-identity flows.
- `azure-keyvault-emulator` supplies Key Vault-backed named values and certificates.
- `fabric-emulator` can be placed behind the gateway as a realistic protected backend.

## License intent

Apache-2.0, matching the emulator family. Implementation will be clean-room,
grounded only in public specifications, public Microsoft documentation,
open-source Microsoft projects, official SDK behavior, and black-box behavioral
study of services the project is authorized to test.

