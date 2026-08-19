# Azure APIM Emulator

Azure APIM Emulator is a clean-room, low-memory Go implementation of the
publicly observable Azure API Management contract. The project validates
compatibility with official Microsoft SDKs and tracks every implemented,
verified, partial, and planned capability in the live parity ledger.

## Current baseline

- Stable management target: `2024-05-01`
- Official Go, JavaScript, Python, and .NET SDK witnesses
- Entra-authenticated management requests
- Service, API, operation, product, subscription, and API-policy vertical slice
- XML policy compilation and immutable gateway snapshots
- 100% aggregate statement coverage for committed Go code

Start with the [quickstart](01-quickstart.md), which publishes an API and calls
it through the gateway. [Installation](02-installation.md) covers the other ways
to run it and [configuration](04-configuration.md) documents every setting.

For scope rather than use, read the [charter](00-charter-and-parity.md), then
the [roadmap](11-roadmap.md) and the [parity ledger](parity.md).
