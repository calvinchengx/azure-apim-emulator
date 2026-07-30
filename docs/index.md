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

Start with the [charter](01-charter-and-parity.md), then use the
[roadmap](09-roadmap.md) and [parity ledger](parity.md) for current scope.
