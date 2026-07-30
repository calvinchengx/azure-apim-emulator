# APIM parity ledger

This is the live top-level ledger. Detailed generated operation, policy,
expression-member, portal-workflow, protocol, tier, and gateway matrices will be
added as implementation inventories are generated.

Snapshot date: 2026-07-30

| Capability track | State | Target phase | Verification witness |
|---|---|---:|---|
| process/config/TLS/store/clock | planned | P0 | Go integration and distribution smoke |
| service ARM lifecycle and LROs | planned | P0 | four official SDKs plus Azure differential |
| APIs/operations/products/subscriptions | planned | P0-P1 | SDK workflow and gateway call |
| stable `2024-05-01` operation inventory | planned | P1-P7 | generated spec audit and SDK/differential tests |
| older SDK API versions | planned | P0-P1 | pinned Go/JS/.NET/Python clients |
| preview `2025-09-01-preview` | planned | P8 | isolated preview suite |
| HTTP gateway and routing | planned | P0-P1 | backend recorder and Azure differential |
| policy XML/inheritance | planned | P0-P2 | compiler fixtures and Azure traces |
| policy inventory | planned | P1-P2 | generated reference audit |
| C# expression member inventory | planned | P2 | .NET vectors and Azure differential fuzzing |
| developer portal | planned | P3 | portal API fixtures and Playwright journeys |
| workspaces | planned | P4 | SDK/RBAC/isolation scenarios |
| self-hosted/workspace gateways | planned | P4 | multi-process disconnect/config tests |
| SOAP | planned | P5 | WSDL clients and Azure differential |
| GraphQL | planned | P5 | real GraphQL clients and resolver fixtures |
| WebSocket/SSE | planned | P1/P5 | streaming clients and backend recorder |
| gRPC | planned | P5 | generated clients and trailer/stream fixtures |
| networking/private/custom domains | planned | P1/P6 | ARM state plus local reachability and Azure differential |
| tiers/SKUs/regions/deployment | planned | P6 | capability audit and tier fixtures |
| diagnostics/analytics/monitoring | planned | P1/P7 | telemetry schema/correlation fixtures |
| authorization providers/integrations | planned | P7 | adapter and Azure differential suites |
| AI gateway and MCP | planned | P8 | deterministic providers and opt-in real suites |
| full dated stable parity audit | planned | P9 | published evidence snapshot |

## Claim policy

The project may say a capability is supported when it is `implemented`, but it
may say it matches Azure only at `verified`. A release may claim full parity only
for the dated stable snapshot in which every inventory entry is classified and
verified or carries a narrowly documented infrastructure substitution.

