# 06 - Developer portal, workspaces, and platform features

## Developer portal scope

The developer portal is part of parity, not merely the emulator's operator UI.
It includes:

- administrative visual editor and content management
- pages, layouts, menus, styles, media, widgets, settings, and custom widgets
- draft/save/publish/reset and revision restore workflows
- API/product discovery and documentation generated from APIM resources
- search, group-based visibility, authenticated and anonymous content
- user signup/signin, invitation, password reset, Entra/external identity, and delegated auth
- product subscription requests, approval, keys, profile, and reports
- interactive API console with subscription key, OAuth, and protocol support
- custom domains, CORS, CSP, localization, accessibility, and self-hosted portal integration

Microsoft's open-source developer portal is a clean-room behavioral and format
reference. Reuse is considered only after license and distribution review;
otherwise interoperability adapters target its public content and runtime APIs.

## Two portals

- The **developer portal** is APIM-compatible and served per logical service.
- The **operator portal** is emulator-only, embedded under `/_emulator/portal/`,
  and exposes clocks, faults, traces, snapshots, parity status, and local setup.

They use separate routes, auth, data APIs, and visual identities. Operator
features never leak into the APIM developer portal contract.

## Portal publication model

Draft content lives in normalized documents and media objects. Publishing
creates an immutable revision and an atomic runtime bundle. Restoring a revision
creates the same observable current/published state transitions as Azure. Portal
runtime reads only the active published revision plus live APIM data authorized
for the current user.

## Workspaces

Workspaces provide control-plane and runtime isolation inside a service:

- workspace-scoped APIs, products, subscriptions, named values, backends,
  policies, fragments, diagnostics, groups, tags, and related resources
- globally unique resource names where Azure requires them
- service-level references only where documented; no cross-workspace references
- workspace RBAC and role scopes
- one or more associated default, shared, or dedicated workspace gateways
- service-level governance policies and federated observability
- deletion cascade and gateway association behavior
- unified developer portal discovery without exposing workspace as a consumer concept

The compiler builds a resource graph per workspace plus explicitly permitted
service references. Reference validation is centralized and tier-aware.

## Products, users, groups, and subscriptions

Implement the full lifecycle and relationships:

- published/unpublished products, approval and subscription requirements
- built-in, custom, and external groups
- user activation, invitations, credentials, identities, and profile state
- product/API/group links and visibility
- service-, product-, API-, and workspace-scoped subscriptions
- primary/secondary keys, regeneration, suspension, cancellation, and expiry
- header/query subscription-key locations and missing/invalid-key errors
- portal ownership and usage reports

Subscription resolution must affect policy scope and gateway authorization, not
just management storage.

## Tier and capability engine

Represent tier behavior as versioned capability data rather than scattered
conditionals. Each capability declares supported tiers, gateway types, protocols,
limits, policy availability, portal availability, workspace support, networking,
and deployment constraints. Validation and the parity UI read the same data.

Changes in Microsoft capability tables produce an upstream-audit diff requiring
review before release.

