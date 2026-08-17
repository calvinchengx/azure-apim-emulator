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

## Workspaces, as implemented

A workspace is a **scope**, not another resource kind. The ARM router peels a
`/workspaces/{id}` segment off the path, records it, and dispatches the rest
unchanged, so every family the emulator implements at service scope is available
inside a workspace with no per-family work. That is the whole mechanism: the
only thing that differs is the parent ID the resources hang off.

**The peel is family-blind, so the exceptions are one explicit list.** Eight
families are ones Azure scopes to a service only, and they answer 404 under a
workspace rather than being dispatched: `caches`, `identityProviders`,
`openidConnectProviders`, `authorizationProviders`, `authorizationServers`,
`documentations`, `gateways` and `users`. The check is `serviceOnlyFamilies` in
`internal/arm/handler.go`, applied once immediately after the segment is peeled,
rather than a guard repeated inside each family.

The list is derived from the SDK rather than judged: `@azure/arm-apimanagement`
publishes a separate `Workspace*` operation group for every family Azure
genuinely scopes to a workspace, so a family with no such group is service-only.
That makes it evidence from one SDK version, not proof — if a later version adds
a group for one of these, the row goes.

`users` is the one worth stating: `WorkspaceGroupUser` does exist, but it is a
membership link, not user CRUD. Users are a service-level directory that a
workspace group draws members from, which is why only the FIRST path segment
after the workspace is checked. `/workspaces/{id}/groups/{g}/users/{u}` is a
membership and still works; `/workspaces/{id}/users/{u}` is a directory entry
and does not.

Without the list every one of these would be created happily inside a workspace,
and that is the dangerous direction, because it has no local symptom. Two shapes
of it were found and fixed: `authorizationProviders` fell through to the SERVICE,
so a PUT created a provider in a scope the caller never named and a GET reported
service-level providers as the workspace's; the other families instead created
the resource IN the workspace, where it is retrievable and simply does not exist
in Azure. Both work here and 404 the first time the same flow runs against a real
tenant.

**The store was rebuilt to allow it.** Every resource table previously declared
`REFERENCES services(id)`, which made "a resource's parent is a service" a
database-level invariant, and workspaces make that false. There is now a
`scopes` table that services and workspaces both register in, with 20 resource
foreign keys repointed at it. A service is its own scope; a workspace is a scope
owned by its service, so deleting a service cascades through its workspaces'
scopes to everything inside them.

Isolation is exact rather than prefix-based, because the store matches parent
IDs exactly. The same API name can exist at service scope and in a workspace,
and neither listing sees the other.

**Existing databases are migrated on open.** SQLite cannot alter a foreign key
in place, so legacy tables are rebuilt: create, copy, drop, rename. The script is
generated from `sqlite_master` rather than a hand-written list, so a table added
later cannot be forgotten, and it runs as one all-or-nothing transaction, so a
failure leaves the original schema untouched rather than half-migrated.

## Azure RBAC

Access to a workspace in Azure is granted through Azure RBAC role assignments,
which belong to `Microsoft.Authorization`, a different resource provider. The
emulator now serves that provider too.

**Two access systems, and they are not the same one.** Azure RBAC governs the
CONTROL plane: who may call ARM to manage the service. APIM's own users, groups,
products and subscriptions govern the DATA plane: who may call an API through
the gateway. Conflating them produces an emulator that enforces the wrong thing.

Role assignments hang off any scope, because a scope is just a resource ID. That
is why workspaces needed nothing special: an assignment made at a workspace
covers everything inside it, and one made at the service covers the workspace,
by resource-ID prefix. The boundary check matters, so `/service/prod` does not
cover `/service/prod-canary`.

Evaluation follows Azure's model. A role definition lists `actions` matched with
wildcards, reduced by `notActions`; an action is named after the resource TYPE,
so instance names are stripped from the path; and the result is deny-by-default.
The published built-in role GUIDs are served unchanged, because tooling
hard-codes them and a caller assigning by GUID must find the same role here.

**Enforcement is opt-in.** `APIM_ENFORCE_RBAC` defaults off, and a valid ARM
token means full access, which is what every existing caller assumes. Enabling
it requires `APIM_RBAC_OWNER`: creating a role assignment is itself an ARM action
needing a role, so without a bootstrap principal nobody could ever grant the
first one, and the emulator would refuse every request including the one that
would fix it. Azure resolves the same circularity through the subscription
owner. The config refuses to start when enforcement is on and no owner is named,
rather than leaving that trap for someone to find at runtime.
