import { ApiManagementClient } from "@azure/arm-apimanagement";

const credential = {
  async getToken() {
    return { token: "sdk-token", expiresOnTimestamp: Date.now() + 3600000 };
  },
};

const endpoint = process.env.APIM_ENDPOINT;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;
const client = new ApiManagementClient(
  credential,
  process.env.APIM_SUBSCRIPTION_ID,
  { endpoint },
);
await client.apiManagementService.beginCreateOrUpdateAndWait(resourceGroup, serviceName, {
  location: "local",
  sku: { name: "Developer", capacity: 1 },
  publisherName: "JavaScript SDK",
  publisherEmail: "javascript@example.test",
});
const result = await client.api.beginCreateOrUpdateAndWait(
  resourceGroup,
  serviceName,
  "javascript-sdk-api",
  {
    displayName: "JavaScript SDK API",
    path: "javascript-sdk",
    serviceUrl: process.env.APIM_BACKEND_URL,
    protocols: ["https"],
    subscriptionRequired: true,
  },
);
if (result.name !== "javascript-sdk-api") {
  throw new Error(`unexpected API name: ${result.name}`);
}
await client.apiOperation.createOrUpdate(resourceGroup, serviceName, "javascript-sdk-api", "get", {
  displayName: "Get",
  method: "GET",
  urlTemplate: "/items",
});
await client.namedValue.beginCreateOrUpdateAndWait(resourceGroup, serviceName, "javascript-sdk-named-value", {
  displayName: "JavaScriptSdkNamedValue",
  value: "sdk-named-value",
  tags: ["javascript", "gateway"],
});
const taggedNamedValues = [];
for await (const item of client.namedValue.listByService(resourceGroup, serviceName, {
  filter: "tags/any(tag: tag eq 'javascript')",
})) {
  taggedNamedValues.push(item);
}
if (taggedNamedValues.length !== 1 || taggedNamedValues[0].name !== "javascript-sdk-named-value") {
  throw new Error("JavaScript SDK named-value tag filter failed");
}
await client.namedValue.delete(resourceGroup, serviceName, "javascript-sdk-named-value", "*");
const fragment = await client.policyFragment.beginCreateOrUpdateAndWait(
  resourceGroup,
  serviceName,
  "javascript-sdk-fragment",
  {
    description: "Created by the JavaScript SDK",
    format: "rawxml",
    value: '<fragment><set-header name="X-JavaScript-Fragment"><value>yes</value></set-header></fragment>',
  },
);
if (fragment.name !== "javascript-sdk-fragment" || fragment.provisioningState !== "Succeeded") {
  throw new Error("JavaScript SDK policy fragment did not round-trip");
}
const gotFragment = await client.policyFragment.get(resourceGroup, serviceName, "javascript-sdk-fragment", { format: "rawxml" });
if (gotFragment.format !== "rawxml" || !gotFragment.value.includes("X-JavaScript-Fragment")) {
  throw new Error("JavaScript SDK policy fragment GET failed");
}
const fragmentState = await client.policyFragment.getEntityTag(resourceGroup, serviceName, "javascript-sdk-fragment");
if (!fragmentState.eTag) {
  throw new Error("JavaScript SDK policy fragment ETag missing");
}
await client.policyFragment.beginCreateOrUpdateAndWait(
  resourceGroup,
  serviceName,
  "aaa-javascript-sdk-fragment",
  {
    description: "Ordering witness",
    format: "rawxml",
    value: "<fragment />",
  },
);
const fragments = [];
for await (const item of client.policyFragment.listByService(resourceGroup, serviceName, {
  filter: "contains(name, 'javascript-sdk-fragment')",
  orderby: "name desc",
})) {
  fragments.push(item);
}
if (fragments.length !== 2 || fragments[0].name !== "javascript-sdk-fragment" || fragments[1].name !== "aaa-javascript-sdk-fragment") {
  throw new Error(`unexpected ordered policy fragments: ${fragments.map((item) => item.name).join(",")}`);
}
const references = await client.policyFragment.listReferences(resourceGroup, serviceName, "javascript-sdk-fragment");
if ((references.value ?? []).length !== 0) {
  throw new Error("unreferenced policy fragment reported references");
}
await client.policyFragment.delete(resourceGroup, serviceName, "javascript-sdk-fragment", "*");
await client.policyFragment.delete(resourceGroup, serviceName, "aaa-javascript-sdk-fragment", "*");
const scope = `/subscriptions/${process.env.APIM_SUBSCRIPTION_ID}/resourceGroups/${resourceGroup}/providers/Microsoft.ApiManagement/service/${serviceName}/apis/javascript-sdk-api`;
await client.subscription.createOrUpdate(resourceGroup, serviceName, "javascript-sdk-subscription", {
  displayName: "JavaScript SDK subscription",
  scope,
  state: "active",
  primaryKey: "javascript-sdk-key",
  secondaryKey: "javascript-sdk-secondary",
});
const originalSecrets = await client.subscription.listSecrets(resourceGroup, serviceName, "javascript-sdk-subscription");
if (originalSecrets.primaryKey !== "javascript-sdk-key" || originalSecrets.secondaryKey !== "javascript-sdk-secondary") {
  throw new Error("JavaScript SDK subscription secrets did not round-trip");
}
await client.subscription.regeneratePrimaryKey(resourceGroup, serviceName, "javascript-sdk-subscription");
const rotatedSecrets = await client.subscription.listSecrets(resourceGroup, serviceName, "javascript-sdk-subscription");
if (rotatedSecrets.primaryKey === "javascript-sdk-key" || rotatedSecrets.secondaryKey !== "javascript-sdk-secondary") {
  throw new Error("JavaScript SDK subscription key did not rotate");
}
const gatewayResponse = await fetch(`${endpoint}/javascript-sdk/items`, {
  headers: { "Ocp-Apim-Subscription-Key": rotatedSecrets.primaryKey },
});
if (gatewayResponse.status !== 200 || (await gatewayResponse.text()) !== "sdk-backend") {
  throw new Error(`gateway response: ${gatewayResponse.status}`);
}
console.log("JavaScript APIM SDK witness passed");

// ---------------------------------------------------------------------------
// Workspaces, driven by Microsoft's own SDK.
//
// This is the assertion that matters for the scoping model: the SDK builds the
// workspace-scoped URLs itself, from its own understanding of the resource
// hierarchy. If the emulator composed those paths or IDs differently, the SDK
// would not find what it just created.
const workspaceId = "team-a";
const workspace = await client.workspace.createOrUpdate(resourceGroup, serviceName, workspaceId, {
  displayName: "Team A",
  description: "workspace witness",
});
if (workspace.name !== workspaceId) {
  throw new Error(`unexpected workspace name: ${workspace.name}`);
}
if (!workspace.id.endsWith(`/service/${serviceName}/workspaces/${workspaceId}`)) {
  throw new Error(`workspace id is not workspace-scoped: ${workspace.id}`);
}

const listed = [];
for await (const item of client.workspace.listByService(resourceGroup, serviceName)) {
  listed.push(item.name);
}
if (!listed.includes(workspaceId)) {
  throw new Error(`workspace missing from listByService: ${listed.join(", ")}`);
}

// An API inside the workspace, created through the SDK's workspace client.
const scopedApi = await client.workspaceApi.beginCreateOrUpdateAndWait(
  resourceGroup,
  serviceName,
  workspaceId,
  "scoped-api",
  {
    displayName: "Scoped API",
    path: "scoped",
    serviceUrl: process.env.APIM_BACKEND_URL,
    protocols: ["https"],
    subscriptionRequired: false,
  },
);
if (!scopedApi.id.includes(`/workspaces/${workspaceId}/apis/scoped-api`)) {
  throw new Error(`workspace API id is not workspace-scoped: ${scopedApi.id}`);
}

// The two scopes must not see each other. This is the property that makes a
// workspace a boundary rather than a naming convention.
const workspaceApis = [];
for await (const item of client.workspaceApi.listByService(resourceGroup, serviceName, workspaceId)) {
  workspaceApis.push(item.name);
}
if (!workspaceApis.includes("scoped-api")) {
  throw new Error(`workspace API listing missing its own API: ${workspaceApis.join(", ")}`);
}
if (workspaceApis.includes("javascript-sdk-api")) {
  throw new Error("the service's API leaked into the workspace listing");
}

const serviceApis = [];
for await (const item of client.api.listByService(resourceGroup, serviceName)) {
  serviceApis.push(item.name);
}
if (!serviceApis.includes("javascript-sdk-api")) {
  throw new Error(`service API listing lost its own API: ${serviceApis.join(", ")}`);
}
if (serviceApis.includes("scoped-api")) {
  throw new Error("the workspace API leaked into the service listing");
}

// A workspace-scoped product, to prove the scoping is not special-cased to APIs.
await client.workspaceProduct.createOrUpdate(resourceGroup, serviceName, workspaceId, "scoped-product", {
  displayName: "Scoped Product",
});
const workspaceProducts = [];
for await (const item of client.workspaceProduct.listByService(resourceGroup, serviceName, workspaceId)) {
  workspaceProducts.push(item.name);
}
if (!workspaceProducts.includes("scoped-product")) {
  throw new Error(`workspace product listing = ${workspaceProducts.join(", ")}`);
}

// Deleting the workspace takes its contents with it.
await client.workspace.delete(resourceGroup, serviceName, workspaceId, "*");
let stillThere = false;
try {
  await client.workspaceApi.get(resourceGroup, serviceName, workspaceId, "scoped-api");
  stillThere = true;
} catch {
  // expected: the scope is gone, so nothing inside it resolves
}
if (stillThere) {
  throw new Error("deleting a workspace left its API addressable");
}
console.log("javascript witness: workspaces scoped, isolated, and cascaded");

// ---------------------------------------------------------------------------
// Role assignments, driven by Microsoft's AUTHORIZATION SDK.
//
// A second client, from a different resource provider, pointed at the same
// emulator. That is the assertion: role assignments are not an APIM resource,
// and a caller manages them exactly as they would in Azure, with the library
// built for Microsoft.Authorization rather than the APIM one.
const { AuthorizationManagementClient } = await import("@azure/arm-authorization");
const authorization = new AuthorizationManagementClient(
  credential,
  process.env.APIM_SUBSCRIPTION_ID,
  { endpoint },
);

const serviceScope =
  `/subscriptions/${process.env.APIM_SUBSCRIPTION_ID}/resourceGroups/${resourceGroup}` +
  `/providers/Microsoft.ApiManagement/service/${serviceName}`;
const workspaceScope = `${serviceScope}/workspaces/rbac-team`;

await client.workspace.createOrUpdate(resourceGroup, serviceName, "rbac-team", {
  displayName: "RBAC Team",
});

// The built-in role GUIDs are fixed in every Azure tenant and tooling hard-codes
// them, so the emulator must answer to the same ones.
const workspaceContributor = "0c34c906-8d99-4cb7-8df9-b5d5b0e4a5f1";
const definition = await authorization.roleDefinitions.get(serviceScope, workspaceContributor);
if (definition.roleName !== "API Management Workspace Contributor") {
  throw new Error(`unexpected role definition: ${definition.roleName}`);
}

const assignmentName = "11111111-2222-3333-4444-555555555555";
const created = await authorization.roleAssignments.create(workspaceScope, assignmentName, {
  roleDefinitionId: `/providers/Microsoft.Authorization/roleDefinitions/${workspaceContributor}`,
  principalId: "ada-object-id",
  principalType: "User",
});
if (created.principalId !== "ada-object-id") {
  throw new Error(`unexpected principal: ${created.principalId}`);
}
if (!created.id.includes("/providers/Microsoft.Authorization/roleAssignments/")) {
  throw new Error(`assignment id is not an authorization resource: ${created.id}`);
}

// Listing at the SERVICE must surface the workspace-scoped assignment, because
// that is where a caller looks to find out who has access to what.
const assignments = [];
for await (const item of authorization.roleAssignments.listForScope(serviceScope)) {
  assignments.push(item.name);
}
if (!assignments.includes(assignmentName)) {
  throw new Error(`assignment missing from listForScope: ${assignments.join(", ")}`);
}

const fetched = await authorization.roleAssignments.get(workspaceScope, assignmentName);
if (fetched.scope !== workspaceScope) {
  throw new Error(`assignment scope = ${fetched.scope}`);
}

await authorization.roleAssignments.delete(workspaceScope, assignmentName);
await client.workspace.delete(resourceGroup, serviceName, "rbac-team", "*");
console.log("javascript witness: role assignments created, listed and deleted through Microsoft.Authorization");

// ---------------------------------------------------------------------------
// Self-hosted gateways, driven by Microsoft's own SDK.
//
// The SDK exposes four separate operation groups for this one resource tree --
// gateway, gatewayApi, gatewayHostnameConfiguration, gatewayCertificateAuthority
// -- so the emulator has to answer all four, at the URLs the SDK composes.
const { createHmac } = await import("node:crypto");

const gatewayId = "edge-witness";
const registered = await client.gateway.createOrUpdate(resourceGroup, serviceName, gatewayId, {
  locationData: { name: "contoso-dc", city: "Wellington", countryOrRegion: "NZ" },
  description: "self-hosted witness",
});
if (registered.name !== gatewayId || registered.locationData.city !== "Wellington") {
  throw new Error(`gateway did not round-trip: ${JSON.stringify(registered)}`);
}
if (registered.primaryKey || registered.secondaryKey) {
  throw new Error("a gateway key was returned by createOrUpdate");
}

const readBack = await client.gateway.get(resourceGroup, serviceName, gatewayId);
if (readBack.primaryKey || readBack.secondaryKey) {
  throw new Error("a gateway key was returned by get");
}

const gatewayKeys = await client.gateway.listKeys(resourceGroup, serviceName, gatewayId);
if (!gatewayKeys.primary || !gatewayKeys.secondary || gatewayKeys.primary === gatewayKeys.secondary) {
  throw new Error(`unexpected gateway keys: ${JSON.stringify(gatewayKeys)}`);
}

// The token is checked by RECOMPUTING it here, from the key listKeys handed
// back, rather than by comparing it to a string the emulator also produced.
// `{gatewayId}&{expiry}&base64(HMAC-SHA512(key, "{gatewayId}\n{expiry}"))` is
// the format Microsoft documents for minting this token by hand, so an
// independent implementation of it is the oracle.
const expiry = new Date(Date.now() + 24 * 3600 * 1000);
const minted = await client.gateway.generateToken(resourceGroup, serviceName, gatewayId, {
  keyType: "primary",
  expiry,
});
const [tokenId, tokenExpiry, tokenSignature] = minted.value.split("&");
if (tokenId !== gatewayId) {
  throw new Error(`token names the wrong gateway: ${minted.value}`);
}
const recomputed = createHmac("sha512", gatewayKeys.primary)
  .update(`${gatewayId}\n${tokenExpiry}`)
  .digest("base64");
if (recomputed !== tokenSignature) {
  throw new Error(`token signature did not verify: ${minted.value}`);
}
if (new Date(tokenExpiry).getTime() !== expiry.getTime()) {
  throw new Error(`token expiry ${tokenExpiry} does not restate ${expiry.toISOString()}`);
}

// Rotating a key must invalidate what that key signed, and leave the other
// key's tokens alone. That is the entire reason there are two.
await client.gateway.regenerateKey(resourceGroup, serviceName, gatewayId, { keyType: "primary" });
const rotatedGatewayKeys = await client.gateway.listKeys(resourceGroup, serviceName, gatewayId);
if (rotatedGatewayKeys.primary === gatewayKeys.primary) {
  throw new Error("the primary gateway key did not rotate");
}
if (rotatedGatewayKeys.secondary !== gatewayKeys.secondary) {
  throw new Error("rotating the primary gateway key disturbed the secondary");
}

// Two APIs, one associated and one not: the assertion is the ABSENCE of the
// second on the gateway, not the presence of the first.
for (const [name, path] of [["gateway-served-api", "gateway-served"], ["gateway-withheld-api", "gateway-withheld"]]) {
  await client.api.beginCreateOrUpdateAndWait(resourceGroup, serviceName, name, {
    displayName: name,
    path,
    serviceUrl: process.env.APIM_BACKEND_URL,
    protocols: ["https"],
    subscriptionRequired: false,
  });
  await client.apiOperation.createOrUpdate(resourceGroup, serviceName, name, "get", {
    displayName: "Get",
    method: "GET",
    urlTemplate: "/items",
  });
}
await client.gatewayApi.createOrUpdate(resourceGroup, serviceName, gatewayId, "gateway-served-api");
const gatewayApis = [];
for await (const item of client.gatewayApi.listByService(resourceGroup, serviceName, gatewayId)) {
  gatewayApis.push(item.name);
}
if (!gatewayApis.includes("gateway-served-api")) {
  throw new Error(`gateway API listing = ${gatewayApis.join(", ")}`);
}
if (gatewayApis.includes("gateway-withheld-api")) {
  throw new Error("an unassociated API appeared in the gateway's listing");
}

const gatewayHost = "edge.witness.test";
await client.gatewayHostnameConfiguration.createOrUpdate(resourceGroup, serviceName, gatewayId, "primary", {
  hostname: gatewayHost,
  http2Enabled: true,
  negotiateClientCertificate: false,
});
const hostnames = [];
for await (const item of client.gatewayHostnameConfiguration.listByService(resourceGroup, serviceName, gatewayId)) {
  hostnames.push(item.hostname);
}
if (!hostnames.includes(gatewayHost)) {
  throw new Error(`gateway hostname listing = ${hostnames.join(", ")}`);
}

// The runtime half. A request arriving on the gateway's hostname is served by
// that gateway, so only its associated API is reachable there -- while both
// stay reachable on the service's own front door. A management plane that
// recorded the association without this would be recording a preference.
const gatewayEndpoint = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const gatewayURL = new URL(gatewayEndpoint);
const { request: httpsRequest } = await import("node:https");
const { checkServerIdentity } = await import("node:tls");

// node:https rather than fetch, and the reason matters: `Host` is a forbidden
// header name, so undici DROPS it silently and every request would arrive at
// the service's own front door while looking like it had been addressed to the
// gateway. The first draft of this witness did exactly that, and only the
// negative assertion below caught it.
const onGateway = (path) =>
  new Promise((resolve, reject) => {
    const call = httpsRequest(
      {
        hostname: gatewayURL.hostname,
        port: gatewayURL.port,
        path,
        method: "GET",
        // The Host header is deliberately NOT the host being connected to.
        // That is exactly how a self-hosted gateway's own hostname is
        // presented in front of it.
        headers: { Host: gatewayHost },
        // The certificate is still verified, against the host actually being
        // connected to. Node would otherwise derive the name to verify from
        // the Host header and fail on a name the emulator's certificate has no
        // reason to carry. Turning verification OFF here would have hidden a
        // real TLS defect, so it is redirected rather than disabled.
        checkServerIdentity: (_, certificate) => checkServerIdentity(gatewayURL.hostname, certificate),
      },
      (response) => {
        response.resume();
        response.on("end", () => resolve({ status: response.statusCode }));
      },
    );
    call.on("error", reject);
    call.end();
  });

const servedOnGateway = await onGateway("/gateway-served/items");
if (servedOnGateway.status !== 200) {
  throw new Error(`associated API on the gateway hostname: ${servedOnGateway.status}`);
}
const withheldOnGateway = await onGateway("/gateway-withheld/items");
if (withheldOnGateway.status !== 404) {
  throw new Error(`unassociated API was served by the gateway: ${withheldOnGateway.status}`);
}
for (const path of ["/gateway-served/items", "/gateway-withheld/items"]) {
  const direct = await fetch(`${gatewayEndpoint}${path}`);
  if (direct.status !== 200) {
    throw new Error(`${path} on the service front door: ${direct.status}`);
  }
}

// Removing the association takes the API off the gateway, which is what makes
// the link a runtime decision rather than a label.
await client.gatewayApi.delete(resourceGroup, serviceName, gatewayId, "gateway-served-api");
const afterDetach = await onGateway("/gateway-served/items");
if (afterDetach.status !== 404) {
  throw new Error(`a detached API was still served by the gateway: ${afterDetach.status}`);
}

// Per-gateway certificate-authority trust: the gateways run in different places
// and answer to different callers, so trust is not a service-wide setting.
await client.gatewayCertificateAuthority.createOrUpdate(resourceGroup, serviceName, gatewayId, "corp-root", {
  isTrusted: true,
});
const authority = await client.gatewayCertificateAuthority.get(resourceGroup, serviceName, gatewayId, "corp-root");
if (authority.isTrusted !== true) {
  throw new Error(`certificate authority = ${JSON.stringify(authority)}`);
}
await client.gatewayCertificateAuthority.delete(resourceGroup, serviceName, gatewayId, "corp-root", "*");

const gateways = [];
for await (const item of client.gateway.listByService(resourceGroup, serviceName)) {
  gateways.push(item.name);
}
if (!gateways.includes(gatewayId)) {
  throw new Error(`gateway listing = ${gateways.join(", ")}`);
}

// Deleting the registration stops the hostname being a gateway's. The
// before/after pair is the assertion: the same request was refused while the
// gateway existed and is not refused once it does not, so the restriction was
// the gateway's and it went with it.
//
// It is answered rather than refused afterwards because an unrecognised Host
// falls back to the default service in this emulator. That fallback predates
// gateways and is NOT asserted here as correct.
await client.gateway.delete(resourceGroup, serviceName, gatewayId, "*");
const afterDelete = await onGateway("/gateway-withheld/items");
if (afterDelete.status !== 200) {
  throw new Error(`the gateway's restriction outlived the gateway: ${afterDelete.status}`);
}
console.log("javascript witness: self-hosted gateway registered, token verified, and serving only its associated APIs");

// ---------------------------------------------------------------------------
// Private networking, driven by Microsoft's own SDK.
//
// Three separate operation groups -- privateEndpointConnection, networkStatus
// and outboundNetworkDependenciesEndpoints -- each with its own URL shape and
// its own response model. The SDK composes all three from its own understanding
// of the contract, which is what makes it evidence rather than a restatement of
// the routes I wrote.
//
// What is NOT asserted here, because it could not be true: that a private
// endpoint carries traffic. One lives in a consumer's own virtual network and
// this emulator never reaches it. The approval workflow is the emulatable part.
const connectionName = "from-consumer-vnet";
const consumerEndpoint =
  `/subscriptions/${process.env.APIM_SUBSCRIPTION_ID}/resourceGroups/${resourceGroup}` +
  `/providers/Microsoft.Network/privateEndpoints/consumer-pe`;

// The consumer's side, which is deliberately NOT the SDK. Microsoft's
// `PrivateEndpointConnectionRequest` model carries only the connection STATE:
// there is no field for the endpoint, because in Azure the endpoint is created
// by the consumer through the Network resource provider and APIM surfaces what
// arrived. So the request is seeded the way it arrives -- from elsewhere -- and
// the SDK is used for the half it actually models, which is the decision.
const connectionArrival = await fetch(
  `${endpoint}/subscriptions/${process.env.APIM_SUBSCRIPTION_ID}/resourceGroups/${resourceGroup}` +
    `/providers/Microsoft.ApiManagement/service/${serviceName}` +
    `/privateEndpointConnections/${connectionName}?api-version=2024-05-01`,
  {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: "Bearer sdk-token" },
    body: JSON.stringify({ properties: { privateEndpoint: { id: consumerEndpoint } } }),
  },
);
if (connectionArrival.status !== 201) {
  throw new Error(`the consumer's connection request was refused: ${connectionArrival.status}`);
}

const pending = await client.privateEndpointConnectionOperations.getByName(resourceGroup, serviceName, connectionName);
// A connection arrives Pending. Anything else would be access the service owner
// never granted.
if (pending.privateLinkServiceConnectionState?.status !== "Pending") {
  throw new Error(`a new connection was ${JSON.stringify(pending.privateLinkServiceConnectionState)}`);
}
if (pending.provisioningState !== "Succeeded") {
  throw new Error(`provisioningState = ${pending.provisioningState}`);
}
// The consumer's endpoint is in another subscription: surfaced to the owner,
// never resolved by this emulator.
if (pending.privateEndpoint?.id !== consumerEndpoint) {
  throw new Error(`the consumer's endpoint was lost: ${JSON.stringify(pending.privateEndpoint)}`);
}

const approved = await client.privateEndpointConnectionOperations.beginCreateOrUpdateAndWait(
  resourceGroup,
  serviceName,
  connectionName,
  { properties: { privateLinkServiceConnectionState: { status: "Approved", description: "reviewed by platform" } } },
);
if (approved.privateLinkServiceConnectionState?.status !== "Approved") {
  throw new Error(`approval = ${JSON.stringify(approved.privateLinkServiceConnectionState)}`);
}
if (approved.privateLinkServiceConnectionState?.description !== "reviewed by platform") {
  throw new Error("the approval reason was lost");
}
// Approving must not discard what the consumer sent, even though the SDK's
// request model has no field for it.
if (approved.privateEndpoint?.id !== consumerEndpoint) {
  throw new Error(`approval dropped the consumer's endpoint: ${JSON.stringify(approved.privateEndpoint)}`);
}

const connections = [];
for await (const item of client.privateEndpointConnectionOperations.listByService(resourceGroup, serviceName)) {
  connections.push(item.name);
}
if (!connections.includes(connectionName)) {
  throw new Error(`connection listing = ${connections.join(", ")}`);
}

// A service exposes exactly one private-link sub-resource, and a consumer needs
// its group id to build an endpoint at all.
const linkResources = await client.privateEndpointConnectionOperations.listPrivateLinkResources(resourceGroup, serviceName);
if (!(linkResources.value ?? []).some((entry) => entry.groupId === "Gateway")) {
  throw new Error(`private link resources = ${JSON.stringify(linkResources.value)}`);
}
const gatewayLink = await client.privateEndpointConnectionOperations.getPrivateLinkResource(resourceGroup, serviceName, "Gateway");
// Compared exactly, and the count checked, rather than asking whether the zone
// appears somewhere in the list. A containment check would pass on a list that
// also carried zones nobody should be told to create, and the idiom reads as
// URL validation to a scanner besides.
const requiredZones = gatewayLink.requiredZoneNames ?? [];
if (requiredZones.length !== 1 || requiredZones[0] !== "privatelink.azure-api.net") {
  throw new Error(`gateway link resource zones = ${JSON.stringify(requiredZones)}`);
}

await client.privateEndpointConnectionOperations.beginDeleteAndWait(resourceGroup, serviceName, connectionName);
let stillConnected = false;
try {
  await client.privateEndpointConnectionOperations.getByName(resourceGroup, serviceName, connectionName);
  stillConnected = true;
} catch {
  // expected: the connection is gone
}
if (stillConnected) {
  throw new Error("a deleted connection was still addressable");
}
console.log("javascript witness: private endpoint connection requested, approved, listed and deleted");

// The two read-only status surfaces an operator uses to find out whether the
// service can reach what it depends on. The SDK models them differently -- one
// is a list by location, the other a single status -- so both shapes are driven.
const byLocation = await client.networkStatus.listByService(resourceGroup, serviceName);
if (!Array.isArray(byLocation) || byLocation.length === 0 || !byLocation[0].networkStatus) {
  throw new Error(`networkStatus.listByService = ${JSON.stringify(byLocation)}`);
}
const located = await client.networkStatus.listByLocation(resourceGroup, serviceName, byLocation[0].location);
if (!Array.isArray(located.dnsServers) || !Array.isArray(located.connectivityStatus) || located.connectivityStatus.length === 0) {
  throw new Error(`networkStatus.listByLocation = ${JSON.stringify(located)}`);
}
// Every dependency reports success, and that is a statement about the emulator
// rather than about a deployment: there is no virtual network here to be
// misconfigured, so a synthesised failure would be a fault it invented.
if (located.connectivityStatus.some((entry) => entry.status !== "success")) {
  throw new Error(`connectivityStatus = ${JSON.stringify(located.connectivityStatus)}`);
}

const outbound = await client.outboundNetworkDependenciesEndpoints.listByService(resourceGroup, serviceName);
if (!(outbound.value ?? []).length) {
  throw new Error("outbound dependencies were empty");
}
for (const entry of outbound.value) {
  if (!entry.category || !(entry.endpoints ?? []).length) {
    throw new Error(`outbound entry = ${JSON.stringify(entry)}`);
  }
  for (const endpoint of entry.endpoints) {
    if (!endpoint.domainName || !(endpoint.endpointDetails ?? []).length) {
      throw new Error(`outbound endpoint = ${JSON.stringify(endpoint)}`);
    }
  }
}
console.log("javascript witness: network status and outbound dependencies served in the SDK's own shapes");
