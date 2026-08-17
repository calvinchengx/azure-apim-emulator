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
