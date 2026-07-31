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
const fragments = [];
for await (const item of client.policyFragment.listByService(resourceGroup, serviceName)) {
  fragments.push(item);
}
if (fragments.length !== 1) {
  throw new Error(`unexpected policy fragment count: ${fragments.length}`);
}
const references = await client.policyFragment.listReferences(resourceGroup, serviceName, "javascript-sdk-fragment");
if ((references.value ?? []).length !== 0) {
  throw new Error("unreferenced policy fragment reported references");
}
await client.policyFragment.delete(resourceGroup, serviceName, "javascript-sdk-fragment", "*");
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
