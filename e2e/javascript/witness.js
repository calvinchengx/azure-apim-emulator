import { ApiManagementClient } from "@azure/arm-apimanagement";

const credential = {
  async getToken() {
    return { token: "sdk-token", expiresOnTimestamp: Date.now() + 3600000 };
  },
};

const endpoint = process.env.APIM_ENDPOINT;
const client = new ApiManagementClient(
  credential,
  process.env.APIM_SUBSCRIPTION_ID,
  { endpoint },
);
const result = await client.api.beginCreateOrUpdateAndWait(
  process.env.APIM_RESOURCE_GROUP,
  process.env.APIM_SERVICE_NAME,
  "javascript-sdk-api",
  {
    displayName: "JavaScript SDK API",
    path: "javascript-sdk",
    serviceUrl: "http://127.0.0.1:1",
    protocols: ["https"],
    subscriptionRequired: false,
  },
);
if (result.name !== "javascript-sdk-api") {
  throw new Error(`unexpected API name: ${result.name}`);
}
console.log("JavaScript APIM SDK witness passed");
