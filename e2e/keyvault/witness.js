// Key Vault secret retrieval, with Microsoft's own client writing the secret
// and a real vault answering the challenge.
//
// WHY THIS EXISTS. The `Key Vault secret retrieval` row was witnessed only by
// `go:TestKeyVaultRetrieval` and `go:TestHTTPGetSecret`, which drive an
// httptest server that returns the JSON we expect. That proves the parser, not
// the integration, and it hid a defect for as long as the row existed: with no
// credentials configured the retriever approximates IMDS by rewriting the
// challenge authority's path, which against entra-emulator reaches the operator
// portal's catch-all and returns `<!doctype html>`. The row was green and the
// feature did not work against the vault the charter names as its reference.
//
// Nothing here is ours except the thing under test:
//
//   the vault      azure-keyvault-emulator, which answers 401
//                  WWW-Authenticate and validates the token against entra's
//                  JWKS at the vault audience
//   the authority  entra-emulator, which mints the token
//   the authoriser arm-emulator, which holds the role assignment the vault polls
//   the writer     @azure/keyvault-secrets with @azure/identity, i.e. the
//                  client an Azure user would use, following the same challenge
//
// apim is asked only to retrieve. If it cannot, this fails.
import assert from "node:assert/strict";
import { ClientSecretCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";

// TLS trust is set by the container environment, before node starts. Setting it
// here would be too late: @azure/identity's MSAL client builds its own agent on
// import, so a value assigned at run time never reaches it.

// Container names, not localhost: see the witness service in compose.yaml.
const vaultURL = process.env.KV_URL ?? "https://keyvault-emulator:8444";
const apimURL = process.env.APIM_URL ?? "https://azure-apim-emulator:8445";
const entraURL = process.env.ENTRA_URL ?? "https://entra-emulator:8443";
const tenant = "6f89cf12-978b-4d23-ac18-9ef0c127cf87";
const clientId = "00d88624-f0d7-46f6-a641-6232c2608928";
const clientSecret = "daemon-app-secret";
const apiVersion = "2024-05-01";

// --- Microsoft's client plants the secret ----------------------------------

const credential = new ClientSecretCredential(tenant, clientId, clientSecret, {
  authorityHost: entraURL,
  disableInstanceDiscovery: true,
});
const secrets = new SecretClient(vaultURL, credential, { disableChallengeResourceVerification: true });

const secretName = "apim-witness-secret";
const secretValue = `planted-by-the-packaged-client-${Date.now()}`;
const written = await secrets.setSecret(secretName, secretValue);
assert.equal(written.value, secretValue, "the packaged client could not write the secret");
console.log(`keyvault witness: @azure/keyvault-secrets wrote ${secretName} through the 401 challenge`);

// --- apim is asked to retrieve it ------------------------------------------

async function arm(path, method, body) {
  const response = await fetch(`${apimURL}${path}?api-version=${apiVersion}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  if (response.status >= 400) {
    throw new Error(`${method} ${path} -> ${response.status} ${text}`);
  }
  return text ? JSON.parse(text) : null;
}

const base = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/emulator-rg" +
  "/providers/Microsoft.ApiManagement/service/emulator";

// The versionless identifier, which is the form that makes rotation work and
// the form a tenant is most often given.
const secretIdentifier = `${vaultURL}/secrets/${secretName}`;

const created = await arm(`${base}/namedValues/vault-backed`, "PUT", {
  properties: {
    displayName: "vault-backed",
    secret: true,
    keyVault: { secretIdentifier },
  },
});

// --- what the retrieval actually did ---------------------------------------

const status = created?.properties?.keyVault?.lastStatus ?? {};
assert.equal(status.code, "Success",
  `apim could not retrieve the secret: ${status.code} ${status.message ?? ""}`);
console.log(`keyvault witness: apim resolved the reference, lastStatus=${status.code}`);

// The value itself, which is the only thing that proves the whole chain rather
// than a status field apim wrote about its own attempt.
const listed = await arm(`${base}/namedValues/vault-backed/listValue`, "POST");
assert.equal(listed.value, secretValue,
  "apim returned a different value than the packaged client wrote");

console.log(
  `keyvault witness: the value apim served is byte-for-byte the one ` +
  `@azure/keyvault-secrets wrote, fetched through a real 401 challenge and a ` +
  `real Entra token`,
);
