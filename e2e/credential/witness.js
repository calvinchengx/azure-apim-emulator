// Credential manager witness: a real OAuth 2.0 authorization server.
//
// The oracle here is inverted from the protocol witnesses. For GraphQL, gRPC
// and SOAP the emulator is the SERVER and a real client grades it. In credential
// manager APIM is the CLIENT, so the counterparty must be a real authorization
// server — and no vendor ships one you can host. GitHub, Google, Dropbox and
// Microsoft all publish *clients*; they ARE the server, in their cloud.
//
// `oidc-provider` is a full OAuth 2.0 / OpenID Connect authorization server. It
// enforces the parts a hand-rolled fake would let us get away with: a code is
// single-use, redirect_uri must match between authorize and redeem, client
// authentication is checked, and a refresh token is only issued when
// offline_access was actually granted.
import { createRequire } from "node:module";
import { createServer } from "node:http";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const { default: Provider } = await import("oidc-provider");

const endpoint = process.env.APIM_ENDPOINT;
const gateway = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const subscriptionId = process.env.APIM_SUBSCRIPTION_ID;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;
const apiVersion = "2024-05-01";

// The redirect the emulator uses for consent. It must match at authorize time
// and at redeem time, which the provider enforces.
const CONSENT_REDIRECT = "http://localhost/apim-credential-consent";

// ---------------------------------------------------------------------------
// A real authorization server.
const ACCOUNT = "witness-user";
const provider = new Provider("http://127.0.0.1:0", {
  clients: [
    {
      client_id: "code-client",
      client_secret: "code-secret",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: [CONSENT_REDIRECT],
      scope: "openid offline_access api.read",
    },
    {
      client_id: "cc-client",
      client_secret: "cc-secret",
      grant_types: ["client_credentials"],
      response_types: [],
      redirect_uris: [],
      scope: "api.read",
    },
  ],
  scopes: ["openid", "offline_access", "api.read"],
  features: {
    clientCredentials: { enabled: true },
    devInteractions: { enabled: false },
    resourceIndicators: { enabled: false },
    // Introspection is how this test asks the authorization server whether it
    // really issued the token the backend received. Without it the witness
    // could only check the token's SHAPE, and a fabricated string would pass.
    introspection: { enabled: true },
  },
  findAccount: async (_ctx, id) => ({ accountId: id, claims: async () => ({ sub: id }) }),
  // Refresh tokens only when offline_access is granted, which is the provider
  // holding us to the spec rather than being generous.
  issueRefreshToken: async (_ctx, client, code) =>
    client.grantTypeAllowed("refresh_token") && code.scopes.has("offline_access"),
});
provider.proxy = true;

// The interaction endpoint is where a human would approve. The TEST plays the
// human; the emulator never does. That separation is the point: an emulator
// that auto-consented would make a flow look complete that in Azure requires
// someone to act.
const app = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const match = url.pathname.match(/^\/interaction\/([^/]+)$/);
  if (match) {
    const details = await provider.interactionDetails(req, res);
    const grant = new provider.Grant({ accountId: ACCOUNT, clientId: details.params.client_id });
    for (const scope of String(details.params.scope ?? "").split(" ").filter(Boolean)) {
      grant.addOIDCScope(scope);
    }
    const grantId = await grant.save();
    await provider.interactionFinished(
      req,
      res,
      { login: { accountId: ACCOUNT }, consent: { grantId } },
      { mergeWithLastSubmission: false },
    );
    return;
  }
  provider.callback()(req, res);
});
await new Promise((resolve) => app.listen(0, "127.0.0.1", resolve));
const issuer = `http://127.0.0.1:${app.address().port}`;

// ---------------------------------------------------------------------------
// A backend that reports the Authorization header it was given.
let seenAuthorization = null;
const backend = createServer((req, res) => {
  seenAuthorization = req.headers.authorization ?? null;
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true }));
});
await new Promise((resolve) => backend.listen(0, "127.0.0.1", resolve));
const backendUrl = `http://127.0.0.1:${backend.address().port}`;

async function arm(path, method, body) {
  const response = await fetch(`${endpoint}${path}?api-version=${apiVersion}`, {
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

const base = `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.ApiManagement/service/${serviceName}`;

async function makeProvider(name, clientId, clientSecret, scopes, grantKey) {
  await arm(`${base}/authorizationProviders/${name}`, "PUT", {
    properties: {
      displayName: name,
      identityProvider: "oauth2",
      oauth2: {
        authorizationEndpoint: `${issuer}/auth`,
        tokenEndpoint: `${issuer}/token`,
        grantTypes: { [grantKey]: { clientId, clientSecret, scopes } },
      },
    },
  });
}

await makeProvider("code-provider", "code-client", "code-secret", "openid offline_access api.read", "authorizationCode");
await makeProvider("cc-provider", "cc-client", "cc-secret", "api.read", "clientCredentials");

// A GET must never echo the client secret back.
const storedProvider = await arm(`${base}/authorizationProviders/code-provider`, "GET");
const storedGrant = storedProvider.properties.oauth2?.grantTypes?.authorizationCode ?? {};
assert.equal(storedGrant.clientSecret, undefined, "the client secret must never be returned by the management plane");

// ---------------------------------------------------------------------------
// 1. CLIENT CREDENTIALS: no human at any point.
await arm(`${base}/authorizationProviders/cc-provider/authorizations/machine`, "PUT", {
  properties: { authorizationType: "OAuth2", oauth2grantType: "ClientCredentials" },
});
const machine = await arm(`${base}/authorizationProviders/cc-provider/authorizations/machine`, "GET");
assert.equal(machine.properties.status, "Connected", "a client-credentials credential needs no consent");

// ---------------------------------------------------------------------------
// 2. AUTHORIZATION CODE: unusable until a person consents.
await arm(`${base}/authorizationProviders/code-provider/authorizations/user`, "PUT", {
  properties: { authorizationType: "OAuth2", oauth2grantType: "AuthorizationCode" },
});
const fresh = await arm(`${base}/authorizationProviders/code-provider/authorizations/user`, "GET");
assert.equal(fresh.properties.status, "Error", "a new authorization-code credential is not connected until consented");
assert.match(fresh.properties.error?.message ?? "", /consent/i, "the reason must name consent");

// The login link is a URL to visit, not a flow the emulator completes itself.
const links = await arm(`${base}/authorizationProviders/code-provider/authorizations/user/getLoginLinks`, "POST", {});
assert.ok(links.loginLink?.startsWith(`${issuer}/auth`), `loginLink = ${links.loginLink}`);
const loginURL = new URL(links.loginLink);
assert.equal(loginURL.searchParams.get("response_type"), "code");
assert.equal(loginURL.searchParams.get("redirect_uri"), CONSENT_REDIRECT);
assert.ok(loginURL.searchParams.get("state"), "the credential must be bound to the request through state");

// The test plays the human: follow the link, complete the interaction, and take
// the code the provider issues.
const jar = new Map();
async function follow(url) {
  for (let hop = 0; hop < 10; hop += 1) {
    const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    const response = await fetch(url, { redirect: "manual", headers: cookie ? { cookie } : {} });
    for (const raw of response.headers.getSetCookie?.() ?? []) {
      const [pair] = raw.split(";");
      const [name, value] = pair.split("=");
      jar.set(name, value);
    }
    const location = response.headers.get("location");
    if (!location) return { url, response };
    const next = new URL(location, url);
    if (next.origin + next.pathname === CONSENT_REDIRECT) return { url: next, response };
    url = next.toString();
  }
  throw new Error("too many redirects completing consent");
}
const consented = await follow(links.loginLink);
const consentCode = consented.url.searchParams.get("code");
assert.ok(consentCode, `the provider must issue a code, got ${consented.url}`);

const confirmed = await arm(
  `${base}/authorizationProviders/code-provider/authorizations/user/confirmConsentCode`,
  "POST",
  { consentCode },
);
assert.equal(confirmed.properties.status, "Connected", "redeeming a valid code must connect the credential");

// ---------------------------------------------------------------------------
// 3. The token reaches the BACKEND and never the caller.
async function makeAPI(name, path, providerName, authorizationName) {
  await arm(`${base}/apis/${name}`, "PUT", {
    properties: { displayName: name, path, serviceUrl: backendUrl, protocols: ["https"], subscriptionRequired: false },
  });
  await arm(`${base}/apis/${name}/operations/call`, "PUT", {
    properties: { displayName: "call", method: "GET", urlTemplate: "/" },
  });
  await arm(`${base}/apis/${name}/policies/policy`, "PUT", {
    properties: {
      format: "xml",
      value:
        `<policies><inbound>` +
        `<get-authorization-context provider-id="${providerName}" authorization-id="${authorizationName}" context-variable-name="auth" ignore-error="false" />` +
        `<set-header name="Authorization" exists-action="override"><value>@("Bearer " + ((Authorization)context.Variables["auth"]).AccessToken)</value></set-header>` +
        `</inbound></policies>`,
    },
  });
}

await makeAPI("machine-api", "machine", "cc-provider", "machine");
await makeAPI("user-api", "user", "code-provider", "user");

for (const [label, path] of [["client credentials", "machine"], ["authorization code", "user"]]) {
  seenAuthorization = null;
  const response = await fetch(`${gateway}/${path}`, { headers: { accept: "application/json" } });
  const text = await response.text();
  assert.equal(response.status, 200, `${label}: gateway returned ${response.status}: ${text}`);

  // The credential reached the backend.
  assert.ok(seenAuthorization?.startsWith("Bearer "), `${label}: backend saw ${JSON.stringify(seenAuthorization)}`);
  const token = seenAuthorization.slice("Bearer ".length);
  assert.ok(token.length > 20, `${label}: token looks empty`);

  // And the provider agrees it issued it. This is the assertion that makes the
  // whole thing a witness rather than a shape check: a fabricated token would
  // pass every test above and fail here.
  const introspection = await fetch(`${issuer}/token/introspection`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: "Basic " + Buffer.from(
        path === "machine" ? "cc-client:cc-secret" : "code-client:code-secret",
      ).toString("base64"),
    },
    body: new URLSearchParams({ token }),
  });
  const introspected = await introspection.json();
  assert.equal(introspected.active, true, `${label}: the authorization server does not recognise the token`);

  // The CALLER never sees it. This is the property credential manager sells.
  assert.ok(!text.includes(token), `${label}: the response body leaked the access token`);
  for (const [name, value] of response.headers) {
    assert.ok(!String(value).includes(token), `${label}: header ${name} leaked the access token`);
  }
}

// ---------------------------------------------------------------------------
// 4. A credential that does not exist fails the call rather than sending it
//    uncredentialed, which would reach the backend as an anonymous request.
await arm(`${base}/apis/broken-api`, "PUT", {
  properties: { displayName: "broken", path: "broken", serviceUrl: backendUrl, protocols: ["https"], subscriptionRequired: false },
});
await arm(`${base}/apis/broken-api/operations/call`, "PUT", {
  properties: { displayName: "call", method: "GET", urlTemplate: "/" },
});
await arm(`${base}/apis/broken-api/policies/policy`, "PUT", {
  properties: {
    format: "xml",
    value:
      `<policies><inbound>` +
      `<get-authorization-context provider-id="cc-provider" authorization-id="absent" context-variable-name="auth" ignore-error="false" />` +
      `</inbound></policies>`,
  },
});
seenAuthorization = null;
const broken = await fetch(`${gateway}/broken`);
assert.ok(broken.status >= 400, `a missing credential returned ${broken.status}`);
assert.equal(seenAuthorization, null, "a request whose credential could not be resolved must not reach the backend");

// ---------------------------------------------------------------------------
// 5. A code is single-use, asserted LAST and on its OWN credential.
//
// Ordering is load-bearing here and cost several debugging rounds to learn:
// a conforming authorization server treats code replay as an attack and
// REVOKES every token issued from that code (RFC 6819). Replaying earlier, on
// the credential the API calls use, silently invalidated a token the emulator
// had stored correctly, and the failure looked exactly like an emulator bug.
await arm(`${base}/authorizationProviders/code-provider/authorizations/replay`, "PUT", {
  properties: { authorizationType: "OAuth2", oauth2grantType: "AuthorizationCode" },
});
const replayLinks = await arm(`${base}/authorizationProviders/code-provider/authorizations/replay/getLoginLinks`, "POST", {});
const replayLanded = await follow(replayLinks.loginLink);
const replayCode = replayLanded.url.searchParams.get("code");
await arm(`${base}/authorizationProviders/code-provider/authorizations/replay/confirmConsentCode`, "POST", { consentCode: replayCode });

let replayFailed = false;
try {
  await arm(`${base}/authorizationProviders/code-provider/authorizations/replay/confirmConsentCode`, "POST", { consentCode: replayCode });
} catch {
  replayFailed = true;
}
assert.ok(replayFailed, "replaying a consumed authorization code must fail: the provider issues it once");

backend.close();
app.close();
console.log("credential witness: both grants, real code exchange, single-use codes, provider-verified tokens, and no leak to the caller");
