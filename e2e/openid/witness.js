// validate-jwt openid-config witness: a real OpenID Connect provider.
//
// The emulator is the RELYING PARTY here, so the counterparty has to be a real
// issuer. `oidc-provider` is an OpenID Certified implementation: it publishes a
// genuine discovery document and JWKS, picks its own `kid`, and mints tokens
// signed with keys this repository never sees. If our discovery parsing, key
// selection or signature verification diverges from what a real provider emits,
// its token does not validate here.
//
// What a hand-rolled fake would let us get away with, and this does not:
//   * the JWKS carries MORE THAN ONE key, so a `kid` lookup that ignored `kid`
//     and simply tried the only key present would pass. Here it must choose.
//   * the discovery document is the provider's own, not a fixture, so a missing
//     or renamed field is its shape rather than ours.
//   * the token is minted by the provider, so `iss`, `aud` and `exp` are what
//     it decided, not what we asserted.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPair, exportJWK } from "jose";

const endpoint = process.env.APIM_ENDPOINT;
const gateway = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const subscriptionId = process.env.APIM_SUBSCRIPTION_ID;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;
const apiVersion = "2024-05-01";

const { default: Provider } = await import("oidc-provider");

// Count what the emulator actually asks the provider for. A policy that merely
// PARSED the url without dereferencing it would leave these at zero.
const fetched = { discovery: 0, jwks: 0 };

// ---------------------------------------------------------------------------
// A real OpenID Connect provider, with two signing keys so `kid` selection is
// actually exercised rather than being the only option.
const RESOURCE = "https://witness.api";
const first = await generateKeyPair("RS256", { extractable: true });
const second = await generateKeyPair("RS256", { extractable: true });
const jwks = {
  keys: [
    { ...(await exportJWK(first.privateKey)), kid: "witness-key-a", alg: "RS256", use: "sig" },
    { ...(await exportJWK(second.privateKey)), kid: "witness-key-b", alg: "RS256", use: "sig" },
  ],
};

// The issuer must be known before the Provider is built, because it bakes it
// into the discovery document, so the port is bound first and the handler
// attached afterwards.
let handler = (_req, res) => {
  res.statusCode = 503;
  res.end();
};
const app = createServer((req, res) => {
  if (req.url.startsWith("/.well-known/openid-configuration")) fetched.discovery += 1;
  if (req.url.startsWith("/jwks")) fetched.jwks += 1;
  handler(req, res);
});
await new Promise((resolve) => app.listen(0, "127.0.0.1", resolve));
const issuer = `http://127.0.0.1:${app.address().port}`;

const provider = new Provider(issuer, {
  jwks,
  clients: [
    {
      client_id: "witness-client",
      client_secret: "witness-secret",
      grant_types: ["client_credentials"],
      redirect_uris: [],
      response_types: [],
    },
  ],
  features: {
    clientCredentials: { enabled: true },
    resourceIndicators: {
      enabled: true,
      defaultResource: () => RESOURCE,
      getResourceServerInfo: () => ({
        scope: "read",
        audience: RESOURCE,
        accessTokenFormat: "jwt",
        accessTokenTTL: 300,
      }),
    },
  },
});

handler = provider.callback();

const discoveryURL = `${issuer}/.well-known/openid-configuration`;
const discovery = await (await fetch(discoveryURL)).json();
assert.equal(discovery.issuer, issuer, "the provider publishes its own issuer");
assert.ok(discovery.jwks_uri, "the provider publishes a jwks_uri");

async function mintToken() {
  const response = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from("witness-client:witness-secret").toString("base64")}`,
    },
    body: new URLSearchParams({ grant_type: "client_credentials", resource: RESOURCE, scope: "read" }),
  });
  const body = await response.json();
  assert.ok(body.access_token, `token endpoint returned ${JSON.stringify(body)}`);
  const [header] = body.access_token.split(".");
  const decoded = JSON.parse(Buffer.from(header, "base64url").toString());
  assert.equal(decoded.alg, "RS256", "the provider signs with RS256");
  assert.ok(decoded.kid, "the provider names the key it signed with");
  return body.access_token;
}


// ---------------------------------------------------------------------------
// A backend the gateway can reach, so a 200 means the policy let the call
// through rather than something else answering.
const backend = createServer((_req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true }));
});
await new Promise((resolve) => backend.listen(0, "127.0.0.1", resolve));
const backendURL = `http://127.0.0.1:${backend.address().port}`;

async function arm(path, method, body) {
  const response = await fetch(`${endpoint}${path}?api-version=${apiVersion}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status >= 400) {
    throw new Error(`${method} ${path} -> ${response.status} ${await response.text()}`);
  }
  return response.status === 204 ? null : response.json();
}

const base = `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.ApiManagement/service/${serviceName}`;

await arm(`${base}/apis/guarded`, "PUT", {
  properties: { displayName: "Guarded", path: "guarded", serviceUrl: backendURL, protocols: ["https"], subscriptionRequired: false },
});
await arm(`${base}/apis/guarded/operations/get`, "PUT", {
  properties: { displayName: "get", method: "GET", urlTemplate: "/" },
});

// The policy under test. No <issuers> is given on purpose: the reference says
// the issuer comes from the configuration endpoint, so the emulator must take
// it from there and still reject a token from anywhere else.
await arm(`${base}/apis/guarded/policies/policy`, "PUT", {
  properties: {
    format: "rawxml",
    value: `<policies><inbound><validate-jwt failed-validation-httpcode="401">
      <openid-config url="${discoveryURL}" />
      <audiences><audience>${RESOURCE}</audience></audiences>
    </validate-jwt></inbound><backend><forward-request /></backend></policies>`,
  },
});

async function call(token) {
  const response = await fetch(`${gateway}/guarded`, {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
  return response.status;
}

// A token the provider minted is accepted.
const token = await mintToken();
assert.equal(await call(token), 200, "a token from the real provider was rejected");

// The emulator must have DEREFERENCED the url, not merely parsed it. Both
// counters come from the provider's own server, so this cannot be satisfied by
// anything the emulator asserts about itself.
assert.ok(fetched.discovery > 0, "the discovery document was never fetched");
assert.ok(fetched.jwks > 0, "the JWKS was never fetched");

// Negatives. Each one is a token that differs from the accepted one in exactly
// one respect, so a pass here means that respect is actually checked.
const [header, payload, signature] = token.split(".");
const flipped = signature.startsWith("A") ? `B${signature.slice(1)}` : `A${signature.slice(1)}`;
assert.equal(await call(`${header}.${payload}.${flipped}`), 401, "a tampered signature was accepted");
assert.equal(await call("not-a-jwt"), 401, "a malformed token was accepted");
assert.equal(await call(), 401, "a request with no token was accepted");

// A token signed by a key the provider does not publish. Same issuer, same
// audience, same shape: only the signing key differs, so this fails only if the
// JWKS is genuinely consulted.
const { SignJWT } = await import("jose");
const stranger = await generateKeyPair("RS256", { extractable: true });
const forged = await new SignJWT({ aud: RESOURCE, iss: issuer })
  .setProtectedHeader({ alg: "RS256", kid: "witness-key-a" })
  .setIssuedAt()
  .setExpirationTime("5m")
  .sign(stranger.privateKey);
assert.equal(await call(forged), 401, "a token signed by an unpublished key was accepted");

// An expired token from the real provider.
const expired = await new SignJWT({ aud: RESOURCE, iss: issuer })
  .setProtectedHeader({ alg: "RS256", kid: "witness-key-a" })
  .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
  .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
  .sign(first.privateKey);
assert.equal(await call(expired), 401, "an expired token was accepted");

// ---------------------------------------------------------------------------
// require-scheme and output-token-variable-name, against the same real tokens.
await arm(`${base}/apis/guarded/policies/policy`, "PUT", {
  properties: {
    format: "rawxml",
    value: `<policies><inbound><validate-jwt failed-validation-httpcode="401" require-scheme="Bearer" output-token-variable-name="jwt">
      <openid-config url="${discoveryURL}" />
      <audiences><audience>${RESOURCE}</audience></audiences>
    </validate-jwt>
    </inbound><backend><forward-request /></backend>
    <outbound><set-header name="X-Token-Subject" exists-action="override"><value>@(((Jwt)context.Variables["jwt"]).Subject)</value></set-header></outbound></policies>`,
  },
});

async function callWith(scheme, value) {
  return fetch(`${gateway}/guarded`, { headers: { authorization: `${scheme} ${value}` } });
}

const fresh = await mintToken();
const accepted = await callWith("Bearer", fresh);
assert.equal(accepted.status, 200, "the required scheme was rejected");
// The Jwt object reached a later policy, which is what storing it is for. The
// provider decides the subject, so this is its value and not one we asserted.
const subject = accepted.headers.get("x-token-subject");
assert.ok(subject && subject.length > 0, `output-token-variable-name produced ${subject}`);

const wrongScheme = await callWith("Token", fresh);
assert.equal(wrongScheme.status, 401, "a scheme other than the required one was accepted");

console.log(`openid-config witness: provider at ${issuer}, discovery fetched ${fetched.discovery}x, jwks ${fetched.jwks}x`);
backend.close();
app.close();
process.exit(0);
