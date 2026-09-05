import { ApiManagementClient } from "@azure/arm-apimanagement";

// The ARM document families, asked of Microsoft's packaged JavaScript client.
//
// ITS OWN SUITE AND ITS OWN CI JOB, for the reason every other witness here has
// one: a break in the ARM round-trips must not hide inside a job that also
// covers workspaces, RBAC and gateways. It is also what keeps the ledger
// honest. A `ci:` witness resolves to a workflow JOB, so that job name is the
// finest thing a claim can cite, and hanging twenty-odd rows off one broad job
// says less about each of them than a job that exists only for these.

const credential = {
  async getToken() {
    return { token: "sdk-token", expiresOnTimestamp: Date.now() + 3600000 };
  },
};

const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;
const client = new ApiManagementClient(credential, process.env.APIM_SUBSCRIPTION_ID, {
  endpoint: process.env.APIM_ENDPOINT,
});

await client.apiManagementService.beginCreateOrUpdateAndWait(resourceGroup, serviceName, {
  location: "local",
  sku: { name: "Developer", capacity: 1 },
  publisherName: "ARM Documents Witness",
  publisherEmail: "arm-documents@example.test",
});

// ---------------------------------------------------------------------------
// THE ARM RESOURCE FAMILIES, THROUGH MICROSOFT'S PACKAGED CLIENT
//
// WHY THIS SECTION EXISTS. Every "canonical <family> ARM documents" row in the
// parity ledger was witnessed only by `armapimanagement` linked INTO our own
// Go test binary. That is Microsoft's client, so it is real evidence, but it is
// evidence gathered in our process, by our harness, against our types. The
// family's own taxonomy ranks it below a packaged client run in CI for exactly
// that reason, and apim had 24 green rows resting on it.
//
// This section is the same claim, asked of `@azure/arm-apimanagement` installed
// from npm and driven by node. Nothing about the emulator is shaped for it.
//
// WHAT EACH FAMILY IS ASKED. The ledger's rows say "lossless PUT/GET/list" and
// "round-trip", so touching the endpoint is not the claim. Each family is
// created, read back, and listed, and the assertions are:
//
//   1. the canonical ARM triple — `id`, `name` and `type` — because a document
//      that round-trips its properties but reports the wrong `type` is not the
//      resource ARM says it is, and a client that navigates by id follows it
//      nowhere;
//   2. a property the caller set, read back from GET rather than from the
//      create response, since a create that echoes its input proves only that
//      the request was parsed;
//   3. presence in the collection, because a resource GET can resolve while
//      the list projection omits it, and every portal and `az` command reads
//      the list.
const arm = `/subscriptions/${process.env.APIM_SUBSCRIPTION_ID}/resourceGroups/${resourceGroup}/providers/Microsoft.ApiManagement/service/${serviceName}`;

function canonical(doc, family, name, type) {
  const want = `${arm}/${family}/${name}`;
  if (doc.id !== want) {
    throw new Error(`${family}/${name}: id = ${doc.id}, want ${want}`);
  }
  if (doc.name !== name) {
    throw new Error(`${family}/${name}: name = ${doc.name}`);
  }
  if (doc.type !== type) {
    throw new Error(`${family}/${name}: type = ${doc.type}, want ${type}`);
  }
}

async function collect(pager) {
  const items = [];
  for await (const item of pager) items.push(item);
  return items;
}

const families = [
  {
    family: "apis",
    type: "Microsoft.ApiManagement/service/apis",
    name: "js-arm-api",
    create: (id) => client.api.beginCreateOrUpdateAndWait(resourceGroup, serviceName, id, {
      displayName: "JS ARM API", path: "js-arm", serviceUrl: process.env.APIM_BACKEND_URL,
      protocols: ["https"], description: "packaged client",
    }),
    get: (id) => client.api.get(resourceGroup, serviceName, id),
    list: () => client.api.listByService(resourceGroup, serviceName),
    check: (doc) => doc.path === "js-arm",
  },
  {
    family: "apis/js-arm-api/operations",
    type: "Microsoft.ApiManagement/service/apis/operations",
    name: "js-arm-op",
    create: (id) => client.apiOperation.createOrUpdate(resourceGroup, serviceName, "js-arm-api", id, {
      displayName: "JS ARM Operation", method: "GET", urlTemplate: "/things",
    }),
    get: (id) => client.apiOperation.get(resourceGroup, serviceName, "js-arm-api", id),
    list: () => client.apiOperation.listByApi(resourceGroup, serviceName, "js-arm-api"),
    check: (doc) => doc.method === "GET" && doc.urlTemplate === "/things",
  },
  {
    family: "namedValues",
    type: "Microsoft.ApiManagement/service/namedValues",
    name: "js-arm-named-value",
    create: (id) => client.namedValue.beginCreateOrUpdateAndWait(resourceGroup, serviceName, id, {
      displayName: "JsArmNamedValue", value: "packaged client",
    }),
    get: (id) => client.namedValue.get(resourceGroup, serviceName, id),
    list: () => client.namedValue.listByService(resourceGroup, serviceName),
    check: (doc) => doc.displayName === "JsArmNamedValue",
  },
  {
    family: "subscriptions",
    type: "Microsoft.ApiManagement/service/subscriptions",
    name: "js-arm-subscription",
    create: (id) => client.subscription.createOrUpdate(resourceGroup, serviceName, id, {
      displayName: "JS ARM Subscription", scope: `${arm}/apis/js-arm-api`,
    }),
    get: (id) => client.subscription.get(resourceGroup, serviceName, id),
    list: () => client.subscription.list(resourceGroup, serviceName),
    check: (doc) => doc.displayName === "JS ARM Subscription",
  },
  {
    family: "products",
    type: "Microsoft.ApiManagement/service/products",
    name: "js-product",
    create: (id) => client.product.createOrUpdate(resourceGroup, serviceName, id, {
      displayName: "JS Product", description: "packaged client", subscriptionRequired: true,
    }),
    get: (id) => client.product.get(resourceGroup, serviceName, id),
    list: () => client.product.listByService(resourceGroup, serviceName),
    check: (doc) => doc.description === "packaged client",
  },
  {
    family: "groups",
    type: "Microsoft.ApiManagement/service/groups",
    name: "js-group",
    create: (id) => client.group.createOrUpdate(resourceGroup, serviceName, id, {
      displayName: "JS Group", description: "packaged client",
    }),
    get: (id) => client.group.get(resourceGroup, serviceName, id),
    list: () => client.group.listByService(resourceGroup, serviceName),
    check: (doc) => doc.description === "packaged client",
  },
  {
    family: "apiVersionSets",
    type: "Microsoft.ApiManagement/service/apiVersionSets",
    name: "js-version-set",
    create: (id) => client.apiVersionSet.createOrUpdate(resourceGroup, serviceName, id, {
      displayName: "JS Version Set", versioningScheme: "Segment",
    }),
    get: (id) => client.apiVersionSet.get(resourceGroup, serviceName, id),
    list: () => client.apiVersionSet.listByService(resourceGroup, serviceName),
    check: (doc) => doc.versioningScheme === "Segment",
  },
  {
    family: "tags",
    type: "Microsoft.ApiManagement/service/tags",
    name: "js-tag",
    create: (id) => client.tag.createOrUpdate(resourceGroup, serviceName, id, { displayName: "JS Tag" }),
    get: (id) => client.tag.get(resourceGroup, serviceName, id),
    list: () => client.tag.listByService(resourceGroup, serviceName),
    check: (doc) => doc.displayName === "JS Tag",
  },
  {
    family: "users",
    type: "Microsoft.ApiManagement/service/users",
    name: "js-user",
    create: (id) => client.user.createOrUpdate(resourceGroup, serviceName, id, {
      firstName: "Packaged", lastName: "Client", email: "packaged.client@example.test",
    }),
    get: (id) => client.user.get(resourceGroup, serviceName, id),
    list: () => client.user.listByService(resourceGroup, serviceName),
    check: (doc) => doc.email === "packaged.client@example.test",
  },
  {
    family: "backends",
    type: "Microsoft.ApiManagement/service/backends",
    name: "js-backend",
    create: (id) => client.backend.createOrUpdate(resourceGroup, serviceName, id, {
      protocol: "http", url: process.env.APIM_BACKEND_URL, description: "packaged client",
    }),
    get: (id) => client.backend.get(resourceGroup, serviceName, id),
    list: () => client.backend.listByService(resourceGroup, serviceName),
    check: (doc) => doc.protocol === "http",
  },
  {
    family: "caches",
    type: "Microsoft.ApiManagement/service/caches",
    name: "js-cache",
    create: (id) => client.cache.createOrUpdate(resourceGroup, serviceName, id, {
      connectionString: "redis.example.test:6380", useFromLocation: "local", description: "packaged client",
    }),
    get: (id) => client.cache.get(resourceGroup, serviceName, id),
    list: () => client.cache.listByService(resourceGroup, serviceName),
    check: (doc) => doc.useFromLocation === "local",
  },
  {
    family: "identityProviders",
    type: "Microsoft.ApiManagement/service/identityProviders",
    name: "aad",
    create: (id) => client.identityProvider.createOrUpdate(resourceGroup, serviceName, id, {
      clientId: "packaged-client-id", clientSecret: "packaged-client-secret",
    }),
    get: (id) => client.identityProvider.get(resourceGroup, serviceName, id),
    list: () => client.identityProvider.listByService(resourceGroup, serviceName),
    check: (doc) => doc.clientId === "packaged-client-id",
  },
  {
    family: "openidConnectProviders",
    type: "Microsoft.ApiManagement/service/openidConnectProviders",
    name: "js-oidc",
    create: (id) => client.openIdConnectProvider.createOrUpdate(resourceGroup, serviceName, id, {
      displayName: "JS OIDC", metadataEndpoint: "https://oidc.example.test/.well-known/openid-configuration",
      clientId: "packaged-client-id",
    }),
    get: (id) => client.openIdConnectProvider.get(resourceGroup, serviceName, id),
    list: () => client.openIdConnectProvider.listByService(resourceGroup, serviceName),
    check: (doc) => doc.clientId === "packaged-client-id",
  },
  {
    family: "authorizationServers",
    type: "Microsoft.ApiManagement/service/authorizationServers",
    name: "js-authorization-server",
    create: (id) => client.authorizationServer.createOrUpdate(resourceGroup, serviceName, id, {
      displayName: "JS Authorization Server",
      clientRegistrationEndpoint: "https://auth.example.test/register",
      authorizationEndpoint: "https://auth.example.test/authorize",
      grantTypes: ["authorizationCode"],
      clientId: "packaged-client-id",
    }),
    get: (id) => client.authorizationServer.get(resourceGroup, serviceName, id),
    list: () => client.authorizationServer.listByService(resourceGroup, serviceName),
    check: (doc) => (doc.grantTypes ?? []).includes("authorizationCode"),
  },
  {
    family: "loggers",
    type: "Microsoft.ApiManagement/service/loggers",
    name: "js-logger",
    create: (id) => client.logger.createOrUpdate(resourceGroup, serviceName, id, {
      loggerType: "applicationInsights", description: "packaged client",
      credentials: { instrumentationKey: "packaged-key" },
    }),
    get: (id) => client.logger.get(resourceGroup, serviceName, id),
    list: () => client.logger.listByService(resourceGroup, serviceName),
    check: (doc) => doc.loggerType === "applicationInsights",
  },
  {
    // A LONG-RUNNING create, so the client polls rather than reading the first
    // response. `beginCreateOrUpdateAndWait` is the whole point of listing it
    // here: a hand-rolled PUT would pass against a response no poller accepts.
    family: "schemas",
    type: "Microsoft.ApiManagement/service/schemas",
    name: "js-global-schema",
    create: (id) => client.globalSchema.beginCreateOrUpdateAndWait(resourceGroup, serviceName, id, {
      schemaType: "json",
      description: "packaged client",
      document: { type: "object", properties: { id: { type: "string" } } },
    }),
    get: (id) => client.globalSchema.get(resourceGroup, serviceName, id),
    list: () => client.globalSchema.listByService(resourceGroup, serviceName),
    check: (doc) => doc.schemaType === "json" && doc.document?.type === "object",
  },
  {
    // The last family still resting on `go:` witnesses alone, i.e. on the
    // emulator agreeing with its own client. `documentation` is a first-class
    // operation group in the packaged SDK, so there was never a reason for it
    // to be the exception; it was simply missed when the other nineteen moved.
    family: "documentations",
    type: "Microsoft.ApiManagement/service/documentations",
    name: "js-documentation",
    create: (id) => client.documentation.createOrUpdate(resourceGroup, serviceName, id, {
      title: "Packaged client documentation",
      content: "# Written by the packaged client",
    }),
    get: (id) => client.documentation.get(resourceGroup, serviceName, id),
    list: () => client.documentation.listByService(resourceGroup, serviceName),
    check: (doc) => doc.title === "Packaged client documentation"
      && (doc.content ?? "").startsWith("# Written by"),
  },
  {
    family: "diagnostics",
    type: "Microsoft.ApiManagement/service/diagnostics",
    name: "applicationinsights",
    create: (id) => client.diagnostic.createOrUpdate(resourceGroup, serviceName, id, {
      loggerId: `${arm}/loggers/js-logger`, alwaysLog: "allErrors",
    }),
    get: (id) => client.diagnostic.get(resourceGroup, serviceName, id),
    list: () => client.diagnostic.listByService(resourceGroup, serviceName),
    check: (doc) => doc.alwaysLog === "allErrors",
  },
  {
    family: "apis/js-arm-api/schemas",
    type: "Microsoft.ApiManagement/service/apis/schemas",
    name: "js-schema",
    create: (id) => client.apiSchema.beginCreateOrUpdateAndWait(
      resourceGroup, serviceName, "js-arm-api", id,
      { contentType: "application/vnd.ms-azure-apim.xsd+xml", value: "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"/>" },
    ),
    get: (id) => client.apiSchema.get(resourceGroup, serviceName, "js-arm-api", id),
    list: () => client.apiSchema.listByApi(resourceGroup, serviceName, "js-arm-api"),
    check: (doc) => (doc.contentType ?? "").includes("xsd+xml"),
  },
  {
    family: "apis/js-arm-api/releases",
    type: "Microsoft.ApiManagement/service/apis/releases",
    name: "js-release",
    create: (id) => client.apiRelease.createOrUpdate(
      resourceGroup, serviceName, "js-arm-api", id,
      { apiId: `${arm}/apis/js-arm-api`, notes: "packaged client" },
    ),
    get: (id) => client.apiRelease.get(resourceGroup, serviceName, "js-arm-api", id),
    list: () => client.apiRelease.listByService(resourceGroup, serviceName, "js-arm-api"),
    check: (doc) => doc.notes === "packaged client",
  },
];

for (const spec of families) {
  await spec.create(spec.name);
  const doc = await spec.get(spec.name);
  canonical(doc, spec.family, spec.name, spec.type);
  if (!spec.check(doc)) {
    throw new Error(`${spec.family}/${spec.name}: GET lost a property the caller set: ${JSON.stringify(doc)}`);
  }
  const listed = await collect(spec.list());
  const found = listed.find((item) => item.name === spec.name);
  if (!found) {
    throw new Error(`${spec.family}/${spec.name}: created and readable, but absent from the collection`);
  }
  canonical(found, spec.family, spec.name, spec.type);
}
console.log(`arm-documents witness: ${families.length} ARM resource families round-trip through the packaged client, id/name/type and list projection included`);

// ---------------------------------------------------------------------------
// CONDITIONAL REQUESTS, THE ERROR ENVELOPE, AND COLLECTION QUERIES
//
// The three cross-cutting ARM rows carried the same in-process-only evidence as
// the families above, and they are the rows most worth asking a packaged client
// about: an SDK is where ETags and error shapes are actually consumed. A client
// that cannot read our `eTag` sends no `If-Match`, and a client that cannot
// parse our error envelope raises something with no `code` for the caller to
// branch on. Neither shows up in a test that reads the HTTP response itself.

// CONDITIONAL REQUESTS. The SDK surfaces the ETag it read and sends it back as
// `ifMatch`, so this is the round trip a real caller makes rather than a header
// we composed.
const conditional = await client.product.get(resourceGroup, serviceName, "js-product");
if (!conditional.eTag) {
  throw new Error("the packaged client saw no ETag on a product, so it can send no If-Match");
}
await client.product.createOrUpdate(
  resourceGroup, serviceName, "js-product",
  { displayName: "JS Product", description: "updated under If-Match", subscriptionRequired: true },
  { ifMatch: conditional.eTag },
);
const updated = await client.product.get(resourceGroup, serviceName, "js-product");
if (updated.description !== "updated under If-Match") {
  throw new Error(`a matching If-Match did not apply the update: ${JSON.stringify(updated)}`);
}

// And the half that matters: a STALE ETag must be refused. Without this the
// check above passes on a service that ignores If-Match entirely, which is the
// failure mode a conditional-request claim exists to rule out.
let stale;
try {
  await client.product.createOrUpdate(
    resourceGroup, serviceName, "js-product",
    { displayName: "JS Product", description: "should not apply", subscriptionRequired: true },
    { ifMatch: '"stale-etag"' },
  );
} catch (error) {
  stale = error;
}
if (!stale || stale.statusCode !== 412) {
  throw new Error(`a stale If-Match was accepted: ${stale?.statusCode ?? "no error"}`);
}
const unchanged = await client.product.get(resourceGroup, serviceName, "js-product");
if (unchanged.description !== "updated under If-Match") {
  throw new Error(`the refused write still landed: ${JSON.stringify(unchanged)}`);
}

// THE ERROR ENVELOPE, as the SDK parses it. The assertion is on `code`, not on
// the status: a 404 with an unparseable body still reaches the caller as an
// error, and every retry and branch a client writes reads the code.
let missing;
try {
  await client.product.get(resourceGroup, serviceName, "js-product-that-was-never-created");
} catch (error) {
  missing = error;
}
if (!missing || missing.statusCode !== 404) {
  throw new Error(`a missing product did not 404: ${missing?.statusCode ?? "no error"}`);
}
if (!missing.code) {
  throw new Error(`the packaged client could not read a code out of the error envelope: ${JSON.stringify(missing.details ?? missing.message)}`);
}

// COLLECTION QUERIES. `$top` is served by the service, so a client that pages
// gets what it asked for rather than the whole collection trimmed locally.
const topped = await collect(client.product.listByService(resourceGroup, serviceName, { top: 1 }));
if (topped.length !== 1) {
  throw new Error(`$top=1 returned ${topped.length} products`);
}
const filtered = await collect(client.product.listByService(resourceGroup, serviceName, {
  filter: "name eq 'js-product'",
}));
if (filtered.length !== 1 || filtered[0].name !== "js-product") {
  throw new Error(`a name filter returned ${JSON.stringify(filtered.map((p) => p.name))}`);
}
console.log("arm-documents witness: If-Match applies and a stale ETag is refused, the error envelope carries a code, and $top/$filter are served");

// ---------------------------------------------------------------------------
// TENANT ACCESS AND THE PUBLIC SETTINGS
//
// These two are singletons rather than collections, so the family loop above
// cannot express them: nothing creates them, `AccessIdName` has exactly two
// members, and `SettingsTypeName` has one. That is also why they are worth
// asking a packaged client about. Four things here are shaped by the generated
// client and by nothing we could have inferred from the REST paths:
//
//   1. `create` and `update` take `ifMatch` as a POSITIONAL, REQUIRED argument.
//      There is no overload without it.
//   2. `create` declares only a 200. A 201 is an undeclared status and the
//      client would fail to deserialize the very response it asked for.
//   3. `get` is typed `AccessInformationContract`, which HAS NO KEY FIELDS.
//      `listSecrets` returns a different type, unwrapped.
//   4. `regeneratePrimaryKey` returns `Promise<void>`: 204, no body.

const beforeSecrets = await client.tenantAccess.listSecrets(resourceGroup, serviceName, "access");
if (!beforeSecrets.primaryKey || !beforeSecrets.secondaryKey) {
  throw new Error(`listSecrets returned no keys: ${JSON.stringify(beforeSecrets)}`);
}

// Both members of the enum exist without anyone creating them.
const accessNames = (await collect(client.tenantAccess.listByService(resourceGroup, serviceName)))
  .map((item) => item.name)
  .sort();
if (accessNames.join(",") !== "access,gitAccess") {
  throw new Error(`tenant access listing = ${JSON.stringify(accessNames)}, want both members of AccessIdName`);
}

let accessBody = "";
const access = await client.tenantAccess.get(resourceGroup, serviceName, "access", {
  onResponse: (raw) => { accessBody = raw.bodyAsText ?? ""; },
});
canonical(access, "tenant", "access", "Microsoft.ApiManagement/service/tenant");
// The GET must not carry key material, and this reads the RAW BODY to say so.
//
// The obvious version of this check -- `"primaryKey" in access` on the object
// the SDK handed back -- is a TAUTOLOGY, and only a negative control showed it.
// `AccessInformationContract` has no key fields, so core-client's deserializer
// drops them before the caller ever sees the response: with the emulator
// deliberately leaking both keys on GET, that check still passed. A client
// being unable to see a leak is not the same as there being none, and it is the
// wire that a proxy, a log or a portal reads.
for (const [label, key] of [["primary", beforeSecrets.primaryKey], ["secondary", beforeSecrets.secondaryKey]]) {
  if (accessBody.includes(key)) {
    throw new Error(`a tenant access GET put the ${label} key on the wire: ${accessBody}`);
  }
}
if (!access.eTag) {
  throw new Error("the packaged client saw no ETag on tenant access, so it can send no If-Match");
}

// `ifMatch` is required and positional. A matching tag applies the write, and
// the response is a 200 the client could deserialize at all.
const created = await client.tenantAccess.create(
  resourceGroup, serviceName, "access", access.eTag, { enabled: true },
);
if (created.enabled !== true) {
  throw new Error(`create did not report the value it set: ${JSON.stringify(created)}`);
}
const reread = await client.tenantAccess.get(resourceGroup, serviceName, "access");
if (reread.enabled !== true) {
  throw new Error(`create did not persist: ${JSON.stringify(reread)}`);
}
await client.tenantAccess.update(resourceGroup, serviceName, "access", reread.eTag, { enabled: false });
if ((await client.tenantAccess.get(resourceGroup, serviceName, "access")).enabled !== false) {
  throw new Error("update did not persist");
}

// The other half, without which the two calls above pass against a service
// that ignores If-Match: a stale tag must be refused.
//
// Note what this canNOT witness: `ifMatch` is a required positional argument,
// so the SDK cannot omit the header, and the 400 that a MISSING If-Match must
// produce is unreachable from here. That half is asserted in the Go suite.
let staleTenant;
try {
  await client.tenantAccess.update(resourceGroup, serviceName, "access", '"stale-etag"', { enabled: true });
} catch (error) {
  staleTenant = error;
}
if (!staleTenant || staleTenant.statusCode !== 412) {
  throw new Error(`a stale If-Match on tenant access was accepted: ${staleTenant?.statusCode ?? "no error"}`);
}

// Regeneration moves exactly one key on exactly one configuration. Asserting
// WHICH key moved is the whole assertion; a check that the call returned would
// pass with every one of these wired to the same row.
const gitBefore = await client.tenantAccess.listSecrets(resourceGroup, serviceName, "gitAccess");
await client.tenantAccess.regeneratePrimaryKey(resourceGroup, serviceName, "access");
const afterPrimary = await client.tenantAccess.listSecrets(resourceGroup, serviceName, "access");
if (afterPrimary.primaryKey === beforeSecrets.primaryKey) {
  throw new Error("regeneratePrimaryKey did not move the primary key");
}
if (afterPrimary.secondaryKey !== beforeSecrets.secondaryKey) {
  throw new Error("regeneratePrimaryKey moved the secondary key as well");
}
await client.tenantAccessGit.regeneratePrimaryKey(resourceGroup, serviceName, "access");
const gitAfter = await client.tenantAccess.listSecrets(resourceGroup, serviceName, "gitAccess");
if (gitAfter.primaryKey === gitBefore.primaryKey) {
  throw new Error("the git regeneration did not move the git primary key");
}
if ((await client.tenantAccess.listSecrets(resourceGroup, serviceName, "access")).primaryKey !== afterPrimary.primaryKey) {
  throw new Error("the git regeneration moved the management key");
}

// The public settings: one settingsType, read-only, and the values a fresh
// service reports.
const settings = await client.tenantSettings.get(resourceGroup, serviceName, "public");
canonical(settings, "settings", "public", "Microsoft.ApiManagement/service/settings");
if (!settings.settings || settings.settings["CustomPortalSettings.DelegationEnabled"] !== "False") {
  throw new Error(`the public settings did not deserialize: ${JSON.stringify(settings)}`);
}
const settingsList = await collect(client.tenantSettings.listByService(resourceGroup, serviceName));
if (settingsList.length !== 1 || settingsList[0].name !== "public") {
  throw new Error(`settings listing = ${JSON.stringify(settingsList.map((s) => s.name))}, want one public entry`);
}
console.log("arm-documents witness: tenant access is a seeded singleton pair whose keys leave only through listSecrets, If-Match is enforced on both writes, each regeneration moves exactly one key, and the public settings deserialize");

// ---------------------------------------------------------------------------
// POLICY RESTRICTIONS, AND THE THREE SERVICE-LEVEL OPERATIONS
//
// PolicyRestriction is ordinary CRUD, so most of it could ride the family loop
// above. It is here instead because the two things worth witnessing are things
// the loop does not look at: the CREATE/REPLACE status distinction, and a field
// whose TYPE is the trap.
//
// `requireBase` is Microsoft's `PolicyRestrictionRequireBase`, an enum whose
// members are the STRINGS "true" and "false", mapped by the generated client as
// a String. Emitting a JSON boolean is the obvious mistake and the SDK is the
// only thing here that can be asked whether it survived the round trip.
let createdStatus = 0;
await client.policyRestriction.createOrUpdate(
  resourceGroup, serviceName, "js-restriction",
  { scope: "/apis", requireBase: "true" },
  { onResponse: (raw) => { createdStatus = raw.status; } },
);
if (createdStatus !== 201) {
  throw new Error(`a first policyRestriction PUT answered ${createdStatus}, want 201`);
}
let replacedStatus = 0;
await client.policyRestriction.createOrUpdate(
  resourceGroup, serviceName, "js-restriction",
  { scope: "/apis", requireBase: "true" },
  { onResponse: (raw) => { replacedStatus = raw.status; } },
);
if (replacedStatus !== 200) {
  throw new Error(`a repeated policyRestriction PUT answered ${replacedStatus}, want 200`);
}

const restriction = await client.policyRestriction.get(resourceGroup, serviceName, "js-restriction");
canonical(restriction, "policyRestrictions", "js-restriction", "Microsoft.ApiManagement/service/policyRestrictions");
// `=== "true"` and not a truthiness check: a boolean `true` on the wire would
// pass the latter and is a different value than the contract names.
if (restriction.requireBase !== "true") {
  throw new Error(`requireBase deserialized as ${JSON.stringify(restriction.requireBase)}, want the string "true"`);
}
if (restriction.scope !== "/apis") {
  throw new Error(`scope = ${JSON.stringify(restriction.scope)}`);
}

// PATCH is a merge, and `ifMatch` is required on it.
await client.policyRestriction.update(
  resourceGroup, serviceName, "js-restriction", restriction.eTag, { scope: "/apis/two" },
);
const merged = await client.policyRestriction.get(resourceGroup, serviceName, "js-restriction");
if (merged.scope !== "/apis/two" || merged.requireBase !== "true") {
  throw new Error(`update did not merge: ${JSON.stringify(merged)}`);
}
const restrictions = await collect(client.policyRestriction.listByService(resourceGroup, serviceName));
if (!restrictions.some((item) => item.name === "js-restriction")) {
  throw new Error("a created restriction is absent from the collection");
}
await client.policyRestriction.delete(resourceGroup, serviceName, "js-restriction");
let deleted;
try {
  await client.policyRestriction.get(resourceGroup, serviceName, "js-restriction");
} catch (error) {
  deleted = error;
}
if (!deleted || deleted.statusCode !== 404) {
  throw new Error(`a deleted restriction still resolves: ${deleted?.statusCode ?? "no error"}`);
}

// checkNameAvailability answers for real rather than always saying yes, and
// BOTH directions are asked. Only the pair rules out a stub.
const taken = await client.apiManagementService.checkNameAvailability({ name: serviceName });
if (taken.nameAvailable !== false || taken.reason !== "AlreadyExists") {
  throw new Error(`the name of the service we just created came back as ${JSON.stringify(taken)}`);
}
const free = await client.apiManagementService.checkNameAvailability({ name: "a-name-nobody-took" });
if (free.nameAvailable !== true || free.reason !== "Valid") {
  throw new Error(`an unused name came back as ${JSON.stringify(free)}`);
}
const invalid = await client.apiManagementService.checkNameAvailability({ name: "-not-a-valid-name-" });
if (invalid.nameAvailable !== false || invalid.reason !== "Invalid") {
  throw new Error(`a name breaking Microsoft's own serviceName pattern came back as ${JSON.stringify(invalid)}`);
}

// The domain ownership identifier is published in a DNS TXT record and checked
// later, so the same subscription must get the same value twice.
const firstIdentifier = await client.apiManagementService.getDomainOwnershipIdentifier();
const secondIdentifier = await client.apiManagementService.getDomainOwnershipIdentifier();
if (!firstIdentifier.domainOwnershipIdentifier) {
  throw new Error("no domain ownership identifier was returned");
}
if (firstIdentifier.domainOwnershipIdentifier !== secondIdentifier.domainOwnershipIdentifier) {
  throw new Error("the domain ownership identifier moved between two calls");
}

// The SSO redirect must be a URI, and one pointing at the host that answered
// rather than at an azure-api.net service that does not exist.
const sso = await client.apiManagementService.getSsoToken(resourceGroup, serviceName);
if (!sso.redirectUri) {
  throw new Error("getSsoToken returned no redirectUri");
}
const redirect = new URL(sso.redirectUri);
if (redirect.host !== new URL(process.env.APIM_ENDPOINT).host) {
  throw new Error(`the SSO redirect points at ${redirect.host}, not at the emulator that issued it`);
}
if (!redirect.searchParams.get("token")) {
  throw new Error(`the SSO redirect carries no token: ${sso.redirectUri}`);
}
console.log("arm-documents witness: policy restrictions create with 201 and replace with 200, requireBase survives as a string, update merges under If-Match, and checkNameAvailability/getDomainOwnershipIdentifier/getSsoToken all answer from real state");
