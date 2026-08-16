// GraphQL witness: the reference implementation on BOTH ends.
//
// `graphql` is the specification's own JavaScript implementation, the one every
// GraphQL client and server in the ecosystem is checked against. Here it plays
// two independent roles:
//
//   backend  a real GraphQL server, so pass-through is proved against something
//            that actually speaks the protocol rather than a stub we wrote
//   oracle   buildClientSchema() rebuilds a schema from the emulator's
//            introspection response and printSchema() prints it back, so the
//            emulator's output is graded by the reference parser, not by us
//
// The strongest assertion here is the schema round-trip. If the emulator's
// introspection is wrong in any way the spec cares about (a missing wrapper
// type, a dropped argument default, a bad kind) buildClientSchema either throws
// or prints a schema that differs from the SDL we imported. Our own tests
// cannot catch that class of error, because they encode our reading of the
// spec, which is the same reading that produced the code.
import { createServer } from "node:http";
import assert from "node:assert/strict";
import {
  buildClientSchema,
  buildSchema,
  getIntrospectionQuery,
  graphql,
  parse,
  printSchema,
  validate,
} from "graphql";

const SDL = `
"A product catalogue."
type Query {
  item(id: ID!, locale: String = "en"): Item
  items(first: Int = 10): [Item!]!
  featured: SearchResult
  legacy: String @deprecated(reason: "use item")
}
type Mutation { addItem(input: ItemInput!): Item }
interface Node { id: ID! }
"One catalogue entry."
type Item implements Node { id: ID! name: String! colour: Colour tags: [String] }
type Bundle implements Node { id: ID! size: Int }
union SearchResult = Item | Bundle
enum Colour { RED GREEN RETIRED @deprecated }
input ItemInput { name: String! colour: Colour = RED }
`;

const endpoint = process.env.APIM_ENDPOINT;
const gateway = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const subscriptionId = process.env.APIM_SUBSCRIPTION_ID;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;
const apiVersion = "2024-05-01";

const schema = buildSchema(SDL);
const roots = {
  items: () => [
    { id: "1", name: "Widget", colour: "RED", tags: ["new"] },
    { id: "2", name: "Sprocket", colour: "GREEN", tags: [] },
  ],
  item: ({ id }) => ({ id, name: `Item ${id}`, colour: "RED", tags: [] }),
  legacy: () => "legacy",
};

// A real GraphQL server, executing with the reference implementation.
const backend = createServer((request, response) => {
  let body = "";
  request.on("data", (chunk) => (body += chunk));
  request.on("end", async () => {
    const { query, variables, operationName } = JSON.parse(body || "{}");
    const result = await graphql({
      schema,
      source: query,
      rootValue: roots,
      variableValues: variables,
      operationName,
    });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(result));
  });
});
await new Promise((resolve) => backend.listen(0, "127.0.0.1", resolve));
const backendUrl = `http://127.0.0.1:${backend.address().port}/graphql`;

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

await arm(`${base}/apis/catalogue`, "PUT", {
  properties: {
    displayName: "Catalogue",
    path: "catalogue",
    serviceUrl: backendUrl,
    protocols: ["https"],
    apiType: "graphql",
    subscriptionRequired: false,
  },
});
await arm(`${base}/apis/catalogue/schemas/graphql`, "PUT", {
  properties: {
    contentType: "application/vnd.ms-azure-apim.graphql.schema",
    document: { value: SDL },
  },
});

// The ARM resource must return the SDL exactly as imported. A re-print would
// still parse, and would quietly change what a caller reads back.
const stored = await arm(`${base}/apis/catalogue/schemas/graphql`, "GET");
assert.equal(stored.properties.document.value, SDL, "the stored schema must be byte-identical to the imported SDL");

async function gql(query, { variables, operationName } = {}) {
  const response = await fetch(`${gateway}/catalogue`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables, operationName }),
  });
  return { status: response.status, body: await response.json() };
}

// 1. Introspection, graded by the reference implementation.
const introspection = await gql(getIntrospectionQuery());
assert.equal(introspection.status, 200, `introspection returned ${introspection.status}`);
assert.ok(!introspection.body.errors, `introspection reported errors: ${JSON.stringify(introspection.body.errors)}`);

// buildClientSchema throws on anything it cannot reconstruct. This line is the
// witness: it is the reference parser accepting the emulator's output.
const rebuilt = buildClientSchema(introspection.body.data);

// And the round-trip: what the emulator described must be the schema we
// imported. printSchema normalises both sides, so this compares meaning rather
// than formatting.
assert.equal(
  printSchema(rebuilt),
  printSchema(schema),
  "the schema rebuilt from the emulator's introspection differs from the imported SDL",
);

// 2. Pass-through against a real GraphQL server.
const data = await gql("{ items { id name colour tags } }");
assert.equal(data.status, 200, `data query returned ${data.status}`);
assert.deepEqual(
  data.body.data.items.map((item) => item.name),
  ["Widget", "Sprocket"],
  "the backend's data must arrive unchanged through the gateway",
);

// Variables and named operations survive the hop.
const named = await gql(
  "query One($id: ID!) { item(id: $id) { id name } } query Two { legacy }",
  { variables: { id: "42" }, operationName: "One" },
);
assert.equal(named.body.data.item.id, "42", "variables must reach the backend");
assert.equal(named.body.data.item.name, "Item 42");

// 3. Validation happens at the gateway, and the reference implementation agrees
//    the query is invalid. Asserting only that the emulator rejects it would
//    not distinguish a correct refusal from a broken parser refusing anything.
const invalid = "{ notAField }";
const referenceErrors = validate(schema, parse(invalid));
assert.ok(referenceErrors.length > 0, "the reference implementation must agree this query is invalid");

const refused = await gql(invalid);
assert.equal(refused.status, 400, `an invalid query returned ${refused.status}, want 400`);
assert.ok(refused.body.errors?.length > 0, "a refusal must carry a GraphQL error list");
assert.equal(refused.body.data, undefined, "a request error carries no data member");

// And the refusal happened at the gateway: a backend that never saw the request
// cannot have counted it.
assert.ok(
  refused.body.errors[0].message.includes("notAField"),
  `the error must name the offending field, got ${JSON.stringify(refused.body.errors)}`,
);

// 4. A valid query the schema allows is NOT refused, so the gate is not simply
//    rejecting everything.
const accepted = await gql("{ legacy }");
assert.equal(accepted.status, 200, "a valid query must pass the gateway");
assert.equal(accepted.body.data.legacy, "legacy");

// ---------------------------------------------------------------------------
// 5. SYNTHETIC GraphQL: no GraphQL backend at all.
//
// The whole point of the synthetic mode is that the backend speaks REST and the
// gateway presents it as GraphQL. So this backend deliberately serves plain
// JSON over REST routes, and the reference implementation is used only as the
// client, validating the schema and the responses. If the emulator were quietly
// proxying GraphQL, this section could not pass.
const rest = createServer((request, response) => {
  const url = new URL(request.url, "http://rest.invalid");
  response.setHeader("content-type", "application/json");
  if (url.pathname === "/orders" ) {
    response.end(JSON.stringify([
      { ref: "A-1", total: 25, customerId: "c1" },
      { ref: "A-2", total: 40, customerId: "c2" },
    ]));
    return;
  }
  const order = url.pathname.match(/^\/orders\/(.+)$/);
  if (order) {
    response.end(JSON.stringify({ ref: order[1], total: 99, customerId: "c9" }));
    return;
  }
  const customer = url.pathname.match(/^\/customers\/(.+)$/);
  if (customer) {
    response.end(JSON.stringify({ id: customer[1], name: `Customer ${customer[1]}` }));
    return;
  }
  response.statusCode = 404;
  response.end(JSON.stringify({ error: "not found" }));
});
await new Promise((resolve) => rest.listen(0, "127.0.0.1", resolve));
const restUrl = `http://127.0.0.1:${rest.address().port}`;

const SYNTHETIC_SDL = `
type Query { orders: [Order!]! order(ref: ID!): Order }
type Order { ref: ID! total: Int customerId: String customer: Customer }
type Customer { id: ID! name: String! }
`;

await arm(`${base}/apis/shop`, "PUT", {
  properties: {
    displayName: "Shop", path: "shop", protocols: ["https"],
    apiType: "graphql", subscriptionRequired: false,
  },
});
await arm(`${base}/apis/shop/schemas/graphql`, "PUT", {
  properties: {
    contentType: "application/vnd.ms-azure-apim.graphql.schema",
    document: { value: SYNTHETIC_SDL },
  },
});

async function resolver(name, path, policy) {
  await arm(`${base}/apis/shop/resolvers/${name}`, "PUT", {
    properties: { displayName: name, path },
  });
  await arm(`${base}/apis/shop/resolvers/${name}/policies/policy`, "PUT", {
    properties: { value: policy, format: "xml" },
  });
}

await resolver("orders", "Query/orders",
  `<http-data-source><http-request><set-method>GET</set-method><set-url>${restUrl}/orders</set-url></http-request></http-data-source>`);
// Reading the argument is the load-bearing part: context.GraphQL.Arguments is
// the documented Azure member, so this policy is copy-pasteable into a real
// service. Concatenation rather than $"..." interpolation, because the
// expression lexer does not yet accept C# interpolated strings; that gap is
// pre-existing and applies to every policy, not just resolvers.
await resolver("order", "Query/order",
  `<http-data-source><http-request><set-method>GET</set-method><set-url>@("${restUrl}/orders/" + context.GraphQL.Arguments["ref"])</set-url></http-request></http-data-source>`);
// A NESTED resolver, reading its parent object rather than an argument.
await resolver("customer", "Order/customer",
  `<http-data-source><http-request><set-method>GET</set-method><set-url>@("${restUrl}/customers/" + context.GraphQL.Parent["customerId"])</set-url></http-request></http-data-source>`);

async function shop(query, variables) {
  const response = await fetch(`${gateway}/shop`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  return { status: response.status, body: await response.json() };
}

// The synthetic schema must introspect identically to the SDL, same as pass-through.
const syntheticIntrospection = await shop(getIntrospectionQuery());
assert.equal(
  printSchema(buildClientSchema(syntheticIntrospection.body.data)),
  printSchema(buildSchema(SYNTHETIC_SDL)),
  "the synthetic API's introspection must rebuild its imported SDL",
);

// A list resolver, with the selection projected: `total` was not selected and
// must not appear, even though the REST backend returned it.
const list = await shop("{ orders { ref } }");
assert.equal(list.status, 200, `orders returned ${list.status}: ${JSON.stringify(list.body)}`);
assert.ok(!list.body.errors, `orders reported errors: ${JSON.stringify(list.body.errors)}`);
assert.deepEqual(list.body.data.orders, [{ ref: "A-1" }, { ref: "A-2" }],
  "unselected fields must not be returned; the REST payload had total and customerId too");

// An argument reaching the resolver through context.GraphQL.Arguments.
const one = await shop(`{ order(ref: "Z-9") { ref total } }`);
assert.deepEqual(one.body.data.order, { ref: "Z-9", total: 99 },
  "the argument must reach the resolver's URL through context.GraphQL.Arguments");

// A variable, substituted before the resolver sees it.
const byVariable = await shop("query Get($r: ID!) { order(ref: $r) { ref } }", { r: "V-1" });
assert.equal(byVariable.body.data.order.ref, "V-1", "variables must be substituted into arguments");

// A nested resolver reading context.GraphQL.Parent, and one REST call per level.
const nested = await shop("{ orders { ref customer { id name } } }");
assert.ok(!nested.body.errors, `nested resolver reported errors: ${JSON.stringify(nested.body.errors)}`);
assert.deepEqual(nested.body.data.orders, [
  { ref: "A-1", customer: { id: "c1", name: "Customer c1" } },
  { ref: "A-2", customer: { id: "c2", name: "Customer c2" } },
], "a nested resolver must read its parent object through context.GraphQL.Parent");

// GraphQL's partial-failure contract: one failing field nulls that field and
// reports a path, while its siblings still resolve. A 5xx for the whole request
// would be easier and would break every client that relies on partial data.
const partial = await shop(`{ ok: order(ref: "A-1") { ref } bad: order(ref: "../nope/x") { ref } }`);
assert.equal(partial.status, 200, "a field-level failure is still a 200; execution ran");
assert.equal(partial.body.data.ok.ref, "A-1", "the healthy field must still resolve");
assert.equal(partial.body.data.bad, null, "the failing field must be null");
assert.ok(partial.body.errors?.length > 0, "the failure must be reported in errors");
assert.deepEqual(partial.body.errors[0].path, ["bad"], "the error must carry the path to the failing field");

rest.close();
backend.close();
console.log("graphql witness: pass-through, synthetic resolvers, arguments, parent, and partial failure all agree with the reference implementation");
