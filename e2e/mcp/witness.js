// An APIM API published as an MCP server, witnessed by the reference client.
//
// `@modelcontextprotocol/sdk` is the implementation every MCP host is built on,
// so it is the oracle for whether this is an MCP server or merely a JSON-RPC
// endpoint that resembles one. It performs the initialize handshake, tracks the
// session id, validates every result against the protocol's own schemas, and
// refuses a response it cannot type -- none of which a hand-written client
// exercising my own reading of the spec would do.
//
// The backend is an ordinary REST service. That is the point of the feature:
// the tools are the API's operations, and an MCP client and an HTTP client are
// talking to one API rather than to two implementations of it.

import { createServer } from "node:http";
import { ApiManagementClient } from "@azure/arm-apimanagement";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const credential = {
  async getToken() {
    return { token: "sdk-token", expiresOnTimestamp: Date.now() + 3600000 };
  },
};

const endpoint = process.env.APIM_ENDPOINT;
const gatewayEndpoint = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;

// A plain REST backend. It records what it was asked for, so the witness can
// assert that a tool call became the HTTP request the operation describes.
const seen = [];
const backend = createServer((request, response) => {
  let body = "";
  request.on("data", (chunk) => (body += chunk));
  request.on("end", () => {
    seen.push({ method: request.method, url: request.url, body });
    if (request.url.startsWith("/orders/missing")) {
      response.writeHead(404, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "no such order" }));
      return;
    }
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ url: request.url, method: request.method, echoed: body || null }));
  });
});
await new Promise((resolve) => backend.listen(0, "127.0.0.1", resolve));
const backendURL = `http://127.0.0.1:${backend.address().port}`;

const client = new ApiManagementClient(credential, process.env.APIM_SUBSCRIPTION_ID, { endpoint });
await client.apiManagementService.beginCreateOrUpdateAndWait(resourceGroup, serviceName, {
  location: "local",
  sku: { name: "Developer", capacity: 1 },
  publisherName: "MCP witness",
  publisherEmail: "mcp@example.test",
});

// An API marked as an MCP server. `apiType` is an open string in the ARM
// contract, which is what lets this be expressed without a bespoke resource.
await client.api.beginCreateOrUpdateAndWait(resourceGroup, serviceName, "orders-mcp", {
  displayName: "Orders",
  path: "orders-mcp",
  serviceUrl: backendURL,
  protocols: ["https"],
  subscriptionRequired: false,
  apiType: "mcp",
});

// Two operations, which become two tools. Their declared parameters become the
// tools' input schemas, so a model knows what to pass without being told twice.
await client.apiOperation.createOrUpdate(resourceGroup, serviceName, "orders-mcp", "get-order", {
  displayName: "Get order",
  description: "Fetch a single order by its identifier.",
  method: "GET",
  urlTemplate: "/orders/{orderId}",
  templateParameters: [{ name: "orderId", type: "string", description: "The order identifier." }],
  request: {
    queryParameters: [{ name: "expand", type: "boolean", description: "Include line items.", required: false }],
  },
});
await client.apiOperation.createOrUpdate(resourceGroup, serviceName, "orders-mcp", "create-order", {
  displayName: "Create order",
  description: "Place a new order.",
  method: "POST",
  urlTemplate: "/orders",
});

const transport = new StreamableHTTPClientTransport(new URL(`${gatewayEndpoint}/orders-mcp/mcp`));
const mcp = new Client({ name: "apim-emulator-witness", version: "1.0.0" });
await mcp.connect(transport);
// connect() performing the initialize handshake without throwing is already an
// assertion: the SDK validates the server's protocolVersion, capabilities and
// serverInfo against the protocol schema and refuses anything it cannot type.
console.log("mcp witness: initialize handshake accepted by the reference client");

const { tools } = await mcp.listTools();
const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]));
if (tools.length !== 2 || !byName["get-order"] || !byName["create-order"]) {
  throw new Error(`tools = ${JSON.stringify(tools.map((t) => t.name))}`);
}
if (byName["get-order"].description !== "Fetch a single order by its identifier.") {
  throw new Error(`description = ${byName["get-order"].description}`);
}

// The input schema has to carry the operation's own parameters, or a model has
// no way to call the tool correctly.
const schema = byName["get-order"].inputSchema;
if (schema.type !== "object") {
  throw new Error(`input schema type = ${schema.type}`);
}
if (schema.properties.orderId?.type !== "string") {
  throw new Error(`orderId schema = ${JSON.stringify(schema.properties.orderId)}`);
}
if (schema.properties.expand?.type !== "boolean") {
  throw new Error(`APIM's boolean parameter type did not map to JSON Schema: ${JSON.stringify(schema.properties.expand)}`);
}
if (!schema.required?.includes("orderId")) {
  throw new Error(`required = ${JSON.stringify(schema.required)}`);
}
// A path parameter is required; an optional query parameter is not.
if (schema.required?.includes("expand")) {
  throw new Error("an optional query parameter was advertised as required");
}
// A POST operation accepts a body; a GET does not.
if (!byName["create-order"].inputSchema.properties.body) {
  throw new Error("a POST tool advertised no body");
}
if (byName["get-order"].inputSchema.properties.body) {
  throw new Error("a GET tool advertised a body");
}
console.log("mcp witness: tools derived from operations, with their declared parameters as schemas");

// --- A tool call becomes the HTTP request the operation describes -----------
const before = seen.length;
const fetched = await mcp.callTool({ name: "get-order", arguments: { orderId: "A-1", expand: true } });
if (fetched.isError) {
  throw new Error(`get-order failed: ${JSON.stringify(fetched.content)}`);
}
const call = seen[before];
if (!call || call.method !== "GET" || call.url !== "/orders/A-1?expand=true") {
  throw new Error(`the backend saw ${JSON.stringify(call)}`);
}
if (!fetched.content?.[0]?.text?.includes("/orders/A-1")) {
  throw new Error(`tool result = ${JSON.stringify(fetched.content)}`);
}
console.log("mcp witness: a tool call reached the backend as the operation's own request");

// --- A body-carrying tool ---------------------------------------------------
const created = await mcp.callTool({
  name: "create-order",
  arguments: { body: JSON.stringify({ sku: "widget" }) },
});
if (created.isError) {
  throw new Error(`create-order failed: ${JSON.stringify(created.content)}`);
}
const post = seen[seen.length - 1];
if (post.method !== "POST" || post.url !== "/orders" || !post.body.includes("widget")) {
  throw new Error(`the backend saw ${JSON.stringify(post)}`);
}
console.log("mcp witness: a POST tool forwarded its body");

// --- A failing operation is a failed TOOL, not a broken protocol ------------
// This distinction is what lets a model retry or apologise instead of dropping
// the session, so it is asserted rather than assumed.
const missing = await mcp.callTool({ name: "get-order", arguments: { orderId: "missing" } });
if (!missing.isError) {
  throw new Error("a 404 from the operation was reported as a successful tool call");
}
if (!missing.content?.[0]?.text?.includes("404")) {
  throw new Error(`failed tool content = ${JSON.stringify(missing.content)}`);
}
console.log("mcp witness: a backend failure surfaced as isError, not as a protocol error");

// --- A tool that was never advertised is refused at the protocol level ------
let refused = null;
try {
  await mcp.callTool({ name: "delete-everything", arguments: {} });
} catch (error) {
  refused = error;
}
if (!refused) {
  throw new Error("an unadvertised tool was called");
}
console.log("mcp witness: an unknown tool is a protocol error, not a silent no-op");

// --- A required argument that was not supplied ------------------------------
const incomplete = await mcp.callTool({ name: "get-order", arguments: {} }).catch((error) => error);
if (!(incomplete instanceof Error) && !incomplete.isError) {
  throw new Error("a call missing its required path parameter was accepted");
}
if (seen.length !== before + 3) {
  throw new Error(`the backend was called ${seen.length - before} times for 3 valid calls`);
}
console.log("mcp witness: a missing required argument never reached the backend");

await mcp.close();
backend.close();

// ---------------------------------------------------------------------------
// MCP passthrough: APIM in front of an MCP server somebody else runs.
//
// The other half of the feature, and the assertion is different in kind. For an
// exposed API the emulator SYNTHESISES the tools, so the witness checks that
// they match the operations. Here the tools belong to an upstream server the
// emulator never inspects, so what is checked is that a real client and a real
// server complete a session THROUGH the gateway without either noticing it.
//
// A REAL MCP server, from the same reference implementation as the client. That
// is the point: a hand-rolled upstream would only prove the proxy agrees with my
// reading of the protocol, which is the reading that produced the proxy.
const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");
const { StreamableHTTPServerTransport } = await import("@modelcontextprotocol/sdk/server/streamableHttp.js");
const { z } = await import("zod");

const upstream = new McpServer({ name: "upstream-orders", version: "2.0.0" });
upstream.tool(
  "upstream-echo",
  "A tool the gateway has never heard of.",
  { text: z.string() },
  async ({ text }) => ({ content: [{ type: "text", text: `upstream saw: ${text}` }] }),
);

const upstreamTransport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => "upstream-session" });
await upstream.connect(upstreamTransport);

let upstreamCalls = 0;
const upstreamHeaders = [];
const upstreamServer = createServer((request, response) => {
  upstreamCalls += 1;
  upstreamHeaders.push(request.headers);
  let body = "";
  request.on("data", (chunk) => (body += chunk));
  request.on("end", () => {
    let parsed;
    try {
      parsed = body ? JSON.parse(body) : undefined;
    } catch {
      parsed = undefined;
    }
    upstreamTransport.handleRequest(request, response, parsed);
  });
});
await new Promise((resolve) => upstreamServer.listen(0, "127.0.0.1", resolve));
const upstreamURL = `http://127.0.0.1:${upstreamServer.address().port}/mcp`;

// An MCP API in passthrough mode. It has no operations, because its tools are
// not its own.
//
// Written through raw ARM rather than the SDK, because `mcpMode` is THIS
// EMULATOR'S OWN property: the preview ARM contract for MCP servers has not
// been captured here, so Microsoft's client has no field for it and
// docs/parity.md says as much. Everything else on the API is the SDK's own
// model, and the API is read back through the SDK below.
const armBase = `/subscriptions/${process.env.APIM_SUBSCRIPTION_ID}/resourceGroups/${resourceGroup}` +
  `/providers/Microsoft.ApiManagement/service/${serviceName}`;
const armPut = async (path, body) => {
  const response = await fetch(`${endpoint}${armBase}${path}?api-version=2024-05-01`, {
    method: "PUT",
    headers: { "content-type": "application/json", authorization: "Bearer sdk-token" },
    body: JSON.stringify(body),
  });
  if (response.status >= 400) {
    throw new Error(`PUT ${path} -> ${response.status} ${await response.text()}`);
  }
  return response.json();
};

await armPut("/apis/orders-proxy", {
  properties: {
    displayName: "Orders proxy",
    path: "orders-proxy",
    serviceUrl: upstreamURL,
    protocols: ["https"],
    subscriptionRequired: false,
    type: "mcp",
    mcpMode: "passthrough",
  },
});
// A policy in front of the proxy, because the reason to put APIM here at all is
// that policies still run.
await armPut("/apis/orders-proxy/policies/policy", {
  properties: {
    format: "rawxml",
    value: `<policies><inbound><base />
      <set-header name="X-Through-Apim" exists-action="override"><value>yes</value></set-header>
    </inbound><backend><forward-request /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>`,
  },
});

// Read back through Microsoft's client, so the resource is still one the SDK
// can see even though one of its properties is ours.
const proxyApi = await client.api.get(resourceGroup, serviceName, "orders-proxy");
if (proxyApi.apiType !== "mcp" || proxyApi.path !== "orders-proxy") {
  throw new Error(`proxy API = ${JSON.stringify({ apiType: proxyApi.apiType, path: proxyApi.path })}`);
}

const proxied = new Client({ name: "apim-emulator-passthrough-witness", version: "1.0.0" });
await proxied.connect(new StreamableHTTPClientTransport(new URL(`${gatewayEndpoint}/orders-proxy/mcp`)));
// The handshake completing at all is the assertion: the SDK validates the
// upstream server's protocolVersion and capabilities, and the session id it was
// given has to survive the round trip or nothing after initialize is accepted.
console.log("mcp witness: a session was established through the gateway to an upstream server");

const upstreamTools = (await proxied.listTools()).tools;
if (upstreamTools.length !== 1 || upstreamTools[0].name !== "upstream-echo") {
  throw new Error(`proxied tools = ${JSON.stringify(upstreamTools.map((t) => t.name))}`);
}
// The tool is the UPSTREAM server's, described by it. The gateway contributed
// nothing to this and could not have: it never saw a tool list of its own.
if (upstreamTools[0].description !== "A tool the gateway has never heard of.") {
  throw new Error(`proxied description = ${upstreamTools[0].description}`);
}

const answered = await proxied.callTool({ name: "upstream-echo", arguments: { text: "hello" } });
if (answered.content?.[0]?.text !== "upstream saw: hello") {
  throw new Error(`proxied call = ${JSON.stringify(answered.content)}`);
}
if (upstreamCalls === 0) {
  throw new Error("the upstream server was never called");
}
console.log("mcp witness: tools and results come from the upstream server, unaltered");

// The proxy is not a tunnel: APIM policies still run, which is the whole reason
// to put it in front of an MCP server. Asserted on what the UPSTREAM SAW rather
// than on a status code, because a header the policy added is direct evidence
// the request went through the policy pipeline.
if (!upstreamHeaders.some((headers) => headers["x-through-apim"] === "yes")) {
  throw new Error("the inbound policy did not run in front of the proxied server");
}
console.log("mcp witness: policies run in front of a proxied MCP server");

// And the proxy does not soften the upstream's own semantics. A stateful MCP
// server refuses a request carrying no session, and that refusal has to reach
// the caller as the upstream issued it -- a gateway that translated it into
// something friendlier would hide a real protocol error.
const sessionless = await fetch(`${gatewayEndpoint}/orders-proxy/mcp`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "ping" }),
});
if (sessionless.status !== 400) {
  throw new Error(`a session-less request through the proxy = ${sessionless.status}, want the upstream's own 400`);
}
console.log("mcp witness: the upstream's refusal reaches the caller unaltered");

await proxied.close();
upstreamServer.close();
