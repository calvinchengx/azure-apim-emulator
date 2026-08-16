// gRPC witness: a real gRPC server behind the gateway, a real gRPC client in
// front of it.
//
// @grpc/grpc-js is gRPC's own JavaScript implementation. It speaks HTTP/2,
// frames messages, and reads the call status out of TRAILERS, which is the part
// a naive proxy silently gets wrong: forward the body but drop the trailers and
// the client hangs forever waiting for a status that never arrives. Nothing we
// could write ourselves would catch that, because our own client would make the
// same assumption our proxy does.
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const require = createRequire(import.meta.url);
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");

const PROTO = `
syntax = "proto3";
package shop.v1;

message Order { string ref = 1; int32 total = 2; }
message GetOrderRequest { string ref = 1; }
message ListOrdersRequest { int32 limit = 1; }

service Orders {
  rpc GetOrder(GetOrderRequest) returns (Order);
  rpc ListOrders(ListOrdersRequest) returns (stream Order);
}
`;

const endpoint = process.env.APIM_ENDPOINT;
const gateway = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const subscriptionId = process.env.APIM_SUBSCRIPTION_ID;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;
const apiVersion = "2024-05-01";

const protoPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "apim-grpc-")), "shop.proto");
fs.writeFileSync(protoPath, PROTO);
const definition = protoLoader.loadSync(protoPath, { keepCase: true, defaults: true });
const loaded = grpc.loadPackageDefinition(definition);
const Orders = loaded.shop.v1.Orders;

// A real gRPC server. It also asserts what the gateway forwarded to it.
let seenMetadata = null;
const server = new grpc.Server();
server.addService(Orders.service, {
  GetOrder(call, callback) {
    seenMetadata = call.metadata.getMap();
    if (call.request.ref === "boom") {
      callback({ code: grpc.status.NOT_FOUND, message: "no such order" });
      return;
    }
    callback(null, { ref: call.request.ref, total: 99 });
  },
  ListOrders(call) {
    const limit = call.request.limit || 2;
    for (let i = 1; i <= limit; i += 1) {
      call.write({ ref: `A-${i}`, total: i * 10 });
    }
    call.end();
  },
});

const backendPort = await new Promise((resolve, reject) => {
  server.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (err, port) =>
    err ? reject(err) : resolve(port),
  );
});
const backendUrl = `http://127.0.0.1:${backendPort}`;

async function arm(p, method, body) {
  const response = await fetch(`${endpoint}${p}?api-version=${apiVersion}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status >= 400) {
    throw new Error(`${method} ${p} -> ${response.status} ${await response.text()}`);
  }
  return response.status === 204 ? null : response.json();
}

const base = `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.ApiManagement/service/${serviceName}`;

await arm(`${base}/apis/orders`, "PUT", {
  properties: {
    displayName: "Orders",
    path: "",
    serviceUrl: backendUrl,
    protocols: ["https"],
    apiType: "grpc",
    subscriptionRequired: false,
  },
});
await arm(`${base}/apis/orders/schemas/proto`, "PUT", {
  properties: {
    contentType: "application/vnd.ms-azure-apim.grpc.schema",
    document: { value: PROTO },
  },
});

// The stored .proto must come back exactly as uploaded.
const stored = await arm(`${base}/apis/orders/schemas/proto`, "GET");
assert.equal(stored.properties.document.value, PROTO, "the stored schema must be byte-identical to the imported .proto");

// The client talks to the GATEWAY, not the backend.
const gatewayUrl = new URL(gateway);
const credentials = gatewayUrl.protocol === "https:"
  ? grpc.credentials.createSsl(fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS))
  : grpc.credentials.createInsecure();
const client = new Orders(gatewayUrl.host, credentials);

function unary(method, request, metadata = new grpc.Metadata()) {
  return new Promise((resolve) => {
    client[method](request, metadata, (error, response) => resolve({ error, response }));
  });
}

// 1. A unary call all the way through: client -> gateway -> real gRPC server.
const metadata = new grpc.Metadata();
metadata.set("x-caller", "witness");
const ok = await unary("GetOrder", { ref: "A-1" }, metadata);
assert.equal(ok.error, null, `unary call failed: ${ok.error?.message}`);
assert.deepEqual({ ref: ok.response.ref, total: ok.response.total }, { ref: "A-1", total: 99 });

// Metadata must survive the hop, since that is where gRPC puts auth and tracing.
assert.equal(seenMetadata["x-caller"], "witness", "request metadata must reach the backend");

// 2. A NON-OK status. This is the trailers assertion: gRPC carries the status
//    in trailers, so a proxy that drops them leaves the client hanging or
//    reporting the wrong code.
const failed = await unary("GetOrder", { ref: "boom" });
assert.ok(failed.error, "a backend error must surface as a gRPC error");
assert.equal(failed.error.code, grpc.status.NOT_FOUND, `status = ${failed.error.code}, want NOT_FOUND through trailers`);
assert.equal(failed.error.details, "no such order", "the backend's status message must survive");

// 3. Server streaming: several messages, then a clean end.
const streamed = await new Promise((resolve, reject) => {
  const received = [];
  const call = client.ListOrders({ limit: 3 });
  call.on("data", (message) => received.push(message.ref));
  call.on("end", () => resolve(received));
  call.on("error", reject);
});
assert.deepEqual(streamed, ["A-1", "A-2", "A-3"], "every streamed message must arrive in order");

// 4. A method the schema does not define is refused BY THE GATEWAY, with the
//    status a real gRPC server would use, and never reaches the backend.
const rogueProto = PROTO.replace("rpc GetOrder", "rpc Absent(GetOrderRequest) returns (Order);\n  rpc GetOrder");
const roguePath = path.join(path.dirname(protoPath), "rogue.proto");
fs.writeFileSync(roguePath, rogueProto);
const rogue = grpc.loadPackageDefinition(protoLoader.loadSync(roguePath, { keepCase: true, defaults: true }));
const rogueClient = new rogue.shop.v1.Orders(gatewayUrl.host, credentials);
const refused = await new Promise((resolve) => {
  rogueClient.Absent({ ref: "x" }, (error, response) => resolve({ error, response }));
});
assert.ok(refused.error, "a method absent from the schema must be refused");
assert.equal(
  refused.error.code,
  grpc.status.UNIMPLEMENTED,
  `status = ${refused.error.code}, want UNIMPLEMENTED from the gateway`,
);

client.close();
rogueClient.close();
await new Promise((resolve) => server.tryShutdown(resolve));
console.log("grpc witness: unary, metadata, trailers-borne status, server streaming, and schema refusal all agree with grpc-js");
