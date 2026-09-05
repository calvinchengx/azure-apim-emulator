// WebSocket and SSE, driven by clients that are not ours.
//
// WHY THIS EXISTS. The `WebSocket/SSE` row was witnessed only by
// `go:TestWebSocketGatewayTunnel`, `go:TestWebSocketRequestDetection` and
// `go:TestWriteGatewayBodyFlushesSSE`. Those are real tests, but they drive
// BOTH ends with `golang.org/x/net/websocket` inside one process, so the row
// said that one lax implementation agrees with itself about a handshake we
// also wrote. The family's taxonomy calls that `go:` for exactly that reason.
//
// Here the two ends are different implementations and neither is ours:
//
//   backend  `ws`, the library nearly every Node WebSocket server uses. It is
//            STRICT about the handshake and the framing, so it rejects things
//            x/net/websocket accepts.
//   client   Node's own global `WebSocket` (undici). A third implementation
//            again, so a handshake that satisfies both is not satisfying one
//            author's reading of RFC 6455.
//
// THE SSE HALF IS THE ONE THAT COULD NOT BE PROVED IN PROCESS. What matters
// about `WriteGatewayBody` flushing is not that bytes arrive, it is that they
// arrive EARLY: an event must reach the caller while the backend is still
// thinking, or a streamed answer is useless and the LLM token counter that
// tees this write path is counting something nobody received yet. An
// in-process test reading a buffered ResponseRecorder cannot tell a flushed
// stream from a buffered one, because both end with the same bytes. This
// measures arrival times over a real socket, so buffering fails it.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { WebSocketServer } from "ws";

const endpoint = process.env.APIM_ENDPOINT;
const gateway = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const subscriptionId = process.env.APIM_SUBSCRIPTION_ID;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;
const apiVersion = "2024-05-01";

// The gap the backend leaves between SSE events, and the separation the client
// must still observe. Buffering collapses the arrivals to one instant, so the
// margin between "flushed" and "buffered" is the whole GAP; asserting only half
// of it leaves room for a slow runner without leaving room for a regression.
const GAP_MS = 300;
const MIN_SEPARATION_MS = 150;

// --- the backends ----------------------------------------------------------

const socketBackend = createServer();
const sockets = new WebSocketServer({
  server: socketBackend,
  handleProtocols: (offered) => (offered.has("binary") ? "binary" : false),
});
sockets.on("connection", (socket) => {
  // Echo whatever arrives, preserving text-vs-binary. `ws` reports the frame
  // type, so a gateway that rewrote a binary frame as text fails here.
  socket.on("message", (data, isBinary) => socket.send(data, { binary: isBinary }));
});
await new Promise((resolve) => socketBackend.listen(0, "127.0.0.1", resolve));
const socketBackendUrl = `http://127.0.0.1:${socketBackend.address().port}`;

const sseWrites = [];
const sseBackend = createServer(async (request, response) => {
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  for (const value of ["first", "second", "third"]) {
    response.write(`data: ${value}\n\n`);
    sseWrites.push({ value, at: Date.now() });
    if (value !== "third") await new Promise((resolve) => setTimeout(resolve, GAP_MS));
  }
  response.end();
});
await new Promise((resolve) => sseBackend.listen(0, "127.0.0.1", resolve));
const sseBackendUrl = `http://127.0.0.1:${sseBackend.address().port}`;

// --- the APIs --------------------------------------------------------------

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

for (const [name, path, serviceUrl] of [
  ["tunnel", "tunnel", socketBackendUrl],
  ["stream", "stream", sseBackendUrl],
]) {
  await arm(`${base}/apis/${name}`, "PUT", {
    properties: {
      displayName: name, path, serviceUrl,
      protocols: ["https"], subscriptionRequired: false,
    },
  });
  await arm(`${base}/apis/${name}/operations/get`, "PUT", {
    properties: { displayName: "get", method: "GET", urlTemplate: "/" },
  });
}

// --- WebSocket, through the gateway ----------------------------------------

const socketUrl = `${gateway.replace(/^http/, "ws")}/tunnel`;

function once(socket, event) {
  return new Promise((resolve, reject) => {
    socket.addEventListener(event, resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error(`${event}: socket errored`)), { once: true });
  });
}

async function roundTrip(payload, protocols) {
  const socket = new WebSocket(socketUrl, protocols);
  socket.binaryType = "arraybuffer";
  await once(socket, "open");
  const received = once(socket, "message");
  socket.send(payload);
  const message = await received;
  const negotiated = socket.protocol;
  socket.close();
  return { data: message.data, negotiated };
}

const text = await roundTrip("hello through the gateway", []);
assert.equal(text.data, "hello through the gateway", "text frame did not survive the tunnel");

const bytes = Uint8Array.from([0, 1, 2, 253, 254, 255]);
const binary = await roundTrip(bytes, ["binary"]);
assert.ok(binary.data instanceof ArrayBuffer, "a binary frame came back as text");
assert.deepEqual(new Uint8Array(binary.data), bytes, "binary payload was altered in the tunnel");
// NOT ASSERTED, AND THE REASON IS A DEFECT THIS WITNESS FOUND.
//
// The gateway does not relay the backend's chosen subprotocol. It reflects the
// client's REQUESTED one, and recognises only the single literal value
// `binary` (internal/gateway/gateway.go, serveWebSocket). Measured three ways:
//
//   backend refuses the subprotocol   -> the client still sees "binary" and
//                                        connects; direct to the same backend
//                                        it correctly refuses the handshake
//   client offers ["binary","chosen"],
//   backend selects "chosen"          -> the handshake fails, because what
//                                        comes back names neither one choice
//                                        nor a protocol the client offered
//
// So `socket.protocol` here is the echo of what we asked for, and asserting it
// would be asserting our own request. It is left unasserted rather than
// dressed up as evidence. The fix belongs in the gateway: complete the client
// handshake only after dialling the backend, and answer with the backend's
// selection or with nothing.

// --- SSE, through the gateway, measured ------------------------------------

const arrivals = [];
const response = await fetch(`${gateway}/stream`, { headers: { accept: "text/event-stream" } });
assert.equal(response.status, 200);
assert.match(response.headers.get("content-type") ?? "", /text\/event-stream/);

const decoder = new TextDecoder();
let buffered = "";
for await (const chunk of response.body) {
  buffered += decoder.decode(chunk, { stream: true });
  let index;
  while ((index = buffered.indexOf("\n\n")) !== -1) {
    const frame = buffered.slice(0, index);
    buffered = buffered.slice(index + 2);
    const value = frame.replace(/^data: /, "");
    if (value) arrivals.push({ value, at: Date.now() });
  }
}

assert.deepEqual(arrivals.map((a) => a.value), ["first", "second", "third"],
  "the event stream did not arrive intact");

const separation = arrivals[2].at - arrivals[0].at;
assert.ok(separation >= MIN_SEPARATION_MS,
  `the stream was BUFFERED: first and last events arrived ${separation}ms apart, ` +
  `but the backend wrote them ${sseWrites[2].at - sseWrites[0].at}ms apart. ` +
  `A flushing gateway delivers each event as it is written.`);

// And the first event must have been READ before the backend wrote the last
// one. This is the assertion an in-process recorder cannot make at all.
assert.ok(arrivals[0].at < sseWrites[2].at,
  "the first event was not delivered until the backend had finished writing");

console.log(
  `websocket witness: text and binary frames round-trip through the gateway, ` +
  `frame type preserved, driven by ws and undici rather than by our own client`,
);
console.log(
  `websocket witness: SSE flushed, ${arrivals.length} events ${separation}ms apart ` +
  `(backend wrote them ${sseWrites[2].at - sseWrites[0].at}ms apart), ` +
  `first delivered before the last was written`,
);

sockets.close();
socketBackend.close();
sseBackend.close();
