// Token governance for model APIs, witnessed by OpenAI's own client.
//
// The point of using the real `openai` package rather than fetch is that it
// composes the request the way a caller's application does -- the Azure-style
// path, the streaming protocol, `stream_options.include_usage` -- and it reads
// the response the way one does. A hand-written client would only prove that
// the emulator agrees with my reading of the protocol, which is the same
// reading that produced the emulator.
//
// The backend here is a deterministic stand-in for a model. That is deliberate
// and is the honest boundary: what is under test is APIM's accounting of what a
// model reports, not a model. A real provider would make the numbers vary and
// the assertions vacuous.

import { createServer } from "node:http";
import { ApiManagementClient } from "@azure/arm-apimanagement";
import OpenAI from "openai";

const credential = {
  async getToken() {
    return { token: "sdk-token", expiresOnTimestamp: Date.now() + 3600000 };
  },
};

const endpoint = process.env.APIM_ENDPOINT;
const gatewayEndpoint = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;

// PROMPT_TOKENS and COMPLETION_TOKENS are what the stand-in model reports it
// spent. Every assertion below is derived from these rather than restating a
// literal, so a change here cannot leave a stale expectation passing.
const PROMPT_TOKENS = 30;
const COMPLETION_TOKENS = 20;
const TOTAL = PROMPT_TOKENS + COMPLETION_TOKENS;
const usage = {
  prompt_tokens: PROMPT_TOKENS,
  completion_tokens: COMPLETION_TOKENS,
  total_tokens: TOTAL,
};

let backendCalls = 0;
const model = createServer((request, response) => {
  let body = "";
  request.on("data", (chunk) => {
    body += chunk;
  });
  request.on("end", () => {
    backendCalls += 1;
    const parsed = JSON.parse(body || "{}");
    if (parsed.stream) {
      response.writeHead(200, { "Content-Type": "text/event-stream" });
      response.write(`data: ${JSON.stringify({ id: "1", object: "chat.completion.chunk", created: 0, model: "gpt-4o", choices: [{ index: 0, delta: { role: "assistant", content: "hello" }, finish_reason: null }], usage: null })}\n\n`);
      response.write(`data: ${JSON.stringify({ id: "1", object: "chat.completion.chunk", created: 0, model: "gpt-4o", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: null })}\n\n`);
      // The usage chunk, which OpenAI sends last and only when the caller
      // passed stream_options.include_usage.
      response.write(`data: ${JSON.stringify({ id: "1", object: "chat.completion.chunk", created: 0, model: "gpt-4o", choices: [], usage })}\n\n`);
      response.write("data: [DONE]\n\n");
      response.end();
      return;
    }
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({
      id: "1",
      object: "chat.completion",
      created: 0,
      model: "gpt-4o",
      choices: [{ index: 0, message: { role: "assistant", content: "hello" }, finish_reason: "stop" }],
      usage,
    }));
  });
});
await new Promise((resolve) => model.listen(0, "127.0.0.1", resolve));
const modelURL = `http://127.0.0.1:${model.address().port}`;

const client = new ApiManagementClient(credential, process.env.APIM_SUBSCRIPTION_ID, { endpoint });
await client.apiManagementService.beginCreateOrUpdateAndWait(resourceGroup, serviceName, {
  location: "local",
  sku: { name: "Developer", capacity: 1 },
  publisherName: "OpenAI witness",
  publisherEmail: "openai@example.test",
});

const TOKENS_PER_MINUTE = 120;
await client.api.beginCreateOrUpdateAndWait(resourceGroup, serviceName, "openai-api", {
  displayName: "OpenAI API",
  path: "openai",
  serviceUrl: modelURL,
  protocols: ["https"],
  subscriptionRequired: false,
});
await client.apiOperation.createOrUpdate(resourceGroup, serviceName, "openai-api", "chat", {
  displayName: "Chat completions",
  method: "POST",
  urlTemplate: "/chat/completions",
});
await client.apiPolicy.createOrUpdate(resourceGroup, serviceName, "openai-api", "policy", {
  format: "rawxml",
  value: `<policies><inbound><base />
    <llm-token-limit counter-key="@(context.Request.Headers.GetValueOrDefault(&quot;X-Tenant&quot;,&quot;anonymous&quot;))"
      tokens-per-minute="${TOKENS_PER_MINUTE}"
      tokens-consumed-header-name="x-tokens-consumed"
      remaining-tokens-header-name="x-tokens-remaining" />
    <llm-emit-token-metric namespace="witness">
      <dimension name="API ID" value="@(context.Api.Id)" />
      <dimension name="Tenant" value="@(context.Request.Headers.GetValueOrDefault(&quot;X-Tenant&quot;,&quot;anonymous&quot;))" />
    </llm-emit-token-metric>
  </inbound><backend><forward-request /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>`,
});

// OpenAI's own client, pointed at the gateway. `apiKey` is required by the
// constructor and unused by this API, which takes no subscription key.
const openaiFor = (tenant) =>
  new OpenAI({
    apiKey: "unused",
    baseURL: `${gatewayEndpoint}/openai`,
    defaultHeaders: { "X-Tenant": tenant },
    maxRetries: 0,
  });

// --- Non-streamed: the counts describe the response they arrive on ----------
const alpha = openaiFor("alpha");
let consumedHeader;
let remainingHeader;
const completion = await alpha.chat.completions
  .create({ model: "gpt-4o", messages: [{ role: "user", content: "hello" }] })
  .withResponse()
  .then(({ data, response }) => {
    consumedHeader = response.headers.get("x-tokens-consumed");
    remainingHeader = response.headers.get("x-tokens-remaining");
    return data;
  });

if (completion.usage.total_tokens !== TOTAL) {
  throw new Error(`the model's usage did not survive the gateway: ${JSON.stringify(completion.usage)}`);
}
if (completion.choices[0].message.content !== "hello") {
  throw new Error(`the completion body was altered: ${JSON.stringify(completion.choices[0])}`);
}
if (Number(consumedHeader) !== TOTAL) {
  throw new Error(`x-tokens-consumed = ${consumedHeader}, want ${TOTAL}`);
}
if (Number(remainingHeader) !== TOKENS_PER_MINUTE - TOTAL) {
  throw new Error(`x-tokens-remaining = ${remainingHeader}, want ${TOKENS_PER_MINUTE - TOTAL}`);
}
console.log("openai witness: non-streamed usage reported on the response that spent it");

// --- Streamed: counted on the way past, bytes untouched ---------------------
const beta = openaiFor("beta");
const stream = await beta.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "hello" }],
  stream: true,
  stream_options: { include_usage: true },
});
let streamedText = "";
let streamedUsage = null;
for await (const chunk of stream) {
  streamedText += chunk.choices[0]?.delta?.content ?? "";
  if (chunk.usage) {
    streamedUsage = chunk.usage;
  }
}
// The SDK only reconstructs these if the stream arrived intact and in order,
// which is the assertion that the counting did not disturb it.
if (streamedText !== "hello") {
  throw new Error(`streamed content = ${JSON.stringify(streamedText)}`);
}
if (!streamedUsage || streamedUsage.total_tokens !== TOTAL) {
  throw new Error(`streamed usage = ${JSON.stringify(streamedUsage)}`);
}
console.log("openai witness: streamed answer delivered intact and its usage chunk preserved");

// --- The budget is enforced from what was actually spent --------------------
// beta has spent TOTAL of TOKENS_PER_MINUTE. Two more streamed calls take it
// past the budget, and the call after that must be refused. The refusal is
// asserted through the SDK's own error type, because that is what a caller's
// code will catch.
const spend = async () => {
  const streamed = await beta.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: "hello" }],
    stream: true,
    stream_options: { include_usage: true },
  });
  for await (const _chunk of streamed) {
    // drain
  }
};
await spend();
await spend();

let refusal = null;
try {
  await beta.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: "hello" }] });
} catch (error) {
  refusal = error;
}
if (!refusal || refusal.status !== 429) {
  throw new Error(`expected a 429 once the budget was spent, got ${refusal ? refusal.status : "success"}`);
}
if (!refusal.headers?.get?.("retry-after") && !refusal.headers?.["retry-after"]) {
  throw new Error("the 429 carried no Retry-After, so a client can only guess");
}
console.log("openai witness: budget enforced from reported usage, refused with 429 and Retry-After");

// --- Budgets are per counter key -------------------------------------------
// alpha spent only TOTAL and must be unaffected by beta exhausting its own.
const callsBefore = backendCalls;
const alphaAgain = await alpha.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "hello" }],
});
if (alphaAgain.usage.total_tokens !== TOTAL) {
  throw new Error("a second tenant was refused because the first exhausted its budget");
}
if (backendCalls !== callsBefore + 1) {
  throw new Error(`the model was called ${backendCalls - callsBefore} times for one request`);
}
console.log("openai witness: counter keys are independent");

// --- A refused request never reaches the model ------------------------------
// This is the property that makes the policy worth having: the point of a token
// limit is to not spend money at the provider, so a 429 that still called the
// backend would be theatre.
const beforeRefusal = backendCalls;
try {
  await beta.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: "hello" }] });
  throw new Error("the exhausted tenant was served");
} catch (error) {
  if (error.status !== 429) {
    throw error;
  }
}
if (backendCalls !== beforeRefusal) {
  throw new Error("a refused request still reached the model");
}
console.log("openai witness: a refused request does not reach the model");

model.close();
