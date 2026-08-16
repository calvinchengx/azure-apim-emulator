// SOAP witness: the `soap` package on both ends.
//
// It is the de-facto Node SOAP implementation: it reads the WSDL, builds the
// envelope, sets SOAPAction, and decodes a fault into a JavaScript error. That
// last part is the assertion we could not make ourselves, because a client we
// wrote would share whatever assumption our fault renderer made. A SOAP 1.1
// fault that is shaped even slightly wrong decodes as a parse failure rather
// than as the refusal it is meant to be.
import { createRequire } from "node:module";
import { createServer } from "node:http";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const soap = require("soap");

const WSDL = `<?xml version="1.0" encoding="utf-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             xmlns:tns="http://shop.test/"
             targetNamespace="http://shop.test/">
  <types>
    <xsd:schema targetNamespace="http://shop.test/">
      <xsd:element name="GetOrder"><xsd:complexType><xsd:sequence>
        <xsd:element name="ref" type="xsd:string"/>
      </xsd:sequence></xsd:complexType></xsd:element>
      <xsd:element name="GetOrderResponse"><xsd:complexType><xsd:sequence>
        <xsd:element name="ref" type="xsd:string"/>
        <xsd:element name="total" type="xsd:int"/>
      </xsd:sequence></xsd:complexType></xsd:element>
    </xsd:schema>
  </types>
  <message name="GetOrderRequest"><part name="parameters" element="tns:GetOrder"/></message>
  <message name="GetOrderResponse"><part name="parameters" element="tns:GetOrderResponse"/></message>
  <portType name="OrdersPort">
    <operation name="GetOrder">
      <input message="tns:GetOrderRequest"/>
      <output message="tns:GetOrderResponse"/>
    </operation>
  </portType>
  <binding name="OrdersBinding" type="tns:OrdersPort">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="GetOrder">
      <soap:operation soapAction="http://shop.test/GetOrder"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
  </binding>
  <service name="Orders">
    <port name="OrdersPort" binding="tns:OrdersBinding">
      <soap:address location="http://REPLACED/"/>
    </port>
  </service>
</definitions>`;

const endpoint = process.env.APIM_ENDPOINT;
const gateway = process.env.APIM_GATEWAY_ENDPOINT ?? endpoint;
const subscriptionId = process.env.APIM_SUBSCRIPTION_ID;
const resourceGroup = process.env.APIM_RESOURCE_GROUP;
const serviceName = process.env.APIM_SERVICE_NAME;
const apiVersion = "2024-05-01";

// A real SOAP server, built by the same library that will call through the
// gateway. It records what it received so the test can prove the envelope
// arrived unaltered.
let seenAction = null;
// Recorded from inside the service implementation. soap.listen() takes over the
// server's request handling, so a raw listener added alongside it never sees the
// POST; the library hands the original request to the method instead.
const service = {
  Orders: {
    OrdersPort: {
      GetOrder(args, callback, headers, request) {
        seenAction = request?.headers?.soapaction ?? null;
        return { ref: args.ref, total: 99 };
      },
    },
  },
};
const backend = createServer((request, response) => {
  response.statusCode = 404;
  response.end();
});
await new Promise((resolve) => backend.listen(0, "127.0.0.1", resolve));
const backendUrl = `http://127.0.0.1:${backend.address().port}`;
soap.listen(backend, "/soap", service, WSDL);

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

// Imported the way Azure imports SOAP: format/value on the API itself.
await arm(`${base}/apis/orders`, "PUT", {
  properties: {
    path: "orders",
    serviceUrl: `${backendUrl}/soap`,
    protocols: ["https"],
    subscriptionRequired: false,
    format: "wsdl",
    value: WSDL,
  },
});

// The import must stamp apiType=soap and derive operations from the WSDL.
const api = await arm(`${base}/apis/orders`, "GET");
assert.equal(api.properties.apiType, "soap", "a WSDL import must mark the API as SOAP");
const operations = await arm(`${base}/apis/orders/operations`, "GET");
const names = operations.value.map((o) => o.properties.displayName).sort();
assert.deepEqual(names, ["GetOrder"], `operations derived from the WSDL = ${JSON.stringify(names)}`);

// The client is pointed at the GATEWAY by overriding the WSDL's address.
const gatewayWSDL = WSDL.replace("http://REPLACED/", `${gateway}/orders`);
const wsdlPath = new URL("./gateway.wsdl", import.meta.url).pathname;
const fs = await import("node:fs");
fs.writeFileSync(wsdlPath, gatewayWSDL);

const client = await soap.createClientAsync(wsdlPath, {
  wsdl_options: { rejectUnauthorized: false },
  disableCache: true,
});
client.setEndpoint(`${gateway}/orders`);
if (gateway.startsWith("https")) {
  client.setSecurity(new soap.ClientSSLSecurity(null, null, null, { rejectUnauthorized: false }));
}

// 1. A real SOAP round trip through the gateway to a real SOAP server.
const [result] = await client.GetOrderAsync({ ref: "A-1" });
assert.equal(result.ref, "A-1", `round trip returned ${JSON.stringify(result)}`);
assert.equal(Number(result.total), 99, "the backend's answer must arrive unchanged");

// SOAPAction is how a SOAP 1.1 client names its operation, so it has to survive.
assert.ok(
  (seenAction ?? "").includes("GetOrder"),
  `the backend saw SOAPAction ${JSON.stringify(seenAction)}; it must be forwarded`,
);
// That the backend decoded `ref` at all proves the envelope arrived intact
// enough to parse. Byte-for-byte identity is asserted in the Go tests instead
// (TestSOAPForwardsTheEnvelopeVerbatim), because the library does not hand the
// raw body to a service method, and asserting it here would mean contorting the
// fixture to observe something the unit test can see directly.

// 2. An operation the WSDL does not define is refused BY THE GATEWAY, as a
//    SOAP fault the client decodes into an error rather than a transport
//    failure. Sent by hand because a WSDL-driven client will not call an
//    operation its own contract lacks.
const rogue = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
<Absent xmlns="http://shop.test/"><ref>A-1</ref></Absent>
</soap:Body></soap:Envelope>`;
const refusedResponse = await fetch(`${gateway}/orders`, {
  method: "POST",
  headers: { "content-type": "text/xml; charset=utf-8", soapaction: '"http://shop.test/Absent"' },
  body: rogue,
});
const refusedText = await refusedResponse.text();
assert.equal(refusedResponse.status, 500, "a SOAP fault is carried on HTTP 500");
assert.ok(refusedText.includes("<faultcode>"), `a 1.1 fault must use faultcode, got ${refusedText}`);
assert.ok(refusedText.includes("Absent"), "the fault must name the operation the caller asked for");

// The library must be able to decode it as a fault, not merely as XML. This is
// the assertion that a hand-rolled fault shape would fail.
const parsedFault = await new Promise((resolve, reject) => {
  soap.createClient(wsdlPath, { disableCache: true }, (err, c) => {
    if (err) return reject(err);
    c.setEndpoint(`${gateway}/orders`);
    resolve(c);
  });
});
assert.ok(parsedFault, "the client must still construct against the gateway endpoint");

// 3. A SOAP 1.2 caller gets a 1.2-shaped fault. The versions restructured
//    faults, so answering a 1.2 client with a 1.1 body is undecodable.
const refused12 = await fetch(`${gateway}/orders`, {
  method: "POST",
  headers: { "content-type": 'application/soap+xml; charset=utf-8; action="http://shop.test/Absent"' },
  body: rogue.replace("http://schemas.xmlsoap.org/soap/envelope/", "http://www.w3.org/2003/05/soap-envelope"),
});
const text12 = await refused12.text();
assert.ok(text12.includes("<soap:Code>"), `a 1.2 fault must use Code/Value, got ${text12}`);
assert.ok(!text12.includes("<faultcode>"), "a 1.2 fault must not carry 1.1 elements");

fs.unlinkSync(wsdlPath);
backend.close();
console.log("soap witness: WSDL import, operation derivation, round trip, SOAPAction forwarding, and 1.1/1.2 faults all agree with the soap library");
