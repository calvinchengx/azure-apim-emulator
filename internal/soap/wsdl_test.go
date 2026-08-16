package soap

import (
	"errors"
	"strings"
	"testing"
)

const ordersWSDL = `<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://shop.test/" targetNamespace="http://shop.test/">
  <message name="GetOrderRequest"><part name="parameters" element="tns:GetOrder"/></message>
  <message name="ListOrdersRequest"><part name="parameters" type="tns:ListOrders"/></message>
  <message name="PingRequest"><part name="parameters"/></message>
  <portType name="OrdersPort">
    <operation name="GetOrder"><input message="tns:GetOrderRequest"/></operation>
    <operation name="ListOrders"><input message="tns:ListOrdersRequest"/></operation>
    <operation name="Ping"><input message="tns:PingRequest"/></operation>
  </portType>
  <binding name="OrdersBinding" type="tns:OrdersPort">
    <operation name="GetOrder"><soap:operation soapAction="http://shop.test/GetOrder"/></operation>
    <operation name="ListOrders"><soap:operation soapAction="http://shop.test/ListOrders"/></operation>
    <operation name="Ping"><soap:operation soapAction=""/></operation>
  </binding>
  <service name="Orders"><port name="OrdersPort" binding="tns:OrdersBinding"/></service>
</definitions>`

func TestParseCollectsOperations(t *testing.T) {
	schema, err := Parse(ordersWSDL)
	if err != nil {
		t.Fatal(err)
	}
	if schema.WSDL != ordersWSDL {
		t.Fatal("the source must be kept verbatim")
	}
	if schema.ServiceName != "Orders" {
		t.Fatalf("ServiceName = %q", schema.ServiceName)
	}
	if got := len(schema.Operations()); got != 3 {
		t.Fatalf("Operations() = %d, want 3", got)
	}
	// The element comes from the message part, whether declared as element or
	// as type.
	if operation, ok := schema.Lookup("http://shop.test/GetOrder", ""); !ok || operation.InputElement != "GetOrder" {
		t.Fatalf("by action = %+v ok=%v", operation, ok)
	}
	if operation, ok := schema.Lookup("", "ListOrders"); !ok || operation.Name != "ListOrders" {
		t.Fatalf("by element = %+v ok=%v", operation, ok)
	}
	// An empty soapAction is legal (WS-I permits it, SOAP 1.2 omits it), so
	// such an operation must still be reachable by its body element.
	if operation, ok := schema.Lookup("", "Ping"); !ok || operation.Name != "Ping" {
		t.Fatalf("an operation with an empty soapAction must route by element, got %+v ok=%v", operation, ok)
	}
	if _, ok := schema.Lookup("http://shop.test/Absent", "Absent"); ok {
		t.Fatal("an undefined operation must not resolve")
	}
	// A wrong action must not match a different operation just because the
	// element happens to be right, and vice versa.
	if operation, ok := schema.Lookup("http://shop.test/Absent", "GetOrder"); !ok || operation.Name != "GetOrder" {
		t.Fatalf("an unknown action must fall through to the body element, got %+v", operation)
	}
}

func TestParseRejectsUnusableDocuments(t *testing.T) {
	for name, source := range map[string]string{
		"empty":       "   ",
		"not XML":     "<definitions",
		"wrong root":  `<schema xmlns="http://www.w3.org/2001/XMLSchema"/>`,
		"no service":  `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="p"/></definitions>`,
		"no bindings": `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><service name="S"/></definitions>`,
	} {
		if _, err := Parse(source); err == nil {
			t.Errorf("Parse(%s) accepted an unusable document", name)
		}
	}
}

func TestActionIsReadFromBothTransports(t *testing.T) {
	if got := Action("text/xml", `"http://shop.test/GetOrder"`); got != "http://shop.test/GetOrder" {
		t.Fatalf("SOAP 1.1 header = %q; quotes must be stripped", got)
	}
	// SOAP 1.2 carries the action in the content type, so a gateway that reads
	// only the header sees every 1.2 client as actionless.
	if got := Action(`application/soap+xml; charset=utf-8; action="http://shop.test/GetOrder"`, ""); got != "http://shop.test/GetOrder" {
		t.Fatalf("SOAP 1.2 content-type parameter = %q", got)
	}
	if got := Action("text/xml", ""); got != "" {
		t.Fatalf("no action = %q", got)
	}
	if got := Action("text/xml; charset=utf-8", `  ""  `); got != "" {
		t.Fatalf("an empty quoted action = %q", got)
	}
}

func TestDetectVersion(t *testing.T) {
	if DetectVersion("application/soap+xml; charset=utf-8") != Version12 {
		t.Error("application/soap+xml is SOAP 1.2")
	}
	if DetectVersion("text/xml; charset=utf-8") != Version11 {
		t.Error("text/xml is SOAP 1.1")
	}
}

func TestBodyElementFindsTheOperation(t *testing.T) {
	envelope := `<?xml version="1.0"?><soap:Envelope xmlns:soap="` + NamespaceSOAP11 + `">` +
		`<soap:Header><Body>a decoy named Body</Body></soap:Header>` +
		`<soap:Body><GetOrder xmlns="http://shop.test/"><ref>A-1</ref></GetOrder></soap:Body></soap:Envelope>`
	name, raw, err := BodyElement(strings.NewReader(envelope))
	if err != nil {
		t.Fatal(err)
	}
	// The decoy is the point: a Header element named Body must not be mistaken
	// for the envelope's own Body, which is why the namespace is matched too.
	if name != "GetOrder" {
		t.Fatalf("body element = %q", name)
	}
	if string(raw) != envelope {
		t.Fatal("the raw envelope must be returned for verbatim forwarding")
	}

	twelve := `<Envelope xmlns="` + NamespaceSOAP12 + `"><Body><Ping/></Body></Envelope>`
	if name, _, err := BodyElement(strings.NewReader(twelve)); err != nil || name != "Ping" {
		t.Fatalf("SOAP 1.2 envelope = %q %v", name, err)
	}
	// An envelope with an empty body yields no element rather than an error:
	// the operation may still be named by SOAPAction.
	empty := `<Envelope xmlns="` + NamespaceSOAP11 + `"><Body></Body></Envelope>`
	if name, _, err := BodyElement(strings.NewReader(empty)); err != nil || name != "" {
		t.Fatalf("empty body = %q %v", name, err)
	}
}

func TestBodyElementRefusesWhatItCannotRead(t *testing.T) {
	if _, _, err := BodyElement(strings.NewReader("<Envelope><Body><A>")); err == nil {
		t.Error("a malformed envelope must be reported")
	}
	if _, _, err := BodyElement(strings.NewReader(strings.Repeat("x", MaxEnvelopeBytes+1))); err == nil {
		t.Error("an oversized envelope must be refused")
	}
	if _, _, err := BodyElement(errReader{}); err == nil {
		t.Error("an unreadable body must be reported")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// A fault is what a SOAP client's stack turns into an exception. The two
// versions restructured it, so answering a 1.2 caller with a 1.1 body produces
// something their library cannot decode.
func TestFaultShapeFollowsTheCallersVersion(t *testing.T) {
	body, contentType, status := Fault(Version11, "Client", "no such operation")
	if status != 500 {
		t.Fatalf("status = %d; a SOAP fault rides on 500", status)
	}
	if !strings.Contains(contentType, "text/xml") {
		t.Fatalf("1.1 content type = %q", contentType)
	}
	if !strings.Contains(body, "<faultcode>soap:Client</faultcode>") || !strings.Contains(body, "<faultstring>no such operation</faultstring>") {
		t.Fatalf("1.1 fault = %s", body)
	}

	body, contentType, _ = Fault(Version12, "Sender", "no such operation")
	if !strings.Contains(contentType, "application/soap+xml") {
		t.Fatalf("1.2 content type = %q", contentType)
	}
	if !strings.Contains(body, "<soap:Code><soap:Value>soap:Sender</soap:Value>") {
		t.Fatalf("1.2 fault must use Code/Value, got %s", body)
	}
	if strings.Contains(body, "<faultcode>") {
		t.Fatal("a 1.2 fault must not carry 1.1 elements")
	}

	// The message carries a caller-supplied name, so an unescaped `<` would
	// produce a document the client cannot parse: a clear refusal turned into a
	// parse error.
	escaped, _, _ := Fault(Version11, "Client", `no operation <script>&"'`)
	if strings.Contains(escaped, "<script>") {
		t.Fatalf("the fault message must be escaped, got %s", escaped)
	}
	if !strings.Contains(escaped, "&lt;script&gt;") {
		t.Fatalf("escaping = %s", escaped)
	}
}

func TestLocalNameStripsBothQualifiers(t *testing.T) {
	for input, want := range map[string]string{
		"tns:GetOrder":               "GetOrder",
		"http://shop.test/#GetOrder": "GetOrder",
		"http://shop.test/x#tns:Get": "Get",
		"GetOrder":                   "GetOrder",
		"":                           "",
	} {
		if got := localName(input); got != want {
			t.Errorf("localName(%q) = %q, want %q", input, got, want)
		}
	}
}

// A message part with neither element nor type contributes no element name, and
// two bindings naming the same operation list it once.
func TestParseHandlesIncompletePartsAndDuplicates(t *testing.T) {
	source := `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:tns="http://x/">
	  <message name="M"><part name="p"/><part name="q" element="tns:Real"/></message>
	  <portType name="P"><operation name="Op"><input message="tns:M"/></operation></portType>
	  <binding name="B1" type="tns:P"><operation name="Op"><soap:operation soapAction="a1"/></operation></binding>
	  <binding name="B2" type="tns:P"><operation name="Op"><soap:operation soapAction="a2"/></operation></binding>
	  <service name="S"><port name="P" binding="tns:B1"/></service>
	</definitions>`
	schema, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	// The nameless part is skipped, so the element resolves from the next one.
	if operation, ok := schema.Lookup("a1", ""); !ok || operation.InputElement != "Real" {
		t.Fatalf("element resolution = %+v ok=%v", operation, ok)
	}
	if _, ok := schema.Lookup("a2", ""); !ok {
		t.Fatal("a second binding's action must also route")
	}
	if got := len(schema.Operations()); got != 1 {
		t.Fatalf("Operations() = %d; one operation named by two bindings is still one operation", got)
	}
}
