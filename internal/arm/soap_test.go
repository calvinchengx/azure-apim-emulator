package arm

import (
	"net/http"
	"strings"
	"testing"
)

const importWSDL = `<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://shop.test/" targetNamespace="http://shop.test/">
  <message name="GetOrderRequest"><part name="parameters" element="tns:GetOrder"/></message>
  <message name="PingRequest"><part name="parameters" element="tns:Ping"/></message>
  <portType name="OrdersPort">
    <operation name="GetOrder"><input message="tns:GetOrderRequest"/></operation>
    <operation name="Ping"><input message="tns:PingRequest"/></operation>
  </portType>
  <binding name="OrdersBinding" type="tns:OrdersPort">
    <operation name="GetOrder"><soap:operation soapAction="http://shop.test/GetOrder"/></operation>
    <operation name="Ping"><soap:operation soapAction="http://shop.test/Ping"/></operation>
  </binding>
  <service name="Orders"><port name="OrdersPort" binding="tns:OrdersBinding"/></service>
</definitions>`

// Azure imports SOAP through format/value on the API itself, not through a
// schema sub-resource, so following that shape is what keeps an import script
// portable between the emulator and a real service.
func TestWSDLImportDerivesOperationsAndMarksTheAPI(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	body := `{"properties":{"path":"orders","serviceUrl":"https://backend.test/soap","format":"wsdl","value":` + quoteJSON(importWSDL) + `}}`
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/orders"+apiQuery, body, http.StatusCreated)

	got := request(t, handler, http.MethodGet, basePath+"/apis/orders"+apiQuery, "")
	if !strings.Contains(got.Body.String(), `"apiType":"soap"`) {
		t.Fatalf("a WSDL import must mark the API as SOAP: %s", got.Body.String())
	}
	// The display name comes from the WSDL's service when the caller omits one.
	if !strings.Contains(got.Body.String(), `"displayName":"Orders"`) {
		t.Fatalf("displayName should default to the WSDL service name: %s", got.Body.String())
	}

	operations := request(t, handler, http.MethodGet, basePath+"/apis/orders/operations"+apiQuery, "")
	for _, name := range []string{"GetOrder", "Ping"} {
		if !strings.Contains(operations.Body.String(), `"displayName":"`+name+`"`) {
			t.Errorf("operation %s missing: %s", name, operations.Body.String())
		}
	}
	// Every SOAP operation is a POST to the same URL; the operation is chosen
	// by SOAPAction, not by path, so distinct templates would invent a REST
	// shape the WSDL does not describe.
	if strings.Count(operations.Body.String(), `"urlTemplate":"/"`) != 2 {
		t.Fatalf("SOAP operations share one URL template: %s", operations.Body.String())
	}
	if !strings.Contains(operations.Body.String(), `"soapAction":"http://shop.test/GetOrder"`) {
		t.Fatalf("the soapAction must be retained: %s", operations.Body.String())
	}

	// An explicit displayName wins over the WSDL's service name.
	named := `{"properties":{"displayName":"Chosen","path":"o2","serviceUrl":"https://backend.test/soap","format":"wsdl","value":` + quoteJSON(importWSDL) + `}}`
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/o2"+apiQuery, named, http.StatusCreated)
	second := request(t, handler, http.MethodGet, basePath+"/apis/o2"+apiQuery, "")
	if !strings.Contains(second.Body.String(), `"displayName":"Chosen"`) {
		t.Fatalf("an explicit displayName must win: %s", second.Body.String())
	}
}

func TestWSDLImportRejectsABrokenDocument(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	body := `{"properties":{"path":"orders","serviceUrl":"https://backend.test","format":"wsdl","value":"<definitions"}}`
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/orders"+apiQuery, body, http.StatusBadRequest)
}

func TestSOAPImportHelpers(t *testing.T) {
	for _, format := range []string{"wsdl", "WSDL", "wsdl-link"} {
		if !isWSDLFormat(format) {
			t.Errorf("%q is a WSDL format", format)
		}
	}
	for _, format := range []string{"openapi", "swagger-json", ""} {
		if isWSDLFormat(format) {
			t.Errorf("%q is not a WSDL format", format)
		}
	}
	// A document whose properties are not an object still gets stamped, rather
	// than panicking on the type assertion.
	document := map[string]any{"properties": "not an object"}
	markSOAPAPIType(document)
	properties, _ := document["properties"].(map[string]any)
	if properties["apiType"] != "soap" {
		t.Fatalf("markSOAPAPIType = %v", document)
	}
}

func quoteJSON(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + replacer.Replace(value) + `"`
}
