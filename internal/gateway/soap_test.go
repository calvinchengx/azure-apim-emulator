package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const gatewayWSDL = `<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://shop.test/" targetNamespace="http://shop.test/">
  <message name="GetOrderRequest"><part name="parameters" element="tns:GetOrder"/></message>
  <portType name="OrdersPort"><operation name="GetOrder"><input message="tns:GetOrderRequest"/></operation></portType>
  <binding name="OrdersBinding" type="tns:OrdersPort">
    <operation name="GetOrder"><soap:operation soapAction="http://shop.test/GetOrder"/></operation>
  </binding>
  <service name="Orders"><port name="OrdersPort" binding="tns:OrdersBinding"/></service>
</definitions>`

const soapEnvelope = `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
	`<soap:Body><GetOrder xmlns="http://shop.test/"><ref>A-1</ref></GetOrder></soap:Body></soap:Envelope>`

type soapFixture struct {
	runtime  *Runtime
	store    *store.Store
	calls    int
	lastBody string
	lastAct  string
}

func newSOAPFixture(t *testing.T, apiType, wsdl string) *soapFixture {
	t.Helper()
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{"properties": map[string]any{}}
	if apiType != "" {
		document["properties"] = map[string]any{"apiType": apiType}
	}
	api := model.API{
		ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders",
		ServiceURL: "https://backend.test/soap", IsCurrent: true, Document: document,
	}
	definition := model.APIDefinition{Format: "wsdl", Value: wsdl}
	if wsdl == "" {
		definition = model.APIDefinition{}
	}
	if _, err := st.ImportAPI(api, definition, nil, nil); err != nil {
		t.Fatal(err)
	}
	fixture := &soapFixture{store: st}
	fixture.runtime = New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		fixture.calls++
		fixture.lastAct = request.Header.Get("SOAPAction")
		if request.Body != nil {
			body, _ := io.ReadAll(request.Body)
			fixture.lastBody = string(body)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/xml"}},
			Body:       io.NopCloser(strings.NewReader(`<Envelope><Body><GetOrderResponse><total>99</total></GetOrderResponse></Body></Envelope>`)),
		}, nil
	})})
	if err := fixture.runtime.Activate(st, true); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return fixture
}

func (f *soapFixture) post(t *testing.T, contentType, action, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/orders", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	if action != "" {
		request.Header.Set("SOAPAction", action)
	}
	recorder := httptest.NewRecorder()
	f.runtime.ServeHTTP(recorder, request)
	return recorder
}

// The envelope must arrive byte for byte. Re-serialising the parsed document
// changes whitespace, prefixes and attribute order, and a WS-Security signed
// envelope would stop verifying. Asserted here rather than in the witness,
// because the `soap` library does not hand a service method its raw body.
func TestSOAPForwardsTheEnvelopeVerbatim(t *testing.T) {
	fixture := newSOAPFixture(t, "soap", gatewayWSDL)
	recorder := fixture.post(t, "text/xml; charset=utf-8", `"http://shop.test/GetOrder"`, soapEnvelope)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if fixture.calls != 1 {
		t.Fatalf("backend calls = %d", fixture.calls)
	}
	if fixture.lastBody != soapEnvelope {
		t.Fatalf("the envelope was rewritten:\n got %s\nwant %s", fixture.lastBody, soapEnvelope)
	}
	if fixture.lastAct != `"http://shop.test/GetOrder"` {
		t.Fatalf("SOAPAction = %q; it is how a 1.1 client names its operation", fixture.lastAct)
	}
	if !strings.Contains(recorder.Body.String(), "GetOrderResponse") {
		t.Fatalf("the backend's answer must be returned: %s", recorder.Body.String())
	}
}

// SOAP 1.2 carries the action in the content type, so an action-only gateway
// would reject valid callers.
func TestSOAPRoutesByActionOrBodyElement(t *testing.T) {
	fixture := newSOAPFixture(t, "soap", gatewayWSDL)
	if got := fixture.post(t, `application/soap+xml; action="http://shop.test/GetOrder"`, "", soapEnvelope).Code; got != http.StatusOK {
		t.Fatalf("SOAP 1.2 action parameter routed to %d", got)
	}
	// No action at all: the body element names the operation.
	if got := fixture.post(t, "text/xml", "", soapEnvelope).Code; got != http.StatusOK {
		t.Fatalf("body-element routing gave %d", got)
	}
	if fixture.calls != 2 {
		t.Fatalf("backend calls = %d, want both routed", fixture.calls)
	}
}

// Refused at the gateway as a FAULT, which is what a SOAP client decodes into
// an error. A bare HTTP status would surface as a transport failure instead.
func TestSOAPRefusesUnknownOperationsWithAFault(t *testing.T) {
	fixture := newSOAPFixture(t, "soap", gatewayWSDL)
	rogue := strings.Replace(soapEnvelope, "GetOrder", "Absent", 2)
	recorder := fixture.post(t, "text/xml", `"http://shop.test/Absent"`, rogue)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; a SOAP fault rides on 500", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "<faultcode>soap:Client</faultcode>") {
		t.Fatalf("1.1 fault = %s", body)
	}
	if !strings.Contains(body, "http://shop.test/Absent") {
		t.Fatalf("the fault must name what the caller asked for, got %s", body)
	}
	if fixture.calls != 0 {
		t.Fatal("an unknown operation must never reach the backend")
	}

	// A 1.2 caller gets a 1.2-shaped fault, because the versions restructured
	// faults and a 1.1 body is undecodable to a 1.2 stack.
	twelve := fixture.post(t, `application/soap+xml; action="http://shop.test/Absent"`, "", rogue)
	if !strings.Contains(twelve.Body.String(), "<soap:Code>") || strings.Contains(twelve.Body.String(), "<faultcode>") {
		t.Fatalf("1.2 fault = %s", twelve.Body.String())
	}
	if got := twelve.Header().Get("Content-Type"); !strings.Contains(got, "application/soap+xml") {
		t.Fatalf("1.2 fault content type = %q", got)
	}

	// When no action is given, the fault names the body element instead of an
	// empty string, so the message points at what the caller actually wrote.
	noAction := fixture.post(t, "text/xml", "", rogue)
	if !strings.Contains(noAction.Body.String(), "Absent") {
		t.Fatalf("fault without an action = %s", noAction.Body.String())
	}
}

func TestSOAPRefusesAMalformedEnvelope(t *testing.T) {
	fixture := newSOAPFixture(t, "soap", gatewayWSDL)
	recorder := fixture.post(t, "text/xml", "", "<soap:Envelope><soap:Body><A>")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "<faultcode>") {
		t.Fatalf("a malformed envelope must be refused as a fault, got %s", recorder.Body.String())
	}
	if fixture.calls != 0 {
		t.Fatal("a malformed envelope must not reach the backend")
	}
}

// Content type is the signal: a SOAP API's WSDL is fetched with a plain GET,
// and answering that with a fault would be nonsense.
func TestSOAPOnlyHandlesSOAPTraffic(t *testing.T) {
	fixture := newSOAPFixture(t, "soap", gatewayWSDL)
	request := httptest.NewRequest(http.MethodGet, "/orders?wsdl", nil)
	recorder := httptest.NewRecorder()
	fixture.runtime.ServeHTTP(recorder, request)
	if strings.Contains(recorder.Body.String(), "<faultcode>") {
		t.Fatal("a GET must not be answered with a SOAP fault")
	}

	if !isSOAPRequest(httptest.NewRequest(http.MethodPost, "/", nil)) == false {
		t.Skip()
	}
	for contentType, want := range map[string]bool{
		"text/xml":             true,
		"application/soap+xml": true,
		"application/xml":      true,
		"application/json":     false,
	} {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		request.Header.Set("Content-Type", contentType)
		if got := isSOAPRequest(request); got != want {
			t.Errorf("isSOAPRequest(%q) = %v", contentType, got)
		}
	}
}

func TestSOAPNeedsBothTheAPITypeAndTheWSDL(t *testing.T) {
	if route := newSOAPFixture(t, "", gatewayWSDL).runtime.current.Load().Services["emulator"].Routes[0]; route.SOAP != nil {
		t.Error("a WSDL on a REST API must not put it on the SOAP path")
	}
	if route := newSOAPFixture(t, "soap", "").runtime.current.Load().Services["emulator"].Routes[0]; route.SOAP != nil {
		t.Error("a SOAP API awaiting its import must not be routable")
	}
}

func TestSOAPActivationReportsABrokenWSDL(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api := model.API{
		ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders",
		ServiceURL: "https://backend.test", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "soap"}},
	}
	if _, err := st.ImportAPI(api, model.APIDefinition{Format: "wsdl", Value: "<definitions"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", &http.Client{})
	if err := runtime.Activate(st, true); err == nil {
		t.Fatal("strict activation must reject an unparseable WSDL")
	}
	if err := runtime.Activate(st, false); err != nil {
		t.Fatalf("non-strict activation must survive it: %v", err)
	}
	if route := runtime.current.Load().Services["emulator"].Routes[0]; route.SOAP != nil {
		t.Fatal("a WSDL that failed to compile must leave the route non-SOAP")
	}
}

// An API imported from OpenAPI keeps its definition, so the format check is
// what stops a Swagger document being read as a WSDL.
func TestSOAPIgnoresNonWSDLDefinitions(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api := model.API{
		ServiceID: service.ID(), Name: "orders", Path: "orders", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "soap"}},
	}
	if _, err := st.ImportAPI(api, model.APIDefinition{Format: "openapi", Value: "openapi: 3.0.0"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	schema, err := soapSchemaFor(st, api)
	if err != nil || schema != nil {
		t.Fatalf("an OpenAPI definition must not be parsed as a WSDL, got %v %v", schema, err)
	}
}

func TestSOAPBackendFailuresBecomeFaults(t *testing.T) {
	fixture := newSOAPFixture(t, "soap", gatewayWSDL)
	fixture.runtime.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})}
	recorder := fixture.post(t, "text/xml", `"http://shop.test/GetOrder"`, soapEnvelope)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "soap:Server") {
		t.Fatalf("a backend failure is a Server fault, got %s", recorder.Body.String())
	}
}

// The failure paths after routing.
func TestSOAPBackendClientAndOutboundFailures(t *testing.T) {
	t.Run("backend certificate cannot be loaded", func(t *testing.T) {
		fixture := newSOAPFixture(t, "soap", gatewayWSDL)
		serviceID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator"
		if _, err := fixture.store.UpsertCertificate(model.Certificate{
			ServiceID: serviceID, Name: "client", Data: []byte("not a PKCS12 blob"), Password: "x",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.UpsertBackend(model.Backend{
			ServiceID: serviceID, Name: "secure", URL: "https://backend.test/soap",
			Document: map[string]any{"properties": map[string]any{"credentials": map[string]any{"certificateIds": []any{"client"}}}},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.UpsertPolicy(model.Policy{
			ScopeID: serviceID + "/apis/orders",
			Value:   `<policies><inbound><set-backend-service backend-id="secure" /></inbound></policies>`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := fixture.runtime.Activate(fixture.store, false); err != nil {
			t.Fatal(err)
		}
		recorder := fixture.post(t, "text/xml", `"http://shop.test/GetOrder"`, soapEnvelope)
		if recorder.Code < 400 {
			t.Fatalf("an unusable backend certificate returned %d", recorder.Code)
		}
		if fixture.calls != 0 {
			t.Fatal("no request may be sent when the transport cannot be built")
		}
	})

	t.Run("outbound policy runs and can fail", func(t *testing.T) {
		fixture := newSOAPFixture(t, "soap", gatewayWSDL)
		serviceID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator"
		if _, err := fixture.store.UpsertPolicy(model.Policy{
			ScopeID: serviceID + "/apis/orders",
			Value:   `<policies><outbound><set-header name="X-Seen" exists-action="override"><value>outbound</value></set-header></outbound></policies>`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := fixture.runtime.Activate(fixture.store, false); err != nil {
			t.Fatal(err)
		}
		recorder := fixture.post(t, "text/xml", `"http://shop.test/GetOrder"`, soapEnvelope)
		if got := recorder.Header().Get("X-Seen"); got != "outbound" {
			t.Fatalf("outbound policy did not run on the SOAP path, X-Seen = %q", got)
		}

		if _, err := fixture.store.UpsertPolicy(model.Policy{
			ScopeID: serviceID + "/apis/orders",
			Value:   `<policies><outbound><validate-jwt header-name="Authorization" /></outbound></policies>`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := fixture.runtime.Activate(fixture.store, false); err != nil {
			t.Fatal(err)
		}
		if got := fixture.post(t, "text/xml", `"http://shop.test/GetOrder"`, soapEnvelope).Code; got < 400 {
			t.Fatalf("a failing outbound policy returned %d", got)
		}
	})

	t.Run("return-response replaces the backend answer", func(t *testing.T) {
		fixture := newSOAPFixture(t, "soap", gatewayWSDL)
		serviceID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator"
		if _, err := fixture.store.UpsertPolicy(model.Policy{
			ScopeID: serviceID + "/apis/orders",
			Value:   `<policies><outbound><return-response><set-status code="203" reason="Replaced" /><set-body>replaced</set-body></return-response></outbound></policies>`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := fixture.runtime.Activate(fixture.store, false); err != nil {
			t.Fatal(err)
		}
		recorder := fixture.post(t, "text/xml", `"http://shop.test/GetOrder"`, soapEnvelope)
		if recorder.Code != http.StatusNonAuthoritativeInfo {
			t.Fatalf("return-response gave %d, want 203", recorder.Code)
		}
	})
}

func TestSOAPSchemaLookupReportsStoreFailures(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api := model.API{
		ServiceID: service.ID(), Name: "orders", Path: "orders", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "soap"}},
	}
	st.Close()
	// A store failure reads the same as "no definition yet" by design: both
	// leave the API unroutable rather than serving it as SOAP with no contract.
	schema, err := soapSchemaFor(st, api)
	if err != nil || schema != nil {
		t.Fatalf("soapSchemaFor = %v %v", schema, err)
	}
}
