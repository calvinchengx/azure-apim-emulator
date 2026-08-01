package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/config"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const (
	testSubscription = "11111111-1111-1111-1111-111111111111"
	testServiceID    = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/emulator"
)

func TestManagementToGatewayVerticalSlice(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "reached")
		_ = json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path, "inbound": r.Header.Get("X-Inbound")})
	}))
	defer backend.Close()

	srv := newTestServer(t, false, backend.Client())
	front := httptest.NewServer(srv.Handler())
	defer front.Close()

	servicePath := "/subscriptions/" + testSubscription + "/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/emulator"
	response := management(t, front.Client(), http.MethodPut, front.URL+servicePath+"?api-version=2024-05-01", `{"location":"local","sku":{"name":"Developer","capacity":1},"properties":{"publisherName":"Local","publisherEmail":"local@example.test"}}`)
	if response.StatusCode != http.StatusCreated {
		fatalResponse(t, response)
	}
	operationURL := response.Header.Get("Azure-AsyncOperation")
	response.Body.Close()
	if operationURL == "" {
		t.Fatal("service PUT omitted Azure-AsyncOperation")
	}
	response = management(t, front.Client(), http.MethodGet, operationURL, "")
	if response.StatusCode != http.StatusOK {
		fatalResponse(t, response)
	}
	response.Body.Close()

	apiPath := servicePath + "/apis/echo"
	putOK(t, front, apiPath, `{"properties":{"displayName":"Echo API","path":"echo","serviceUrl":"`+backend.URL+`","protocols":["https"],"subscriptionRequired":true}}`)
	putOK(t, front, apiPath+"/operations/get-item", `{"properties":{"displayName":"Get item","method":"GET","urlTemplate":"/items/{id}"}}`)

	policyXML := `<policies><inbound><base/><set-header name="X-Inbound" exists-action="override"><value>from-policy</value></set-header></inbound><backend><base/><forward-request/></backend><outbound><base/><set-header name="X-Outbound" exists-action="override"><value>from-policy</value></set-header></outbound><on-error><base/></on-error></policies>`
	policyBody, _ := json.Marshal(map[string]any{"properties": map[string]any{"format": "rawxml", "value": policyXML}})
	putOK(t, front, apiPath+"/policies/policy", string(policyBody))

	productPath := servicePath + "/products/starter"
	putOK(t, front, productPath, `{"properties":{"displayName":"Starter","state":"published","approvalRequired":false}}`)
	putOK(t, front, productPath+"/apis/echo", `{}`)
	putOK(t, front, servicePath+"/subscriptions/test-sub", `{"properties":{"displayName":"Test subscription","scope":"`+testServiceID+`/products/starter","state":"active","primaryKey":"primary-test-key","secondaryKey":"secondary-test-key"}}`)

	request, _ := http.NewRequest(http.MethodGet, front.URL+"/echo/items/42?view=full", nil)
	request.Host = "emulator.azure-api.localhost"
	request.Header.Set("Ocp-Apim-Subscription-Key", "primary-test-key")
	response, err := front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fatalResponse(t, response)
	}
	if got := response.Header.Get("X-Outbound"); got != "from-policy" {
		t.Fatalf("X-Outbound = %q", got)
	}
	if got := response.Header.Get("X-Backend"); got != "reached" {
		t.Fatalf("X-Backend = %q", got)
	}
	var backendResult map[string]string
	if err := json.NewDecoder(response.Body).Decode(&backendResult); err != nil {
		t.Fatal(err)
	}
	if backendResult["path"] != "/items/42" || backendResult["inbound"] != "from-policy" {
		t.Fatalf("backend saw %#v", backendResult)
	}

	request, _ = http.NewRequest(http.MethodGet, front.URL+"/echo/items/42", nil)
	request.Host = "emulator.azure-api.localhost"
	response, err = front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		fatalResponse(t, response)
	}
}

func TestUnsupportedExpressionDefaultAndStrictModes(t *testing.T) {
	expressionXML := `<policies><inbound><set-header name="X"><value>@(context.Request.Method)</value></set-header></inbound><backend><forward-request/></backend><outbound/><on-error/></policies>`
	body, _ := json.Marshal(map[string]any{"properties": map[string]any{"format": "rawxml", "value": expressionXML}})

	for _, test := range []struct {
		name   string
		strict bool
		want   int
	}{{"default accepts", false, http.StatusCreated}, {"strict rejects", true, http.StatusBadRequest}} {
		t.Run(test.name, func(t *testing.T) {
			srv := newTestServer(t, test.strict, http.DefaultClient)
			front := httptest.NewServer(srv.Handler())
			defer front.Close()
			servicePath := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/emulator-rg/providers/Microsoft.ApiManagement/service/emulator"
			putOK(t, front, servicePath+"/apis/expr", `{"properties":{"displayName":"Expressions","path":"expr","serviceUrl":"http://127.0.0.1:1","protocols":["https"],"subscriptionRequired":false}}`)
			response := management(t, front.Client(), http.MethodPut, front.URL+servicePath+"/apis/expr/policies/policy?api-version=2024-05-01", string(body))
			defer response.Body.Close()
			if response.StatusCode != test.want {
				fatalResponse(t, response)
			}
		})
	}
}

func TestControlAndDispatchEndpoints(t *testing.T) {
	cfg := &config.Config{Addr: ":0", DefaultService: "emulator", Location: "local", DisableTLS: true, DisableAuth: true}
	srv, err := New(cfg, nil, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	withValidator, err := New(cfg, auth.New("https://issuer.test", "https://keys.test", false, func() int64 { return 0 }, http.DefaultClient), http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	withValidator.Close()

	for _, path := range []string{"/health", "/_emulator/clock", "/_emulator/portal/api/status", "/_emulator/portal/api/snapshot", "/_emulator/portal/api/parity", "/_emulator/portal/api/faults", "/_emulator/portal/api/diagnostics"} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("%s = %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
	status := httptest.NewRecorder()
	srv.Handler().ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/status", nil))
	if !strings.Contains(status.Body.String(), `"name":"emulator"`) {
		t.Fatalf("portal resource summary = %s", status.Body.String())
	}
	diagnostics := httptest.NewRecorder()
	srv.Handler().ServeHTTP(diagnostics, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/diagnostics", nil))
	if diagnostics.Code != http.StatusOK || !strings.Contains(diagnostics.Body.String(), `"events":[]`) {
		t.Fatalf("portal diagnostics = %d %s", diagnostics.Code, diagnostics.Body.String())
	}
	if !strings.Contains(status.Body.String(), `"counts"`) || !strings.Contains(status.Body.String(), `"products"`) {
		t.Fatalf("portal core resource counts = %s", status.Body.String())
	}
	fault := httptest.NewRecorder()
	srv.Handler().ServeHTTP(fault, httptest.NewRequest(http.MethodPost, "/_emulator/portal/api/faults", strings.NewReader(`{"service":"emulator","backend":"default","status":503,"remaining":1}`)))
	if fault.Code != http.StatusOK || !strings.Contains(fault.Body.String(), "emulator/default") {
		t.Fatalf("fault update = %d %s", fault.Code, fault.Body.String())
	}
	badFault := httptest.NewRecorder()
	srv.Handler().ServeHTTP(badFault, httptest.NewRequest(http.MethodPost, "/_emulator/portal/api/faults", strings.NewReader("{")))
	if badFault.Code != http.StatusBadRequest {
		t.Fatalf("bad fault = %d", badFault.Code)
	}
	clearFault := httptest.NewRecorder()
	srv.Handler().ServeHTTP(clearFault, httptest.NewRequest(http.MethodPost, "/_emulator/portal/api/faults", strings.NewReader(`{"service":"emulator","backend":"default","clear":true}`)))
	if clearFault.Code != http.StatusOK || strings.Contains(clearFault.Body.String(), "emulator/default") {
		t.Fatalf("fault clear = %d %s", clearFault.Code, clearFault.Body.String())
	}
	scope := "/subscriptions/test/resourceGroups/test/providers/Microsoft.ApiManagement/service/emulator/apis/portal"
	missingPolicy := httptest.NewRecorder()
	srv.Handler().ServeHTTP(missingPolicy, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), nil))
	if missingPolicy.Code != http.StatusNotFound {
		t.Fatalf("missing portal policy = %d", missingPolicy.Code)
	}
	updatedPolicy := httptest.NewRecorder()
	srv.Handler().ServeHTTP(updatedPolicy, httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader(`{"format":"rawxml","value":"<policies><inbound><base/></inbound></policies>"}`)))
	if updatedPolicy.Code != http.StatusOK || !strings.Contains(updatedPolicy.Body.String(), "rawxml") {
		t.Fatalf("portal policy update = %d %s", updatedPolicy.Code, updatedPolicy.Body.String())
	}
	readPolicy := httptest.NewRecorder()
	srv.Handler().ServeHTTP(readPolicy, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), nil))
	if readPolicy.Code != http.StatusOK || !strings.Contains(readPolicy.Body.String(), "policies") {
		t.Fatalf("portal policy read = %d %s", readPolicy.Code, readPolicy.Body.String())
	}
	portalAPI := model.API{ServiceID: model.Service{SubscriptionID: defaultSubscription, ResourceGroup: defaultResourceGroup, Name: "emulator"}.ID(), Name: "portal-api", DisplayName: "Portal API", Path: "portal", ServiceURL: "https://backend.test"}
	if _, err := srv.Store.UpsertAPI(portalAPI); err != nil {
		t.Fatal(err)
	}
	resourceURL := "/_emulator/portal/api/resource?resourceId=" + url.QueryEscape(portalAPI.ID())
	resourceRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resourceRead, httptest.NewRequest(http.MethodGet, resourceURL, nil))
	if resourceRead.Code != http.StatusOK || !strings.Contains(resourceRead.Body.String(), "Portal API") {
		t.Fatalf("portal resource read = %d %s", resourceRead.Code, resourceRead.Body.String())
	}
	resourceUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resourceUpdate, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":"Updated Portal API","path":"updated"}`)))
	if resourceUpdate.Code != http.StatusOK || !strings.Contains(resourceUpdate.Body.String(), "Updated Portal API") {
		t.Fatalf("portal resource update = %d %s", resourceUpdate.Code, resourceUpdate.Body.String())
	}
	portalProduct := model.Product{ServiceID: portalAPI.ServiceID, Name: "portal-product", DisplayName: "Portal Product", State: "notPublished"}
	if _, err := srv.Store.UpsertProduct(portalProduct); err != nil {
		t.Fatal(err)
	}
	productURL := "/_emulator/portal/api/product?resourceId=" + url.QueryEscape(portalProduct.ID())
	productRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productRead, httptest.NewRequest(http.MethodGet, productURL, nil))
	if productRead.Code != http.StatusOK || !strings.Contains(productRead.Body.String(), "Portal Product") {
		t.Fatalf("portal product read = %d %s", productRead.Code, productRead.Body.String())
	}
	productUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productUpdate, httptest.NewRequest(http.MethodPut, productURL, strings.NewReader(`{"displayName":"Updated Product","state":"published","approvalRequired":true}`)))
	if productUpdate.Code != http.StatusOK || !strings.Contains(productUpdate.Body.String(), "published") {
		t.Fatalf("portal product update = %d %s", productUpdate.Code, productUpdate.Body.String())
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/product", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/product?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, productURL, strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, productURL, strings.NewReader(`{"displayName":" "}`)),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal product invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	fullResourceUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(fullResourceUpdate, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":"Full Portal API","path":"full","serviceUrl":"https://new-backend.test","subscriptionRequired":true}`)))
	if fullResourceUpdate.Code != http.StatusOK || !strings.Contains(fullResourceUpdate.Body.String(), "new-backend.test") {
		t.Fatalf("full portal resource update = %d %s", fullResourceUpdate.Code, fullResourceUpdate.Body.String())
	}
	if _, err := srv.Store.UpsertPolicy(model.Policy{ScopeID: portalAPI.ID(), Value: "<invalid>"}); err != nil {
		t.Fatal(err)
	}
	activationResourceUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(activationResourceUpdate, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":"Activation Failure"}`)))
	if activationResourceUpdate.Code != http.StatusBadRequest {
		t.Fatalf("portal resource activation failure = %d %s", activationResourceUpdate.Code, activationResourceUpdate.Body.String())
	}
	productActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productActivationFailure, httptest.NewRequest(http.MethodPut, productURL, strings.NewReader(`{"state":"published"}`)))
	if productActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal product activation failure = %d %s", productActivationFailure.Code, productActivationFailure.Body.String())
	}
	srv.portalUpsertProduct = func(model.Product) (model.Product, error) {
		return model.Product{}, errors.New("injected product persistence failure")
	}
	productStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productStoreFailure, httptest.NewRequest(http.MethodPut, productURL, strings.NewReader(`{"state":"published"}`)))
	if productStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal product persistence failure = %d %s", productStoreFailure.Code, productStoreFailure.Body.String())
	}
	srv.portalUpsertProduct = srv.Store.UpsertProduct
	srv.portalUpsertAPI = func(model.API) (model.API, error) { return model.API{}, errors.New("injected API persistence failure") }
	apiStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(apiStoreFailure, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":"Store Failure"}`)))
	if apiStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal API persistence failure = %d %s", apiStoreFailure.Code, apiStoreFailure.Body.String())
	}
	srv.portalUpsertAPI = srv.Store.UpsertAPI
	emptyUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(emptyUpdate, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":" "}`)))
	if emptyUpdate.Code != http.StatusBadRequest {
		t.Fatalf("empty portal resource name = %d %s", emptyUpdate.Code, emptyUpdate.Body.String())
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/resource", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/resource?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader("{")),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal resource invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/policy", nil),
		httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader(`{"value":"<broken>"}`)),
	} {
		badPolicy := httptest.NewRecorder()
		srv.Handler().ServeHTTP(badPolicy, request)
		if badPolicy.Code != http.StatusBadRequest {
			t.Fatalf("bad portal policy = %d %s", badPolicy.Code, badPolicy.Body.String())
		}
	}
	if _, err := srv.Store.UpsertPolicy(model.Policy{ScopeID: "/invalid-policy", Value: "<broken/>"}); err != nil {
		t.Fatal(err)
	}
	activationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(activationFailure, httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader(`{"format":"rawxml","value":"<policies/>"}`)))
	if activationFailure.Code != http.StatusBadRequest {
		t.Fatalf("activation failure = %d %s", activationFailure.Code, activationFailure.Body.String())
	}
	portal := httptest.NewRecorder()
	srv.Handler().ServeHTTP(portal, httptest.NewRequest(http.MethodGet, "/_emulator/portal/", nil))
	if portal.Code != http.StatusOK || !strings.Contains(portal.Body.String(), "Azure APIM Emulator") || !strings.Contains(portal.Body.String(), "Diagnostic Events") || !strings.Contains(portal.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("portal = %d %s", portal.Code, portal.Body.String())
	}

	for _, test := range []struct {
		body string
		want int
	}{
		{`{"offset":5,"advance":7,"freeze":true}`, http.StatusOK},
		{`{"freeze":false}`, http.StatusOK},
		{`{`, http.StatusBadRequest},
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/_emulator/clock", strings.NewReader(test.body)))
		if recorder.Code != test.want {
			t.Fatalf("clock %q = %d %s", test.body, recorder.Code, recorder.Body.String())
		}
	}

	managementRecorder := httptest.NewRecorder()
	path := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/emulator-rg/providers/Microsoft.ApiManagement/service/emulator?api-version=2024-05-01"
	srv.Handler().ServeHTTP(managementRecorder, httptest.NewRequest(http.MethodGet, path, nil))
	if managementRecorder.Code != http.StatusOK {
		t.Fatalf("management dispatch = %d %s", managementRecorder.Code, managementRecorder.Body.String())
	}
	gatewayRecorder := httptest.NewRecorder()
	gatewayRequest := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	gatewayRequest.Header.Set("Ocp-Apim-Trace", "true")
	srv.Handler().ServeHTTP(gatewayRecorder, gatewayRequest)
	if gatewayRecorder.Code != http.StatusNotFound {
		t.Fatalf("gateway dispatch = %d", gatewayRecorder.Code)
	}
	traceLocation := gatewayRecorder.Header().Get("Ocp-Apim-Trace-Location")
	traceRecorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(traceRecorder, httptest.NewRequest(http.MethodGet, traceLocation, nil))
	if traceRecorder.Code != http.StatusOK || !strings.Contains(traceRecorder.Body.String(), `"status":404`) {
		t.Fatalf("trace = %d %s", traceRecorder.Code, traceRecorder.Body.String())
	}
	missingTrace := httptest.NewRecorder()
	srv.Handler().ServeHTTP(missingTrace, httptest.NewRequest(http.MethodGet, "/_emulator/traces/missing", nil))
	if missingTrace.Code != http.StatusNotFound {
		t.Fatalf("missing trace = %d", missingTrace.Code)
	}
	if err := srv.Store.Close(); err != nil {
		t.Fatal(err)
	}
	updateStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(updateStoreFailure, httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader(`{"format":"rawxml","value":"<policies/>"}`)))
	if updateStoreFailure.Code != http.StatusInternalServerError {
		t.Fatalf("update store failure = %d %s", updateStoreFailure.Code, updateStoreFailure.Body.String())
	}
	storeFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(storeFailure, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), nil))
	if storeFailure.Code != http.StatusInternalServerError {
		t.Fatalf("store failure = %d %s", storeFailure.Code, storeFailure.Body.String())
	}
	resourceFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resourceFailure, httptest.NewRequest(http.MethodGet, resourceURL, nil))
	if resourceFailure.Code != http.StatusInternalServerError {
		t.Fatalf("resource store failure = %d %s", resourceFailure.Code, resourceFailure.Body.String())
	}
	productFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productFailure, httptest.NewRequest(http.MethodGet, productURL, nil))
	if productFailure.Code != http.StatusInternalServerError {
		t.Fatalf("product store failure = %d %s", productFailure.Code, productFailure.Body.String())
	}
	diagnosticFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(diagnosticFailure, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/diagnostics", nil))
	if diagnosticFailure.Code != http.StatusInternalServerError {
		t.Fatalf("diagnostic store failure = %d %s", diagnosticFailure.Code, diagnosticFailure.Body.String())
	}
}

func TestNewRejectsInvalidDataDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: filepath.Join(file, "child"), DefaultService: "emulator", Location: "local", DisableAuth: true}
	if srv, err := New(cfg, nil, nil, nil); err == nil || srv != nil {
		t.Fatalf("New = %v, %v", srv, err)
	}
}

func TestNewRollsBackInitializationFailures(t *testing.T) {
	cfg := func(dir string) *config.Config {
		return &config.Config{DataDir: dir, DefaultService: "emulator", Location: "local", DisableAuth: true}
	}

	t.Run("get seeded service", func(t *testing.T) {
		dir := t.TempDir()
		db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TABLE services (id TEXT PRIMARY KEY)`); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if srv, err := New(cfg(dir), nil, nil, nil); err == nil || srv != nil {
			t.Fatalf("New = %v, %v", srv, err)
		}
	})

	t.Run("seed service", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.Open(dir, clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TRIGGER reject_service BEFORE INSERT ON services BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if srv, err := New(cfg(dir), nil, nil, nil); err == nil || srv != nil {
			t.Fatalf("New = %v, %v", srv, err)
		}
	})

	t.Run("activate runtime", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.Open(dir, clock.New())
		if err != nil {
			t.Fatal(err)
		}
		service := model.Service{SubscriptionID: defaultSubscription, ResourceGroup: defaultResourceGroup, Name: "emulator", Location: "local"}
		service, err = st.UpsertService(service)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertPolicy(model.Policy{ScopeID: service.ID(), Value: `<policies><inbound><choose/></inbound></policies>`}); err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		configuration := cfg(dir)
		configuration.StrictPolicies = true
		if srv, err := New(configuration, nil, nil, nil); err == nil || srv != nil {
			t.Fatalf("New = %v, %v", srv, err)
		}
	})
}

func newTestServer(t *testing.T, strict bool, backend *http.Client) *Server {
	t.Helper()
	cfg := &config.Config{Addr: ":0", DefaultService: "emulator", Location: "local", DisableTLS: true, DisableAuth: true, StrictPolicies: strict}
	srv, err := New(cfg, auth.AllowAll{}, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func putOK(t *testing.T, front *httptest.Server, path, body string) {
	t.Helper()
	response := management(t, front.Client(), http.MethodPut, front.URL+path+"?api-version=2024-05-01", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		fatalResponse(t, response)
	}
}

func management(t *testing.T, client *http.Client, method, endpoint, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func fatalResponse(t *testing.T, response *http.Response) {
	t.Helper()
	body, _ := io.ReadAll(response.Body)
	t.Fatalf("status %d: %s", response.StatusCode, body)
}
