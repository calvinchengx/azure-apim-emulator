package server

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

	for _, path := range []string{"/health", "/_emulator/clock", "/_emulator/portal/api/status", "/_emulator/portal/api/snapshot", "/_emulator/portal/api/parity"} {
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
	portal := httptest.NewRecorder()
	srv.Handler().ServeHTTP(portal, httptest.NewRequest(http.MethodGet, "/_emulator/portal/", nil))
	if portal.Code != http.StatusOK || !strings.Contains(portal.Body.String(), "Azure APIM Emulator") || !strings.Contains(portal.Header().Get("Content-Type"), "text/html") {
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
