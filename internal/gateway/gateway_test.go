package gateway

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func TestRoutingHelpers(t *testing.T) {
	if got := serviceNameFromID("/x/service/MyService/apis/a"); got != "MyService" {
		t.Fatalf("serviceNameFromID = %q", got)
	}
	if serviceNameFromID("/missing") != "" {
		t.Fatal("invalid ID should have no service")
	}
	hostTests := map[string]string{
		"alpha.azure-api.localhost:8445": "alpha",
		"beta.azure-api.net":             "beta",
		"localhost:8445":                 "fallback",
	}
	for host, want := range hostTests {
		if got := serviceFromHost(host, "fallback"); got != want {
			t.Errorf("serviceFromHost(%q) = %q", host, got)
		}
	}

	root := &Route{API: model.API{Path: ""}}
	api := &Route{API: model.API{Path: "api"}}
	if got, relative := matchRoute([]*Route{api}, "/api"); got != api || relative != "/" {
		t.Fatalf("exact route = %v %q", got, relative)
	}
	if got, relative := matchRoute([]*Route{api}, "/api/items"); got != api || relative != "/items" {
		t.Fatalf("nested route = %v %q", got, relative)
	}
	if got, relative := matchRoute([]*Route{root}, "/anything"); got != root || relative != "/anything" {
		t.Fatalf("root route = %v %q", got, relative)
	}
	if got, _ := matchRoute([]*Route{api}, "/other"); got != nil {
		t.Fatal("unexpected route match")
	}
	if !templateMatches("/{id}", "/42") || !templateMatches("/fixed", "/fixed") ||
		templateMatches("/a/b", "/a") || templateMatches("/fixed", "/other") {
		t.Fatal("template matching mismatch")
	}
	if len(splitPath("/")) != 0 || len(splitPath("/a/b/")) != 2 {
		t.Fatal("splitPath mismatch")
	}
	operations := []model.Operation{{Method: "GET", URLTemplate: "/{id}"}}
	if !matchOperation(operations, "get", "/1") || matchOperation(operations, "POST", "/1") {
		t.Fatal("operation matching mismatch")
	}
}

func TestHeaderHelpers(t *testing.T) {
	source := http.Header{"X-Test": {"one", "two"}, "Connection": {"close"}}
	target := make(http.Header)
	copyHeaders(target, source)
	if len(target.Values("X-Test")) != 2 || target.Get("Connection") != "" {
		t.Fatalf("copied headers = %v", target)
	}
	for _, name := range []string{"connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"} {
		if !hopByHop(name) {
			t.Errorf("%s should be hop-by-hop", name)
		}
	}
	if hopByHop("content-type") {
		t.Fatal("content-type is not hop-by-hop")
	}
	request := httptest.NewRequest(http.MethodGet, "/?subscription-key=query", nil)
	if subscriptionKey(request) != "query" {
		t.Fatal("query key not found")
	}
	request.Header.Set("Ocp-Apim-Subscription-Key", "header")
	if subscriptionKey(request) != "header" || !validSubscription(request, map[string]bool{"header": true}) {
		t.Fatal("header key not preferred")
	}
}

func TestForwardValidationAndTransport(t *testing.T) {
	runtime := New("emulator", nil)
	request := httptest.NewRequest(http.MethodGet, "http://gateway/original?q=1", nil)
	if _, err := runtime.forward(request, "not-a-url", "/x"); err == nil {
		t.Fatal("invalid backend should fail")
	}
	runtime.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed")
	})}
	if _, err := runtime.forward(request, "https://backend.test", "/x"); err == nil {
		t.Fatal("transport error should propagate")
	}

	var seen *http.Request
	runtime.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		seen = request
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})}
	response, err := runtime.forward(request, "https://backend.test/base/", "/items")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if seen.URL.String() != "https://backend.test/base/items?q=1" || seen.RequestURI != "" || seen.Host != "backend.test" {
		t.Fatalf("forwarded request = %s requestURI=%q host=%q", seen.URL, seen.RequestURI, seen.Host)
	}
}

func TestServeHTTPFailuresAndPolicyResponses(t *testing.T) {
	runtime := New("emulator", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("backend unavailable")
	})})
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusNotFound)

	route := &Route{
		API:        model.API{Name: "api", Path: "api", ServiceURL: "https://backend.test", SubscriptionRequired: false},
		Operations: []model.Operation{{Method: "GET", URLTemplate: "/items"}},
	}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Name: "emulator", Routes: []*Route{route}}}})
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodPost, "/api/items", nil), http.StatusNotFound)

	route.API.SubscriptionRequired = true
	route.AcceptedKeys = map[string]bool{"good": true}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/api/items", nil), http.StatusUnauthorized)
	bad := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	bad.Header.Set("Ocp-Apim-Subscription-Key", "bad")
	assertGatewayStatus(t, runtime, bad, http.StatusUnauthorized)

	route.API.SubscriptionRequired = false
	route.Plan.Inbound = []policy.Action{{Kind: policy.ActionReturnResponse, StatusCode: http.StatusAccepted, Body: "local", Headers: []policy.Header{{Name: "X-Local", Value: "yes"}}}}
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "local" || recorder.Header().Get("X-Local") != "yes" {
		t.Fatalf("local response = %d %q %v", recorder.Code, recorder.Body.String(), recorder.Header())
	}

	route.Plan.Inbound = nil
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/api/items", nil), http.StatusInternalServerError)

	route.Plan.Inbound = []policy.Action{{Kind: policy.ActionUnsupported, Source: "unsupported"}}
	route.Plan.OnError = []policy.Action{{Kind: policy.ActionReturnResponse, StatusCode: 599, Body: "handled"}}
	recorder = httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if recorder.Code != 599 || recorder.Body.String() != "handled" {
		t.Fatalf("on-error response = %d %q", recorder.Code, recorder.Body.String())
	}

	route.Plan.OnError = []policy.Action{{Kind: policy.ActionUnsupported, Source: "also-unsupported"}}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/api/items", nil), http.StatusInternalServerError)
}

func TestSuccessfulBackendAndOutboundReturn(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Backend", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("backend"))
	}))
	defer backend.Close()
	runtime := New("emulator", backend.Client())
	route := &Route{
		API:        model.API{Path: "api", ServiceURL: backend.URL},
		Operations: []model.Operation{{Method: "GET", URLTemplate: "/items"}},
		Plan:       policy.Plan{Outbound: []policy.Action{{Kind: policy.ActionReturnResponse, Body: "outbound"}}},
	}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Routes: []*Route{route}}}})
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "outbound" {
		t.Fatalf("outbound return = %d %q", recorder.Code, recorder.Body.String())
	}

	route.Plan.Outbound = nil
	recorder = httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if recorder.Code != http.StatusCreated || recorder.Body.String() != "backend" || recorder.Header().Get("X-Backend") != "yes" || recorder.Header().Get("Connection") != "" {
		t.Fatalf("backend response = %d %q %v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

func TestBackendAndOutboundPolicyFailures(t *testing.T) {
	runtime := New("emulator", http.DefaultClient)
	route := &Route{
		API:        model.API{Path: "api", ServiceURL: "https://backend.test"},
		Operations: []model.Operation{{Method: "GET", URLTemplate: "/items"}},
	}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Routes: []*Route{route}}}})

	route.Plan.Backend = []policy.Action{{Kind: policy.ActionReturnResponse, StatusCode: http.StatusAccepted, Body: "backend phase"}}
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "backend phase" {
		t.Fatalf("backend return = %d %q", recorder.Code, recorder.Body.String())
	}

	route.Plan.Backend = []policy.Action{{Kind: policy.ActionUnsupported}}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/api/items", nil), http.StatusInternalServerError)

	route.Plan.Backend = nil
	runtime.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})}
	route.Plan.Outbound = []policy.Action{{Kind: policy.ActionUnsupported}}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/api/items", nil), http.StatusInternalServerError)
}

func TestActivateFailuresAndSubscriptionStates(t *testing.T) {
	runtime := New("emulator", nil)
	closed, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(closed, false); err == nil {
		t.Fatal("closed store activation succeeded")
	}

	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service := model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"}
	service, _ = st.UpsertService(service)
	apiA, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "a", Path: "short"})
	apiB, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "b", Path: "much/longer"})
	_, _ = st.UpsertSubscription(model.Subscription{ServiceID: service.ID(), Name: "inactive", Scope: apiA.ID(), State: "suspended", PrimaryKey: "inactive"})
	product, _ := st.UpsertProduct(model.Product{ServiceID: service.ID(), Name: "p"})
	_ = st.LinkProductAPI(product.ID(), apiB.ID())
	_, _ = st.UpsertSubscription(model.Subscription{ServiceID: service.ID(), Name: "linked", Scope: product.ID(), State: "active", PrimaryKey: "linked"})
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	snapshot := runtime.current.Load()
	routes := snapshot.Services["emulator"].Routes
	if len(routes) != 2 || routes[0].API.Name != "b" || routes[0].AcceptedKeys["inactive"] || !routes[0].AcceptedKeys["linked"] {
		t.Fatalf("activated routes = %+v", routes)
	}
	_, _ = st.UpsertPolicy(model.Policy{ScopeID: apiA.ID(), Value: `<policies><inbound><choose/></inbound></policies>`})
	if err := runtime.Activate(st, true); err == nil {
		t.Fatal("strict invalid policy activation succeeded")
	}
}

func TestActivateRejectsOrphanAPI(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	api := model.API{ServiceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/missing", Name: "orphan"}
	if _, err := db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO apis (id, service_id, name, display_name, path, service_url, protocols_json, subscription_required, etag) VALUES (?, ?, ?, '', '', '', '[]', 0, '')`, api.ID(), api.ServiceID, api.Name); err != nil {
		t.Fatal(err)
	}
	if err := New("emulator", nil).Activate(st, false); err == nil {
		t.Fatal("orphan API activation succeeded")
	}
}

func TestWritePolicyResponseDefaultStatus(t *testing.T) {
	recorder := httptest.NewRecorder()
	writePolicyResponse(recorder, &policy.State{Body: "ok", Headers: http.Header{"X": {"y"}}})
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" || recorder.Header().Get("X") != "y" {
		t.Fatalf("response = %d %q %v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

func assertGatewayStatus(t *testing.T, runtime *Runtime, request *http.Request, want int) {
	t.Helper()
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	if recorder.Code != want {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, want, recorder.Body.String())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
