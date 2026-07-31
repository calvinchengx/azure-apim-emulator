package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
	"software.sslmate.com/src/go-pkcs12"
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
	if got, relative := matchRoute([]*Route{api}, httptest.NewRequest(http.MethodGet, "/api", nil)); got != api || relative != "/" {
		t.Fatalf("exact route = %v %q", got, relative)
	}
	if got, relative := matchRoute([]*Route{api}, httptest.NewRequest(http.MethodGet, "/api/items", nil)); got != api || relative != "/items" {
		t.Fatalf("nested route = %v %q", got, relative)
	}
	if got, relative := matchRoute([]*Route{root}, httptest.NewRequest(http.MethodGet, "/anything", nil)); got != root || relative != "/anything" {
		t.Fatalf("root route = %v %q", got, relative)
	}
	if got, _ := matchRoute([]*Route{api}, httptest.NewRequest(http.MethodGet, "/other", nil)); got != nil {
		t.Fatal("unexpected route match")
	}
	segment := &Route{API: model.API{Path: "api", Version: "v1"}, VersionSet: &model.APIVersionSet{VersioningScheme: "Segment"}}
	if got, relative := matchRoute([]*Route{segment}, httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)); got != segment || relative != "/items" {
		t.Fatalf("segment version = %v %q", got, relative)
	}
	headerV1 := &Route{API: model.API{Path: "api", Version: "v1"}, VersionSet: &model.APIVersionSet{VersioningScheme: "Header", VersionHeaderName: "X-Version"}}
	headerV2 := &Route{API: model.API{Path: "api", Version: "v2"}, VersionSet: headerV1.VersionSet}
	headerRequest := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	headerRequest.Header.Set("X-Version", "v2")
	if got, _ := matchRoute([]*Route{headerV1, headerV2}, headerRequest); got != headerV2 {
		t.Fatalf("header version = %v", got)
	}
	queryV1 := &Route{API: model.API{Path: "api", Version: "v1"}, VersionSet: &model.APIVersionSet{VersioningScheme: "Query", VersionQueryName: "version"}}
	queryV2 := &Route{API: model.API{Path: "api", Version: "v2"}, VersionSet: queryV1.VersionSet}
	if got, _ := matchRoute([]*Route{queryV1, queryV2}, httptest.NewRequest(http.MethodGet, "/api/items?version=v2", nil)); got != queryV2 {
		t.Fatalf("query version = %v", got)
	}
	if got, _ := matchRoute([]*Route{headerV1, queryV1}, httptest.NewRequest(http.MethodGet, "/api/items", nil)); got != nil {
		t.Fatalf("missing version matched %v", got)
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

func TestNamedValueResolution(t *testing.T) {
	values := map[string]string{"token": "resolved"}
	got, err := resolveNamedValues("before {{ Token }} after", values)
	if err != nil || got != "before resolved after" {
		t.Fatalf("resolved = %q, %v", got, err)
	}
	if _, err := resolveNamedValues("{{missing}}", values); err == nil {
		t.Fatal("missing named value should fail")
	}
	if got, err := resolveNamedValues("{{xml}}", map[string]string{"xml": `a&<"`}); err != nil || got != "a&amp;&lt;&#34;" {
		t.Fatalf("XML-safe named value = %q, %v", got, err)
	}
	for scope, want := range map[string]string{
		"/service/s":                   "/service/s",
		"/service/s/apis/a":            "/service/s",
		"/service/s/products/p":        "/service/s",
		"/service/s/subscriptions/key": "/service/s",
		"/service/s/namedValues/value": "/service/s",
	} {
		if got := serviceIDFromScope(scope); got != want {
			t.Errorf("serviceIDFromScope(%q) = %q", scope, got)
		}
	}
}

func TestActivateResolvesNamedValuesInPolicies(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "named", DisplayName: "Named", Path: "named", ServiceURL: "https://backend.test", Protocols: []string{"https"}, IsCurrent: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: http.MethodGet, URLTemplate: "/"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNamedValue(model.NamedValue{ServiceID: service.ID(), Name: "header", DisplayName: "Header", Value: "from-named-value"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Format: "xml", Value: `<policies><inbound><set-header name="X-Named" exists-action="override"><value>{{header}}</value></set-header></inbound><backend><base /></backend><outbound /><on-error /></policies>`}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Named") != "from-named-value" {
			t.Errorf("named header = %q", request.Header.Get("X-Named"))
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/named", nil), http.StatusNoContent)
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Format: "xml", Value: `<policies><inbound><set-header name="X" exists-action="override"><value>{{missing}}</value></set-header></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, false); err == nil {
		t.Fatal("missing named value should reject activation")
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
	request := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	request.Header.Set("Ocp-Apim-Trace", "true")
	runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "outbound" {
		t.Fatalf("outbound return = %d %q", recorder.Code, recorder.Body.String())
	}
	traceID := strings.TrimPrefix(recorder.Header().Get("Ocp-Apim-Trace-Location"), "/_emulator/traces/")
	trace, ok := runtime.GetTrace(traceID)
	if !ok || trace.API == "" || len(trace.Events) < 4 {
		t.Fatalf("successful trace = %+v, %v", trace, ok)
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
	_, _ = st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "a;rev=2", Path: "private", Revision: "2", IsCurrent: false})
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
	revision := apiA
	revision.Name, revision.Path, revision.Revision, revision.IsCurrent = "a;rev=2", "promoted", "2", false
	revision, _ = st.CloneAPIRevision(apiA.ID(), revision)
	if _, err := st.UpsertAPIRelease(model.APIRelease{APIID: apiA.ID(), Name: "release", TargetAPIID: revision.ID()}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	snapshot = runtime.current.Load()
	routes = snapshot.Services["emulator"].Routes
	if len(routes) != 2 || routes[1].API.Name != "a;rev=2" {
		t.Fatalf("promoted routes = %+v", routes)
	}
	_, _ = st.UpsertPolicy(model.Policy{ScopeID: apiA.ID(), Value: `<policies><inbound><choose/></inbound></policies>`})
	if err := runtime.Activate(st, true); err == nil {
		t.Fatal("strict invalid policy activation succeeded")
	}
	if runtime.current.Load() != snapshot {
		t.Fatal("failed activation replaced the last-known-good snapshot")
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

func TestActivateVersionSets(t *testing.T) {
	newStore := func(t *testing.T) (*store.Store, string, model.Service) {
		t.Helper()
		dir := t.TempDir()
		st, err := store.Open(dir, clock.New())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
		if err != nil {
			t.Fatal(err)
		}
		return st, filepath.Join(dir, "azure-apim-emulator.db"), service
	}

	t.Run("resolved and missing reference", func(t *testing.T) {
		st, path, service := newStore(t)
		versionSet, err := st.UpsertAPIVersionSet(model.APIVersionSet{ServiceID: service.ID(), Name: "versions", DisplayName: "Versions", VersioningScheme: "Segment"})
		if err != nil {
			t.Fatal(err)
		}
		api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "v1", Path: "api", Version: "v1", VersionSetID: versionSet.ID()})
		if err != nil {
			t.Fatal(err)
		}
		runtime := New("emulator", nil)
		if err := runtime.Activate(st, false); err != nil {
			t.Fatal(err)
		}
		if runtime.current.Load().Services["emulator"].Routes[0].VersionSet == nil {
			t.Fatal("version set was not resolved")
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(`PRAGMA foreign_keys=OFF; UPDATE api_version_metadata SET version_set_id='/missing' WHERE api_id=?`, api.ID()); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Activate(st, false); err == nil {
			t.Fatal("missing version set activated")
		}
	})

	t.Run("query failure", func(t *testing.T) {
		st, path, _ := newStore(t)
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(`DROP TABLE api_version_sets`); err != nil {
			t.Fatal(err)
		}
		if err := New("emulator", nil).Activate(st, false); err == nil {
			t.Fatal("missing version-set table activated")
		}
	})
}

func TestActivateNamedValueStoreFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE named_values`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := New("emulator", nil).Activate(st, false); err == nil {
		t.Fatal("activation should fail when named values cannot be read")
	}
}

func TestActivateBackendReferences(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api", Path: "api", ServiceURL: "https://default", IsCurrent: true})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := st.UpsertBackend(model.Backend{ServiceID: service.ID(), Name: "primary", URL: "https://selected", Protocol: "http", Document: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound><set-backend-service backend-id="primary"/></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	action := runtime.current.Load().Services["emulator"].Routes[0].Plan.Inbound[0]
	if action.Value != backend.URL || action.BackendID != backend.Name {
		t.Fatalf("resolved backend = %+v", action)
	}
	backend.Document = map[string]any{"properties": map[string]any{"credentials": map[string]any{"certificateIds": []any{"missing"}}}}
	if _, err := st.UpsertBackend(backend); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, false); err == nil {
		t.Fatal("dangling backend certificate should reject activation")
	}
	backend.Document = map[string]any{}
	if _, err := st.UpsertBackend(backend); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound><set-backend-service backend-id="missing"/></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, false); err == nil {
		t.Fatal("missing backend should reject activation")
	}
}

func TestBackendClientCertificateTransport(t *testing.T) {
	pfx := gatewayTestPKCS12(t, "password")
	certificate := model.Certificate{Name: "client", Data: pfx, Password: "password"}
	backend := model.Backend{Name: "secure", Document: map[string]any{"properties": map[string]any{"credentials": map[string]any{"certificateIds": []any{"client"}}}}}
	service := &Service{Backends: map[string]model.Backend{"secure": backend}, Certificates: map[string]model.Certificate{"client": certificate}}
	seenCertificate := false
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seenCertificate = request.TLS != nil && len(request.TLS.PeerCertificates) == 1
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	client, err := backendHTTPClient(server.Client(), service, "secure")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !seenCertificate {
		t.Fatal("backend did not receive a client certificate")
	}
	base := &http.Client{}
	if got, err := backendHTTPClient(base, service, "secure"); err != nil || got.Transport == nil {
		t.Fatalf("default certificate transport = %+v, %v", got, err)
	}
	if got, err := backendHTTPClient(base, service, ""); err != nil || got != base {
		t.Fatalf("empty backend = %p, %v", got, err)
	}
	if _, err := backendHTTPClient(base, service, "missing"); err == nil {
		t.Fatal("missing backend should fail")
	}
	plain := &Service{Backends: map[string]model.Backend{"plain": {Name: "plain"}}}
	if got, err := backendHTTPClient(base, plain, "plain"); err != nil || got != base {
		t.Fatalf("plain backend = %p, %v", got, err)
	}
	if _, err := backendHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })}, service, "secure"); err == nil {
		t.Fatal("custom transport should reject client certificates")
	}
	missingCertificate := &Service{Backends: service.Backends, Certificates: map[string]model.Certificate{}}
	if _, err := backendHTTPClient(base, missingCertificate, "secure"); err == nil {
		t.Fatal("missing certificate should fail")
	}
	badCertificate := &Service{Backends: service.Backends, Certificates: map[string]model.Certificate{"client": {Data: []byte("bad")}}}
	if _, err := backendHTTPClient(base, badCertificate, "secure"); err == nil {
		t.Fatal("invalid certificate should fail")
	}
	if err := validateBackendCertificates(service.Backends, service.Certificates); err != nil {
		t.Fatal(err)
	}
	if err := validateBackendCertificates(service.Backends, nil); err == nil {
		t.Fatal("dangling certificate should fail validation")
	}
	runtime := New("emulator", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })})
	route := &Route{API: model.API{Path: "api", ServiceURL: "https://backend"}, Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}}, Plan: policy.Plan{Inbound: []policy.Action{{Kind: policy.ActionSetBackend, BackendID: "secure", Value: "https://backend"}}}}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Routes: []*Route{route}, Backends: service.Backends, Certificates: service.Certificates}}})
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/api", nil), http.StatusInternalServerError)
}

func gatewayTestPKCS12(t *testing.T, password string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client.test"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.Modern.Encode(key, leaf, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	return pfx
}

func TestActivateBackendStoreFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE backends`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := New("emulator", nil).Activate(st, false); err == nil {
		t.Fatal("activation should fail when backends cannot be read")
	}
}

func TestActivateCertificateStoreFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertCertificate(model.Certificate{ServiceID: service.ID(), Name: "client", KeyVaultSecretID: "vault"}); err != nil {
		t.Fatal(err)
	}
	if err := New("emulator", nil).Activate(st, false); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE certificates`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := New("emulator", nil).Activate(st, false); err == nil {
		t.Fatal("activation should fail when certificates cannot be read")
	}
}

func TestWritePolicyResponseDefaultStatus(t *testing.T) {
	recorder := httptest.NewRecorder()
	writePolicyResponse(recorder, &policy.State{Body: "ok", Headers: http.Header{"X": {"y"}}})
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" || recorder.Header().Get("X") != "y" {
		t.Fatalf("response = %d %q %v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

func TestStructuredTraceAndBound(t *testing.T) {
	runtime := New("emulator", nil)
	request := httptest.NewRequest(http.MethodGet, "/missing?q=1", nil)
	request.Header.Set("Ocp-Apim-Trace", "TRUE")
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	location := recorder.Header().Get("Ocp-Apim-Trace-Location")
	id := strings.TrimPrefix(location, "/_emulator/traces/")
	trace, ok := runtime.GetTrace(id)
	if !ok || trace.Status != http.StatusNotFound || trace.Path != "/missing?q=1" || len(trace.Events) != 1 {
		t.Fatalf("trace = %+v, %v", trace, ok)
	}
	if _, ok := runtime.GetTrace("missing"); ok {
		t.Fatal("missing trace found")
	}

	for index := 0; index < traceLimit; index++ {
		item := &Trace{ID: fmt.Sprintf("trace-%d", index)}
		runtime.finishTrace(item, &traceWriter{status: http.StatusNoContent})
	}
	if _, ok := runtime.GetTrace(id); ok || len(runtime.traceOrder) != traceLimit {
		t.Fatalf("trace bound = %d, original retained=%v", len(runtime.traceOrder), ok)
	}
}

func TestTraceWriterAndEvents(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &traceWriter{ResponseWriter: recorder}
	if _, err := writer.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	writer.WriteHeader(http.StatusCreated)
	if writer.status != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("writer = %+v", writer)
	}
	traceEvent(nil, "ignored", "")
	runtime := New("emulator", nil)
	trace, writer := runtime.beginTrace(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if trace != nil || writer != nil {
		t.Fatal("trace unexpectedly enabled")
	}
	item := &Trace{ID: "default"}
	runtime.finishTrace(item, &traceWriter{})
	if got, _ := runtime.GetTrace("default"); got.Status != http.StatusOK {
		t.Fatalf("default status = %d", got.Status)
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
