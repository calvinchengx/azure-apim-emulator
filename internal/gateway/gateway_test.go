package gateway

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
	"golang.org/x/net/websocket"
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
	snapshot := &Snapshot{Services: map[string]*Service{
		"alpha": {Name: "alpha", Hostnames: map[string]bool{"api.example.test": true}},
		"beta": {Name: "beta", Hostnames: map[string]bool{"api.example.test:8443": true},
			Gateways: []*SelfHostedGateway{{Name: "edge", Hostnames: map[string]bool{"edge.example.test": true}}}},
	}}
	got, selfHosted := serviceForHost(snapshot, "api.example.test", "fallback")
	if got != "alpha" || selfHosted != nil {
		t.Fatalf("custom host routing = %q %v", got, selfHosted)
	}
	if got, selfHosted := serviceForHost(snapshot, "unknown.example.test", "fallback"); got != "fallback" || selfHosted != nil {
		t.Fatalf("unknown host routing = %q %v", got, selfHosted)
	}
	// A gateway hostname resolves to its service AND to the gateway, which is
	// what narrows the routable set to that gateway's associations.
	if got, selfHosted := serviceForHost(snapshot, "edge.example.test:443", "fallback"); got != "beta" || selfHosted == nil || selfHosted.Name != "edge" {
		t.Fatalf("gateway host routing = %q %v", got, selfHosted)
	}
	if hosts := customHostnames(map[string]any{"hostnameConfigurations": []any{map[string]any{"hostName": "API.Example.Test"}}, "properties": map[string]any{"hostnameConfigurations": []any{map[string]any{"hostName": "portal.example.test"}}}}); !hosts["api.example.test"] || !hosts["portal.example.test"] {
		t.Fatalf("custom hostnames = %#v", hosts)
	}
	if publicNetworkAccess(map[string]any{"properties": map[string]any{"publicNetworkAccess": "Disabled"}}) || !publicNetworkAccess(map[string]any{"properties": map[string]any{"publicNetworkAccess": "Enabled"}}) {
		t.Fatal("public network access projection mismatch")
	}
	runtime := New("fallback", nil)
	runtime.current.Store(&Snapshot{Services: map[string]*Service{
		"custom": {Name: "custom", Hostnames: map[string]bool{"custom.example.test": true}, Routes: []*Route{{API: model.API{Path: "api"}, Operations: []model.Operation{{Method: "GET", URLTemplate: "/"}}, Plan: policy.Plan{Inbound: []policy.Action{{Kind: policy.ActionReturnResponse, StatusCode: http.StatusAccepted, Body: "custom"}}}}}},
	}})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://custom.example.test/api", nil)
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Body.String() != "custom" {
		t.Fatalf("custom-domain gateway response = %d %q", response.Code, response.Body.String())
	}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"custom": {Name: "custom", Hostnames: map[string]bool{"custom.example.test": true}, PublicNetworkDisabled: true}}})
	response = httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("disabled public network response = %d", response.Code)
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

func TestIndexServiceIdentitiesAndBindRequestContext(t *testing.T) {
	if displayName("Shown", "raw") != "Shown" || displayName("", "raw") != "raw" {
		t.Fatal("displayName mismatch")
	}
	services := map[string]*Service{
		"emulator": {Name: "emulator", Location: "local", Products: map[string]model.Product{}, Subscriptions: map[string]model.Subscription{}},
		"empty":    {Name: "empty"},
	}
	product := model.Product{ServiceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator", Name: "starter", DisplayName: "Starter"}
	subscription := model.Subscription{ServiceID: product.ServiceID, Name: "dev", DisplayName: "Dev", Scope: product.ID(), PrimaryKey: "primary", SecondaryKey: "secondary"}
	indexServiceIdentities(services, []model.Product{product, {ServiceID: "/missing", Name: "orphan"}}, []model.Subscription{subscription, {ServiceID: "/missing", Name: "lost", PrimaryKey: "lost"}, {ServiceID: product.ServiceID, Name: "blank"}, {ServiceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/empty", Name: "skip", PrimaryKey: "skip"}})
	if _, ok := services["emulator"].Products[strings.ToLower(product.ID())]; !ok {
		t.Fatal("product not indexed")
	}
	if _, ok := services["emulator"].Subscriptions["primary"]; !ok || services["empty"].Products != nil {
		t.Fatalf("subscription index = %#v empty=%#v", services["emulator"].Subscriptions, services["empty"])
	}

	route := &Route{API: model.API{Name: "pets", DisplayName: "Pets API", Path: "/pets/"}}
	operation := model.Operation{Name: "get-pet", DisplayName: "Get pet", Method: http.MethodGet, URLTemplate: "/{id}"}
	request := httptest.NewRequest(http.MethodGet, "/pets/1", nil)
	request.Header.Set("Ocp-Apim-Subscription-Key", "PRIMARY")
	api, op, productCtx, subscriptionCtx, user, deployment := bindRequestContext(services["emulator"], route, operation, request, nil)
	if api.Id != "pets" || api.Name != "Pets API" || api.Path != "pets" || op.UrlTemplate != "/{id}" || productCtx.Name != "Starter" || subscriptionCtx.Id != "dev" || user != nil || deployment.Region != "local" {
		t.Fatalf("bound context = api=%+v op=%+v product=%+v sub=%+v user=%v deploy=%+v", api, op, productCtx, subscriptionCtx, user, deployment)
	}
	api, _, productCtx, subscriptionCtx, _, deployment = bindRequestContext(nil, nil, model.Operation{Name: "anon"}, nil, nil)
	if api != nil || productCtx != nil || subscriptionCtx != nil || deployment != nil {
		t.Fatalf("nil service/route = api=%v product=%v sub=%v deploy=%v", api, productCtx, subscriptionCtx, deployment)
	}
	bare := &Service{Name: "bare", Location: "east"}
	_, _, productCtx, subscriptionCtx, _, deployment = bindRequestContext(bare, route, operation, request, nil)
	if productCtx != nil || subscriptionCtx != nil || deployment.ServiceName != "bare" {
		t.Fatalf("nil maps = product=%v sub=%v deploy=%+v", productCtx, subscriptionCtx, deployment)
	}
	noProduct := &Service{Name: "np", Subscriptions: map[string]model.Subscription{"primary": {Name: "only"}}}
	_, _, productCtx, subscriptionCtx, _, _ = bindRequestContext(noProduct, route, operation, request, nil)
	if productCtx != nil || subscriptionCtx.Id != "only" {
		t.Fatalf("subscription without product = %+v %+v", productCtx, subscriptionCtx)
	}
	unknown := httptest.NewRequest(http.MethodGet, "/", nil)
	unknown.Header.Set("Ocp-Apim-Subscription-Key", "nope")
	_, _, productCtx, subscriptionCtx, _, _ = bindRequestContext(services["emulator"], route, operation, unknown, nil)
	if productCtx != nil || subscriptionCtx != nil {
		t.Fatal("unknown key bound identity")
	}
}

func TestGatewayBindsDeploymentContext(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "pets", DisplayName: "Pets API", Path: "pets", ServiceURL: "https://backend.test", IsCurrent: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "list", DisplayName: "List pets", Method: http.MethodGet, URLTemplate: "/"}); err != nil {
		t.Fatal(err)
	}
	product, err := st.UpsertProduct(model.Product{ServiceID: service.ID(), Name: "starter", DisplayName: "Starter"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkProductAPI(product.ID(), api.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertSubscription(model.Subscription{ServiceID: service.ID(), Name: "dev", DisplayName: "Dev", Scope: product.ID(), State: "active", PrimaryKey: "product-key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound><set-header name="X-Api" exists-action="override"><value>@(context.Api.Id)</value></set-header><set-header name="X-Op" exists-action="override"><value>@(context.Operation.Name)</value></set-header><set-header name="X-Deploy" exists-action="override"><value>@(context.Deployment.ServiceName + ':' + context.Deployment.Region)</value></set-header><set-header name="X-Product" exists-action="override"><value>@(context.Product != null ? context.Product.Name : '')</value></set-header><set-header name="X-Sub" exists-action="override"><value>@(context.Subscription != null ? context.Subscription.Id : '')</value></set-header></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	var seen http.Header
	runtime := New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		seen = request.Header.Clone()
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/pets", nil), http.StatusNoContent)
	if seen.Get("X-Api") != "pets" || seen.Get("X-Op") != "List pets" || seen.Get("X-Deploy") != "emulator:local" || seen.Get("X-Product") != "" || seen.Get("X-Sub") != "" {
		t.Fatalf("unscoped headers = %v", seen)
	}
	productRequest := httptest.NewRequest(http.MethodGet, "/pets", nil)
	productRequest.Header.Set("Ocp-Apim-Subscription-Key", "product-key")
	assertGatewayStatus(t, runtime, productRequest, http.StatusNoContent)
	if seen.Get("X-Product") != "Starter" || seen.Get("X-Sub") != "dev" {
		t.Fatalf("product headers = %v", seen)
	}
}

func TestRetryConditionMatches(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := &http.Response{StatusCode: http.StatusServiceUnavailable}
	for _, test := range []struct {
		condition string
		want      bool
	}{
		{"", true},
		{"@(context.Response.StatusCode == 503)", true},
		{"@(context.Response.StatusCode != 500)", true},
		{"@(context.Response.StatusCode >= 503)", true},
		{"@(context.Response.StatusCode <= 503)", true},
		{"@(context.Response.StatusCode > 500)", true},
		{"@(context.Response.StatusCode < 500)", false},
		{"@(context.Request.Method == 'GET')", true},
		{"@(context.Response.StatusCode)", false},
	} {
		if got := retryConditionMatches(test.condition, request, response, nil); got != test.want {
			t.Errorf("retryConditionMatches(%q) = %v, want %v", test.condition, got, test.want)
		}
	}
	if retryConditionMatches("", request, &http.Response{StatusCode: http.StatusOK}, nil) {
		t.Fatal("successful response should not retry by default")
	}
	if retryConditionMatches("", request, nil, nil) {
		t.Fatal("nil response should not retry")
	}
	if !retryConditionMatches("@(context.LastError != null)", request, nil, errors.New("temporary")) {
		t.Fatal("last-error condition should retry request errors")
	}
	if !retryConditionMatches("", request, nil, errors.New("temporary")) {
		t.Fatal("unconditional retry should retry request errors")
	}
	if retryConditionMatches("@(context.Response.StatusCode >= 500)", request, nil, errors.New("temporary")) {
		t.Fatal("response condition should not retry request errors")
	}
}

func TestForwardWithRetryReplaysRequestBody(t *testing.T) {
	attempts := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		if request.Body != nil && request.Body != http.NoBody {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			if string(body) != "payload" {
				t.Errorf("attempt %d body = %q", attempts, body)
			}
		}
		status := http.StatusServiceUnavailable
		if attempts == 3 {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})}
	request := httptest.NewRequest(http.MethodPost, "http://gateway/input", strings.NewReader("payload"))
	response, err := forwardWithRetry(client, request, "https://backend.example", "/input", []policy.Action{{Kind: policy.ActionRetry, RetryCount: 2, RetryInterval: time.Millisecond, Condition: "@(context.Response.StatusCode >= 500)"}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if attempts != 3 || response.StatusCode != http.StatusOK {
		t.Fatalf("retry result = attempts %d status %d", attempts, response.StatusCode)
	}

	noRetry, err := forwardWithRetry(client, httptest.NewRequest(http.MethodGet, "/", nil), "https://backend.example", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	noRetry.Body.Close()
}

func TestAcquireConcurrency(t *testing.T) {
	runtime := New("emulator", nil)
	release := runtime.acquireConcurrency("tenant", 1)
	if release == nil || runtime.acquireConcurrency("tenant", 1) != nil {
		t.Fatal("concurrency slot was not enforced")
	}
	release()
	if runtime.acquireConcurrency("tenant", 1) == nil {
		t.Fatal("released concurrency slot was not reusable")
	}
	// Named, because three identical calls chained with || read to a linter
	// as one expression repeated, and to a human as a copy-paste slip. The
	// point is that the first two acquire and the third is refused.
	first := runtime.acquireConcurrency("other", 2)
	second := runtime.acquireConcurrency("other", 2)
	third := runtime.acquireConcurrency("other", 2)
	if first == nil || second == nil || third != nil {
		t.Fatal("independent concurrency slots were not isolated")
	}
}

func TestMergeProductActionsSupportsBaseAndAppend(t *testing.T) {
	product := []policy.Action{{Kind: policy.ActionSetHeader, Name: "product"}}
	child := []policy.Action{{Kind: policy.ActionSetHeader, Name: "child"}}
	merged := mergeProductActions(product, child)
	if len(merged) != 2 || merged[0].Name != "product" || merged[1].Name != "child" {
		t.Fatalf("append merge = %+v", merged)
	}
	merged = mergeProductActions([]policy.Action{{Kind: policy.ActionBase}}, child)
	if len(merged) != 1 || merged[0].Name != "child" {
		t.Fatalf("base merge = %+v", merged)
	}
}

func TestForwardWithRetryHandlesErrorsAndCancellation(t *testing.T) {
	attempts := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		return nil, errors.New("temporary")
	})}
	_, err := forwardWithRetry(client, httptest.NewRequest(http.MethodGet, "/", nil), "https://backend.example", "/", []policy.Action{{Kind: policy.ActionRetry, RetryCount: 1, Condition: "@(context.LastError != null)"}})
	if err == nil || attempts != 2 {
		t.Fatalf("error retry = %v attempts %d", err, attempts)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("retry"))}, nil
	})}
	request := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	_, err = forwardWithRetry(cancelClient, request, "https://backend.example", "/", []policy.Action{{Kind: policy.ActionRetry, RetryCount: 1, RetryInterval: time.Hour}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled retry = %v", err)
	}
	badBody := httptest.NewRequest(http.MethodPost, "/", nil)
	badBody.Body = failingReadCloser{}
	if _, err := forwardWithRetry(client, badBody, "https://backend.example", "/", []policy.Action{{Kind: policy.ActionRetry}}); err == nil {
		t.Fatal("body read error should fail before forwarding")
	}
}

func TestWriteGatewayBodyFlushesSSE(t *testing.T) {
	writer := &flushWriter{ResponseRecorder: httptest.NewRecorder()}
	response := &http.Response{Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: one\n\ndata: two\n\n"))}
	writeGatewayBody(writer, response)
	if writer.Body.String() != "data: one\n\ndata: two\n\n" || writer.flushes != 1 {
		t.Fatalf("SSE body = %q flushes %d", writer.Body.String(), writer.flushes)
	}
	response.Body.Close()

	plain := &flushWriter{ResponseRecorder: httptest.NewRecorder()}
	writeGatewayBody(plain, &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("plain"))})
	if plain.Body.String() != "plain" {
		t.Fatalf("plain body = %q", plain.Body.String())
	}
}

func TestBackendCircuitBreaker(t *testing.T) {
	rule := map[string]any{
		"failureCondition": map[string]any{
			"count": float64(2), "interval": "PT60S",
			"statusCodeRanges": []any{map[string]any{"min": float64(500), "max": float64(599)}},
		},
		"tripDuration": "PT30S",
	}
	service := &Service{Name: "emulator", Backends: map[string]model.Backend{"backend": {
		Document: map[string]any{"properties": map[string]any{"circuitBreaker": map[string]any{"rules": []any{rule}}}},
	}}}
	runtime := New("emulator", nil)
	now := time.Now()
	if runtime.circuitOpen(service, "backend", now) {
		t.Fatal("new circuit should be closed")
	}
	runtime.recordCircuit(service, "backend", &http.Response{StatusCode: http.StatusBadGateway}, nil, now)
	runtime.recordCircuit(service, "backend", &http.Response{StatusCode: http.StatusServiceUnavailable}, nil, now.Add(time.Second))
	if !runtime.circuitOpen(service, "backend", now.Add(2*time.Second)) {
		t.Fatal("circuit should be open after threshold")
	}
	if runtime.circuitOpen(service, "missing", now) {
		t.Fatal("missing backend should not open a circuit")
	}
	runtime.recordCircuit(service, "backend", &http.Response{StatusCode: http.StatusOK}, nil, now.Add(31*time.Second))
	if runtime.circuitOpen(service, "backend", now.Add(31*time.Second)) {
		t.Fatal("successful response should reset circuit")
	}
	second := New("emulator", nil)
	second.recordCircuit(service, "backend", &http.Response{StatusCode: http.StatusInternalServerError}, nil, now)
	second.recordCircuit(service, "backend", &http.Response{StatusCode: http.StatusBadGateway}, nil, now.Add(time.Second))
	if second.circuitOpen(service, "backend", now.Add(31*time.Second)) {
		t.Fatal("expired circuit should close")
	}
	if second.circuitOpen(service, "backend", now.Add(32*time.Second)) {
		t.Fatal("closed circuit should remain closed")
	}
	for _, value := range []any{int(1), int64(2), float64(3), "bad"} {
		_ = intNumber(value)
	}
	for _, value := range []struct {
		service *Service
		id      string
	}{
		{nil, "backend"}, {service, ""}, {&Service{Backends: map[string]model.Backend{}}, "backend"},
	} {
		if _, ok := backendCircuitRule(value.service, value.id); ok {
			t.Fatalf("invalid circuit configuration accepted: %+v", value)
		}
	}
	if _, ok := backendCircuitRule(&Service{Backends: map[string]model.Backend{"bad": {Document: map[string]any{"properties": map[string]any{"circuitBreaker": map[string]any{"rules": []any{map[string]any{"failureCondition": map[string]any{"count": float64(0)}}}}}}}}}, "bad"); ok {
		t.Fatal("zero-count circuit configuration accepted")
	}
	if summary := runtime.SnapshotSummary(); len(summary["services"].([]map[string]any)) != 0 {
		t.Fatal("empty snapshot summary was not empty")
	}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{
		"emulator": {Name: "emulator", Routes: []*Route{{API: model.API{Name: "api", Path: "api"}, Operations: []model.Operation{{Name: "get"}}}}},
		"alpha":    {Name: "alpha"},
	}})
	services := runtime.SnapshotSummary()["services"].([]map[string]any)
	if len(services) != 2 || services[1]["routes"].([]map[string]any)[0]["operations"] != 1 {
		t.Fatalf("snapshot services = %#v", services)
	}
	if routes := services[1]["routes"].([]map[string]any); len(routes) != 1 {
		t.Fatalf("snapshot routes = %#v", routes)
	}
	if got := parseAPIMDuration("2s", time.Minute); got != 2*time.Second {
		t.Fatalf("Go duration = %s", got)
	}
	if got := parseAPIMDuration("invalid", 3*time.Second); got != 3*time.Second {
		t.Fatalf("fallback duration = %s", got)
	}
}

func TestGatewayCircuitBreakerOpenPath(t *testing.T) {
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()
	runtime := New("emulator", backend.Client())
	service := &Service{Name: "emulator", Backends: map[string]model.Backend{"breaker": {
		Document: map[string]any{"properties": map[string]any{"circuitBreaker": map[string]any{"rules": []any{map[string]any{
			"failureCondition": map[string]any{"count": float64(1)}, "tripDuration": "PT1H",
		}}}}},
	}}}
	route := &Route{API: model.API{Name: "api", Path: "api", ServiceURL: backend.URL}, Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}}, Plan: policy.Plan{Inbound: []policy.Action{{Kind: policy.ActionSetBackend, BackendID: "breaker", Value: backend.URL}}}}
	service.Routes = []*Route{route}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": service}})
	first := httptest.NewRecorder()
	runtime.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api", nil))
	second := httptest.NewRecorder()
	runtime.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api", nil))
	if first.Code != http.StatusInternalServerError || second.Code != http.StatusInternalServerError || calls != 1 || !strings.Contains(second.Body.String(), "circuit breaker") {
		t.Fatalf("circuit requests = first %d second %d calls %d body %q", first.Code, second.Code, calls, second.Body.String())
	}
}

func TestGatewayFaultControls(t *testing.T) {
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend"))
	}))
	defer backend.Close()
	runtime := New("emulator", backend.Client())
	route := &Route{API: model.API{Name: "api", Path: "api", ServiceURL: backend.URL}, Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}}}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Name: "emulator", Routes: []*Route{route}}}})
	runtime.SetFault("emulator", "", Fault{Status: http.StatusBadGateway, Body: "injected", Remaining: 1})
	first := httptest.NewRecorder()
	runtime.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api", nil))
	second := httptest.NewRecorder()
	runtime.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api", nil))
	if first.Code != http.StatusBadGateway || first.Body.String() != "injected" || second.Code != http.StatusOK || calls != 1 {
		t.Fatalf("fault responses = %d/%q, %d, calls %d", first.Code, first.Body.String(), second.Code, calls)
	}
	if len(runtime.FaultsSnapshot()) != 0 {
		t.Fatal("one-shot fault was not removed")
	}
	runtime.SetFault("emulator", "", Fault{Error: true})
	failed := httptest.NewRecorder()
	runtime.ServeHTTP(failed, httptest.NewRequest(http.MethodGet, "/api", nil))
	if failed.Code != http.StatusInternalServerError || !strings.Contains(failed.Body.String(), "injected backend fault") {
		t.Fatalf("error fault = %d %s", failed.Code, failed.Body.String())
	}
	runtime.SetFault("emulator", "", Fault{})
	runtime.SetFault("emulator", "*", Fault{DelayMS: 1, Remaining: 2})
	if fault, ok := runtime.takeFault("emulator", "named"); !ok || fault.DelayMS != 1 {
		t.Fatalf("wildcard fault = %+v %v", fault, ok)
	}
	if _, ok := runtime.takeFault("emulator", "named"); !ok {
		t.Fatal("remaining wildcard fault disappeared early")
	}
	if _, ok := runtime.takeFault("emulator", "named"); ok {
		t.Fatal("expired wildcard fault remained")
	}
	withBody := httptest.NewRecorder()
	runtime.serveInjectedFault(withBody, httptest.NewRequest(http.MethodGet, "/", nil), policy.Plan{Outbound: []policy.Action{{Kind: policy.ActionSetBody, Body: "rewritten"}}}, &policy.State{Headers: make(http.Header)}, Fault{Status: http.StatusOK, DelayMS: 1})
	if withBody.Code != http.StatusOK || withBody.Body.String() != "rewritten" {
		t.Fatalf("injected body = %d %q", withBody.Code, withBody.Body.String())
	}
	returned := httptest.NewRecorder()
	runtime.serveInjectedFault(returned, httptest.NewRequest(http.MethodGet, "/", nil), policy.Plan{Outbound: []policy.Action{{Kind: policy.ActionReturnResponse, StatusCode: http.StatusAccepted, Body: "returned"}}}, &policy.State{Headers: make(http.Header)}, Fault{Status: http.StatusOK})
	if returned.Code != http.StatusAccepted || returned.Body.String() != "returned" {
		t.Fatalf("injected return = %d %q", returned.Code, returned.Body.String())
	}
	broken := httptest.NewRecorder()
	runtime.serveInjectedFault(broken, httptest.NewRequest(http.MethodGet, "/", nil), policy.Plan{Outbound: []policy.Action{{Kind: policy.ActionUnsupported, Source: "broken"}}}, &policy.State{Headers: make(http.Header)}, Fault{Status: http.StatusOK})
	if broken.Code != http.StatusInternalServerError {
		t.Fatalf("injected policy failure = %d", broken.Code)
	}
	defaultStatus := httptest.NewRecorder()
	runtime.serveInjectedFault(defaultStatus, httptest.NewRequest(http.MethodGet, "/", nil), policy.Plan{}, &policy.State{Headers: make(http.Header)}, Fault{})
	if defaultStatus.Code != http.StatusServiceUnavailable {
		t.Fatalf("default injected status = %d", defaultStatus.Code)
	}
	statused := httptest.NewRecorder()
	runtime.serveInjectedFault(statused, httptest.NewRequest(http.MethodGet, "/", nil), policy.Plan{Outbound: []policy.Action{{Kind: policy.ActionSetStatus, StatusCode: http.StatusTeapot}}}, &policy.State{Headers: make(http.Header)}, Fault{Status: http.StatusOK})
	if statused.Code != http.StatusTeapot {
		t.Fatalf("injected set-status = %d", statused.Code)
	}
	if hosts := customHostnames(map[string]any{"properties": map[string]any{"hostnameConfigurations": []any{"invalid", map[string]any{"hostName": "portal.example"}}}}); !hosts["portal.example"] {
		t.Fatalf("custom host extraction = %#v", hosts)
	}
	// As above: two calls inside the limit, the third over it.
	call1 := runtime.rateLimit("client", 2, time.Minute, 1)
	call2 := runtime.rateLimit("client", 2, time.Minute, 1)
	call3 := runtime.rateLimit("client", 2, time.Minute, 1)
	if call1.Exceeded || call2.Exceeded || !call3.Exceeded {
		t.Fatal("rate limiter did not enforce calls")
	}
	if runtime.rateLimit("other", 1, time.Minute, 1).Exceeded {
		t.Fatal("separate rate key was limited")
	}
	// The counters the rate-limit attributes report come from here, so they are
	// worth asserting as values and not just as a tripped/not-tripped flag.
	firstCall := runtime.rateLimit("counted", 3, time.Minute, 1)
	secondCall := runtime.rateLimit("counted", 3, time.Minute, 1)
	if firstCall.Remaining != 2 || secondCall.Remaining != 1 || firstCall.RetryAfter != 0 {
		t.Fatalf("remaining calls = %+v then %+v", firstCall, secondCall)
	}
	// An increment-count larger than the allowance overshoots it, and remaining
	// reports 0 rather than a negative number of calls.
	over := runtime.rateLimit("overshoot", 2, time.Minute, 5)
	if over.Exceeded || over.Remaining != 0 {
		t.Fatalf("overshooting increment = %+v, want remaining 0", over)
	}
	if next := runtime.rateLimit("overshoot", 2, time.Minute, 1); !next.Exceeded {
		t.Fatalf("call after an overshooting increment = %+v, want exceeded", next)
	}
	runtime.rateLimit("counted", 3, time.Minute, 1)
	fullWindow := runtime.rateLimit("counted", 3, time.Minute, 1)
	if !fullWindow.Exceeded || fullWindow.Remaining != 0 || fullWindow.RetryAfter <= 0 || fullWindow.RetryAfter > time.Minute {
		t.Fatalf("exhausted window = %+v", fullWindow)
	}
	if runtime.bandwidthLimit("bw", -1, 4, time.Minute).Exceeded || runtime.bandwidthLimit("bw", 3, 4, time.Minute).Exceeded || !runtime.bandwidthLimit("bw", 2, 4, time.Minute).Exceeded {
		t.Fatal("bandwidth limiter did not enforce budget")
	}
	if runtime.bandwidthLimit("other-bw", 1, 4, time.Minute).Exceeded {
		t.Fatal("separate bandwidth key was limited")
	}
	runtime.bandwidthWindows["expired-bw"] = []bandwidthStamp{{at: time.Now().Add(-time.Hour), bytes: 8}}
	if runtime.bandwidthLimit("expired-bw", 1, 4, time.Second).Exceeded {
		t.Fatal("expired bandwidth window was limited")
	}
	runtime.cacheSet("cache", http.StatusOK, http.Header{"X-Test": {"yes"}}, "body", time.Minute)
	status, headers, body, ok := runtime.cacheGet("cache")
	if !ok || status != http.StatusOK || headers.Get("X-Test") != "yes" || body != "body" {
		t.Fatalf("cache get = %d %v %q %v", status, headers, body, ok)
	}
	runtime.cacheSet("expired", http.StatusOK, nil, "old", -time.Second)
	if _, _, _, ok := runtime.cacheGet("expired"); ok {
		t.Fatal("expired cache entry returned")
	}
	if _, _, _, ok := runtime.cacheGet("missing"); ok {
		t.Fatal("missing cache entry returned")
	}
	runtime.valueCacheSet("value", "cached", time.Minute)
	if value, ok := runtime.valueCacheGet("value"); !ok || value != "cached" {
		t.Fatalf("value cache get = %q %v", value, ok)
	}
	runtime.valueCacheSet("expired-value", "old", -time.Second)
	if _, ok := runtime.valueCacheGet("expired-value"); ok {
		t.Fatal("expired value cache returned")
	}
	runtime.valueCacheRemove("value")
	if _, ok := runtime.valueCacheGet("value"); ok {
		t.Fatal("removed value cache returned")
	}
}

func TestGatewayOperationAndSubscriptionRejections(t *testing.T) {
	runtime := New("emulator", nil)
	route := &Route{API: model.API{Name: "api", Path: "api", SubscriptionRequired: true}, Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}}, AcceptedKeys: map[string]bool{"valid": true}}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Name: "emulator", Routes: []*Route{route}}}})
	missingRoute := httptest.NewRecorder()
	runtime.ServeHTTP(missingRoute, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if missingRoute.Code != http.StatusNotFound {
		t.Fatalf("missing route = %d", missingRoute.Code)
	}
	missingOperation := httptest.NewRecorder()
	runtime.ServeHTTP(missingOperation, httptest.NewRequest(http.MethodGet, "/api/missing", nil))
	if missingOperation.Code != http.StatusNotFound {
		t.Fatalf("missing operation = %d", missingOperation.Code)
	}
	missingSubscription := httptest.NewRecorder()
	runtime.ServeHTTP(missingSubscription, httptest.NewRequest(http.MethodGet, "/api", nil))
	if missingSubscription.Code != http.StatusUnauthorized {
		t.Fatalf("missing subscription = %d", missingSubscription.Code)
	}
}

func TestWebSocketGatewayTunnel(t *testing.T) {
	backendServer := websocket.Server{Handler: websocket.Handler(func(conn *websocket.Conn) {
		if len(conn.Config().Protocol) > 0 && conn.Config().Protocol[0] == "binary" {
			conn.PayloadType = websocket.BinaryFrame
			var message []byte
			if err := websocket.Message.Receive(conn, &message); err == nil {
				_ = websocket.Message.Send(conn, message)
			}
			return
		}
		conn.PayloadType = websocket.TextFrame
		var message string
		if err := websocket.Message.Receive(conn, &message); err == nil {
			_ = websocket.Message.Send(conn, message)
		}
	})}
	backend := httptest.NewServer(backendServer)
	defer backend.Close()
	runtime := New("emulator", nil)
	route := &Route{API: model.API{Name: "socket", Path: "socket", ServiceURL: backend.URL}, Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}}}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Name: "emulator", Routes: []*Route{route}}}})
	front := httptest.NewServer(runtime)
	defer front.Close()
	frontURL := "ws" + strings.TrimPrefix(front.URL, "http") + "/socket"
	conn, err := websocket.Dial(frontURL, "", "http://example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := websocket.Message.Send(conn, "hello"); err != nil {
		t.Fatal(err)
	}
	var message string
	if err := websocket.Message.Receive(conn, &message); err != nil || message != "hello" {
		t.Fatalf("websocket echo = %q, %v", message, err)
	}
	time.Sleep(10 * time.Millisecond)
	_ = websocket.Message.Send(conn, "after-close")
	var ignored string
	_ = websocket.Message.Receive(conn, &ignored)
	binaryConn, err := websocket.Dial(frontURL, "binary", "http://example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = binaryConn.Close() }()
	if err := websocket.Message.Send(binaryConn, []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	var binaryMessage []byte
	if err := websocket.Message.Receive(binaryConn, &binaryMessage); err != nil || string(binaryMessage) != "bytes" {
		t.Fatalf("binary websocket echo = %q, %v", binaryMessage, err)
	}
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	failedRuntime := New("emulator", nil)
	failedRoute := &Route{API: model.API{Name: "socket", Path: "socket", ServiceURL: closedURL}, Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}}}
	failedRuntime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Name: "emulator", Routes: []*Route{failedRoute}}}})
	failedFront := httptest.NewServer(failedRuntime)
	failedConn, err := websocket.Dial("ws"+strings.TrimPrefix(failedFront.URL, "http")+"/socket", "", "http://example.test")
	if err == nil {
		_ = failedConn.Close()
	}
	failedFront.Close()
}

func TestWebSocketRequestDetection(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if isWebSocketRequest(request) {
		t.Fatal("ordinary request detected as WebSocket")
	}
	request.Header.Set("Upgrade", "websocket")
	if isWebSocketRequest(request) {
		t.Fatal("upgrade without connection token detected")
	}
	request.Header.Set("Connection", "keep-alive, Upgrade")
	if !isWebSocketRequest(request) {
		t.Fatal("WebSocket request not detected")
	}
	bad := httptest.NewRecorder()
	New("emulator", nil).serveWebSocket(bad, request, "://invalid", "/")
	if bad.Code != http.StatusBadGateway {
		t.Fatalf("invalid WebSocket backend = %d", bad.Code)
	}
	for _, test := range []struct {
		backend string
		want    string
	}{
		{"http://backend.test/base", "ws://backend.test/base/items?q=1"},
		{"https://backend.test", "wss://backend.test/items?q=1"},
		{"ws://backend.test", "ws://backend.test/items?q=1"},
	} {
		got, err := websocketBackendURL(test.backend, "/items", "q=1")
		if err != nil || got.String() != test.want {
			t.Fatalf("WebSocket URL %q = %v, %v", test.backend, got, err)
		}
	}
	if _, err := websocketBackendURL("ftp://backend.test", "/", ""); err == nil {
		t.Fatal("unsupported WebSocket scheme accepted")
	}
}

func TestDiagnosticWriterCapabilities(t *testing.T) {
	unsupported := &diagnosticWriter{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := unsupported.Hijack(); err == nil {
		t.Fatal("unsupported hijack succeeded")
	}
	unsupported.Flush()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	supported := &diagnosticWriter{ResponseWriter: &hijackResponseWriter{conn: left}}
	conn, _, err := supported.Hijack()
	if err != nil || conn != left {
		t.Fatalf("supported hijack = %v, %v", conn, err)
	}
}

type hijackResponseWriter struct{ conn net.Conn }

func (w *hijackResponseWriter) Header() http.Header             { return make(http.Header) }
func (w *hijackResponseWriter) Write(value []byte) (int, error) { return len(value), nil }
func (w *hijackResponseWriter) WriteHeader(int)                 {}
func (w *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

type flushWriter struct {
	*httptest.ResponseRecorder
	flushes int
}

func (w *flushWriter) Flush() { w.flushes++ }

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (failingReadCloser) Close() error             { return nil }

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
	defer func() { _ = st.Close() }()
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

func TestActivateInheritsServicePolicyWhenAPIHasNone(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "inherited", Path: "inherited", ServiceURL: "https://backend.test", IsCurrent: true})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", Method: http.MethodGet, URLTemplate: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: service.ID(), Value: `<policies><inbound><set-header name="X-Service-Policy" exists-action="override"><value>inherited</value></set-header></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	apiComposed := false
	operationComposed := false
	productComposed := false
	runtime := New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Service-Policy") != "inherited" {
			t.Errorf("inherited header = %q", request.Header.Get("X-Service-Policy"))
		}
		if apiComposed && request.Header.Get("X-API-Policy") != "composed" {
			t.Errorf("composed API header = %q", request.Header.Get("X-API-Policy"))
		}
		if operationComposed && request.Header.Get("X-Operation-Policy") != "operation" {
			t.Errorf("composed operation header = %q", request.Header.Get("X-Operation-Policy"))
		}
		if productComposed && request.Header.Get("X-Product-Policy") != "product" {
			t.Errorf("composed product header = %q", request.Header.Get("X-Product-Policy"))
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/inherited", nil), http.StatusNoContent)
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound><base/><set-header name="X-API-Policy" exists-action="override"><value>composed</value></set-header></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	apiComposed = true
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/inherited", nil), http.StatusNoContent)
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: operation.APIID + "/operations/" + operation.Name, Value: `<policies><inbound><base/><set-header name="X-Operation-Policy" exists-action="override"><value>operation</value></set-header></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	operationComposed = true
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/inherited", nil), http.StatusNoContent)
	product, err := st.UpsertProduct(model.Product{ServiceID: service.ID(), Name: "product", State: "published"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkProductAPI(product.ID(), api.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertSubscription(model.Subscription{ServiceID: service.ID(), Name: "product-subscription", Scope: product.ID(), State: "active", PrimaryKey: "product-key"}); err != nil {
		t.Fatal(err)
	}
	api.SubscriptionRequired = true
	if _, err := st.UpsertAPI(api); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: product.ID(), Value: `<policies><inbound><set-header name="X-Product-Policy" exists-action="override"><value>product</value></set-header></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	productComposed = true
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	productRequest := httptest.NewRequest(http.MethodGet, "/inherited", nil)
	productRequest.Header.Set("Ocp-Apim-Subscription-Key", "product-key")
	assertGatewayStatus(t, runtime, productRequest, http.StatusNoContent)
	post, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "post", Method: http.MethodPost, URLTemplate: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: post.APIID + "/operations/" + post.Name, Value: `<policies><inbound><base/><set-header name="X-Post-Policy" exists-action="override"><value>post</value></set-header></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	sawGet, sawPost := false, false
	runtime = New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Product-Policy") != "product" {
			t.Errorf("product header = %q", request.Header.Get("X-Product-Policy"))
		}
		switch request.Method {
		case http.MethodGet:
			sawGet = true
			if request.Header.Get("X-Operation-Policy") != "operation" || request.Header.Get("X-Post-Policy") != "" {
				t.Errorf("get operation headers = %q %q", request.Header.Get("X-Operation-Policy"), request.Header.Get("X-Post-Policy"))
			}
		case http.MethodPost:
			sawPost = true
			if request.Header.Get("X-Post-Policy") != "post" || request.Header.Get("X-Operation-Policy") != "" {
				t.Errorf("post operation headers = %q %q", request.Header.Get("X-Post-Policy"), request.Header.Get("X-Operation-Policy"))
			}
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	getReq := httptest.NewRequest(http.MethodGet, "/inherited", nil)
	getReq.Header.Set("Ocp-Apim-Subscription-Key", "product-key")
	assertGatewayStatus(t, runtime, getReq, http.StatusNoContent)
	postReq := httptest.NewRequest(http.MethodPost, "/inherited", nil)
	postReq.Header.Set("Ocp-Apim-Subscription-Key", "product-key")
	assertGatewayStatus(t, runtime, postReq, http.StatusNoContent)
	if !sawGet || !sawPost {
		t.Fatalf("matching operation compose get=%v post=%v", sawGet, sawPost)
	}
}

func TestActivateExpandsPolicyFragments(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "fragment", Path: "fragment", ServiceURL: "https://backend.test", IsCurrent: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", Method: http.MethodGet, URLTemplate: "/"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicyFragment(model.PolicyFragment{ServiceID: service.ID(), Name: "headers", Format: "rawxml", Value: `<fragment><set-header name="X-Fragment"><value>expanded</value></set-header></fragment>`}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound><include-fragment fragment-id="headers"/></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Fragment") != "expanded" {
			t.Errorf("fragment header = %q", request.Header.Get("X-Fragment"))
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/fragment", nil), http.StatusNoContent)
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound><include-fragment fragment-id="missing"/></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, true); err == nil {
		t.Fatal("missing fragment should reject activation")
	}
}

func TestActivatePolicyFragmentStoreFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.UpsertService(model.Service{Name: "emulator"}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE policy_fragments`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := New("emulator", nil).Activate(st, false); err == nil {
		t.Fatal("activation should fail when fragments cannot be read")
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
	route.Plan.Inbound = []policy.Action{{Kind: policy.ActionLimitConcurrency, Value: "tenant", LimitCalls: 1, StatusCode: http.StatusTooManyRequests, Body: "busy"}, {Kind: policy.ActionReturnResponse, StatusCode: http.StatusOK, Body: "limited"}}
	limited := httptest.NewRecorder()
	runtime.ServeHTTP(limited, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if limited.Code != http.StatusOK || limited.Body.String() != "limited" {
		t.Fatalf("limit-concurrency gateway response = %d %q", limited.Code, limited.Body.String())
	}
	route.Plan.Inbound = []policy.Action{{Kind: policy.ActionTrace, TraceSource: "test", TraceSeverity: "info", TraceMessage: "policy trace"}, {Kind: policy.ActionReturnResponse, StatusCode: http.StatusOK, Body: "traced"}}
	traceRequest := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	traceRequest.Header.Set("Ocp-Apim-Trace", "true")
	recorder = httptest.NewRecorder()
	runtime.ServeHTTP(recorder, traceRequest)
	traceID := strings.TrimPrefix(recorder.Header().Get("Ocp-Apim-Trace-Location"), "/_emulator/traces/")
	trace, ok := runtime.GetTrace(traceID)
	if !ok || len(trace.Events) < 1 || trace.Events[len(trace.Events)-1].Detail != "test info policy trace" {
		t.Fatalf("policy trace = %+v, %v", trace, ok)
	}

	route.Plan.Inbound = nil
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/api/items", nil), http.StatusInternalServerError)

	route.Plan.Inbound = []policy.Action{{Kind: policy.ActionUnsupported, Source: "unsupported"}}
	route.Plan.OnError = []policy.Action{{Kind: policy.ActionChoose, Branches: []policy.ChooseBranch{{Condition: "@(context.LastError != null)", Actions: []policy.Action{{Kind: policy.ActionReturnResponse, StatusCode: 599, Body: "handled"}}}}}}
	recorder = httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if recorder.Code != 599 || recorder.Body.String() != "handled" {
		t.Fatalf("on-error response = %d %q", recorder.Code, recorder.Body.String())
	}

	route.Plan.OnError = []policy.Action{{Kind: policy.ActionUnsupported, Source: "also-unsupported"}}
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/api/items", nil), http.StatusInternalServerError)
}

func TestDiagnosticEmissionAndSampling(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	serviceModel, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
	apiModel, _ := st.UpsertAPI(model.API{ServiceID: serviceModel.ID(), Name: "api", Path: "api", ServiceURL: "https://backend"})
	runtime := New("emulator", nil)
	runtime.eventStore.Store(st)
	d100 := model.Diagnostic{ServiceID: serviceModel.ID(), ScopeID: serviceModel.ID(), Name: "all", SamplingPercentage: 100, LogClientIP: true, Document: map[string]any{"properties": map[string]any{"logHeaders": true}}}
	d0 := model.Diagnostic{ServiceID: serviceModel.ID(), ScopeID: apiModel.ID(), Name: "none", SamplingPercentage: 0}
	route := &Route{API: apiModel, Diagnostics: []model.Diagnostic{d0}}
	service := &Service{Diagnostics: []model.Diagnostic{d100, d100}}

	request := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	request.Header.Set("traceparent", "trace-correlation")
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Diagnostic", "visible")
	request.RemoteAddr = "127.0.0.1:1234"
	responseWriter := httptest.NewRecorder()
	responseWriter.Header().Set("X-Response", "visible")
	runtime.emitDiagnostics(request, service, route, &diagnosticWriter{ResponseWriter: responseWriter}, time.Now())
	events, err := st.ListDiagnosticEvents(serviceModel.ID())
	if err != nil || len(events) != 1 || events[0].CorrelationID != "trace-correlation" || events[0].ClientIP != "127.0.0.1" || events[0].StatusCode != http.StatusOK {
		t.Fatalf("trace event = %+v, %v", events, err)
	}
	requestHeaders := events[0].Metadata["requestHeaders"].(map[string]any)
	if requestHeaders["Authorization"].([]any)[0] != "[REDACTED]" || requestHeaders["X-Diagnostic"].([]any)[0] != "visible" {
		t.Fatalf("diagnostic header metadata = %#v", events[0].Metadata)
	}

	d0.AlwaysLog = "allErrors"
	request = httptest.NewRequest(http.MethodPost, "/api/fail", nil)
	request.Header.Set("Request-Id", "request-correlation")
	request.RemoteAddr = "local-client"
	runtime.emitDiagnostics(request, &Service{}, &Route{API: apiModel, Diagnostics: []model.Diagnostic{d0}}, &diagnosticWriter{ResponseWriter: httptest.NewRecorder(), status: http.StatusInternalServerError}, time.Now())
	events, _ = st.ListDiagnosticEvents(serviceModel.ID())
	byCorrelation := map[string]model.DiagnosticEvent{}
	for _, event := range events {
		byCorrelation[event.CorrelationID] = event
	}
	errorEvent := byCorrelation["request-correlation"]
	if len(events) != 2 || errorEvent.ClientIP != "" || errorEvent.StatusCode != http.StatusInternalServerError {
		t.Fatalf("error event = %+v", events)
	}

	d0.LogClientIP = true
	request = httptest.NewRequest(http.MethodGet, "/api/generated", nil)
	request.RemoteAddr = "local-client"
	runtime.emitDiagnostics(request, &Service{}, &Route{API: apiModel, Diagnostics: []model.Diagnostic{d0}}, &diagnosticWriter{ResponseWriter: httptest.NewRecorder(), status: http.StatusBadRequest}, time.Now())
	events, _ = st.ListDiagnosticEvents(serviceModel.ID())
	generatedFound := false
	for _, event := range events {
		generatedFound = generatedFound || (event.CorrelationID != "trace-correlation" && event.CorrelationID != "request-correlation" && event.ClientIP == "local-client")
	}
	if len(events) != 3 || !generatedFound {
		t.Fatalf("generated event = %+v", events)
	}

	emptyRuntime := New("emulator", nil)
	emptyRuntime.emitDiagnostics(request, service, route, &diagnosticWriter{ResponseWriter: httptest.NewRecorder()}, time.Now())
	writer := &diagnosticWriter{ResponseWriter: httptest.NewRecorder()}
	if count, err := writer.Write([]byte("ok")); err != nil || count != 2 || writer.status != http.StatusOK {
		t.Fatalf("diagnostic writer = %d, %v, %d", count, err, writer.status)
	}
	if !diagnosticSampled("anything", 100) || diagnosticSampled("anything", 0) {
		t.Fatal("sampling boundaries failed")
	}
	seenTrue, seenFalse := false, false
	for index := 0; index < 1000 && (!seenTrue || !seenFalse); index++ {
		if diagnosticSampled(fmt.Sprint(index), 50) {
			seenTrue = true
		} else {
			seenFalse = true
		}
	}
	if !seenTrue || !seenFalse {
		t.Fatal("deterministic sampling did not exercise both outcomes")
	}

	bodies := model.Diagnostic{ServiceID: serviceModel.ID(), ScopeID: serviceModel.ID(), Name: "bodies", SamplingPercentage: 100, Document: map[string]any{"properties": map[string]any{
		"frontend": map[string]any{
			"request":  map[string]any{"body": map[string]any{"bytes": 8.0}},
			"response": map[string]any{"body": map[string]any{"bytes": 4}},
		},
	}}}
	bodyReq := httptest.NewRequest(http.MethodPost, "/api/body", strings.NewReader("tok-data"))
	bodyReq.Header.Set("Authorization", "tok")
	bodyReq.GetBody = nil
	bodyWriter := httptest.NewRecorder()
	bodyWriter.Header().Set("Set-Cookie", "tok")
	output := &diagnosticWriter{ResponseWriter: bodyWriter, bodyLimit: 4, requestBody: snapshotRequestBody(bodyReq, 8)}
	_, _ = output.Write([]byte("tok!extra"))
	runtime.emitDiagnostics(bodyReq, &Service{Diagnostics: []model.Diagnostic{bodies}}, &Route{API: apiModel}, output, time.Now())
	events, _ = st.ListDiagnosticEvents(serviceModel.ID())
	var bodyEvent model.DiagnosticEvent
	for _, event := range events {
		if event.DiagnosticID == bodies.ID() {
			bodyEvent = event
		}
	}
	if bodyEvent.Metadata["requestBody"] != "[REDACTED]-data" || bodyEvent.Metadata["responseBody"] != "[REDACTED]!" {
		t.Fatalf("body metadata = %#v", bodyEvent.Metadata)
	}
	if snapshotRequestBody(nil, 8) != "" || snapshotRequestBody(&http.Request{}, 8) != "" {
		t.Fatal("empty request snapshot")
	}
	if bodyReq.GetBody == nil {
		t.Fatal("request GetBody not restored")
	}
	replayed, err := bodyReq.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayedBody, _ := io.ReadAll(replayed)
	if string(replayedBody) != "tok-data" {
		t.Fatalf("restored request body = %q", replayedBody)
	}
	failGet := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcd"))
	failGet.GetBody = func() (io.ReadCloser, error) { return nil, fmt.Errorf("get-body") }
	if snapshotRequestBody(failGet, 8) != "" {
		t.Fatal("GetBody error snapshot")
	}
	failRead := &http.Request{Body: io.NopCloser(&errReader{})}
	if snapshotRequestBody(failRead, 8) != "" {
		t.Fatal("read error snapshot")
	}
	if diagnosticBytes(nil, "frontend", "request") != 0 || truncateBody("abcd", 0) != "abcd" || truncateBody("abcd", 8) != "abcd" {
		t.Fatal("body helpers")
	}
	if diagnosticBytes(map[string]any{"frontend": map[string]any{"request": map[string]any{"body": map[string]any{"bytes": -4}}}}, "frontend", "request") != 0 {
		t.Fatal("negative body limit")
	}
	if diagnosticBytes(map[string]any{"frontend": map[string]any{"response": map[string]any{"body": map[string]any{"bytes": 9000.0}}}}, "frontend", "response") != maxDiagnosticBodyBytes {
		t.Fatal("capped body limit")
	}
	if maskedBody("plain", http.Header{"Authorization": {""}, "X-Visible": {"keep"}}) != "plain" {
		t.Fatal("empty secret body mask")
	}
	ready := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcd"))
	if snapshotRequestBody(ready, 2) != "ab" {
		t.Fatal("GetBody snapshot")
	}
	reqLimit, respLimit := diagnosticBodyLimits([]model.Diagnostic{bodies})
	if reqLimit != 8 || respLimit != 4 {
		t.Fatalf("body limits = %d %d", reqLimit, respLimit)
	}
	limited := &diagnosticWriter{ResponseWriter: httptest.NewRecorder(), bodyLimit: 3}
	_, _ = limited.Write([]byte("ab"))
	_, _ = limited.Write([]byte("cdef"))
	if string(limited.body) != "abc" {
		t.Fatalf("truncated writer = %q", limited.body)
	}
}

func TestActivatedGatewayPersistsDiagnosticEvent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer backend.Close()
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api", Path: "api", ServiceURL: backend.URL})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", Method: http.MethodGet, URLTemplate: "/items"})
	logger, _ := st.UpsertLogger(model.Logger{ServiceID: service.ID(), Name: "local", LoggerType: "azureMonitor"})
	diagnostic, _ := st.UpsertDiagnostic(model.Diagnostic{ServiceID: service.ID(), ScopeID: api.ID(), Name: "local", LoggerID: logger.ID(), SamplingType: "fixed", SamplingPercentage: 100, LogClientIP: true})
	runtime := New("emulator", backend.Client())
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	request.Header.Set("traceparent", "integration-correlation")
	request.RemoteAddr = "10.0.0.1:4321"
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("gateway status = %d", recorder.Code)
	}
	events, err := st.ListDiagnosticEvents(service.ID())
	if err != nil || len(events) != 1 || events[0].DiagnosticID != diagnostic.ID() || events[0].CorrelationID != "integration-correlation" || events[0].StatusCode != http.StatusCreated || events[0].ClientIP != "10.0.0.1" {
		t.Fatalf("gateway diagnostic event = %+v, %v", events, err)
	}
}

func TestActivatedGatewayCapturesDiagnosticBodies(t *testing.T) {
	var received []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		received, _ = io.ReadAll(request.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("response-body"))
	}))
	defer backend.Close()
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api", Path: "api", ServiceURL: backend.URL})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "post", Method: http.MethodPost, URLTemplate: "/items"})
	logger, _ := st.UpsertLogger(model.Logger{ServiceID: service.ID(), Name: "local", LoggerType: "azureMonitor"})
	_, _ = st.UpsertDiagnostic(model.Diagnostic{
		ServiceID: service.ID(), ScopeID: api.ID(), Name: "local", LoggerID: logger.ID(),
		SamplingType: "fixed", SamplingPercentage: 100,
		Document: map[string]any{"properties": map[string]any{
			"logHeaders": true,
			"frontend": map[string]any{
				"request":  map[string]any{"body": map[string]any{"bytes": 6.0}},
				"response": map[string]any{"body": map[string]any{"bytes": 8}},
			},
		}},
	})
	runtime := New("emulator", backend.Client())
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/items", strings.NewReader("request-body"))
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Body.String() != "response-body" || string(received) != "request-body" {
		t.Fatalf("gateway = %d %q backend=%q", recorder.Code, recorder.Body.String(), received)
	}
	events, err := st.ListDiagnosticEvents(service.ID())
	if err != nil || len(events) != 1 {
		t.Fatalf("events = %+v, %v", events, err)
	}
	if events[0].Metadata["requestBody"] != "reques" || events[0].Metadata["responseBody"] != "response" {
		t.Fatalf("captured bodies = %#v", events[0].Metadata)
	}
	requestHeaders := events[0].Metadata["requestHeaders"].(map[string]any)
	if requestHeaders["Authorization"].([]any)[0] != "[REDACTED]" {
		t.Fatalf("integration headers = %#v", requestHeaders)
	}
}

func TestActivateDiagnosticStoreFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator"}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE diagnostics`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := New("emulator", nil).Activate(st, false); err == nil {
		t.Fatal("activation accepted missing diagnostics table")
	}
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
	route.Plan.Outbound = []policy.Action{{Kind: policy.ActionSetBody, Body: "rewritten"}}
	recorder = httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if recorder.Code != http.StatusCreated || recorder.Body.String() != "rewritten" {
		t.Fatalf("set-body response = %d %q", recorder.Code, recorder.Body.String())
	}
	route.Plan.Outbound = []policy.Action{{Kind: policy.ActionSetStatus, StatusCode: http.StatusUnauthorized, Reason: "Unauthorized"}}
	recorder = httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/items", nil))
	if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != "backend" {
		t.Fatalf("set-status response = %d %q", recorder.Code, recorder.Body.String())
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
	defer func() { _ = st.Close() }()
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
	defer func() { _ = st.Close() }()
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
	defer func() { _ = st.Close() }()
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
	defer func() { _ = st.Close() }()
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
	if got, err := backendHTTPClient(&http.Client{Transport: &http.Transport{}}, service, "secure"); err != nil || got.Transport == nil {
		t.Fatalf("nil TLS config transport = %+v, %v", got, err)
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
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer tlsBackend.Close()
	verificationService := &Service{Backends: map[string]model.Backend{"tls": {Name: "tls", Document: map[string]any{"properties": map[string]any{"tls": map[string]any{"validateCertificateChain": true}}}}}}
	verifiedClient, err := backendHTTPClient(&http.Client{}, verificationService, "tls")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedClient.Get(tlsBackend.URL); err == nil {
		t.Fatal("verified TLS backend unexpectedly accepted a self-signed certificate")
	}
	verificationService.Backends["tls"] = model.Backend{Name: "tls", Document: map[string]any{"properties": map[string]any{"tls": map[string]any{"validateCertificateChain": false}}}}
	unverifiedClient, err := backendHTTPClient(&http.Client{}, verificationService, "tls")
	if err != nil {
		t.Fatal(err)
	}
	response, err = unverifiedClient.Get(tlsBackend.URL)
	if err != nil {
		t.Fatalf("unverified TLS backend request failed: %v", err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unverified TLS backend = %d", response.StatusCode)
	}
	response.Body.Close()
	if value, present := backendTLSSetting(model.Backend{Document: map[string]any{"properties": map[string]any{"tls": map[string]any{"validateCertificateChain": "false"}}}}, "validateCertificateChain"); present || value {
		t.Fatalf("invalid TLS setting = %v, %v", value, present)
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
	defer func() { _ = st.Close() }()
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
	defer func() { _ = st.Close() }()
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

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read") }

// A product's subscription limit lives in the lossless ARM document rather than
// a column, and it is nullable: a product with no limit must report null, not
// zero, because zero reads as "no subscriptions allowed".
func TestProductContextReadsTheSubscriptionsLimit(t *testing.T) {
	limited := productContext(model.Product{
		Name: "starter", DisplayName: "Starter", State: "published",
		Document: map[string]any{"properties": map[string]any{
			"subscriptionsLimit": float64(3), "subscriptionRequired": true,
		}},
	})
	if limited.SubscriptionsLimit.String() != "3" || !limited.SubscriptionRequired {
		t.Fatalf("limited product = %#v", limited)
	}
	unlimited := productContext(model.Product{Name: "open", DisplayName: "Open"})
	if unlimited.SubscriptionsLimit.String() != "" {
		t.Fatalf("a product with no limit reported %q", unlimited.SubscriptionsLimit.String())
	}
}

// The subscription context reports the key the CALLER presented, and reads its
// dates from the stored document.
func TestSubscriptionContextReportsThePresentedKey(t *testing.T) {
	got := subscriptionContext(model.Subscription{
		Name: "dev", DisplayName: "Dev", PrimaryKey: "primary", SecondaryKey: "secondary",
		Document: map[string]any{"properties": map[string]any{
			"createdDate": "2026-01-01T00:00:00Z", "startDate": "2026-01-02T00:00:00Z",
		}},
	}, "secondary")
	if got.Key != "secondary" || got.PrimaryKey != "primary" {
		t.Fatalf("presented key = %#v", got)
	}
	if got.CreatedDate != "2026-01-01T00:00:00Z" || got.EndDate != "" {
		t.Fatalf("dates = %#v", got)
	}
}

// A request served by a self-hosted gateway reports that gateway, and one on
// the service's own front door reports the managed gateway. A policy testing
// IsManaged is the reason both exist.
func TestDeploymentContextNamesTheServingGateway(t *testing.T) {
	service := &Service{Name: "emulator", Location: "local", ID: "/subscriptions/s/service/emulator"}
	_, _, _, _, _, managed := bindRequestContext(service, nil, model.Operation{}, nil, nil)
	if managed.Gateway == nil || !managed.Gateway.IsManaged || managed.GatewayId != "managed" {
		t.Fatalf("managed gateway = %#v", managed.Gateway)
	}
	if managed.ServiceId != "/subscriptions/s/service/emulator" {
		t.Fatalf("service id = %q", managed.ServiceId)
	}
	_, _, _, _, _, edge := bindRequestContext(service, nil, model.Operation{}, nil, &SelfHostedGateway{Name: "edge"})
	if edge.Gateway == nil || edge.Gateway.IsManaged || edge.Gateway.Id != "edge" {
		t.Fatalf("self-hosted gateway = %#v", edge.Gateway)
	}
}

// The URL as the caller sent it, captured before a policy can rewrite it.
func TestOriginalRequestURL(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/orders/A-1?x=1", nil)
	plain.Host = "api.example"
	if got := originalRequestURL(plain); got != "http://api.example/orders/A-1?x=1" {
		t.Fatalf("plain = %q", got)
	}
	secure := httptest.NewRequest(http.MethodGet, "/orders", nil)
	secure.Host, secure.TLS = "api.example", &tls.ConnectionState{}
	if got := originalRequestURL(secure); got != "https://api.example/orders" {
		t.Fatalf("secure = %q", got)
	}
	// Outside a request there is nothing to capture, which must not panic.
	if got := originalRequestURL(nil); got != "" {
		t.Fatalf("nil request = %q", got)
	}
	if got := originalRequestURL(&http.Request{}); got != "" {
		t.Fatalf("request with no URL = %q", got)
	}
}

// The matcher reports what the template captured, so a policy reads the same
// values routing used rather than a second implementation that could disagree.
func TestTemplateBindings(t *testing.T) {
	bindings, ok := templateBindings("/orders/{orderId}/items/{itemId:int}", "/orders/A-1/items/7")
	if !ok || bindings["orderId"] != "A-1" || bindings["itemId"] != "7" {
		t.Fatalf("bindings = %v, %v", bindings, ok)
	}
	if _, ok := templateBindings("/orders/{orderId}", "/invoices/A-1"); ok {
		t.Fatal("a non-matching template bound")
	}
	if _, ok := templateBindings("/orders", "/orders/extra"); ok {
		t.Fatal("a template of the wrong length bound")
	}
	// A nameless placeholder still matches the segment; there is simply nothing
	// to bind it to.
	if bindings, ok := templateBindings("/orders/{}", "/orders/A-1"); !ok || len(bindings) != 0 {
		t.Fatalf("nameless placeholder = %v, %v", bindings, ok)
	}
}

// A certificate that will not parse is omitted rather than failing the request:
// a policy asking for a DIFFERENT certificate should still work.
func TestServiceCertificatesSkipsUnparsableEntries(t *testing.T) {
	if got := serviceCertificates(nil); got != nil {
		t.Fatalf("nil service = %v", got)
	}
	if got := serviceCertificates(&Service{}); got != nil {
		t.Fatalf("service with no certificates = %v", got)
	}
	service := &Service{Certificates: map[string]model.Certificate{
		"broken": {Name: "broken", Data: []byte("not a pfx"), Password: "x"},
	}}
	if got := serviceCertificates(service); len(got) != 0 {
		t.Fatalf("an unparsable certificate was exposed: %v", got)
	}
}

// The request's own clock and identity, read through a REAL policy.
//
// #72 bound `context.Timestamp`, `Elapsed`, `RequestId` and `Tracing` on the
// binder but never carried them on policy.State, so they evaluated as zero
// through any actual policy while the binder's own tests passed on a hand-built
// context. A member can be bound and still be empty; only an end-to-end path
// tells the difference, which is why this test drives the gateway rather than
// the binder.
func TestRequestClockAndIdentityReachPolicies(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var seen http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders", ServiceURL: backend.URL, IsCurrent: true})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: http.MethodGet, URLTemplate: "/orders/{orderId}"})
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound>` +
		`<set-header name="X-Stamp" exists-action="override"><value>@(context.Timestamp)</value></set-header>` +
		`<set-header name="X-Elapsed" exists-action="override"><value>@(context.Elapsed)</value></set-header>` +
		`<set-header name="X-Request" exists-action="override"><value>@(context.RequestId)</value></set-header>` +
		`<set-header name="X-Traced" exists-action="override"><value>@(context.Tracing ? "yes" : "no")</value></set-header>` +
		`<set-header name="X-Order" exists-action="override"><value>@(context.Request.MatchedParameters["orderId"])</value></set-header>` +
		`<set-header name="X-Original" exists-action="override"><value>@(context.Request.OriginalUrl.Path)</value></set-header>` +
		`</inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/orders/orders/A-1", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d %s", recorder.Code, recorder.Body.String())
	}
	// A zero timestamp would render as year 1, which is what the #72 gap
	// produced; the assertion is that it is a real clock reading.
	if stamp := seen.Get("X-Stamp"); !strings.HasPrefix(stamp, "20") {
		t.Fatalf("timestamp did not reach the policy: %q", stamp)
	}
	if elapsed := seen.Get("X-Elapsed"); !strings.HasPrefix(elapsed, "00:00:0") {
		t.Fatalf("elapsed did not reach the policy: %q", elapsed)
	}
	if seen.Get("X-Request") == "" {
		t.Fatal("request id did not reach the policy")
	}
	if got := seen.Get("X-Traced"); got != "no" {
		t.Fatalf("tracing on an untraced request = %q", got)
	}
	// And the request-time facts this change adds.
	if got := seen.Get("X-Order"); got != "A-1" {
		t.Fatalf("matched parameter did not reach the policy: %q", got)
	}
	if got := seen.Get("X-Original"); got != "/orders/orders/A-1" {
		t.Fatalf("original url did not reach the policy: %q", got)
	}
}

// <on-error> is the last place a fault can be reported from, so a fault IN it has
// nowhere further to go. It used to go nowhere at all: policyFailure ran the
// section, and on any error fell through to the generic 500 carrying only the
// cause it had been called with. A document whose <on-error> could not run was
// indistinguishable from one that had no <on-error>, and the custom error
// response it promised was dropped with no trace anywhere -- not at the PUT, not
// in the response, not in a trace event.
func TestAFailingOnErrorSectionIsReportedBesideTheCause(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders", ServiceURL: "https://backend.test", IsCurrent: true})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: http.MethodGet, URLTemplate: "/"})
	// An inbound expression that compiles and cannot evaluate, and an <on-error>
	// whose own expression cannot evaluate either.
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies>` +
		`<inbound><set-header name="X-Broken" exists-action="override"><value>@(context.Product.Name)</value></set-header></inbound>` +
		`<on-error><return-response><set-status code="503" reason="Down"/>` +
		`<set-body>@(context.Nope.Thing)</set-body></return-response></on-error></policies>`}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	var reported struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &reported); err != nil {
		t.Fatalf("body %s: %v", recorder.Body.String(), err)
	}
	// The cause is what the caller asked about, and stays first.
	if !strings.HasPrefix(reported.Error.Message, "member access on null") {
		t.Errorf("the original cause was dropped or displaced: %q", reported.Error.Message)
	}
	// The section's own fault, which is why they are not getting the 503 the
	// document promised. Distinct from the cause, so one cannot pass for both.
	if !strings.Contains(reported.Error.Message, "<on-error> section also failed: unknown member Nope") {
		t.Errorf("the on-error failure was swallowed: %q", reported.Error.Message)
	}
}

// An <on-error> section that runs is untouched by the above: the response it
// returns is the response, and the cause is not appended to it.
func TestAWorkingOnErrorSectionStillOwnsTheResponse(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders", ServiceURL: "https://backend.test", IsCurrent: true})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: http.MethodGet, URLTemplate: "/"})
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies>` +
		`<inbound><set-header name="X-Broken" exists-action="override"><value>@(context.Product.Name)</value></set-header></inbound>` +
		`<on-error><return-response><set-status code="503" reason="Down"/>` +
		`<set-body>{"error":"down"}</set-body></return-response></on-error></policies>`}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want the 503 the section returned", recorder.Code)
	}
	if body := recorder.Body.String(); body != `{"error":"down"}` {
		t.Errorf("body = %s, want the section's own", body)
	}
}

// A failure reports WHERE it happened, which is what an on-error policy routes
// on. Driven through the gateway rather than the engine, because the section
// and the scope are only known there.
func TestLastErrorReportsItsLocation(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders", ServiceURL: "https://backend.test", IsCurrent: true})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: http.MethodGet, URLTemplate: "/"})
	// An inbound expression that compiles and cannot evaluate, and an on-error
	// section that reports where it happened.
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies>` +
		`<inbound><set-header name="X-Broken" id="broken-header" exists-action="override"><value>@(context.Product.Name)</value></set-header></inbound>` +
		`<on-error><return-response><set-status code="500" reason="Failed"/>` +
		`<set-body>@(context.LastError.Section + "|" + context.LastError.Source + "|" + context.LastError.Scope + "|" + context.LastError.Reason + "|" + context.LastError.PolicyId)</set-body>` +
		`</return-response></on-error></policies>`}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/orders", nil))
	body := recorder.Body.String()
	// section | source | scope | reason | policyId. PolicyId is read through a
	// real policy rather than off a hand-built error, because a member can be
	// bound on the binder and still arrive empty through the gateway.
	if body != "inbound|set-header|api|ExpressionValueEvaluationFailure|broken-header" {
		t.Fatalf("last error location = %q", body)
	}
}

// A service-scoped policy reports the global scope, which is how an on-error
// handler tells a service-wide failure from an API's own.
func TestLastErrorScopeFollowsTheDocument(t *testing.T) {
	if got := policy.ScopeOf("/subscriptions/s/service/emulator"); got != "global" {
		t.Fatalf("service scope = %q", got)
	}
	if got := policy.ScopeOf("/subscriptions/s/service/emulator/apis/orders"); got != "api" {
		t.Fatalf("api scope = %q", got)
	}
	if got := policy.ScopeOf("/subscriptions/s/service/emulator/apis/orders/operations/get"); got != "operation" {
		t.Fatalf("operation scope = %q", got)
	}
	if got := policy.ScopeOf("/subscriptions/s/service/emulator/products/starter"); got != "product" {
		t.Fatalf("product scope = %q", got)
	}
}

// context.Backend reports the backend a policy actually routed to. Asserted
// through a real request rather than off a hand-built state, because the
// failure mode this guards is the gateway never supplying the catalogue at all,
// which leaves the member bound and permanently null.
func TestBackendContextReportsTheChosenBackend(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "orders", Path: "orders", ServiceURL: "https://backend.test", IsCurrent: true})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", Method: http.MethodGet, URLTemplate: "/"})
	if _, err := st.UpsertBackend(model.Backend{ServiceID: service.ID(), Name: "primary", URL: "https://selected", Protocol: "http", Document: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	// A pool backend is reported as a Pool even though this emulator does not
	// implement pools: the type is read from the document, not assumed.
	if _, err := st.UpsertBackend(model.Backend{ServiceID: service.ID(), Name: "pooled", URL: "https://pool", Protocol: "http",
		Document: map[string]any{"properties": map[string]any{"pool": map[string]any{"services": []any{}}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound>` +
		`<set-backend-service backend-id="primary"/>` +
		`<return-response><set-status code="200"/><set-body>@(context.Backend.Id + "|" + context.Backend.Type)</set-body></return-response>` +
		`</inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if body := recorder.Body.String(); body != "primary|Single" {
		t.Fatalf("context.Backend = %q", body)
	}
	// A pool backend reports Pool, read from its document. This emulator does
	// not implement pools, so assuming Single would be wrong in exactly the
	// case a policy is asking about.
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound>` +
		`<set-backend-service backend-id="pooled"/>` +
		`<return-response><set-status code="200"/><set-body>@(context.Backend.Id + "|" + context.Backend.Type)</set-body></return-response>` +
		`</inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	pooled := httptest.NewRecorder()
	runtime.ServeHTTP(pooled, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if body := pooled.Body.String(); body != "pooled|Pool" {
		t.Fatalf("pool backend = %q", body)
	}
	// Until a policy names one there is no backend resource, and the member is
	// null rather than invented: `context.Backend == null` is the question a
	// policy asks to find out whether a backend was chosen.
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound>` +
		`<return-response><set-status code="200"/><set-body>@(context.Backend == null ? "none" : "set")</set-body></return-response>` +
		`</inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	unset := httptest.NewRecorder()
	runtime.ServeHTTP(unset, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if body := unset.Body.String(); body != "none" {
		t.Fatalf("unset backend = %q", body)
	}
}

// TestKeylessRateLimitCountsPerSubscription drives the documented behaviour over
// HTTP rather than through a stub limiter: one subscription exhausting its calls
// must not throttle another, which a single shared counter would.
func TestKeylessRateLimitCountsPerSubscription(t *testing.T) {
	plan, err := policy.Compile(`<policies><inbound><rate-limit calls="1" renewal-period="60"/><return-response><set-status code="200"/></return-response></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	serviceID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator"
	runtime := New("fallback", nil)
	runtime.current.Store(&Snapshot{Services: map[string]*Service{
		"emulator": {
			Name: "emulator", ID: serviceID, Hostnames: map[string]bool{"emulator.example.test": true},
			Subscriptions: map[string]model.Subscription{
				"key-a": {ServiceID: serviceID, Name: "sub-a", PrimaryKey: "key-a"},
				"key-b": {ServiceID: serviceID, Name: "sub-b", PrimaryKey: "key-b"},
			},
			Routes: []*Route{{
				API:          model.API{Path: "api"},
				Operations:   []model.Operation{{Method: "GET", URLTemplate: "/"}},
				Plan:         plan,
				AcceptedKeys: map[string]bool{"key-a": true, "key-b": true},
			}},
		},
	}})
	var lastResponse *httptest.ResponseRecorder
	call := func(key string) int {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "http://emulator.example.test/api", nil)
		if key != "" {
			request.Header.Set("Ocp-Apim-Subscription-Key", key)
		}
		runtime.ServeHTTP(response, request)
		lastResponse = response
		return response.Code
	}
	if code := call("key-a"); code != http.StatusOK {
		t.Fatalf("first call for sub-a = %d", code)
	}
	if code := call("key-a"); code != http.StatusTooManyRequests {
		t.Fatalf("second call for sub-a = %d, want 429", code)
	}
	// The 429 carries a wait the caller can act on. It was the literal string
	// "true" until the limiter started reporting an interval.
	retryAfter := lastResponse.Header().Get("Retry-After")
	seconds, err := strconv.Atoi(retryAfter)
	if err != nil || seconds < 1 || seconds > 60 {
		t.Fatalf("Retry-After on the throttled response = %q", retryAfter)
	}
	if code := call("key-b"); code != http.StatusOK {
		t.Fatalf("sub-b throttled by sub-a's traffic = %d", code)
	}
}

// TestPostponedIncrementDependsOnTheResponse drives the reason Microsoft
// postpones an expression increment at all: the counter can depend on how the
// call turned out. A backend that keeps failing never consumes the caller's
// allowance, so the caller is never throttled for it.
func TestPostponedIncrementDependsOnTheResponse(t *testing.T) {
	status := http.StatusInternalServerError
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	defer backend.Close()

	plan, err := policy.Compile(`<policies><inbound><rate-limit-by-key calls="1" renewal-period="60" counter-key="caller" `+
		`increment-condition="@(context.Response.StatusCode == 200)"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	runtime := New("fallback", nil)
	runtime.current.Store(&Snapshot{Services: map[string]*Service{
		"emulator": {Name: "emulator", Hostnames: map[string]bool{"emulator.example.test": true}, Routes: []*Route{{
			API:        model.API{Path: "api", ServiceURL: backend.URL},
			Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}},
			Plan:       plan,
		}}},
	}})
	call := func() int {
		response := httptest.NewRecorder()
		runtime.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://emulator.example.test/api", nil))
		return response.Code
	}

	// Failures are not counted, so the allowance of one is never consumed.
	for attempt := 1; attempt <= 4; attempt++ {
		if code := call(); code != http.StatusInternalServerError {
			t.Fatalf("failing call %d = %d, want the backend's 500 rather than a throttle", attempt, code)
		}
	}
	// The first success consumes it, and the next call is throttled.
	status = http.StatusOK
	if code := call(); code != http.StatusOK {
		t.Fatalf("first successful call = %d", code)
	}
	if code := call(); code != http.StatusTooManyRequests {
		t.Fatalf("call after the allowance was consumed = %d, want 429", code)
	}
}
