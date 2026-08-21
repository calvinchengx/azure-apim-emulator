package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const serviceScopeID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator"

const apiScopeID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator/apis/catalogue"

const gatewaySDL = `type Query { items: [Item!]! } type Item { id: ID! name: String! }`

type graphQLFixture struct {
	runtime  *Runtime
	store    *store.Store
	calls    int
	lastBody string
	lastVerb string
	lastType string
}

// newGraphQLFixture builds a service with one GraphQL API and a stub backend.
// apiType and sdl are parameters so a test can leave either out and assert what
// the gateway does with a half-configured API.
func newGraphQLFixture(t *testing.T, apiType, sdl string, strict bool) *graphQLFixture {
	t.Helper()
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{"properties": map[string]any{}}
	if apiType != "" {
		document["properties"] = map[string]any{"apiType": apiType}
	}
	api, err := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "catalogue", DisplayName: "Catalogue",
		Path: "catalogue", ServiceURL: "https://backend.test/graphql", IsCurrent: true, Document: document,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sdl != "" {
		if _, err := st.UpsertAPISchema(model.APISchema{
			APIID: api.ID(), Name: "gql", ContentType: GraphQLSchemaContentType,
			Document: map[string]any{"value": sdl},
		}); err != nil {
			t.Fatal(err)
		}
	}
	fixture := &graphQLFixture{store: st}
	fixture.runtime = New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		fixture.calls++
		fixture.lastVerb = request.Method
		fixture.lastType = request.Header.Get("Content-Type")
		if request.Body != nil {
			body, _ := io.ReadAll(request.Body)
			fixture.lastBody = string(body)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"data":{"items":[{"id":"1","name":"Widget"}]}}`)),
		}, nil
	})})
	if err := fixture.runtime.Activate(st, strict); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return fixture
}

func (f *graphQLFixture) post(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/catalogue", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	f.runtime.ServeHTTP(recorder, request)
	return recorder
}

// Introspection is answered from the schema the gateway holds. The backend call
// count is the assertion that matters: a passing status would not distinguish
// "answered locally" from "the stub happened to return something valid".
func TestGraphQLIntrospectionIsAnsweredWithoutTheBackend(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	recorder := fixture.post(t, `{"query":"{ __schema { queryType { name } types { name } } }"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("introspection returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if fixture.calls != 0 {
		t.Fatalf("introspection reached the backend %d times; it must be answered from the schema", fixture.calls)
	}
	var envelope struct {
		Data struct {
			Schema struct {
				QueryType struct{ Name string } `json:"queryType"`
				Types     []struct{ Name string }
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("introspection body is not JSON: %v", err)
	}
	if envelope.Data.Schema.QueryType.Name != "Query" {
		t.Fatalf("queryType = %q", envelope.Data.Schema.QueryType.Name)
	}
	names := map[string]bool{}
	for _, entry := range envelope.Data.Schema.Types {
		names[entry.Name] = true
	}
	if !names["Item"] || !names["Query"] {
		t.Fatalf("introspection omitted schema types: %v", names)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
}

// A data query is forwarded, and the body must arrive byte for byte. Re-encoding
// it would drop `extensions`, which is where Apollo puts persisted-query hashes.
func TestGraphQLDataQueryIsForwardedVerbatim(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	body := `{"query":"{ items { id name } }","extensions":{"persistedQuery":{"sha256Hash":"abc"}}}`
	recorder := fixture.post(t, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("query returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if fixture.calls != 1 {
		t.Fatalf("backend calls = %d, want 1", fixture.calls)
	}
	if fixture.lastBody != body {
		t.Fatalf("forwarded body was rewritten:\n got %s\nwant %s", fixture.lastBody, body)
	}
	if !strings.Contains(recorder.Body.String(), "Widget") {
		t.Fatalf("backend response was not returned: %s", recorder.Body.String())
	}
}

// A GET carries the query in the URL and has no body to replay, so the gateway
// encodes one. Without this, `?query=` fails against a POST-only backend.
func TestGraphQLGetIsForwardedAsAPostBody(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	request := httptest.NewRequest(http.MethodGet, "/catalogue?query={items{id}}", nil)
	recorder := httptest.NewRecorder()
	fixture.runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if fixture.lastVerb != http.MethodPost {
		t.Fatalf("forwarded method = %s, want POST", fixture.lastVerb)
	}
	if fixture.lastType != "application/json" {
		t.Fatalf("forwarded Content-Type = %q", fixture.lastType)
	}
	var forwarded struct{ Query string }
	if err := json.Unmarshal([]byte(fixture.lastBody), &forwarded); err != nil {
		t.Fatalf("forwarded body is not JSON: %v (%s)", err, fixture.lastBody)
	}
	if forwarded.Query != "{items{id}}" {
		t.Fatalf("forwarded query = %q", forwarded.Query)
	}
}

// The schema on the gateway is what makes this possible: the backend never sees
// a request it would have to reject.
func TestGraphQLRefusesQueriesTheSchemaRejects(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	recorder := fixture.post(t, `{"query":"{ notAField }"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("an invalid query returned %d, want 400", recorder.Code)
	}
	if fixture.calls != 0 {
		t.Fatalf("an invalid query reached the backend %d times", fixture.calls)
	}
	var envelope struct {
		Errors []struct{ Message string }
		Data   any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if len(envelope.Errors) == 0 || !strings.Contains(envelope.Errors[0].Message, "notAField") {
		t.Fatalf("error must name the offending field, got %+v", envelope.Errors)
	}
	if envelope.Data != nil {
		t.Fatal("a request error carries no data member; a null one would say execution ran")
	}
}

func TestGraphQLRefusesMalformedRequests(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	for name, body := range map[string]string{
		"not JSON":     "<xml/>",
		"no query":     `{"variables":{}}`,
		"syntax error": `{"query":"{ items { id "}`,
	} {
		recorder := fixture.post(t, body)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s returned %d, want 400", name, recorder.Code)
		}
	}
	if fixture.calls != 0 {
		t.Fatalf("a malformed request reached the backend %d times", fixture.calls)
	}
}

// The two signals are required together. Either one alone is a misconfiguration,
// and acting on it would turn that mistake into GraphQL traffic.
func TestGraphQLNeedsBothTheAPITypeAndTheSchema(t *testing.T) {
	plain := newGraphQLFixture(t, "", "", true)
	if route := plain.runtime.current.Load().Services["emulator"].Routes[0]; route.GraphQL != nil {
		t.Fatal("an API with no apiType must not be treated as GraphQL")
	}
	withSchemaOnly := newGraphQLFixture(t, "", gatewaySDL, true)
	if route := withSchemaOnly.runtime.current.Load().Services["emulator"].Routes[0]; route.GraphQL != nil {
		t.Fatal("a schema attached to a REST API must not put it on the GraphQL path")
	}
}

func TestGraphQLActivationReportsBrokenImports(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "catalogue", DisplayName: "Catalogue", Path: "catalogue",
		ServiceURL: "https://backend.test", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "graphql"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", &http.Client{})

	// apiType graphql with no schema YET is not an error. ARM cannot create an
	// API and its schema in one call, so every import passes through this
	// state; rejecting it would make the documented order impossible.
	if err := runtime.Activate(st, true); err != nil {
		t.Fatalf("a GraphQL API awaiting its schema must not fail activation: %v", err)
	}
	if route := runtime.current.Load().Services["emulator"].Routes[0]; route.GraphQL != nil {
		t.Fatal("an API with no schema yet must not be GraphQL-routable")
	}

	if _, err := st.UpsertAPISchema(model.APISchema{
		APIID: api.ID(), Name: "gql", ContentType: GraphQLSchemaContentType,
		Document: map[string]any{"value": "type Query { broken"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, true); err == nil {
		t.Fatal("strict activation must reject an unparseable schema")
	}

	// Non-strict is startup replay of state the management plane already
	// accepted. Failing the whole activation would take every healthy API down
	// with the broken one, so the API degrades to a plain proxy instead.
	if err := runtime.Activate(st, false); err != nil {
		t.Fatalf("non-strict activation must survive a broken schema: %v", err)
	}
	if route := runtime.current.Load().Services["emulator"].Routes[0]; route.GraphQL != nil {
		t.Fatal("a schema that failed to compile must leave the route non-GraphQL")
	}
}

func TestGraphQLSchemaLookupIgnoresOtherContentTypes(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "catalogue", DisplayName: "Catalogue", Path: "catalogue",
		ServiceURL: "https://backend.test", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "graphql"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// An OpenAPI component schema sitting on the same API must not be read as
	// SDL: the content type is the only thing that says which one is GraphQL.
	if _, err := st.UpsertAPISchema(model.APISchema{
		APIID: api.ID(), Name: "json", ContentType: "application/vnd.oai.openapi.components+json",
		Document: map[string]any{"value": `{"components":{}}`},
	}); err != nil {
		t.Fatal(err)
	}
	schema, err := graphQLSchemaFor(st, api)
	if err != nil {
		t.Fatalf("an unrelated schema must be skipped, not reported as an error: %v", err)
	}
	if schema != nil {
		t.Fatal("an OpenAPI component schema must not be compiled as GraphQL SDL")
	}
}

// The failure paths after validation. Each one must surface as a gateway error
// rather than a half-written GraphQL response, because a client that has already
// seen a 200 cannot be told later that the backend never answered.
func TestGraphQLBackendFailuresSurfaceAsGatewayErrors(t *testing.T) {
	t.Run("unreachable backend", func(t *testing.T) {
		fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
		fixture.runtime.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial refused")
		})}
		recorder := fixture.post(t, `{"query":"{ items { id } }"}`)
		if recorder.Code < 500 {
			t.Fatalf("an unreachable backend returned %d, want 5xx", recorder.Code)
		}
	})

	t.Run("backend certificate cannot be loaded", func(t *testing.T) {
		// Activation checks that a referenced certificate EXISTS; it does not
		// decode it. backendHTTPClient builds the per-backend transport at
		// request time, so an undecodable certificate fails there. The GraphQL
		// path must report that rather than forward without the client
		// certificate the backend requires.
		fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
		if _, err := fixture.store.UpsertCertificate(model.Certificate{
			ServiceID: serviceScopeID, Name: "client", Data: []byte("not a PKCS12 blob"), Password: "x",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.UpsertBackend(model.Backend{
			ServiceID: serviceScopeID, Name: "secure", URL: "https://backend.test/graphql",
			Document: map[string]any{"properties": map[string]any{"credentials": map[string]any{"certificateIds": []any{"client"}}}},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.UpsertPolicy(model.Policy{
			ScopeID: apiScopeID,
			Value:   `<policies><inbound><set-backend-service backend-id="secure" /></inbound></policies>`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := fixture.runtime.Activate(fixture.store, false); err != nil {
			t.Fatalf("a certificate that merely fails to DECODE must not block activation: %v", err)
		}
		recorder := fixture.post(t, `{"query":"{ items { id } }"}`)
		if recorder.Code < 400 {
			t.Fatalf("an unusable backend certificate returned %d, want an error", recorder.Code)
		}
		if fixture.calls != 0 {
			t.Fatal("no request may be sent when the backend transport cannot be built")
		}
	})
}

// Outbound policy runs on the GraphQL path exactly as it does on the REST path.
// This is the assertion that the branch reuses the pipeline rather than
// reimplementing a shortened copy of it.
func TestGraphQLOutboundPolicyStillRuns(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	if _, err := fixture.store.UpsertPolicy(model.Policy{
		ScopeID: apiScopeID,
		Value:   `<policies><outbound><set-header name="X-Seen" exists-action="override"><value>outbound</value></set-header></outbound></policies>`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Activate(fixture.store, false); err != nil {
		t.Fatal(err)
	}
	recorder := fixture.post(t, `{"query":"{ items { id } }"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Seen"); got != "outbound" {
		t.Fatalf("outbound policy did not run on the GraphQL path, X-Seen = %q", got)
	}
}

// return-response in outbound replaces the backend's answer entirely, so the
// GraphQL branch must honour state.Returned rather than writing the forwarded
// body over it.
func TestGraphQLOutboundCanReturnItsOwnResponse(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	if _, err := fixture.store.UpsertPolicy(model.Policy{
		ScopeID: apiScopeID,
		Value:   `<policies><outbound><return-response><set-status code="203" reason="Replaced" /><set-body>{"data":{"items":[]}}</set-body></return-response></outbound></policies>`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Activate(fixture.store, false); err != nil {
		t.Fatal(err)
	}
	recorder := fixture.post(t, `{"query":"{ items { id } }"}`)
	if recorder.Code != http.StatusNonAuthoritativeInfo {
		t.Fatalf("return-response in outbound gave %d, want 203", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "Widget") {
		t.Fatalf("the backend body was written over the policy response: %s", recorder.Body.String())
	}
	if fixture.calls != 1 {
		t.Fatalf("backend calls = %d; outbound runs after the backend answers", fixture.calls)
	}
}

func TestGraphQLSchemaLookupReportsStoreFailures(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	api := model.API{
		ServiceID: service.ID(), Name: "catalogue", Path: "catalogue", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "graphql"}},
	}
	_ = st.Close()
	if _, err := graphQLSchemaFor(st, api); err == nil {
		t.Fatal("a store read failure must be reported, not read as an API with no schema")
	}
}

// An outbound policy that fails must produce a gateway error, not the backend's
// body with a policy half-applied. xsl-transform is the cheapest way to make
// outbound fail deterministically: it is documented in <outbound> and this
// emulator does not implement it, so reaching it is an ErrUnsupported.
func TestGraphQLOutboundPolicyFailureIsReported(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	if _, err := fixture.store.UpsertPolicy(model.Policy{
		ScopeID: apiScopeID,
		Value:   `<policies><outbound><xsl-transform/></outbound></policies>`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Activate(fixture.store, false); err != nil {
		t.Fatal(err)
	}
	recorder := fixture.post(t, `{"query":"{ items { id } }"}`)
	if recorder.Code < 400 {
		t.Fatalf("a failing outbound policy returned %d, want an error", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "Widget") {
		t.Fatalf("the backend body was returned despite the outbound failure: %s", recorder.Body.String())
	}
}

// The other half of the same guarantee, and the one xsl-transform cannot cover:
// an outbound policy that RUNS and then fails, after an earlier action in the
// same section has already changed the response. An unsupported action stops
// before anything has been applied, so it never exercises the half-applied case
// the section above is named for.
//
// <xml-to-json apply="always"> over the backend's JSON is the executed failure:
// xml-to-json is documented in <outbound>, this emulator implements it, and it
// fails on reaching a body it cannot parse as XML.
func TestGraphQLOutboundPolicyFailureAfterAMutationIsReported(t *testing.T) {
	fixture := newGraphQLFixture(t, "graphql", gatewaySDL, true)
	if _, err := fixture.store.UpsertPolicy(model.Policy{
		ScopeID: apiScopeID,
		Value: `<policies><outbound>` +
			`<set-header name="X-Half-Applied" exists-action="override"><value>yes</value></set-header>` +
			`<xml-to-json kind="direct" apply="always"/>` +
			`</outbound></policies>`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Activate(fixture.store, false); err != nil {
		t.Fatal(err)
	}
	recorder := fixture.post(t, `{"query":"{ items { id } }"}`)
	if recorder.Code < 400 {
		t.Fatalf("a failing outbound policy returned %d, want an error", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "Widget") {
		t.Fatalf("the backend body was returned despite the outbound failure: %s", recorder.Body.String())
	}
	// The half-applied response must not be what the caller gets either.
	if got := recorder.Header().Get("X-Half-Applied"); got != "" {
		t.Errorf("the half-applied response was served: X-Half-Applied = %q", got)
	}
}
