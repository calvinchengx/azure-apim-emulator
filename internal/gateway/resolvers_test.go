package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/graphql"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const syntheticSDL = `
type Query { orders: [Order!]! order(ref: ID!): Order }
type Order { ref: ID! total: Int customerId: String customer: Customer }
type Customer { id: ID! name: String! }
`

type syntheticFixture struct {
	runtime *Runtime
	store   *store.Store
	calls   []string
}

// newSyntheticFixture builds a GraphQL API with NO backend URL: its fields come
// from resolvers pointed at a REST stub, which is what makes the API synthetic.
func newSyntheticFixture(t *testing.T, resolvers map[string]string) *syntheticFixture {
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
	api, err := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "shop", DisplayName: "Shop", Path: "shop", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "graphql"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAPISchema(model.APISchema{
		APIID: api.ID(), Name: "gql", ContentType: GraphQLSchemaContentType,
		Document: map[string]any{"value": syntheticSDL},
	}); err != nil {
		t.Fatal(err)
	}
	fixture := &syntheticFixture{store: st}
	for name, spec := range resolvers {
		path, policyXML, _ := strings.Cut(spec, "|")
		typeName, field, _ := strings.Cut(path, "/")
		if _, err := st.UpsertAPIResolver(model.APIResolver{
			APIID: api.ID(), Name: name, DisplayName: name, Type: typeName, Field: field,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID() + "/resolvers/" + name, Value: policyXML}); err != nil {
			t.Fatal(err)
		}
	}
	fixture.runtime = New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		fixture.calls = append(fixture.calls, request.URL.String())
		body := restStub(request.URL.Path)
		if body == "" {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: httpBody(body)}, nil
	})})
	if err := fixture.runtime.Activate(st, true); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return fixture
}

func restStub(path string) string {
	switch {
	case path == "/orders":
		return `[{"ref":"A-1","total":25,"customerId":"c1"},{"ref":"A-2","total":40,"customerId":"c2"}]`
	case strings.HasPrefix(path, "/orders/"):
		return fmt.Sprintf(`{"ref":%q,"total":99,"customerId":"c9"}`, strings.TrimPrefix(path, "/orders/"))
	case strings.HasPrefix(path, "/customers/"):
		id := strings.TrimPrefix(path, "/customers/")
		return fmt.Sprintf(`{"id":%q,"name":"Customer %s"}`, id, id)
	}
	return ""
}

func httpBody(value string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(value))
}

func (f *syntheticFixture) query(t *testing.T, query string) map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/shop", strings.NewReader(`{"query":`+quote(query)+`}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	f.runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("query returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, recorder.Body.String())
	}
	return envelope
}

func quote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func ordersResolver(url string) string {
	return "Query/orders|<http-data-source><http-request><set-method>GET</set-method><set-url>" + url + "/orders</set-url></http-request></http-data-source>"
}

func orderResolver(url string) string {
	return `Query/order|<http-data-source><http-request><set-method>GET</set-method><set-url>@("` + url + `/orders/" + context.GraphQL.GraphQLArguments["ref"])</set-url></http-request></http-data-source>`
}

func customerResolver(url string) string {
	return `Order/customer|<http-data-source><http-request><set-method>GET</set-method><set-url>@("` + url + `/customers/" + context.GraphQL.Parent["customerId"])</set-url></http-request></http-data-source>`
}

const stub = "https://rest.test"

// The API has no serviceUrl at all: every field comes from a REST call the
// resolver makes. If the gateway were proxying GraphQL, this could not pass.
func TestSyntheticGraphQLResolvesFromRESTBackends(t *testing.T) {
	fixture := newSyntheticFixture(t, map[string]string{"orders": ordersResolver(stub)})
	envelope := fixture.query(t, "{ orders { ref } }")
	if envelope["errors"] != nil {
		t.Fatalf("errors = %v", envelope["errors"])
	}
	data, _ := envelope["data"].(map[string]any)
	orders, _ := data["orders"].([]any)
	if len(orders) != 2 {
		t.Fatalf("orders = %v", data["orders"])
	}
	// The REST payload carried total and customerId; neither was selected.
	first, _ := orders[0].(map[string]any)
	if len(first) != 1 || first["ref"] != "A-1" {
		t.Fatalf("unselected fields leaked: %v", first)
	}
	if len(fixture.calls) != 1 || !strings.HasSuffix(fixture.calls[0], "/orders") {
		t.Fatalf("resolver calls = %v", fixture.calls)
	}
}

func TestSyntheticGraphQLPassesArgumentsAndParent(t *testing.T) {
	fixture := newSyntheticFixture(t, map[string]string{
		"orders":   ordersResolver(stub),
		"order":    orderResolver(stub),
		"customer": customerResolver(stub),
	})
	envelope := fixture.query(t, `{ order(ref: "Z-9") { ref total } }`)
	data, _ := envelope["data"].(map[string]any)
	order, _ := data["order"].(map[string]any)
	if order["ref"] != "Z-9" {
		t.Fatalf("argument did not reach the resolver URL: %v (calls %v)", order, fixture.calls)
	}

	fixture.calls = nil
	envelope = fixture.query(t, "{ orders { ref customer { name } } }")
	if envelope["errors"] != nil {
		t.Fatalf("nested resolver errors = %v", envelope["errors"])
	}
	data, _ = envelope["data"].(map[string]any)
	orders, _ := data["orders"].([]any)
	first, _ := orders[0].(map[string]any)
	customer, _ := first["customer"].(map[string]any)
	if customer["name"] != "Customer c1" {
		t.Fatalf("nested resolver read the wrong parent: %v", customer)
	}
	// One call for the list, then one per element: the parent's customerId is
	// what each nested call is keyed on.
	if len(fixture.calls) != 3 {
		t.Fatalf("calls = %v, want the list plus one per element", fixture.calls)
	}
}

// A failing resolver nulls its own field and reports a path; the request is
// still a 200 because execution ran.
func TestSyntheticGraphQLReportsResolverFailuresPerField(t *testing.T) {
	fixture := newSyntheticFixture(t, map[string]string{
		"orders": ordersResolver(stub),
		"order":  "Query/order|<http-data-source><http-request><set-method>GET</set-method><set-url>" + stub + "/missing</set-url></http-request></http-data-source>",
	})
	envelope := fixture.query(t, `{ orders { ref } order(ref: "x") { ref } }`)
	data, _ := envelope["data"].(map[string]any)
	if data["order"] != nil {
		t.Fatalf("the failing field must be null, got %v", data["order"])
	}
	if orders, _ := data["orders"].([]any); len(orders) != 2 {
		t.Fatalf("the healthy field must still resolve, got %v", data["orders"])
	}
	errs, _ := envelope["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("errors = %v", envelope["errors"])
	}
	entry, _ := errs[0].(map[string]any)
	if message, _ := entry["message"].(string); !strings.Contains(message, "404") {
		t.Fatalf("the error must name the backend status, got %q", message)
	}
}

// A resolver bound to a coordinate the schema does not define can never run.
// Catching it at import time is the difference between a clear error and a
// field that is silently always null.
func TestResolverBindingIsCheckedAgainstTheSchema(t *testing.T) {
	for name, spec := range map[string]string{
		"unknown type":  "Nonsense/x|<http-data-source><http-request><set-method>GET</set-method><set-url>" + stub + "/x</set-url></http-request></http-data-source>",
		"unknown field": "Query/nonsense|<http-data-source><http-request><set-method>GET</set-method><set-url>" + stub + "/x</set-url></http-request></http-data-source>",
	} {
		func() {
			defer func() { _ = recover() }()
			st, err := store.Open("", clock.New())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
			api, _ := st.UpsertAPI(model.API{
				ServiceID: service.ID(), Name: "shop", DisplayName: "Shop", Path: "shop", IsCurrent: true,
				Document: map[string]any{"properties": map[string]any{"apiType": "graphql"}},
			})
			_, _ = st.UpsertAPISchema(model.APISchema{APIID: api.ID(), Name: "gql", ContentType: GraphQLSchemaContentType, Document: map[string]any{"value": syntheticSDL}})
			path, policyXML, _ := strings.Cut(spec, "|")
			typeName, field, _ := strings.Cut(path, "/")
			_, _ = st.UpsertAPIResolver(model.APIResolver{APIID: api.ID(), Name: "r", Type: typeName, Field: field})
			_, _ = st.UpsertPolicy(model.Policy{ScopeID: api.ID() + "/resolvers/r", Value: policyXML})
			runtime := New("emulator", &http.Client{})
			if err := runtime.Activate(st, true); err == nil {
				t.Errorf("%s must be refused at activation", name)
			}
			// Non-strict is startup replay: the API degrades to pass-through
			// rather than taking every other API down with it.
			if err := runtime.Activate(st, false); err != nil {
				t.Errorf("%s must not fail a non-strict activation: %v", name, err)
			}
			if route := runtime.current.Load().Services["emulator"].Routes[0]; len(route.Resolvers) != 0 {
				t.Errorf("%s left resolvers attached", name)
			}
		}()
	}
}

func TestResolverWithoutAPolicyIsRefused(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "shop", DisplayName: "Shop", Path: "shop", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "graphql"}},
	})
	_, _ = st.UpsertAPISchema(model.APISchema{APIID: api.ID(), Name: "gql", ContentType: GraphQLSchemaContentType, Document: map[string]any{"value": syntheticSDL}})
	if _, err := st.UpsertAPIResolver(model.APIResolver{APIID: api.ID(), Name: "orders", Type: "Query", Field: "orders"}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", &http.Client{})
	if err := runtime.Activate(st, true); err == nil {
		t.Fatal("a resolver with no policy has nothing to run and must be refused")
	}

	// And one whose policy does not compile.
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID() + "/resolvers/orders", Value: "<http-data-source><http-request/></http-data-source>"}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, true); err == nil {
		t.Fatal("a resolver whose data source does not compile must be refused")
	}
}

// An API with a schema but no resolvers stays pass-through, so the two modes
// cannot both be active.
func TestNoResolversLeavesTheAPIPassThrough(t *testing.T) {
	fixture := newSyntheticFixture(t, nil)
	route := fixture.runtime.current.Load().Services["emulator"].Routes[0]
	if len(route.Resolvers) != 0 {
		t.Fatalf("resolvers = %v", route.Resolvers)
	}
	if route.GraphQL == nil {
		t.Fatal("the API is still GraphQL, just pass-through")
	}
}

func TestResolverKeyIsCaseInsensitive(t *testing.T) {
	if resolverKey("Query", "Orders") != resolverKey("query", "orders") {
		t.Fatal("the resolver index must not depend on the stored casing")
	}
}

func TestGraphQLResolversForSkipsNonGraphQLAPIs(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	resolvers, err := graphQLResolversFor(st, model.API{}, nil)
	if err != nil || resolvers != nil {
		t.Fatalf("a non-GraphQL API has no resolvers, got %v %v", resolvers, err)
	}
}

// The failure paths inside one resolver call. Each becomes a field-level error
// rather than a failed request, so the rest of the query still answers.
func TestSyntheticResolverFailureModes(t *testing.T) {
	t.Run("backend returns something that is not JSON", func(t *testing.T) {
		fixture := newSyntheticFixture(t, map[string]string{"orders": ordersResolver(stub)})
		fixture.runtime.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: httpBody("<html>not json</html>")}, nil
		})}
		envelope := fixture.query(t, "{ orders { ref } }")
		errs, _ := envelope["errors"].([]any)
		if len(errs) != 1 {
			t.Fatalf("errors = %v", envelope["errors"])
		}
		entry, _ := errs[0].(map[string]any)
		if message, _ := entry["message"].(string); !strings.Contains(message, "not JSON") {
			t.Fatalf("message = %q; it must say the payload was not JSON", message)
		}
	})

	t.Run("backend is unreachable", func(t *testing.T) {
		fixture := newSyntheticFixture(t, map[string]string{"orders": ordersResolver(stub)})
		fixture.runtime.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial refused")
		})}
		envelope := fixture.query(t, "{ orders { ref } }")
		if envelope["errors"] == nil {
			t.Fatal("an unreachable resolver backend must be reported")
		}
	})

	t.Run("empty body resolves to null", func(t *testing.T) {
		fixture := newSyntheticFixture(t, map[string]string{"order": orderResolver(stub)})
		fixture.runtime.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: httpBody("")}, nil
		})}
		envelope := fixture.query(t, `{ order(ref: "x") { ref } }`)
		if envelope["errors"] != nil {
			t.Fatalf("an empty body is null, not an error: %v", envelope["errors"])
		}
		data, _ := envelope["data"].(map[string]any)
		if data["order"] != nil {
			t.Fatalf("order = %v, want null", data["order"])
		}
	})

	t.Run("the resolver request cannot be built", func(t *testing.T) {
		// The URL expression reads context.GraphQL.Parent at the ROOT, where it
		// is null, so building the request fails before any call is made.
		fixture := newSyntheticFixture(t, map[string]string{
			"orders": `Query/orders|<http-data-source><http-request><set-method>GET</set-method><set-url>@("` + stub + `/" + context.GraphQL.Parent["nope"])</set-url></http-request></http-data-source>`,
		})
		envelope := fixture.query(t, "{ orders { ref } }")
		if envelope["errors"] == nil {
			t.Fatal("an unevaluatable resolver URL must be reported as a field error")
		}
		if len(fixture.calls) != 0 {
			t.Fatalf("no request may be sent when the URL cannot be built, got %v", fixture.calls)
		}
	})
}

// Each field gets its own expression state. Sharing one would leak the previous
// field's arguments into the next, which is a disclosure bug rather than merely
// a wrong value.
func TestEachResolverCallSeesOnlyItsOwnArguments(t *testing.T) {
	fixture := newSyntheticFixture(t, map[string]string{"order": orderResolver(stub)})
	fixture.query(t, `{ a: order(ref: "A") { ref } b: order(ref: "B") { ref } }`)
	if len(fixture.calls) != 2 {
		t.Fatalf("calls = %v", fixture.calls)
	}
	if !strings.HasSuffix(fixture.calls[0], "/orders/A") || !strings.HasSuffix(fixture.calls[1], "/orders/B") {
		t.Fatalf("arguments leaked between fields: %v", fixture.calls)
	}
}

// A store read failure while compiling resolvers is an error, not "this API has
// no resolvers": the second would silently serve an API with every field null.
func TestGraphQLResolversForReportsStoreFailures(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api := model.API{ServiceID: service.ID(), Name: "shop", Path: "shop", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "graphql"}}}
	schema, err := graphqlParse(syntheticSDL)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if _, err := graphQLResolversFor(st, api, schema); err == nil {
		t.Fatal("a failed resolver read must be reported")
	}
}

// The per-backend transport is built at request time, so an unusable backend
// certificate fails there. It must abort the whole operation rather than
// resolve some fields against a client that was never configured.
func TestSyntheticGraphQLReportsBackendClientFailures(t *testing.T) {
	fixture := newSyntheticFixture(t, map[string]string{"orders": ordersResolver(stub)})
	if _, err := fixture.store.UpsertCertificate(model.Certificate{
		ServiceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator",
		Name:      "client", Data: []byte("not a PKCS12 blob"), Password: "x",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.UpsertBackend(model.Backend{
		ServiceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator",
		Name:      "secure", URL: stub,
		Document: map[string]any{"properties": map[string]any{"credentials": map[string]any{"certificateIds": []any{"client"}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.UpsertPolicy(model.Policy{
		ScopeID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator/apis/shop",
		Value:   `<policies><inbound><set-backend-service backend-id="secure" /></inbound></policies>`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Activate(fixture.store, false); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/shop", strings.NewReader(`{"query":"{ orders { ref } }"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	fixture.runtime.ServeHTTP(recorder, request)
	if recorder.Code < 400 {
		t.Fatalf("an unusable backend transport returned %d", recorder.Code)
	}
	if len(fixture.calls) != 0 {
		t.Fatal("no resolver may run when the transport cannot be built")
	}
}

// graphqlParse is a thin alias so the test reads at the level it asserts.
func graphqlParse(sdl string) (*graphql.Schema, error) { return graphql.Parse(sdl) }

// A response body that fails mid-read becomes a field error rather than a
// truncated value silently presented as the resolver's result.
func TestSyntheticResolverReportsBodyReadFailures(t *testing.T) {
	fixture := newSyntheticFixture(t, map[string]string{"orders": ordersResolver(stub)})
	fixture.runtime.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(failingReader{})}, nil
	})}
	envelope := fixture.query(t, "{ orders { ref } }")
	if envelope["errors"] == nil {
		t.Fatal("a body that fails mid-read must be reported, not treated as an empty payload")
	}
	data, _ := envelope["data"].(map[string]any)
	if data["orders"] != nil {
		t.Fatalf("orders = %v, want null", data["orders"])
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
