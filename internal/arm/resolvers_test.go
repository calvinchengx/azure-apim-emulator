package arm

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
)

func TestAPIResolverLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	// The server wires this; the bare test handler does not, and a nil
	// validator skips validation entirely, so without it this test would prove
	// nothing about the resolver policy grammar.
	handler.ValidateResolverPolicy = func(value string) error {
		_, err := policy.CompileHTTPDataSource(value)
		return err
	}
	seedService(t, st)
	// A synthetic GraphQL API has no serviceUrl at all: its fields come from
	// resolvers. Requiring one would make the shape impossible to create.
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/shop"+apiQuery,
		`{"properties":{"displayName":"Shop","path":"shop","apiType":"graphql"}}`, http.StatusCreated)

	collection := basePath + "/apis/shop/resolvers" + apiQuery
	path := basePath + "/apis/shop/resolvers/orders" + apiQuery

	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)

	// The coordinate is required, and must name both halves.
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Orders"}}`, http.StatusBadRequest)
	for _, bad := range []string{"Query", "/orders", "Query/", "Query/orders/extra", "   "} {
		assertStatus(t, handler, http.MethodPut, path,
			`{"properties":{"displayName":"Orders","path":"`+bad+`"}}`, http.StatusBadRequest)
	}

	body := `{"id":"malicious","name":"malicious","properties":{"displayName":"Orders","path":"Query/orders","description":"list","custom":{"kept":true}}}`
	assertStatus(t, handler, http.MethodPut, path, body, http.StatusCreated)
	got := request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"path":"Query/orders"`) {
		t.Fatalf("the coordinate must round-trip as it was sent: %s", got.Body.String())
	}
	if !strings.Contains(got.Body.String(), `"custom":{"kept":true}`) || strings.Contains(got.Body.String(), `"id":"malicious"`) {
		t.Fatalf("resolver GET = %s", got.Body.String())
	}
	if !strings.Contains(got.Body.String(), `"description":"list"`) {
		t.Fatalf("description dropped: %s", got.Body.String())
	}
	list := request(t, handler, http.MethodGet, collection, "")
	if !strings.Contains(list.Body.String(), `"count":1`) {
		t.Fatalf("resolver list = %s", list.Body.String())
	}

	// PATCH keeps what it does not mention, so clearing the description must be
	// explicit rather than a side effect of omitting it.
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"displayName":"Orders v2"}}`, http.StatusOK)
	got = request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"displayName":"Orders v2"`) || !strings.Contains(got.Body.String(), `"path":"Query/orders"`) {
		t.Fatalf("PATCH lost fields: %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"description":""}}`, http.StatusOK)
	got = request(t, handler, http.MethodGet, path, "")
	if strings.Contains(got.Body.String(), `"description"`) {
		t.Fatalf("an emptied description must be absent, not empty: %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/shop/resolvers/absent"+apiQuery, `{"properties":{}}`, http.StatusNotFound)

	// The resolver's own policy is an <http-data-source>, not a <policies>
	// document. Validating it as a policy would reject every resolver Azure's
	// own portal produces.
	policyPath := basePath + "/apis/shop/resolvers/orders/policies/policy" + apiQuery
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/shop/resolvers/absent/policies/policy"+apiQuery, `{"properties":{"value":"<http-data-source/>"}}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, policyPath, `{"properties":{"value":"<policies><inbound/></policies>"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, policyPath,
		`{"properties":{"value":"<http-data-source><http-request><set-method>GET</set-method><set-url>https://rest.test/orders</set-url></http-request></http-data-source>","format":"xml"}}`,
		http.StatusCreated)
	stored := request(t, handler, http.MethodGet, policyPath, "")
	if !strings.Contains(stored.Body.String(), "http-data-source") {
		t.Fatalf("resolver policy GET = %s", stored.Body.String())
	}

	// A resolver changes what the gateway serves, so both mutations republish.
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Orders","path":"Query/orders"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusInternalServerError)
	handler.Activate = nil

	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
}

func TestSplitResolverPath(t *testing.T) {
	for input, want := range map[string][2]string{
		"Query/orders":     {"Query", "orders"},
		" Query / orders ": {"Query", "orders"},
		"Order/customer":   {"Order", "customer"},
	} {
		typeName, field, ok := splitResolverPath(input)
		if !ok || typeName != want[0] || field != want[1] {
			t.Errorf("splitResolverPath(%q) = %q %q %v", input, typeName, field, ok)
		}
	}
	for _, input := range []string{"", "Query", "/orders", "Query/", "a/b/c", "  /  "} {
		if _, _, ok := splitResolverPath(input); ok {
			t.Errorf("splitResolverPath(%q) accepted a coordinate that cannot bind", input)
		}
	}
}

// A resolver whose stored document has no properties object still renders,
// rather than panicking on a type assertion.
func TestAPIResolverWireHandlesADocumentWithoutProperties(t *testing.T) {
	wire := apiResolverWire(model.APIResolver{
		APIID: "/apis/shop", Name: "orders", DisplayName: "Orders",
		Type: "Query", Field: "orders",
		Document: map[string]any{"properties": "not an object"},
	})
	properties, _ := wire["properties"].(map[string]any)
	if properties["path"] != "Query/orders" {
		t.Fatalf("wire = %v", wire)
	}
	if wire["type"] != "Microsoft.ApiManagement/service/apis/resolvers" {
		t.Fatalf("ARM type = %v", wire["type"])
	}
}

// A store failure must be reported rather than read as "this API has no
// resolvers": the two are different answers and a caller acts differently on
// each. Driven through the handlers directly, because request dispatch reads
// the API first and would fail there before reaching any of this.
func TestAPIResolverStoreFailuresAreReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	api := model.API{ServiceID: serviceModel().ID(), Name: "shop"}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.apiResolverCollection(recorder, httptest.NewRequest(http.MethodGet, "/", nil), api)
	if recorder.Code < 400 {
		t.Fatalf("a failed collection read returned %d", recorder.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		recorder = httptest.NewRecorder()
		body := strings.NewReader(`{"properties":{"displayName":"Orders","path":"Query/orders"}}`)
		request := httptest.NewRequest(method, "/", body)
		request.Header.Set("Content-Type", "application/json")
		handler.apiResolverResource(recorder, request, model.APIResolver{APIID: api.ID(), Name: "orders"})
		if recorder.Code < 400 {
			t.Errorf("%s against a failed store returned %d", method, recorder.Code)
		}
	}
}

// The write itself can fail even when the read succeeded: an API that does not
// exist violates the foreign key. Reported rather than answered 201, which
// would tell the caller a resolver exists when none was stored.
func TestAPIResolverWriteFailureIsReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	_ = st
	recorder := httptest.NewRecorder()
	body := strings.NewReader(`{"properties":{"displayName":"Orders","path":"Query/orders"}}`)
	request := httptest.NewRequest(http.MethodPut, "/", body)
	request.Header.Set("Content-Type", "application/json")
	handler.apiResolverResource(recorder, request, model.APIResolver{APIID: serviceModel().ID() + "/apis/absent", Name: "orders"})
	if recorder.Code < 400 {
		t.Fatalf("a resolver on a non-existent API returned %d, want an error", recorder.Code)
	}
}
