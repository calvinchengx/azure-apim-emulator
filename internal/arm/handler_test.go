package arm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	basePath = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/svc"
	apiQuery = "?api-version=2024-05-01"
)

type rejectingAuth struct{}

type testRoundTripFunc func(*http.Request) (*http.Response, error)

func (f testRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingReadCloser) Close() error             { return nil }

func (rejectingAuth) ValidateRequest(*http.Request) (*auth.Principal, error) {
	return nil, errors.New("rejected")
}

func TestTopLevelRoutingErrors(t *testing.T) {
	handler, _ := testHandler(t)
	tests := []struct {
		name, method, path string
		auth               auth.RequestValidator
		want               int
	}{
		{"auth", http.MethodGet, basePath + apiQuery, rejectingAuth{}, http.StatusUnauthorized},
		{"version", http.MethodGet, basePath + "?api-version=old", auth.AllowAll{}, http.StatusBadRequest},
		{"bad path", http.MethodGet, "/not-arm" + apiQuery, auth.AllowAll{}, http.StatusNotFound},
		{"unknown child", http.MethodGet, basePath + "/unknown/x" + apiQuery, auth.AllowAll{}, http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler.Auth = test.auth
			response := request(t, handler, test.method, test.path, "")
			if response.Code != test.want || response.Header().Get("x-ms-error-code") == "" {
				t.Fatalf("%s %s = %d, error code %q: %s", test.method, test.path, response.Code, response.Header().Get("x-ms-error-code"), response.Body.String())
			}
		})
	}
	if _, ok := parse(nil); ok {
		t.Fatal("empty path parsed")
	}
	if got := split("/"); got != nil {
		t.Fatalf("split root = %v", got)
	}
	if got, ok := parse(split("/subscriptions/sub/providers/Microsoft.ApiManagement/service/svc/apis/a")); !ok || got.ServiceName != "svc" || len(got.Tail) != 2 {
		t.Fatalf("subscription service route = %+v, %v", got, ok)
	}
}

func TestConditionalRequests(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/tags/concurrency" + apiQuery
	body := `{"properties":{"displayName":"Concurrency"}}`
	created := conditionalRequest(t, handler, http.MethodPut, path, body, "If-None-Match", "*")
	if created.Code != http.StatusCreated {
		t.Fatalf("conditional create = %d: %s", created.Code, created.Body.String())
	}
	etag := created.Header().Get("ETag")
	if etag == "" {
		t.Fatal("conditional create omitted ETag")
	}

	tests := []struct {
		name, method, header, value string
		want                        int
	}{
		{"not modified", http.MethodGet, "If-None-Match", etag, http.StatusNotModified},
		{"weak not modified", http.MethodGet, "If-None-Match", "W/" + etag, http.StatusNotModified},
		{"changed", http.MethodGet, "If-None-Match", `"stale"`, http.StatusOK},
		{"matching read", http.MethodGet, "If-Match", `"other", ` + etag, http.StatusOK},
		{"weak strong comparison", http.MethodGet, "If-Match", "W/" + etag, http.StatusPreconditionFailed},
		{"existing create", http.MethodPut, "If-None-Match", "*", http.StatusPreconditionFailed},
		{"stale update", http.MethodPatch, "If-Match", `"stale"`, http.StatusPreconditionFailed},
		{"malformed", http.MethodGet, "If-None-Match", "stale", http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := conditionalRequest(t, handler, test.method, path, body, test.header, test.value)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.want, response.Body.String())
			}
			if response.Code == http.StatusNotModified && response.Body.Len() != 0 {
				t.Fatalf("304 body = %q", response.Body.String())
			}
		})
	}

	updated := conditionalRequest(t, handler, http.MethodPatch, path, `{"properties":{"displayName":"Updated"}}`, "If-Match", etag)
	if updated.Code != http.StatusOK || updated.Header().Get("ETag") == etag {
		t.Fatalf("matching update = %d, ETag %q: %s", updated.Code, updated.Header().Get("ETag"), updated.Body.String())
	}
	missing := conditionalRequest(t, handler, http.MethodDelete, basePath+"/tags/missing"+apiQuery, "", "If-Match", "*")
	if missing.Code != http.StatusPreconditionFailed {
		t.Fatalf("missing conditional delete = %d: %s", missing.Code, missing.Body.String())
	}
	readMissing := conditionalRequest(t, handler, http.MethodGet, basePath+"/tags/missing"+apiQuery, "", "If-Match", "*")
	if readMissing.Code != http.StatusPreconditionFailed {
		t.Fatalf("missing conditional read = %d: %s", readMissing.Code, readMissing.Body.String())
	}
	deleted := conditionalRequest(t, handler, http.MethodDelete, path, "", "If-Match", "*")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("wildcard delete = %d: %s", deleted.Code, deleted.Body.String())
	}

	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		recorder := httptest.NewRecorder()
		missingHeader := httptest.NewRequest(method, path, strings.NewReader(body))
		missingHeader.Header.Set("Authorization", "Bearer token")
		handler.ServeHTTP(recorder, missingHeader)
		if recorder.Code != http.StatusBadRequest || recorder.Header().Get("x-ms-error-code") != "MissingRequiredHeader" || !strings.Contains(recorder.Body.String(), `"target":"If-Match"`) {
			t.Fatalf("missing %s If-Match = %d: %s", method, recorder.Code, recorder.Body.String())
		}
	}
}

func TestRequiredIfMatchInventory(t *testing.T) {
	tests := []struct {
		method string
		tail   []string
		want   bool
	}{
		{http.MethodGet, []string{"tags", "tag"}, false},
		{http.MethodPatch, []string{"tags", "tag"}, true},
		{http.MethodPatch, []string{"certificates", "certificate"}, false},
		{http.MethodDelete, []string{"certificates", "certificate"}, true},
		{http.MethodDelete, []string{"products", "product", "apis", "api"}, false},
		{http.MethodPatch, []string{"apis", "api", "operations", "operation"}, true},
		{http.MethodPatch, []string{"apis", "api", "Operations", "operation"}, true},
		{http.MethodPatch, []string{"apis", "api", "schemas", "schema"}, false},
		{http.MethodDelete, []string{"apis", "api", "schemas", "schema"}, true},
		{http.MethodDelete, []string{"apis", "api", "operations", "operation", "tags", "tag"}, false},
	}
	for _, test := range tests {
		if got := requiresIfMatch(route{Tail: test.tail}, test.method); got != test.want {
			t.Errorf("requiresIfMatch(%s, %v) = %v, want %v", test.method, test.tail, got, test.want)
		}
	}
}

func TestConditionalEntityTagParsing(t *testing.T) {
	if tags, present, valid := entityTags(nil); tags != nil || present || !valid {
		t.Fatalf("absent tags = %v, %v, %v", tags, present, valid)
	}
	for _, value := range []string{"", `"unterminated`, `"has space"`, "W/*", "\"bad\x7f\""} {
		if _, present, valid := entityTags([]string{value}); !present || valid {
			t.Fatalf("entityTags(%q) accepted", value)
		}
	}
	if tags, present, valid := entityTags([]string{`W/"one", "two"`, "*"}); !present || !valid || len(tags) != 3 {
		t.Fatalf("valid tags = %v, %v, %v", tags, present, valid)
	}
	if strongTagMatch([]string{`"different"`}, `"current"`, true) || strongTagMatch([]string{"*"}, `"current"`, false) {
		t.Fatal("strong non-match accepted")
	}
	if weakTagMatch([]string{`"different"`}, `"current"`, true) || weakTagMatch([]string{"*"}, `"current"`, false) {
		t.Fatal("weak non-match accepted")
	}
}

func TestCollectionPagingAndFiltering(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	for _, tag := range []struct{ name, displayName string }{{"alpha", "Alpha"}, {"beta", "Beta"}, {"gamma", "Gamma"}} {
		if _, err := st.UpsertTag(model.Tag{ServiceID: serviceModel().ID(), Name: tag.name, DisplayName: tag.displayName}); err != nil {
			t.Fatal(err)
		}
	}
	path := basePath + "/tags" + apiQuery + "&$top=1"
	first := request(t, handler, http.MethodGet, path, "")
	var page struct {
		Value    []map[string]any `json:"value"`
		Count    int              `json:"count"`
		NextLink string           `json:"nextLink"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if first.Code != http.StatusOK || page.Count != 3 || len(page.Value) != 1 || page.Value[0]["name"] != "alpha" || page.NextLink == "" {
		t.Fatalf("first page = %d %+v", first.Code, page)
	}
	nextURL, err := url.Parse(page.NextLink)
	if err != nil {
		t.Fatal(err)
	}
	second := request(t, handler, http.MethodGet, nextURL.RequestURI(), "")
	if err := json.Unmarshal(second.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Count != 3 || len(page.Value) != 1 || page.Value[0]["name"] != "beta" || page.NextLink == "" {
		t.Fatalf("second page = %+v", page)
	}

	query := url.Values{"api-version": {"2024-05-01"}, "$filter": {"startswith(displayName, 'B') or endswith(displayName, 'ma')"}, "$skip": {"1"}, "$top": {"1"}}
	filtered := request(t, handler, http.MethodGet, basePath+"/tags?"+query.Encode(), "")
	if err := json.Unmarshal(filtered.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Count != 2 || len(page.Value) != 1 || page.Value[0]["name"] != "gamma" || page.NextLink != "" {
		t.Fatalf("filtered page = %+v", page)
	}

	for _, rawQuery := range []string{
		"$top=0", "$top=not-a-number", "$top=2147483648", "$top=1&$top=2", "$skip=-1", "$skip=1&$skip=2",
		"$filter=name", "$filter=unknown+eq+%27value%27", "$filter=contains%28displayName%2C+1%29",
	} {
		response := request(t, handler, http.MethodGet, basePath+"/tags?api-version=2024-05-01&"+rawQuery, "")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "InvalidQueryParameterValue") {
			t.Fatalf("invalid query %q = %d: %s", rawQuery, response.Code, response.Body.String())
		}
	}
	missing := request(t, handler, http.MethodGet, basePath+"/missing?api-version=2024-05-01&$top=1", "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing collection = %d: %s", missing.Code, missing.Body.String())
	}
	resource := request(t, handler, http.MethodGet, basePath+"/tags/alpha?api-version=2024-05-01&$top=1", "")
	if resource.Code != http.StatusOK || !strings.Contains(resource.Body.String(), `"name":"alpha"`) {
		t.Fatalf("resource query = %d: %s", resource.Code, resource.Body.String())
	}
	beyond := request(t, handler, http.MethodGet, basePath+"/tags?api-version=2024-05-01&$skip=10", "")
	if beyond.Code != http.StatusOK || !strings.Contains(beyond.Body.String(), `"value":[]`) {
		t.Fatalf("skip beyond collection = %d: %s", beyond.Code, beyond.Body.String())
	}
	post := httptest.NewRequest(http.MethodPost, basePath+"/tags"+apiQuery, nil)
	if handler.handleCollectionRequest(httptest.NewRecorder(), post, route{}) {
		t.Fatal("POST was treated as a collection query")
	}
	for _, body := range []string{"not-json", `{"value":"scalar"}`, `{"value":["scalar"]}`} {
		source := httptest.NewRecorder()
		source.Header().Set("Content-Type", "application/json")
		source.WriteHeader(http.StatusOK)
		_, _ = source.WriteString(body)
		target := httptest.NewRecorder()
		writeCollectionResponse(target, httptest.NewRequest(http.MethodGet, basePath+apiQuery, nil), source, route{})
		if target.Code != http.StatusOK && body != `{"value":["scalar"]}` {
			t.Fatalf("collection response %q = %d", body, target.Code)
		}
		if body == `{"value":["scalar"]}` && target.Code != http.StatusBadRequest {
			t.Fatalf("scalar collection = %d: %s", target.Code, target.Body.String())
		}
	}
}

func TestCollectionOptionMatrixAndOrdering(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	for _, name := range []string{"alpha", "middle", "zulu"} {
		if _, err := st.UpsertPolicyFragment(model.PolicyFragment{ServiceID: serviceModel().ID(), Name: name, Value: "<fragment/>"}); err != nil {
			t.Fatal(err)
		}
	}
	path := basePath + "/policyFragments?api-version=2024-05-01&$orderby=name+desc&$top=2"
	response := request(t, handler, http.MethodGet, path, "")
	var page struct {
		Value []struct{ Name string } `json:"value"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(page.Value) != 2 || page.Value[0].Name != "zulu" || page.Value[1].Name != "middle" {
		t.Fatalf("ordered fragments = %d %+v", response.Code, page.Value)
	}

	for _, path := range []string{
		basePath + "/tags?api-version=2024-05-01&$orderby=name",
		basePath + "/tags?api-version=2024-05-01&$select=name",
		basePath + "/policyFragments?api-version=2024-05-01&$orderby=description",
		"/subscriptions/sub/providers/Microsoft.ApiManagement/service?api-version=2024-05-01&$top=1",
	} {
		response := request(t, handler, http.MethodGet, path, "")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "InvalidQueryParameterValue") {
			t.Fatalf("unsupported option = %d %s", response.Code, response.Body.String())
		}
	}

	rt := route{ServiceName: "service", Tail: []string{"policyFragments"}}
	for _, test := range []struct {
		query url.Values
		want  int
		err   bool
	}{
		{url.Values{"$orderby": {"name"}}, 1, false},
		{url.Values{"$orderby": {"NAME ASC"}}, 1, false},
		{url.Values{"$orderby": {"name DESC"}}, -1, false},
		{url.Values{"$orderby": {""}}, 0, true},
		{url.Values{"$orderby": {"description"}}, 0, true},
		{url.Values{"$orderby": {"name sideways"}}, 0, true},
		{url.Values{"$orderby": {"name", "name desc"}}, 0, true},
	} {
		got, err := parseCollectionOrder(test.query, rt)
		if got != test.want || (err != nil) != test.err {
			t.Errorf("parseCollectionOrder(%v) = %d, %v", test.query, got, err)
		}
	}
	if _, err := parseCollectionOrder(url.Values{"$orderby": {"name"}}, route{}); err == nil {
		t.Fatal("unsupported route accepted $orderby")
	}
}

func TestCollectionFilterContracts(t *testing.T) {
	for key, contract := range collectionFilterContracts {
		parts := strings.Split(key, "/")
		tail := []string{parts[0]}
		if len(parts) >= 2 {
			tail = append(tail, "resource", parts[1])
		}
		if len(parts) == 3 {
			tail = append(tail, "child", parts[2])
		}
		if got := collectionFilterKey(tail); got != key {
			t.Fatalf("collectionFilterKey(%v) = %q, want %q", tail, got, key)
		}
		if len(contract) == 0 {
			if _, err := parseFilterForRoute("name eq 'value'", route{Tail: tail}); err == nil {
				t.Fatalf("empty contract %q accepted a field", key)
			}
			continue
		}
		for field, rule := range contract {
			if _, err := parseFilterForRoute(field+" "+rule.operators[0]+" 'value'", route{Tail: tail}); err != nil {
				t.Fatalf("contract %q field %q: %v", key, field, err)
			}
			break
		}
	}
	if got := collectionFilterKey([]string{"unexpected", "shape"}); got != "" {
		t.Fatalf("unexpected collection key = %q", got)
	}
	if _, err := parseFilterForRoute("custom eq 'value'", route{Tail: []string{"unaudited"}}); err != nil {
		t.Fatalf("unaudited route rejected generic filter: %v", err)
	}

	tests := []struct {
		tail   []string
		filter string
		valid  bool
	}{
		{[]string{"apis"}, "isCurrent eq true", true},
		{[]string{"apis"}, "isCurrent gt false", false},
		{[]string{"apis"}, "contains(isCurrent, 't')", false},
		{[]string{"products"}, "state eq 'published'", true},
		{[]string{"products"}, "state ne 'published'", false},
		{[]string{"groups"}, "externalId eq 'entra'", true},
		{[]string{"groups"}, "externalId ne 'entra'", false},
		{[]string{"certificates"}, "expirationDate gt '2026-01-01'", true},
		{[]string{"certificates"}, "startswith(expirationDate, '2026')", false},
		{[]string{"products", "p", "groups"}, "name gt 'a'", true},
		{[]string{"products", "p", "groups"}, "contains(name, 'a')", false},
		{[]string{"products", "p", "groups"}, "displayName ne 'a'", true},
		{[]string{"products", "p", "groups"}, "displayName gt 'a'", false},
		{[]string{"tags"}, "description eq 'hidden'", false},
		{[]string{"tags"}, "name eq displayName", false},
		{[]string{"tags"}, "contains(name, displayName)", false},
		{[]string{"tags"}, "contains('a', 'b')", false},
	}
	for _, test := range tests {
		_, err := parseFilterForRoute(test.filter, route{Tail: test.tail})
		if (err == nil) != test.valid {
			t.Errorf("filter %q on %v valid=%v: %v", test.filter, test.tail, test.valid, err)
		}
	}
}

func TestCollectionSelectors(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/starter"+apiQuery, `{"properties":{"displayName":"Starter","state":"published"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/tags/gateway"+apiQuery, `{"properties":{"displayName":"Gateway"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/starter/tags/gateway"+apiQuery, "", http.StatusCreated)
	filtered := request(t, handler, http.MethodGet, basePath+"/products?api-version=2024-05-01&tags=gateway", "")
	if filtered.Code != http.StatusOK || !strings.Contains(filtered.Body.String(), `"count":1`) || !strings.Contains(filtered.Body.String(), `"name":"starter"`) {
		t.Fatalf("product tag selector = %d %s", filtered.Code, filtered.Body.String())
	}
	api, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "scoped-api", DisplayName: "Scoped API"})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "scoped-operation", DisplayName: "Scoped Operation"})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []model.Tag{{ServiceID: serviceModel().ID(), Name: "api-scope", DisplayName: "API scope"}, {ServiceID: serviceModel().ID(), Name: "operation-scope", DisplayName: "Operation scope"}, {ServiceID: serviceModel().ID(), Name: "product-scope", DisplayName: "Product scope"}} {
		created, err := st.UpsertTag(value)
		if err != nil {
			t.Fatal(err)
		}
		resourceID := api.ID()
		if created.Name == "operation-scope" {
			resourceID = operation.APIID + "/operations/" + operation.Name
		} else if created.Name == "product-scope" {
			resourceID = serviceModel().ID() + "/products/starter"
		}
		if err := st.AssignTag(resourceID, created.ID()); err != nil {
			t.Fatal(err)
		}
	}
	tags, err := st.ListTags(serviceModel().ID())
	if err != nil {
		t.Fatal(err)
	}
	apiScoped, err := handler.applyCollectionSelectors([]any{tagWire(tags[0]), tagWire(tags[1]), tagWire(tags[2])}, url.Values{"scope": {"apis"}}, route{ServiceName: "svc", SubscriptionID: "sub", ResourceGroup: "rg", Tail: []string{"tags"}})
	if err != nil || len(apiScoped) != 1 || resourceName(apiScoped[0]) != "api-scope" {
		t.Fatalf("API tag scope = %#v, %v", apiScoped, err)
	}
	operationScoped, err := handler.applyCollectionSelectors([]any{tagWire(tags[0]), tagWire(tags[1]), tagWire(tags[2])}, url.Values{"scope": {"operations"}}, route{ServiceName: "svc", SubscriptionID: "sub", ResourceGroup: "rg", Tail: []string{"tags"}})
	if err != nil || len(operationScoped) != 1 || resourceName(operationScoped[0]) != "operation-scope" {
		t.Fatalf("operation tag scope = %#v, %v", operationScoped, err)
	}
	productScoped, err := handler.applyCollectionSelectors([]any{tagWire(tags[0]), tagWire(tags[1]), tagWire(tags[2])}, url.Values{"scope": {"products"}}, route{ServiceName: "svc", SubscriptionID: "sub", ResourceGroup: "rg", Tail: []string{"tags"}})
	if err != nil || len(productScoped) != 2 || !containsResourceName(productScoped, "product-scope") {
		t.Fatalf("product tag scope = %#v, %v", productScoped, err)
	}
	if _, err := handler.applyCollectionSelectors([]any{tagWire(tags[0])}, url.Values{"scope": {"invalid"}}, route{ServiceName: "svc", SubscriptionID: "sub", ResourceGroup: "rg", Tail: []string{"tags"}}); err == nil {
		t.Fatal("unsupported tag scope was accepted")
	}
	projected, err := handler.applyCollectionSelectors([]any{
		map[string]any{"properties": map[string]any{"isKeyVaultRefreshFailed": true}},
		map[string]any{"properties": map[string]any{}},
	}, url.Values{"isKeyVaultRefreshFailed": {"true"}}, route{Tail: []string{"namedValues"}})
	if err != nil || projected[1].(map[string]any)["properties"].(map[string]any)["isKeyVaultRefreshFailed"] != false {
		t.Fatalf("Key Vault projection = %#v, %v", projected, err)
	}
	if _, err := handler.applyCollectionSelectors([]any{"scalar"}, url.Values{"isKeyVaultRefreshFailed": {"true"}}, route{Tail: []string{"certificates"}}); err == nil {
		t.Fatal("scalar Key Vault projection was accepted")
	}
	for _, path := range []string{
		basePath + "/products?api-version=2024-05-01&expandGroups=maybe",
		basePath + "/tags?api-version=2024-05-01&tags=gateway",
		basePath + "/tags?api-version=2024-05-01&scope=invalid",
	} {
		response := request(t, handler, http.MethodGet, path, "")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "InvalidQueryParameterValue") {
			t.Fatalf("invalid selector = %d %s", response.Code, response.Body.String())
		}
	}

	for _, test := range []struct {
		rt    route
		query url.Values
		valid bool
	}{
		{route{Tail: []string{"products"}}, url.Values{"expandGroups": {"true"}}, true},
		{route{Tail: []string{"apis"}}, url.Values{"expandApiVersionSet": {"false"}}, true},
		{route{Tail: []string{"tags"}}, url.Values{"scope": {"apis"}}, true},
		{route{Tail: []string{"users"}}, url.Values{"expandGroups": {"maybe"}}, false},
		{route{Tail: []string{"tags"}}, url.Values{"tags": {"gateway"}}, false},
		{route{Tail: []string{"products"}}, url.Values{"scope": {"apis"}}, false},
	} {
		if err := validateCollectionSelectors(test.query, test.rt); (err == nil) != test.valid {
			t.Errorf("selector %v on %v valid=%v: %v", test.query, test.rt.Tail, test.valid, err)
		}
	}
	if _, err := handler.applyCollectionSelectors([]any{"scalar"}, url.Values{"tags": {"gateway"}}, route{Tail: []string{"products"}}); err == nil {
		t.Fatal("scalar product collection accepted tag selector")
	}
	brokenHandler, brokenStore := testHandler(t)
	if err := brokenStore.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := brokenHandler.applyCollectionSelectors([]any{map[string]any{"id": "product"}}, url.Values{"tags": {"gateway"}}, route{Tail: []string{"products"}}); err == nil {
		t.Fatal("closed store accepted tag selector")
	}
	source := httptest.NewRecorder()
	source.WriteHeader(http.StatusOK)
	_, _ = source.WriteString(`{"value":[{"id":"product"}]}`)
	target := httptest.NewRecorder()
	brokenHandler.writeCollectionResponse(target, httptest.NewRequest(http.MethodGet, basePath+"/products?api-version=2024-05-01&tags=gateway", nil), source, route{Tail: []string{"products"}})
	if target.Code != http.StatusBadRequest {
		t.Fatalf("closed store response = %d %s", target.Code, target.Body.String())
	}
	_ = st
}

func resourceName(value any) string {
	resource, _ := value.(map[string]any)
	name, _ := resource["name"].(string)
	return name
}

func containsResourceName(values []any, want string) bool {
	for _, value := range values {
		if resourceName(value) == want {
			return true
		}
	}
	return false
}

func TestCollectionSelectorExpansion(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	serviceID := serviceModel().ID()
	versionSet, err := st.UpsertAPIVersionSet(model.APIVersionSet{ServiceID: serviceID, Name: "versions", DisplayName: "Versions", VersioningScheme: "Segment"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: serviceID, Name: "expanded-api", DisplayName: "Expanded API", VersionSetID: versionSet.ID()})
	if err != nil {
		t.Fatal(err)
	}
	product, err := st.UpsertProduct(model.Product{ServiceID: serviceID, Name: "expanded-product", DisplayName: "Expanded Product"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := st.UpsertGroup(model.Group{ServiceID: serviceID, Name: "expanded-group", DisplayName: "Expanded Group", Type: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.UpsertUser(model.User{ServiceID: serviceID, Name: "expanded-user", FirstName: "Expanded", State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	tag, err := st.UpsertTag(model.Tag{ServiceID: serviceID, Name: "expanded-tag", DisplayName: "Expanded Tag"})
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []error{st.AssignTag(api.ID(), tag.ID()), st.LinkProductGroup(product.ID(), group.ID()), st.LinkGroupUser(group.ID(), user.ID())} {
		if link != nil {
			t.Fatal(link)
		}
	}

	apiValues, err := handler.applyCollectionSelectors([]any{apiWire(api)}, url.Values{"expandApiVersionSet": {"true"}, "tags": {"include"}}, route{Tail: []string{"apis"}})
	if err != nil || len(apiValues) != 1 {
		t.Fatalf("expanded API = %#v, %v", apiValues, err)
	}
	apiProperties := apiValues[0].(map[string]any)["properties"].(map[string]any)
	if apiProperties["apiVersionSet"] == nil || len(apiProperties["tags"].([]any)) != 1 {
		t.Fatalf("expanded API properties = %#v", apiProperties)
	}
	operation := model.Operation{APIID: api.ID(), Name: "get"}
	if _, err := st.UpsertOperation(operation); err != nil {
		t.Fatal(err)
	}
	operationValues, err := handler.applyCollectionSelectors([]any{operationWire(operation)}, url.Values{"tags": {"include"}}, route{Tail: []string{"apis", "expanded-api", "operations"}})
	if err != nil || len(operationValues[0].(map[string]any)["properties"].(map[string]any)["tags"].([]any)) != 0 {
		t.Fatalf("expanded operation = %#v, %v", operationValues, err)
	}
	productValues, err := handler.applyCollectionSelectors([]any{productWire(product)}, url.Values{"expandGroups": {"true"}}, route{Tail: []string{"products"}})
	if err != nil || len(productValues[0].(map[string]any)["properties"].(map[string]any)["groups"].([]any)) != 1 {
		t.Fatalf("expanded product = %#v, %v", productValues, err)
	}
	userValues, err := handler.applyCollectionSelectors([]any{userWire(user)}, url.Values{"expandGroups": {"true"}}, route{Tail: []string{"users"}})
	if err != nil || len(userValues[0].(map[string]any)["properties"].(map[string]any)["groups"].([]any)) != 1 {
		t.Fatalf("expanded user = %#v, %v", userValues, err)
	}
	if properties := resourceProperties(map[string]any{}); properties == nil {
		t.Fatal("resourceProperties returned nil")
	}

	for _, test := range []struct {
		query url.Values
		route route
	}{
		{url.Values{"expandApiVersionSet": {"true"}}, route{Tail: []string{"apis"}}},
		{url.Values{"tags": {"include"}}, route{Tail: []string{"apis"}}},
		{url.Values{"tags": {"include"}}, route{Tail: []string{"apis", "expanded-api", "operations"}}},
		{url.Values{"expandGroups": {"true"}}, route{Tail: []string{"products"}}},
		{url.Values{"expandGroups": {"true"}}, route{Tail: []string{"users"}}},
	} {
		if _, err := handler.applyCollectionSelectors([]any{"scalar"}, test.query, test.route); err == nil {
			t.Fatalf("scalar expansion accepted for %v", test.route.Tail)
		}
	}
	brokenHandler, brokenStore := testHandler(t)
	if err := brokenStore.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		query url.Values
		route route
	}{
		{url.Values{"expandApiVersionSet": {"true"}}, route{Tail: []string{"apis"}}},
		{url.Values{"tags": {"include"}}, route{Tail: []string{"apis"}}},
		{url.Values{"tags": {"include"}}, route{Tail: []string{"apis", "expanded-api", "operations"}}},
		{url.Values{"expandGroups": {"true"}}, route{Tail: []string{"products"}}},
		{url.Values{"expandGroups": {"true"}}, route{Tail: []string{"users"}}},
	} {
		if _, err := brokenHandler.applyCollectionSelectors([]any{map[string]any{"id": "missing"}}, test.query, test.route); err == nil {
			t.Fatalf("closed store expansion accepted for %v", test.route.Tail)
		}
	}
}

func TestValidationErrorDetails(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeError(recorder, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	errorValue := document["error"].(map[string]any)
	details := errorValue["details"].([]any)
	if len(details) != 1 || details[0].(map[string]any)["target"] != "properties.displayName" || recorder.Header().Get("x-ms-error-code") != "ValidationError" {
		t.Fatalf("validation error details = %#v", document)
	}
	recorder = httptest.NewRecorder()
	writeError(recorder, http.StatusNotFound, "ResourceNotFound", "missing", "resource")
	var plain map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &plain); err != nil {
		t.Fatal(err)
	}
	if _, present := plain["error"].(map[string]any)["details"]; present {
		t.Fatalf("non-validation error unexpectedly has details: %#v", plain)
	}
}

func TestFilterGrammar(t *testing.T) {
	resource := map[string]any{
		"name":       "o'brien",
		"properties": map[string]any{"displayName": "Gateway API", "enabled": true, "rank": float64(3), "empty": nil},
	}
	tests := []struct {
		filter string
		want   bool
	}{
		{`name eq 'o''brien'`, true},
		{`name ne 'other' and (rank gt 2 and rank ge 3)`, true},
		{`rank lt 4 and rank le 3`, true},
		{`enabled eq true`, true},
		{`enabled ne false`, true},
		{`empty eq null`, true},
		{`empty ne 'value'`, true},
		{`contains(displayName, 'way')`, true},
		{`startswith(displayName, 'Gate')`, true},
		{`endswith(displayName, 'API')`, true},
		{`substringof('way', displayName)`, true},
		{`name eq 'other' or rank eq 3`, true},
		{`properties/displayName eq 'Gateway API'`, true},
		{`rank ne 3`, false},
	}
	for _, test := range tests {
		predicate, err := parseFilter(test.filter)
		if err != nil {
			t.Fatalf("parseFilter(%q): %v", test.filter, err)
		}
		got, err := predicate(resource)
		if err != nil || got != test.want {
			t.Fatalf("filter %q = %v, %v; want %v", test.filter, got, err, test.want)
		}
	}

	invalid := []string{
		"(", "name", "name xx 'x'", "name eq", "name eq 'unterminated", "unknown(name, 'x')",
		"contains(name)", "contains(name, 'x'", "contains(name, 'x', 'y')", "name eq 'x' trailing",
	}
	for _, filter := range invalid {
		if _, err := parseFilter(filter); err == nil {
			t.Fatalf("parseFilter(%q) succeeded", filter)
		}
	}
	for _, filter := range []string{
		"missing eq 'x'", "properties/missing eq 'x'", "displayName/value eq 'x'", "rank eq '3'", "name eq 3",
		"empty gt null", "enabled gt false", "properties eq 'x'", "name eq missing", "contains(missing, 'x')", "contains(name, missing)",
		"missing eq 'x' and name eq 'x'",
	} {
		predicate, err := parseFilter(filter)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := predicate(resource); err == nil {
			t.Fatalf("filter %q evaluated without error", filter)
		}
	}
	predicate, err := parseFilter("")
	if matched, evaluateErr := predicate(resource); err != nil || evaluateErr != nil || !matched {
		t.Fatalf("empty filter = %v, %v, %v", matched, err, evaluateErr)
	}
}

func TestServiceBranches(t *testing.T) {
	handler, st := testHandler(t)
	validService := `{"location":"local","sku":{},"tags":{"environment":"test"},"zones":["1"],"identity":{"type":"SystemAssigned"},"properties":{"publisherName":"Local","publisherEmail":"local@example.test","customProperties":{"one":"1","remove":"x"},"publicNetworkAccess":"Enabled","hostnameConfigurations":[{"type":"Proxy","hostName":"api.example.test"}]}}`
	assertStatus(t, handler, http.MethodGet, basePath+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, `{"sku":{"name":"Developer"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, validService, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, validService, http.StatusOK)
	recorder := request(t, handler, http.MethodGet, basePath+apiQuery, "")
	var service map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &service); err != nil {
		t.Fatal(err)
	}
	properties := service["properties"].(map[string]any)
	if service["tags"].(map[string]any)["environment"] != "test" || service["identity"].(map[string]any)["type"] != "SystemAssigned" || properties["publicNetworkAccess"] != "Enabled" {
		t.Fatalf("service document was not preserved: %#v", service)
	}
	assertStatus(t, handler, http.MethodPost, basePath+apiQuery, `{}`, http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPatch, basePath+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+apiQuery, `{"sku":{"name":"Basic","capacity":2},"tags":{"owner":"platform"},"properties":{"publisherName":"Updated","publisherEmail":"updated@example.test","customProperties":{"two":"2","remove":null}}}`, http.StatusOK)
	recorder = request(t, handler, http.MethodGet, basePath+apiQuery, "")
	if err := json.Unmarshal(recorder.Body.Bytes(), &service); err != nil {
		t.Fatal(err)
	}
	properties = service["properties"].(map[string]any)
	custom := properties["customProperties"].(map[string]any)
	if custom["one"] != "1" || custom["two"] != "2" || custom["remove"] != nil || properties["publisherName"] != "Updated" {
		t.Fatalf("service patch was not merged: %#v", service)
	}

	handler.Activate = func() error { return errors.New("compile failed") }
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, validService, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+apiQuery, `{}`, http.StatusBadRequest)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, basePath+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodPatch, basePath+apiQuery, `{}`, http.StatusNotFound)

	recorder = httptest.NewRecorder()
	handler.storeError(recorder, errors.New("database"), "target")
	if recorder.Code != http.StatusConflict {
		t.Fatalf("store error status = %d", recorder.Code)
	}
	_ = st
}

func TestServiceDocumentHelpers(t *testing.T) {
	target := map[string]any{"replace": "old", "object": map[string]any{"keep": true}, "remove": true}
	mergeObject(target, map[string]any{"replace": map[string]any{"new": true}, "object": "scalar", "remove": nil})
	clone := cloneObject(target)
	clone["replace"].(map[string]any)["new"] = false
	if _, ok := target["remove"]; ok || target["object"] != "scalar" || target["replace"].(map[string]any)["new"] != true {
		t.Fatalf("merged target = %#v", target)
	}
}

func TestLoggerAndDiagnosticBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	api := model.API{ServiceID: serviceModel().ID(), Name: "api", DisplayName: "API", Path: "api", ServiceURL: "https://backend", Protocols: []string{"https"}}
	if _, err := st.UpsertAPI(api); err != nil {
		t.Fatal(err)
	}
	loggerPath := basePath + "/loggers/app" + apiQuery
	loggerBody := `{"credentials":{"root":"secret"},"id":"malicious","properties":{"loggerType":"applicationInsights","description":"App Insights","isBuffered":false,"resourceId":"/components/app","credentials":{"instrumentationKey":"secret"},"custom":"kept"}}`
	assertStatus(t, handler, http.MethodPost, basePath+"/loggers"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/loggers/too/deep"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, loggerPath, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, loggerPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, loggerPath, `{"properties":{"loggerType":"wrong"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, loggerPath, loggerBody, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, loggerPath, loggerBody, http.StatusOK)
	assertStatus(t, handler, http.MethodHead, loggerPath, "", http.StatusOK)
	loggerGet := request(t, handler, http.MethodGet, loggerPath, "")
	if strings.Contains(loggerGet.Body.String(), `"secret"`) || !strings.Contains(loggerGet.Body.String(), `"instrumentationKey":"{{Logger-Credentials-`) || !strings.Contains(loggerGet.Body.String(), `"custom":"kept"`) || strings.Contains(loggerGet.Body.String(), `"id":"malicious"`) {
		t.Fatalf("logger GET = %s", loggerGet.Body.String())
	}
	storedLogger, err := st.GetLogger(serviceModel().ID() + "/loggers/app")
	if err != nil || storedLogger.Document["credentials"] != nil || storedLogger.Document["properties"].(map[string]any)["credentials"] != nil || storedLogger.Credentials["instrumentationKey"] != "secret" {
		t.Fatalf("stored logger = %+v, %v", storedLogger, err)
	}
	assertStatus(t, handler, http.MethodPatch, basePath+"/loggers/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, loggerPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, loggerPath, `{"properties":{"loggerType":"azureMonitor","description":"Updated","isBuffered":true,"resourceId":"","credentials":{}}}`, http.StatusOK)
	list := request(t, handler, http.MethodGet, basePath+"/loggers"+apiQuery, "")
	if !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), `"loggerType":"azureMonitor"`) {
		t.Fatalf("logger list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, loggerPath, "", http.StatusMethodNotAllowed)

	diagnosticPath := basePath + "/diagnostics/local" + apiQuery
	diagnosticBody := `{"id":"malicious","name":"malicious","type":"malicious","customRoot":{"retained":true},"properties":{"loggerId":"` + serviceModel().ID() + `/loggers/app","alwaysLog":"allErrors","logClientIp":true,"verbosity":"information","sampling":{"samplingType":"fixed","percentage":50},"httpCorrelationProtocol":"W3C","operationNameFormat":"Url","frontend":{"request":{"body":{"bytes":64}}}}}`
	assertStatus(t, handler, http.MethodPost, basePath+"/diagnostics"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/diagnostics/too/deep"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, diagnosticPath, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{"properties":{"loggerId":"/missing"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{"properties":{"loggerId":"`+serviceModel().ID()+`/loggers/app","sampling":{"samplingType":"random","percentage":50}}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{"properties":{"loggerId":"`+serviceModel().ID()+`/loggers/app","sampling":{"samplingType":"fixed","percentage":101}}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{"properties":{"loggerId":"`+serviceModel().ID()+`/loggers/app","alwaysLog":"everything"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{"properties":{"loggerId":"`+serviceModel().ID()+`/loggers/app","verbosity":"debug"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, diagnosticBody, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, diagnosticBody, http.StatusOK)
	assertStatus(t, handler, http.MethodHead, diagnosticPath, "", http.StatusOK)
	diagnosticGet := request(t, handler, http.MethodGet, diagnosticPath, "")
	if !strings.Contains(diagnosticGet.Body.String(), `"bytes":64`) || !strings.Contains(diagnosticGet.Body.String(), `"percentage":50`) || !strings.Contains(diagnosticGet.Body.String(), `"customRoot":{"retained":true}`) || strings.Contains(diagnosticGet.Body.String(), `"id":"malicious"`) {
		t.Fatalf("diagnostic GET = %s", diagnosticGet.Body.String())
	}
	storedDiagnostic, err := st.GetDiagnostic(serviceModel().ID() + "/diagnostics/local")
	if err != nil || storedDiagnostic.Document["id"] != nil || storedDiagnostic.Document["properties"].(map[string]any)["httpCorrelationProtocol"] != "W3C" {
		t.Fatalf("stored diagnostic = %+v, %v", storedDiagnostic, err)
	}
	assertStatus(t, handler, http.MethodPatch, basePath+"/diagnostics/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, diagnosticPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, diagnosticPath, `{"properties":{"loggerId":null}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, diagnosticPath, `{"properties":{"alwaysLog":null,"logClientIp":null,"verbosity":null,"sampling":{"samplingType":null,"percentage":null}}}`, http.StatusOK)
	diagnosticGet = request(t, handler, http.MethodGet, diagnosticPath, "")
	if !strings.Contains(diagnosticGet.Body.String(), `"alwaysLog":""`) || !strings.Contains(diagnosticGet.Body.String(), `"logClientIp":false`) || !strings.Contains(diagnosticGet.Body.String(), `"percentage":100`) {
		t.Fatalf("cleared diagnostic GET = %s", diagnosticGet.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, diagnosticPath, `{"properties":{"sampling":null}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, diagnosticPath, `{"properties":{"alwaysLog":"","logClientIp":false,"verbosity":"verbose","sampling":{"samplingType":"fixed","percentage":100}}}`, http.StatusOK)
	list = request(t, handler, http.MethodGet, basePath+"/diagnostics"+apiQuery, "")
	if !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), `"verbosity":"verbose"`) {
		t.Fatalf("diagnostic list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, diagnosticPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodDelete, loggerPath, "", http.StatusConflict)

	apiDiagnosticPath := basePath + "/apis/api/diagnostics/app" + apiQuery
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/missing/diagnostics"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/api/diagnostics"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPut, apiDiagnosticPath, diagnosticBody, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, apiDiagnosticPath, "", http.StatusOK)
	assertStatus(t, handler, http.MethodHead, apiDiagnosticPath, "", http.StatusOK)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/api/diagnostics/app/deep"+apiQuery, "", http.StatusNotFound)

	handler.Activate = func() error { return errors.New("compile failed") }
	assertStatus(t, handler, http.MethodPatch, apiDiagnosticPath, `{"properties":{"verbosity":"error"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, apiDiagnosticPath, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, diagnosticPath, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, diagnosticPath, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodDelete, loggerPath, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, loggerPath, "", http.StatusPreconditionFailed)
}

func TestLoggerDiagnosticStoreErrorsAndWireFallbacks(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedService(t, st)
	logger, _ := st.UpsertLogger(model.Logger{ServiceID: serviceModel().ID(), Name: "app", LoggerType: "azureMonitor"})
	diagnostic, _ := st.UpsertDiagnostic(model.Diagnostic{ServiceID: serviceModel().ID(), ScopeID: serviceModel().ID(), Name: "d", LoggerID: logger.ID(), SamplingType: "fixed", SamplingPercentage: 100})
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	loggerPath := basePath + "/loggers/app" + apiQuery
	diagnosticPath := basePath + "/diagnostics/d" + apiQuery
	if _, err := db.Exec(`CREATE TRIGGER reject_logger_write BEFORE INSERT ON loggers BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, loggerPath, `{"properties":{"loggerType":"azureMonitor"}}`, http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_logger_write; CREATE TRIGGER reject_logger_delete BEFORE DELETE ON loggers BEGIN SELECT RAISE(FAIL, 'rejected'); END; DELETE FROM diagnostics`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, loggerPath, "", http.StatusConflict)
	if _, err := st.UpsertDiagnostic(diagnostic); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_logger_delete; CREATE TRIGGER reject_diagnostic_write BEFORE INSERT ON diagnostics BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{"properties":{"loggerId":"`+logger.ID()+`","sampling":{"samplingType":"fixed","percentage":100}}}`, http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_diagnostic_write; CREATE TRIGGER reject_diagnostic_delete BEFORE DELETE ON diagnostics BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, diagnosticPath, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_diagnostic_delete; DROP TABLE diagnostics; DROP TABLE loggers`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/loggers"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, loggerPath, `{"properties":{"loggerType":"azureMonitor"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/diagnostics"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, diagnosticPath, `{"properties":{"loggerId":"`+logger.ID()+`"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, diagnosticPath, "", http.StatusConflict)

	loggerResult := loggerWire(model.Logger{ServiceID: "service", Name: "l", Credentials: map[string]string{"reference": "{{existing}}"}, Document: map[string]any{"properties": "scalar"}})
	diagnosticResult := diagnosticWire(model.Diagnostic{ServiceID: "service", ScopeID: "service/apis/a", Name: "d", Document: map[string]any{"properties": "scalar"}})
	if loggerResult["properties"].(map[string]any)["credentials"].(map[string]string)["reference"] != "{{existing}}" || diagnosticResult["type"] != "Microsoft.ApiManagement/service/apis/diagnostics" {
		t.Fatalf("wire fallbacks = %#v %#v", loggerResult, diagnosticResult)
	}
}

func TestServiceLists(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	other := serviceModel()
	other.SubscriptionID, other.ResourceGroup, other.Name = "other", "elsewhere", "other"
	if _, err := st.UpsertService(other); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service" + apiQuery,
		"/subscriptions/sub/providers/Microsoft.ApiManagement/service" + apiQuery,
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer token")
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || strings.Count(recorder.Body.String(), `"type":"Microsoft.ApiManagement/service"`) != 1 {
			t.Fatalf("list %s = %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
	assertStatus(t, handler, http.MethodPost, "/subscriptions/sub/providers/Microsoft.ApiManagement/service"+apiQuery, "", http.StatusMethodNotAllowed)
}

func TestAPIBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/apis"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/missing"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","path":"a","serviceUrl":"https://backend"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"tags":{"owner":"platform"},"customRoot":{"kept":true},"properties":{"displayName":"A","path":"a","serviceUrl":"https://backend","protocols":["https"],"subscriptionRequired":false,"description":"Original","customMetadata":{"keep":"one","remove":"old"}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"Updated","path":"updated","serviceUrl":"https://updated","protocols":["http","https"],"subscriptionRequired":true,"description":null,"customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	apiGet := request(t, handler, http.MethodGet, basePath+"/apis/a"+apiQuery, "")
	if !strings.Contains(apiGet.Body.String(), `"owner":"platform"`) || !strings.Contains(apiGet.Body.String(), `"keep":"one"`) || !strings.Contains(apiGet.Body.String(), `"add":"two"`) || strings.Contains(apiGet.Body.String(), `"remove"`) || strings.Contains(apiGet.Body.String(), `"description"`) {
		t.Fatalf("lossless API patch = %s", apiGet.Body.String())
	}
	list := request(t, handler, http.MethodGet, basePath+"/apis"+apiQuery, "")
	if strings.Count(list.Body.String(), `"type":"Microsoft.ApiManagement/service/apis"`) != 1 || !strings.Contains(list.Body.String(), `"displayName":"Updated"`) {
		t.Fatalf("API list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a;rev=2"+apiQuery, `{"properties":{"displayName":"Revision 2","path":"updated","serviceUrl":"https://revision","protocols":["https"],"subscriptionRequired":true,"apiRevision":"2","apiRevisionDescription":"Second revision","isCurrent":false}}`, http.StatusCreated)
	revisions := request(t, handler, http.MethodGet, basePath+"/apis/a/revisions"+apiQuery, "")
	if !strings.Contains(revisions.Body.String(), `"count":2`) || !strings.Contains(revisions.Body.String(), `"apiRevision":"2"`) || !strings.Contains(revisions.Body.String(), `"description":"Second revision"`) || strings.Count(revisions.Body.String(), `"isCurrent":true`) != 1 {
		t.Fatalf("API revisions = %s", revisions.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/apis/a/revisions"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, basePath+"/apis/a"+apiQuery, `{}`, http.StatusMethodNotAllowed)

	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/operations"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/apis/a/operations"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/operations/missing"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"displayName":"Get"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"displayName":"Get","method":"GET","urlTemplate":"/"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"displayName":"Get","method":"GET","urlTemplate":"/","description":"Original","request":{"headers":[{"name":"X-Test","required":true}]},"templateParameters":[{"name":"id","type":"string"}]}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/operations/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/operations/get"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"displayName":"Updated","method":"POST","urlTemplate":"/updated","description":null,"responses":[{"statusCode":200}]}}`, http.StatusOK)
	operationGet := request(t, handler, http.MethodGet, basePath+"/apis/a/operations/get"+apiQuery, "")
	if !strings.Contains(operationGet.Body.String(), `"X-Test"`) || !strings.Contains(operationGet.Body.String(), `"statusCode":200`) || strings.Contains(operationGet.Body.String(), `"description"`) {
		t.Fatalf("lossless operation patch = %s", operationGet.Body.String())
	}
	list = request(t, handler, http.MethodGet, basePath+"/apis/a/operations"+apiQuery, "")
	if strings.Count(list.Body.String(), `"type":"Microsoft.ApiManagement/service/apis/operations"`) != 1 || !strings.Contains(list.Body.String(), `"method":"POST"`) {
		t.Fatalf("operation list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/apis/a/operations/get"+apiQuery, `{}`, http.StatusMethodNotAllowed)

	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/policies/policy"+apiQuery, "", http.StatusNotFound)
	handler.ValidatePolicy = func(string) error { return errors.New("invalid policy") }
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{"properties":{"format":"rawxml","value":"x"}}`, http.StatusBadRequest)
	handler.ValidatePolicy = nil
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{"properties":{"format":"rawxml","value":"<policies/>"}}`, http.StatusCreated)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, basePath+"/apis/a/policies/policy"+apiQuery, nil)
	req.Header.Set("Authorization", "Bearer token")
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `\u003cpolicies/\u003e`) || recorder.Header().Get("ETag") == "" {
		t.Fatalf("policy GET = %d %s", recorder.Code, recorder.Body.String())
	}
	sourceID := serviceModel().ID() + "/apis/a;rev=1"
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a;rev=3"+apiQuery, `{"properties":{"sourceApiId":"`+sourceID+`","apiRevision":"3","apiRevisionDescription":"Cloned revision"}}`, http.StatusCreated)
	clonedDocument := request(t, handler, http.MethodGet, basePath+"/apis/a;rev=3"+apiQuery, "")
	if !strings.Contains(clonedDocument.Body.String(), `"owner":"platform"`) || strings.Contains(clonedDocument.Body.String(), "sourceApiId") {
		t.Fatalf("cloned API document = %s", clonedDocument.Body.String())
	}
	clonedOperation := request(t, handler, http.MethodGet, basePath+"/apis/a;rev=3/operations/get"+apiQuery, "")
	if clonedOperation.Code != http.StatusOK || !strings.Contains(clonedOperation.Body.String(), `"X-Test"`) || !strings.Contains(clonedOperation.Body.String(), `"statusCode":200`) {
		t.Fatalf("cloned operation document = %d: %s", clonedOperation.Code, clonedOperation.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a;rev=3/policies/policy"+apiQuery, "", http.StatusOK)
	revisions = request(t, handler, http.MethodGet, basePath+"/apis/a/revisions"+apiQuery, "")
	if !strings.Contains(revisions.Body.String(), `"count":3`) || !strings.Contains(revisions.Body.String(), `"description":"Cloned revision"`) {
		t.Fatalf("cloned API revision list = %s", revisions.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/releases"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/apis/a/releases"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/releases/r"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/releases/r"+apiQuery, `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/releases/r"+apiQuery, `{"properties":{"apiId":"/missing"}}`, http.StatusNotFound)
	targetRevision3 := serviceModel().ID() + "/apis/a;rev=3"
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/releases/r"+apiQuery, `{"customRoot":{"retained":true},"properties":{"apiId":"`+targetRevision3+`","notes":"Release 3","customMetadata":{"keep":"one","remove":"old"}}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodHead, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusOK)
	releases := request(t, handler, http.MethodGet, basePath+"/apis/a/releases"+apiQuery, "")
	if !strings.Contains(releases.Body.String(), `"count":1`) || !strings.Contains(releases.Body.String(), `"notes":"Release 3"`) {
		t.Fatalf("API releases = %s", releases.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/releases/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/releases/r"+apiQuery, `{`, http.StatusBadRequest)
	targetRevision2 := serviceModel().ID() + "/apis/a;rev=2"
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/releases/r"+apiQuery, `{"properties":{"apiId":"`+targetRevision2+`","notes":null,"customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	release := request(t, handler, http.MethodGet, basePath+"/apis/a/releases/r"+apiQuery, "")
	if !strings.Contains(release.Body.String(), `"retained":true`) || !strings.Contains(release.Body.String(), `"keep":"one"`) || !strings.Contains(release.Body.String(), `"add":"two"`) || !strings.Contains(release.Body.String(), `"notes":""`) || strings.Contains(release.Body.String(), `"remove"`) {
		t.Fatalf("patched API release = %s", release.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/releases/r"+apiQuery, `{"properties":{"apiId":null}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/other"+apiQuery, `{"properties":{"displayName":"Other","path":"other","serviceUrl":"https://other"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/other/releases/r"+apiQuery, `{"properties":{"apiId":"`+targetRevision2+`"}}`, http.StatusConflict)
	revisions = request(t, handler, http.MethodGet, basePath+"/apis/a/revisions"+apiQuery, "")
	if !strings.Contains(revisions.Body.String(), `"apiRevision":"2","createdDateTime"`) || strings.Count(revisions.Body.String(), `"isCurrent":true`) != 1 {
		t.Fatalf("promoted API revisions = %s", revisions.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a;rev=4"+apiQuery, `{"properties":{"sourceApiId":"/missing","apiRevision":"4"}}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/policies/missing"+apiQuery, "", http.StatusNotFound)

	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/releases/r"+apiQuery, `{"properties":{"apiId":"`+targetRevision3+`"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","path":"a","serviceUrl":"https://backend"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/two"+apiQuery, `{"properties":{"displayName":"Two","method":"GET","urlTemplate":"/two"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{"properties":{"value":"<policies/>"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/operations/get"+apiQuery, "", http.StatusInternalServerError)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a"+apiQuery, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/operations/get"+apiQuery, "", http.StatusPreconditionFailed)
	assertRoutedStatus(t, handler, http.MethodDelete, basePath+"/apis/a/operations/get"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a"+apiQuery, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a"+apiQuery, "", http.StatusPreconditionFailed)
}

func TestAPIReleaseDocumentFallbacks(t *testing.T) {
	wire := apiReleaseWire(model.APIRelease{Name: "invalid", Document: map[string]any{"properties": "invalid"}})
	if _, ok := wire["properties"].(map[string]any); !ok {
		t.Fatalf("release wire properties = %#v", wire["properties"])
	}

	handler, st := testHandler(t)
	seedService(t, st)
	base, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	target := base
	target.Name, target.Revision = "legacy;rev=2", "2"
	target, err = st.CloneAPIRevision(base.ID(), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAPIRelease(model.APIRelease{APIID: base.ID(), Name: "release", TargetAPIID: target.ID()}); err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPatch, basePath+"/apis/legacy/releases/release"+apiQuery, `{"properties":{"notes":"hydrated"}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"notes":"hydrated"`) {
		t.Fatalf("legacy release PATCH = %d %s", response.Code, response.Body.String())
	}
}

func TestAPIDocumentHelpersAndLegacyPatch(t *testing.T) {
	document := map[string]any{"id": "supplied", "name": "supplied", "type": "supplied", "etag": "supplied", "properties": map[string]any{"format": "openapi", "value": "source", "sourceApiId": "/source"}}
	cleanAPIDocument(document)
	if len(document) != 1 || len(document["properties"].(map[string]any)) != 0 {
		t.Fatalf("clean API document = %#v", document)
	}
	cleanAPIDocument(map[string]any{})
	api := model.API{RevisionDescription: "description", Version: "v1", VersionSetID: "/set"}
	clearNullAPIProperties(&api, map[string]any{"properties": map[string]any{"apiRevisionDescription": nil, "apiVersion": nil, "apiVersionSetId": nil}})
	if api.RevisionDescription != "" || api.Version != "" || api.VersionSetID != "" {
		t.Fatalf("null API properties = %+v", api)
	}
	wired := apiWire(model.API{ServiceID: "/service", Name: "api", Document: map[string]any{"properties": "invalid"}})
	if _, ok := wired["properties"].(map[string]any); !ok {
		t.Fatalf("API wire properties = %#v", wired)
	}

	handler, st := testHandler(t)
	seedService(t, st)
	if _, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "legacy", DisplayName: "Legacy", Path: "legacy", ServiceURL: "https://legacy"}); err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPatch, basePath+"/apis/legacy"+apiQuery, `{"properties":{"displayName":"Patched"},"custom":true}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"custom":true`) {
		t.Fatalf("legacy API patch = %d: %s", response.Code, response.Body.String())
	}
	replaced := request(t, handler, http.MethodPut, basePath+"/apis/legacy"+apiQuery, `{"properties":{"displayName":"Replaced","path":"legacy","serviceUrl":"https://legacy"}}`)
	if replaced.Code != http.StatusOK || strings.Contains(replaced.Body.String(), `"custom"`) {
		t.Fatalf("API PUT replacement = %d: %s", replaced.Code, replaced.Body.String())
	}
}

func TestOperationDocumentFallbacks(t *testing.T) {
	wired := operationWire(model.Operation{APIID: "/api", Name: "operation", Document: map[string]any{"properties": "invalid"}})
	if _, ok := wired["properties"].(map[string]any); !ok {
		t.Fatalf("operation wire properties = %#v", wired)
	}
	handler, st := testHandler(t)
	seedService(t, st)
	api, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "api", DisplayName: "API", ServiceURL: "https://backend"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "legacy", DisplayName: "Legacy", Method: "GET", URLTemplate: "/legacy"}); err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPatch, basePath+"/apis/api/operations/legacy"+apiQuery, `{"properties":{"description":"retained"}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"description":"retained"`) {
		t.Fatalf("legacy operation patch = %d: %s", response.Code, response.Body.String())
	}
}

func TestOpenAPIImportExportAndLinkedImport(t *testing.T) {
	linked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/definition":
			_, _ = w.Write([]byte("openapi: 3.0.3\ninfo:\n  title: Linked API\nservers:\n  - url: https://linked.example.test\npaths:\n  /linked:\n    post:\n      operationId: postLinked\n"))
		case "/large":
			_, _ = w.Write([]byte(strings.Repeat("x", maxImportBytes+1)))
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer linked.Close()
	handler, st := testHandler(t)
	handler.ImportClient = linked.Client()
	seedService(t, st)
	definition := `{"openapi":"3.1.0","info":{"title":"Imported API"},"servers":[{"url":"https://backend.example.test/v1"}],"paths":{"/items":{"get":{"operationId":"listItems","summary":"List items"},"post":{}}},"components":{"schemas":{"Item":{"type":"object"}}}}`
	body, _ := json.Marshal(map[string]any{"properties": map[string]any{"path": "imported", "format": "openapi+json", "value": definition, "subscriptionRequired": false}})
	path := basePath + "/apis/imported" + apiQuery
	assertStatus(t, handler, http.MethodPut, path, string(body), http.StatusCreated)
	api, err := st.GetAPI(serviceModel().ID() + "/apis/imported")
	if err != nil || api.DisplayName != "Imported API" || api.ServiceURL != "https://backend.example.test/v1" || len(api.Protocols) != 1 || api.Protocols[0] != "https" {
		t.Fatalf("imported API = %+v, %v", api, err)
	}
	operations, err := st.ListOperations(api.ID())
	if err != nil || len(operations) != 2 || operations[0].Name != "listItems" || operations[1].Name != "post-items" {
		t.Fatalf("imported operations = %+v, %v", operations, err)
	}
	schemas, err := st.ListAPISchemas(api.ID())
	if err != nil || len(schemas) != 1 || schemas[0].Name != "openapi" || schemas[0].Document["components"] == nil {
		t.Fatalf("imported schemas = %+v, %v", schemas, err)
	}
	if _, _, _, err := handler.renderAPIExport(api, "openapi+json-link"); err != nil {
		t.Fatal(err)
	}
	retained, err := st.GetAPIDefinition(strings.ToUpper(api.ID()))
	if err != nil || retained.Value != definition || retained.SourceURL != "" {
		t.Fatalf("retained definition = %+v, %v", retained, err)
	}

	linkedBody, _ := json.Marshal(map[string]any{"properties": map[string]any{"path": "imported", "format": "openapi-link", "value": linked.URL + "/definition", "subscriptionRequired": false}})
	assertStatus(t, handler, http.MethodPut, path, string(linkedBody), http.StatusOK)
	operations, _ = st.ListOperations(api.ID())
	retained, _ = st.GetAPIDefinition(api.ID())
	if len(operations) != 1 || operations[0].Name != "postLinked" || retained.SourceURL != linked.URL+"/definition" {
		t.Fatalf("linked import = %+v, %+v", operations, retained)
	}
	if _, err := st.UpsertAPISchema(model.APISchema{APIID: api.ID(), Name: "other", ContentType: "application/json", Document: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAPISchema(model.APISchema{APIID: api.ID(), Name: "openapi", ContentType: "application/json", Document: map[string]any{"definitions": map[string]any{"Linked": map[string]any{"type": "object"}}}}); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"openapi-link", "openapi+json-link", "swagger-link"} {
		exportPath := basePath + "/apis/imported?format=" + url.QueryEscape(format) + "&export=true&api-version=2024-05-01"
		recorder := request(t, handler, http.MethodGet, exportPath, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("export %s = %d %s", format, recorder.Code, recorder.Body.String())
		}
		var result struct {
			Format string `json:"format"`
			Value  struct {
				Link string `json:"link"`
			} `json:"value"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil || result.Format == "" || result.Value.Link == "" {
			t.Fatalf("export result = %+v, %v", result, err)
		}
		download := httptest.NewRecorder()
		handler.ServeHTTP(download, httptest.NewRequest(http.MethodGet, result.Value.Link, nil))
		if download.Code != http.StatusOK || download.Header().Get("Content-Type") == "" || !strings.Contains(download.Body.String(), "postLinked") {
			t.Fatalf("download %s = %d %s", format, download.Code, download.Body.String())
		}
		if format == "openapi-link" {
			st.Clock.Advance(301)
			expired := httptest.NewRecorder()
			handler.ServeHTTP(expired, httptest.NewRequest(http.MethodGet, result.Value.Link, nil))
			if expired.Code != http.StatusGone {
				t.Fatalf("expired export = %d %s", expired.Code, expired.Body.String())
			}
			st.Clock.Advance(-301)
		}
	}
	swagger := `{"swagger":"2.0","info":{"title":"Swagger API"},"host":"swagger.example.test","basePath":"/v2","paths":{},"definitions":{"Pet":{"type":"object"}}}`
	swaggerBody, _ := json.Marshal(map[string]any{"properties": map[string]any{"path": "swagger", "format": "swagger-json", "value": swagger}})
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/swagger"+apiQuery, string(swaggerBody), http.StatusCreated)
	if values, err := st.ListAPISchemas(serviceModel().ID() + "/apis/swagger"); err != nil || len(values) != 1 || values[0].ContentType != "application/vnd.ms-azure-apim.swagger.definitions+json" || values[0].Document["definitions"] == nil {
		t.Fatalf("Swagger schema = %+v, %v", values, err)
	}

	assertStatus(t, handler, http.MethodPut, basePath+"/apis/bad"+apiQuery, `{"properties":{"path":"bad","format":"unknown","value":"x"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/bad"+apiQuery, `{"properties":{"path":"bad","format":"openapi+json"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"format":"openapi+json","value":"{}"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/bad"+apiQuery, `{"properties":{"path":"bad","format":"openapi+json","value":"{}"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/bad"+apiQuery, `{"properties":{"path":"bad","format":"openapi-link","value":"relative"}}`, http.StatusBadRequest)
	badStatus, _ := json.Marshal(map[string]any{"properties": map[string]any{"path": "bad", "format": "openapi-link", "value": linked.URL + "/missing"}})
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/bad"+apiQuery, string(badStatus), http.StatusBadRequest)
	tooLarge, _ := json.Marshal(map[string]any{"properties": map[string]any{"path": "bad", "format": "openapi-link", "value": linked.URL + "/large"}})
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/bad"+apiQuery, string(tooLarge), http.StatusBadRequest)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/imported?format=wsdl-link&export=true&api-version=2024-05-01", "", http.StatusBadRequest)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/missing?format=openapi-link&export=true&api-version=2024-05-01", "", http.StatusNotFound)

	invalidDownload := httptest.NewRecorder()
	handler.ServeHTTP(invalidDownload, httptest.NewRequest(http.MethodGet, basePath+"/apis/imported?export=download&api-version=2024-05-01", nil))
	if invalidDownload.Code != http.StatusForbidden {
		t.Fatalf("invalid export signature = %d", invalidDownload.Code)
	}
	missingDownload := httptest.NewRecorder()
	handler.ServeHTTP(missingDownload, httptest.NewRequest(http.MethodGet, basePath+"/not-an-api?export=download&api-version=2024-05-01", nil))
	if missingDownload.Code != http.StatusNotFound {
		t.Fatalf("invalid export route = %d", missingDownload.Code)
	}
}

func TestLinkedImportBlocksMetadataSSRF(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	request := httptest.NewRequest(http.MethodPut, basePath+"/apis/a"+apiQuery, nil)

	reached := false
	handler.ImportClient = &http.Client{Transport: testRoundTripFunc(func(*http.Request) (*http.Response, error) {
		reached = true
		return nil, errors.New("import request must not escape the guard")
	})}
	for _, blocked := range []string{
		"http://169.254.169.254/latest/meta-data/", // cloud metadata (IPv4 link-local)
		"http://[fe80::1]/openapi",                 // IPv6 link-local
		"http://0.0.0.0/openapi",                   // unspecified
	} {
		if _, _, err := handler.resolveImport(request, "openapi-link", blocked); err == nil {
			t.Errorf("SSRF guard allowed blocked host %q", blocked)
		}
	}
	if reached {
		t.Fatal("a blocked import reached the network — the guard runs before the fetch")
	}

	// A loopback backend — the normal local-development case — stays allowed.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"A"},"paths":{}}`))
	}))
	defer server.Close()
	handler.ImportClient = server.Client()
	if _, _, err := handler.resolveImport(request, "openapi-link", server.URL); err != nil {
		t.Fatalf("loopback import should be allowed: %v", err)
	}
}

func TestImportAddressBlocked(t *testing.T) {
	cases := map[string]bool{
		"169.254.169.254": true,  // cloud metadata (IPv4 link-local)
		"169.254.1.1":     true,  // link-local
		"fe80::1":         true,  // IPv6 link-local
		"224.0.0.1":       true,  // multicast
		"0.0.0.0":         true,  // unspecified
		"127.0.0.1":       false, // loopback — allowed (local dev)
		"10.0.0.5":        false, // private — allowed
		"93.184.216.34":   false, // public — allowed
	}
	for ip, want := range cases {
		if got := importAddressBlocked(net.ParseIP(ip)); got != want {
			t.Errorf("importAddressBlocked(%s) = %v, want %v", ip, got, want)
		}
	}
}

// TestImportClientDialerBlocksMetadata verifies the connect-time guard: even if
// guardImportHost is bypassed (e.g. DNS rebinding resolving to a blocked IP
// after the pre-check), the dialer's Control hook refuses the connection.
func TestImportClientDialerBlocksMetadata(t *testing.T) {
	client := newImportClient()
	if _, err := client.Get("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Fatal("import client dialed the cloud-metadata address; connect-time guard failed")
	}

	// Loopback (the normal local-dev backend) still connects.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	resp, err := newImportClient().Get(server.URL)
	if err != nil {
		t.Fatalf("import client should reach a loopback backend: %v", err)
	}
	_ = resp.Body.Close()
}

func TestOpenAPIImportTransportAndExportFailures(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	request := httptest.NewRequest(http.MethodPut, basePath+"/apis/a"+apiQuery, nil)
	if _, _, err := handler.resolveImport(request, "openapi+json", strings.Repeat("x", maxImportBytes+1)); err == nil {
		t.Fatal("oversized inline import succeeded")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"A"},"paths":{}}`))
	}))
	defer server.Close()
	if source, sourceURL, err := handler.resolveImport(request, "openapi+json-link", server.URL); err != nil || source == "" || sourceURL != server.URL {
		t.Fatalf("default import client = %q, %q, %v", source, sourceURL, err)
	}
	handler.ImportClient = &http.Client{Transport: testRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("transport failed") })}
	if _, _, err := handler.resolveImport(request, "openapi-link", "https://example.test/openapi"); err == nil {
		t.Fatal("transport failure accepted")
	}
	handler.ImportClient = &http.Client{Transport: testRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingReadCloser{}, Header: make(http.Header)}, nil
	})}
	if _, _, err := handler.resolveImport(request, "openapi-link", "https://example.test/openapi"); err == nil {
		t.Fatal("read failure accepted")
	}
	api, _ := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "a", DisplayName: "A", ServiceURL: "https://backend"})
	expires := st.Clock.Now() + 300
	signedDownload := func(name, format string) string {
		id := serviceModel().ID() + "/apis/" + name
		return basePath + "/apis/" + name + "?api-version=2024-05-01&export=download&format=" + url.QueryEscape(format) + "&expires=" + fmt.Sprint(expires) + "&sig=" + url.QueryEscape(handler.exportSignature(id, format, expires))
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, signedDownload("missing", "openapi-link"), nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing signed export = %d %s", missing.Code, missing.Body.String())
	}
	unsupported := httptest.NewRecorder()
	handler.ServeHTTP(unsupported, httptest.NewRequest(http.MethodGet, signedDownload("a", "wsdl-link"), nil))
	if unsupported.Code != http.StatusBadRequest {
		t.Fatalf("unsupported signed export = %d %s", unsupported.Code, unsupported.Body.String())
	}

	dir := t.TempDir()
	broken, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	brokenService, _ := broken.UpsertService(serviceModel())
	brokenAPI, _ := broken.UpsertAPI(model.API{ServiceID: brokenService.ID(), Name: "a"})
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE api_schemas`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := (&Handler{Store: broken}).renderAPIExport(brokenAPI, "openapi-link"); err == nil {
		t.Fatal("missing schema table export succeeded")
	}
	if err := broken.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := (&Handler{Store: broken}).renderAPIExport(api, "openapi-link"); err == nil {
		t.Fatal("closed store export succeeded")
	}
}

func TestProductAndSubscriptionBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	_, _ = st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "a", DisplayName: "A", Path: "a", ServiceURL: "https://backend"})

	assertStatus(t, handler, http.MethodGet, basePath+"/products"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/products"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/missing"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/invalid"+apiQuery, `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P","state":"notPublished","approvalRequired":true,"description":"Original","terms":"Accept these terms","subscriptionRequired":false,"subscriptionsLimit":2}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/products/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/products/p"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"Updated","state":"published","approvalRequired":false,"description":null,"terms":"Updated terms"}}`, http.StatusOK)
	productGet := request(t, handler, http.MethodGet, basePath+"/products/p"+apiQuery, "")
	if !strings.Contains(productGet.Body.String(), `"terms":"Updated terms"`) || !strings.Contains(productGet.Body.String(), `"subscriptionsLimit":2`) || !strings.Contains(productGet.Body.String(), `"subscriptionRequired":false`) || strings.Contains(productGet.Body.String(), `"description"`) {
		t.Fatalf("lossless product patch = %s", productGet.Body.String())
	}
	list := request(t, handler, http.MethodGet, basePath+"/products"+apiQuery, "")
	if strings.Count(list.Body.String(), `"type":"Microsoft.ApiManagement/service/products"`) != 1 || !strings.Contains(list.Body.String(), `"displayName":"Updated"`) {
		t.Fatalf("product list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/products/p"+apiQuery, `{}`, http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p/apis"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/products/p/apis"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusCreated)
	list = request(t, handler, http.MethodGet, basePath+"/products/p/apis"+apiQuery, "")
	if strings.Count(list.Body.String(), `"type":"Microsoft.ApiManagement/service/apis"`) != 1 {
		t.Fatalf("product API list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p/unknown"+apiQuery, "", http.StatusNotFound)

	assertStatus(t, handler, http.MethodGet, basePath+"/subscriptions"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/subscriptions/s"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/invalid"+apiQuery, `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"primaryKey":"root-primary","secondaryKey":"root-secondary","customRoot":{"retained":true},"properties":{"displayName":"S","scope":"`+serviceModel().ID()+`","primaryKey":"initial-primary","secondaryKey":"initial-secondary","customMetadata":{"keep":"one","remove":"old"}}}`, http.StatusCreated)
	storedSubscription, err := st.GetSubscription(model.Subscription{ServiceID: serviceModel().ID(), Name: "s"}.ID())
	if err != nil {
		t.Fatal(err)
	}
	storedSubscriptionProperties := storedSubscription.Document["properties"].(map[string]any)
	if storedSubscription.Document["primaryKey"] != nil || storedSubscription.Document["secondaryKey"] != nil || storedSubscriptionProperties["primaryKey"] != nil || storedSubscriptionProperties["secondaryKey"] != nil || storedSubscriptionProperties["customMetadata"] == nil {
		t.Fatalf("stored subscription document = %#v", storedSubscription.Document)
	}
	got := request(t, handler, http.MethodGet, basePath+"/subscriptions/s"+apiQuery, "")
	if strings.Contains(got.Body.String(), "primaryKey") || got.Header().Get("ETag") == "" {
		t.Fatalf("subscription GET leaked secrets or omitted ETag: %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"customRoot":{"retained":true},"properties":{"displayName":"S","scope":"`+serviceModel().ID()+`","state":"suspended","primaryKey":"primary","secondaryKey":"secondary","customMetadata":{"keep":"one","remove":"old"}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/subscriptions/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/subscriptions/s"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"Updated","scope":"`+serviceModel().ID()+`/apis/a","state":null,"primaryKey":"primary","secondaryKey":"secondary","customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	for _, field := range []string{"displayName", "scope"} {
		assertStatus(t, handler, http.MethodPatch, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"`+field+`":null}}`, http.StatusBadRequest)
	}
	got = request(t, handler, http.MethodGet, basePath+"/subscriptions/s"+apiQuery, "")
	if !strings.Contains(got.Body.String(), `"displayName":"Updated"`) || !strings.Contains(got.Body.String(), `"state":"active"`) || !strings.Contains(got.Body.String(), `"retained":true`) || !strings.Contains(got.Body.String(), `"keep":"one"`) || !strings.Contains(got.Body.String(), `"add":"two"`) || strings.Contains(got.Body.String(), "primaryKey") || strings.Contains(got.Body.String(), "secondaryKey") || strings.Contains(got.Body.String(), `"remove"`) {
		t.Fatalf("canonical subscription GET = %s", got.Body.String())
	}
	list = request(t, handler, http.MethodGet, basePath+"/subscriptions"+apiQuery, "")
	if strings.Count(list.Body.String(), `"type":"Microsoft.ApiManagement/service/subscriptions"`) != 1 || strings.Contains(list.Body.String(), "primaryKey") {
		t.Fatalf("subscription list = %s", list.Body.String())
	}
	secretsBefore := request(t, handler, http.MethodPost, basePath+"/subscriptions/s/listSecrets"+apiQuery, "")
	var before map[string]any
	if err := json.Unmarshal(secretsBefore.Body.Bytes(), &before); err != nil || before["primaryKey"] != "primary" || before["secondaryKey"] != "secondary" {
		t.Fatalf("subscription secrets = %#v, %v", before, err)
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/s/regeneratePrimaryKey"+apiQuery, "", http.StatusNoContent)
	secretsAfterPrimary := request(t, handler, http.MethodPost, basePath+"/subscriptions/s/listSecrets"+apiQuery, "")
	var afterPrimary map[string]any
	if err := json.Unmarshal(secretsAfterPrimary.Body.Bytes(), &afterPrimary); err != nil || afterPrimary["primaryKey"] == "primary" || afterPrimary["secondaryKey"] != "secondary" {
		t.Fatalf("primary regeneration = %#v, %v", afterPrimary, err)
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/s/regenerateSecondaryKey"+apiQuery, "", http.StatusNoContent)
	secretsAfterSecondary := request(t, handler, http.MethodPost, basePath+"/subscriptions/s/listSecrets"+apiQuery, "")
	var afterSecondary map[string]any
	if err := json.Unmarshal(secretsAfterSecondary.Body.Bytes(), &afterSecondary); err != nil || afterSecondary["primaryKey"] != afterPrimary["primaryKey"] || afterSecondary["secondaryKey"] == "secondary" {
		t.Fatalf("secondary regeneration = %#v, %v", afterSecondary, err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/subscriptions/s/listSecrets"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/s/unknown"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/missing/listSecrets"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/missing/regeneratePrimaryKey"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/s"+apiQuery, "", http.StatusMethodNotAllowed)

	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p/apis/a"+apiQuery, "", http.StatusInternalServerError)
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p"+apiQuery, "", http.StatusInternalServerError)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"S","scope":"`+serviceModel().ID()+`"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/s/regeneratePrimaryKey"+apiQuery, "", http.StatusInternalServerError)
	assertStatus(t, handler, http.MethodDelete, basePath+"/subscriptions/s"+apiQuery, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p/apis/a"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p"+apiQuery, "", http.StatusPreconditionFailed)
	assertRoutedStatus(t, handler, http.MethodDelete, basePath+"/products/p"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p"+apiQuery, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodDelete, basePath+"/subscriptions/s"+apiQuery, "", http.StatusPreconditionFailed)
	assertRoutedStatus(t, handler, http.MethodDelete, basePath+"/subscriptions/s"+apiQuery, "", http.StatusNoContent)

	secrets := subscriptionWire(model.Subscription{ServiceID: serviceModel().ID(), Name: "s", PrimaryKey: "one", SecondaryKey: "two"}, true)
	properties := secrets["properties"].(map[string]any)
	if properties["primaryKey"] != "one" || properties["secondaryKey"] != "two" {
		t.Fatalf("subscription secrets = %v", properties)
	}
}

func TestSubscriptionDocumentFallbacks(t *testing.T) {
	wire := subscriptionWire(model.Subscription{Name: "invalid", Document: map[string]any{"properties": "invalid", "primaryKey": "secret"}}, false)
	if _, ok := wire["properties"].(map[string]any); !ok || wire["primaryKey"] != nil {
		t.Fatalf("subscription wire = %#v", wire)
	}

	handler, st := testHandler(t)
	seedService(t, st)
	subscription := model.Subscription{ServiceID: serviceModel().ID(), Name: "legacy", DisplayName: "Legacy", Scope: serviceModel().ID()}
	if _, err := st.UpsertSubscription(subscription); err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPatch, basePath+"/subscriptions/legacy"+apiQuery, `{"properties":{"customMetadata":{"hydrated":true}}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"hydrated":true`) {
		t.Fatalf("legacy subscription PATCH = %d %s", response.Code, response.Body.String())
	}
}

func TestProductDocumentFallbacks(t *testing.T) {
	wired := productWire(model.Product{ServiceID: "/service", Name: "product", Document: map[string]any{"properties": "invalid"}})
	properties, ok := wired["properties"].(map[string]any)
	if !ok || properties["subscriptionRequired"] != true {
		t.Fatalf("product wire = %#v", wired)
	}
	handler, st := testHandler(t)
	seedService(t, st)
	product, err := st.UpsertProduct(model.Product{ServiceID: serviceModel().ID(), Name: "legacy", DisplayName: "Legacy"})
	if err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPatch, basePath+"/products/legacy"+apiQuery, `{"properties":{"description":"retained"}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"description":"retained"`) {
		t.Fatalf("legacy product patch = %d: %s (%+v)", response.Code, response.Body.String(), product)
	}
}

func TestTagAndResourceAssociationBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	api, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "a", DisplayName: "A", Path: "a", ServiceURL: "https://backend"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: "GET", URLTemplate: "/"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertProduct(model.Product{ServiceID: serviceModel().ID(), Name: "p", DisplayName: "P"}); err != nil {
		t.Fatal(err)
	}

	tagPath := basePath + "/tags/public" + apiQuery
	assertStatus(t, handler, http.MethodGet, basePath+"/tags"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/tags"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, tagPath, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, tagPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, tagPath, `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, tagPath, `{"properties":{"displayName":"  "}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, tagPath, `{"properties":{"displayName":"Public"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, tagPath, `{"customRoot":{"retained":true},"properties":{"displayName":"Public API","customMetadata":{"keep":"one","remove":"old"}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/tags/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, tagPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, tagPath, `{"properties":{"displayName":"Updated","customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	got := request(t, handler, http.MethodGet, tagPath, "")
	if !strings.Contains(got.Body.String(), `"displayName":"Updated"`) || !strings.Contains(got.Body.String(), `"retained":true`) || !strings.Contains(got.Body.String(), `"add":"two"`) || strings.Contains(got.Body.String(), `"remove"`) || got.Header().Get("ETag") == "" {
		t.Fatalf("tag GET = %d %s", got.Code, got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, tagPath, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, basePath+"/tags"+apiQuery, "")
	if !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), `"name":"public"`) {
		t.Fatalf("tag list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, tagPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/tags/public/unknown"+apiQuery, "", http.StatusNotFound)

	associationPaths := []string{
		basePath + "/apis/a/tags/public" + apiQuery,
		basePath + "/apis/a/operations/get/tags/public" + apiQuery,
		basePath + "/products/p/tags/public" + apiQuery,
	}
	collectionPaths := []string{
		basePath + "/apis/a/tags" + apiQuery,
		basePath + "/apis/a/operations/get/tags" + apiQuery,
		basePath + "/products/p/tags" + apiQuery,
	}
	for i, path := range associationPaths {
		assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
		assertStatus(t, handler, http.MethodPut, path, `{}`, http.StatusCreated)
		assertStatus(t, handler, http.MethodPut, path, `{}`, http.StatusOK)
		assertStatus(t, handler, http.MethodGet, path, "", http.StatusOK)
		assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
		collection := request(t, handler, http.MethodGet, collectionPaths[i], "")
		if !strings.Contains(collection.Body.String(), `"count":1`) || !strings.Contains(collection.Body.String(), `"retained":true`) {
			t.Fatalf("association list %s = %s", collectionPaths[i], collection.Body.String())
		}
		assertStatus(t, handler, http.MethodPost, collectionPaths[i], "", http.StatusMethodNotAllowed)
		assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	}
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/tags/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/missing/tags"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/operations/missing/tags"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/missing/tags"+apiQuery, "", http.StatusNotFound)

	for _, path := range associationPaths {
		assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
		assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	}
	assertStatus(t, handler, http.MethodDelete, tagPath, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, tagPath, "", http.StatusPreconditionFailed)
}

func TestTagDocumentFallbacks(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	tag := model.Tag{ServiceID: serviceModel().ID(), Name: "legacy", DisplayName: "Legacy"}
	if _, err := st.UpsertTag(tag); err != nil {
		t.Fatal(err)
	}
	path := basePath + "/tags/legacy" + apiQuery
	response := request(t, handler, http.MethodPatch, path, `{"properties":{"customMetadata":{"hydrated":true}}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"hydrated":true`) {
		t.Fatalf("legacy tag PATCH = %d %s", response.Code, response.Body.String())
	}

	wire := tagWire(model.Tag{Name: "invalid", Document: map[string]any{"properties": "invalid"}})
	if _, ok := wire["properties"].(map[string]any); !ok {
		t.Fatalf("tag wire properties = %#v", wire["properties"])
	}
}

func TestGroupAndProductAssociationBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	if _, err := st.UpsertProduct(model.Product{ServiceID: serviceModel().ID(), Name: "p", DisplayName: "P"}); err != nil {
		t.Fatal(err)
	}
	collectionPath := basePath + "/groups" + apiQuery
	groupPath := basePath + "/groups/partners" + apiQuery
	list := request(t, handler, http.MethodGet, collectionPath, "")
	if !strings.Contains(list.Body.String(), `"count":3`) || strings.Count(list.Body.String(), `"builtIn":true`) != 3 {
		t.Fatalf("built-in group list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, collectionPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, groupPath, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, groupPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, groupPath, `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, groupPath, `{"properties":{"displayName":"Partners","type":"invalid"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, groupPath, `{"properties":{"displayName":"Partners","type":"system"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, groupPath, `{"properties":{"displayName":"Partners","type":"external"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, groupPath, `{"properties":{"displayName":"Partners","description":"Initial","type":"custom"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, groupPath, `{"customRoot":{"retained":true},"properties":{"displayName":"Partners","description":"Updated","type":"external","externalId":"aad://partners","customMetadata":{"keep":"one","remove":"old"}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/groups/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, groupPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, groupPath, `{"properties":{"displayName":"Updated Partners","description":null,"type":"custom","externalId":null,"customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	got := request(t, handler, http.MethodGet, groupPath, "")
	var group map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	properties := group["properties"].(map[string]any)
	metadata := properties["customMetadata"].(map[string]any)
	if properties["displayName"] != "Updated Partners" || properties["description"] != "" || properties["type"] != "custom" || properties["externalId"] != nil ||
		group["customRoot"].(map[string]any)["retained"] != true || metadata["keep"] != "one" || metadata["add"] != "two" || metadata["remove"] != nil || got.Header().Get("ETag") == "" {
		t.Fatalf("group GET = %d %s", got.Code, got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, groupPath, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, groupPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/groups/partners/unknown"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, basePath+"/groups/administrators"+apiQuery, "", http.StatusBadRequest)

	productCollection := basePath + "/products/p/groups" + apiQuery
	productGroup := basePath + "/products/p/groups/partners" + apiQuery
	assertStatus(t, handler, http.MethodGet, productCollection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, productCollection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, productGroup, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodHead, productGroup, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, productGroup, "", http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, productGroup, "", http.StatusOK)
	assertStatus(t, handler, http.MethodGet, productGroup, "", http.StatusOK)
	assertStatus(t, handler, http.MethodHead, productGroup, "", http.StatusNoContent)
	list = request(t, handler, http.MethodGet, productCollection, "")
	if !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), `"name":"partners"`) {
		t.Fatalf("product group list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, productGroup, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/missing/groups"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/groups/missing"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, productGroup, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, productGroup, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, groupPath, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, groupPath, "", http.StatusPreconditionFailed)
}

func TestGroupDocumentFallbacks(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	group := model.Group{ServiceID: serviceModel().ID(), Name: "legacy", DisplayName: "Legacy", Type: "custom"}
	if _, err := st.UpsertGroup(group); err != nil {
		t.Fatal(err)
	}
	path := basePath + "/groups/legacy" + apiQuery
	response := request(t, handler, http.MethodPatch, path, `{"properties":{"description":"hydrated"}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"description":"hydrated"`) {
		t.Fatalf("legacy group PATCH = %d %s", response.Code, response.Body.String())
	}

	wire := groupWire(model.Group{Name: "invalid", Document: map[string]any{"properties": "invalid"}})
	if _, ok := wire["properties"].(map[string]any); !ok {
		t.Fatalf("group wire properties = %#v", wire["properties"])
	}
}

func TestUserAndGroupMembershipBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	if _, err := st.UpsertGroup(model.Group{ServiceID: serviceModel().ID(), Name: "partners", DisplayName: "Partners", Type: "custom"}); err != nil {
		t.Fatal(err)
	}
	collectionPath := basePath + "/users" + apiQuery
	userPath := basePath + "/users/calvin" + apiQuery
	assertStatus(t, handler, http.MethodGet, collectionPath, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collectionPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, userPath, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, userPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, userPath, `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, userPath, `{"properties":{"firstName":"Calvin","lastName":"Cheng","email":"calvin@example.test","state":"invalid"}}`, http.StatusBadRequest)
	body := `{"password":"root-secret","customRoot":{"retained":true},"properties":{"firstName":"Calvin","lastName":"Cheng","email":"calvin@example.test","state":"active","password":"secret","primaryKey":"injected-primary","secondaryKey":"injected-secondary","note":"initial","identities":[{"provider":"Azure","id":"object"}],"customMetadata":{"keep":"one","remove":"old"}}}`
	assertStatus(t, handler, http.MethodPut, userPath, body, http.StatusCreated)
	stored, err := st.GetUser(model.User{ServiceID: serviceModel().ID(), Name: "calvin"}.ID())
	if err != nil {
		t.Fatal(err)
	}
	storedProperties := stored.Document["properties"].(map[string]any)
	if stored.Document["password"] != nil || storedProperties["password"] != nil || storedProperties["primaryKey"] != nil || storedProperties["secondaryKey"] != nil || storedProperties["customMetadata"] == nil {
		t.Fatalf("stored user document = %#v", stored.Document)
	}
	assertStatus(t, handler, http.MethodPut, userPath, body, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/users/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, userPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, userPath, `{"properties":{"firstName":"Updated","state":"blocked","customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	got := request(t, handler, http.MethodGet, userPath, "")
	if !strings.Contains(got.Body.String(), `"firstName":"Updated"`) || !strings.Contains(got.Body.String(), `"provider":"Azure"`) || !strings.Contains(got.Body.String(), `"retained":true`) || !strings.Contains(got.Body.String(), `"keep":"one"`) || !strings.Contains(got.Body.String(), `"add":"two"`) || strings.Contains(got.Body.String(), "secret") || strings.Contains(got.Body.String(), "primaryKey") || strings.Contains(got.Body.String(), "secondaryKey") || strings.Contains(got.Body.String(), `"remove"`) || got.Header().Get("ETag") == "" {
		t.Fatalf("user GET = %d %s", got.Code, got.Body.String())
	}
	for _, field := range []string{"firstName", "lastName", "email", "state"} {
		assertStatus(t, handler, http.MethodPatch, userPath, `{"properties":{"`+field+`":null}}`, http.StatusBadRequest)
	}
	assertStatus(t, handler, http.MethodPatch, userPath, `{"properties":{"note":null,"identities":null}}`, http.StatusOK)
	got = request(t, handler, http.MethodGet, userPath, "")
	if !strings.Contains(got.Body.String(), `"note":""`) || !strings.Contains(got.Body.String(), `"identities":[]`) || strings.Contains(got.Body.String(), `"provider":"Azure"`) {
		t.Fatalf("cleared user = %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, userPath, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, collectionPath, "")
	if !strings.Contains(list.Body.String(), `"count":1`) || strings.Contains(list.Body.String(), "secret") {
		t.Fatalf("user list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, userPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/users/calvin/unknown"+apiQuery, "", http.StatusNotFound)

	assertStatus(t, handler, http.MethodGet, basePath+"/users/calvin/groups"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/users/calvin/groups"+apiQuery, "", http.StatusMethodNotAllowed)
	groupUsers := basePath + "/groups/partners/users" + apiQuery
	membership := basePath + "/groups/partners/users/calvin" + apiQuery
	assertStatus(t, handler, http.MethodGet, groupUsers, "", http.StatusOK)
	assertStatus(t, handler, http.MethodGet, basePath+"/groups/missing/users"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, groupUsers, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodHead, membership, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, membership, "", http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, membership, "", http.StatusOK)
	assertStatus(t, handler, http.MethodHead, membership, "", http.StatusNoContent)
	if list := request(t, handler, http.MethodGet, groupUsers, ""); !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), `"retained":true`) || strings.Contains(list.Body.String(), "secret") {
		t.Fatalf("group users = %s", list.Body.String())
	}
	if list := request(t, handler, http.MethodGet, basePath+"/users/calvin/groups"+apiQuery, ""); !strings.Contains(list.Body.String(), `"count":1`) {
		t.Fatalf("user groups = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, membership, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, basePath+"/groups/partners/users/missing"+apiQuery, "", http.StatusNotFound)

	sso := request(t, handler, http.MethodPost, basePath+"/users/calvin/generateSsoUrl"+apiQuery, "")
	if sso.Code != http.StatusOK || !strings.Contains(sso.Body.String(), "signin-sso") {
		t.Fatalf("SSO URL = %d %s", sso.Code, sso.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/users/calvin/generateSsoUrl"+apiQuery, "", http.StatusMethodNotAllowed)
	tokenPath := basePath + "/users/calvin/token" + apiQuery
	assertStatus(t, handler, http.MethodPost, tokenPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, tokenPath, `{"properties":{"keyType":"invalid","expiry":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, tokenPath, `{"properties":{"keyType":"primary","expiry":"`+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)+`"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, tokenPath, `{"properties":{"keyType":"primary","expiry":"`+time.Now().Add(31*24*time.Hour).UTC().Format(time.RFC3339)+`"}}`, http.StatusBadRequest)
	token := request(t, handler, http.MethodPost, tokenPath, `{"properties":{"keyType":"secondary","expiry":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}}`)
	if token.Code != http.StatusOK || !strings.Contains(token.Body.String(), "SharedAccessSignature") || !strings.Contains(token.Body.String(), "skn=secondary") {
		t.Fatalf("user token = %d %s", token.Code, token.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, tokenPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodDelete, membership, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, membership, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, userPath, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, userPath, "", http.StatusPreconditionFailed)
}

func TestUserDocumentFallbacks(t *testing.T) {
	wire := userWire(model.User{Name: "invalid", Document: map[string]any{"properties": "invalid", "password": "secret"}})
	if _, ok := wire["properties"].(map[string]any); !ok || wire["password"] != nil {
		t.Fatalf("user wire = %#v", wire)
	}

	handler, st := testHandler(t)
	seedService(t, st)
	user := model.User{ServiceID: serviceModel().ID(), Name: "legacy", FirstName: "Legacy", LastName: "User", Email: "legacy@example.test", State: "active"}
	if _, err := st.UpsertUser(user); err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPatch, basePath+"/users/legacy"+apiQuery, `{"properties":{"note":"hydrated"}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"note":"hydrated"`) {
		t.Fatalf("legacy user PATCH = %d %s", response.Code, response.Body.String())
	}
}

func TestPolicyFragmentBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	api, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	collectionPath := basePath + "/policyFragments" + apiQuery
	fragmentPath := basePath + "/policyFragments/headers" + apiQuery
	assertStatus(t, handler, http.MethodGet, collectionPath, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collectionPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, fragmentPath, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, fragmentPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, fragmentPath, `{"properties":{"format":"invalid","value":"<fragment/>"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, fragmentPath, `{"properties":{"format":"rawxml","value":"<policies/>"}}`, http.StatusBadRequest)
	value := `<fragment><set-header name="X-Fragment"><value>yes</value></set-header></fragment>`
	assertStatus(t, handler, http.MethodPut, fragmentPath, `{"replaceMe":true,"properties":{"description":"Shared headers","format":"rawxml","value":"`+strings.ReplaceAll(value, `"`, `\"`)+`"}}`, http.StatusCreated)
	body := `{"customRoot":{"retained":true},"properties":{"description":"Shared headers","format":"rawxml","value":"` + strings.ReplaceAll(value, `"`, `\"`) + `","customMetadata":{"keep":"yes"}}}`
	assertStatus(t, handler, http.MethodPut, fragmentPath, body, http.StatusOK)
	got := request(t, handler, http.MethodGet, basePath+"/policyFragments/headers?api-version=2024-05-01&format=xml", "")
	if !strings.Contains(got.Body.String(), `"format":"xml"`) || !strings.Contains(got.Body.String(), `"provisioningState":"Succeeded"`) || !strings.Contains(got.Body.String(), `"retained":true`) || !strings.Contains(got.Body.String(), `"keep":"yes"`) || strings.Contains(got.Body.String(), `"replaceMe"`) || got.Header().Get("ETag") == "" {
		t.Fatalf("fragment GET = %d %s", got.Code, got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, fragmentPath, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, basePath+"/policyFragments?api-version=2024-05-01&format=rawxml", "")
	if !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), `"name":"headers"`) || !strings.Contains(list.Body.String(), `"retained":true`) {
		t.Fatalf("fragment list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, fragmentPath, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/policyFragments/headers/unknown"+apiQuery, "", http.StatusNotFound)
	refsPath := basePath + "/policyFragments/headers/references" + apiQuery
	assertStatus(t, handler, http.MethodGet, refsPath, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/policyFragments/headers/listReferences"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, refsPath, "", http.StatusMethodNotAllowed)
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound><include-fragment fragment-id="headers"/></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	refs := request(t, handler, http.MethodGet, refsPath, "")
	if !strings.Contains(refs.Body.String(), `"count":1`) || !strings.Contains(refs.Body.String(), api.ID()) {
		t.Fatalf("fragment refs = %s", refs.Body.String())
	}
	assertStatus(t, handler, http.MethodDelete, fragmentPath, "", http.StatusConflict)
	if err := st.DeleteAPI(api.ID()); err != nil {
		t.Fatal(err)
	}
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPut, fragmentPath, body, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, fragmentPath, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, fragmentPath, "", http.StatusPreconditionFailed)
	assertRoutedStatus(t, handler, http.MethodDelete, fragmentPath, "", http.StatusNoContent)
}

func TestPolicyFragmentDocumentFallback(t *testing.T) {
	wire := policyFragmentWire(model.PolicyFragment{Name: "invalid", Document: map[string]any{"properties": "invalid"}}, "invalid")
	properties, ok := wire["properties"].(map[string]any)
	if !ok || properties["format"] != "" {
		t.Fatalf("fragment wire = %#v", wire)
	}
}

func TestAPIVersionSetLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/apiVersionSets/versions" + apiQuery
	assertStatus(t, handler, http.MethodGet, basePath+"/apiVersionSets"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/apiVersionSets"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Versions","versioningScheme":"invalid"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Versions","versioningScheme":"Header"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Versions","versioningScheme":"Query"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Versions","versioningScheme":"Segment","description":"Segment versions"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, path, `{"customRoot":{"retained":true},"properties":{"displayName":"Versions","versioningScheme":"Header","versionHeaderName":"X-API-Version","versionQueryName":"version","description":"Header versions","customMetadata":{"keep":"one","remove":"old"}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apiVersionSets/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"displayName":"Updated","versioningScheme":"Query","versionQueryName":"api-version","versionHeaderName":null,"description":null,"customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	got := request(t, handler, http.MethodGet, path, "")
	var versionSet map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &versionSet); err != nil {
		t.Fatal(err)
	}
	properties := versionSet["properties"].(map[string]any)
	metadata := properties["customMetadata"].(map[string]any)
	if properties["displayName"] != "Updated" || properties["versioningScheme"] != "Query" || properties["versionHeaderName"] != "" || properties["description"] != "" ||
		versionSet["customRoot"].(map[string]any)["retained"] != true || metadata["keep"] != "one" || metadata["add"] != "two" || metadata["remove"] != nil {
		t.Fatalf("version-set GET = %d %s", got.Code, got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, basePath+"/apiVersionSets"+apiQuery, "")
	if !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), `"versioningScheme":"Query"`) {
		t.Fatalf("version-set list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/apiVersionSets/versions/unknown"+apiQuery, "", http.StatusNotFound)
	versionSetID := serviceModel().ID() + "/apiVersionSets/versions"
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/versioned"+apiQuery, `{"properties":{"displayName":"Versioned","path":"versioned","serviceUrl":"https://backend","apiVersion":"v1","apiVersionSetId":"`+versionSetID+`"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/version-only"+apiQuery, `{"properties":{"displayName":"Version","serviceUrl":"https://backend","apiVersion":"v1"}}`, http.StatusBadRequest)
	api := request(t, handler, http.MethodGet, basePath+"/apis/versioned"+apiQuery, "")
	if !strings.Contains(api.Body.String(), `"apiVersion":"v1"`) || !strings.Contains(api.Body.String(), `"apiVersionSetId":"`+versionSetID+`"`) {
		t.Fatalf("versioned API = %s", api.Body.String())
	}
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/bad-version"+apiQuery, `{"properties":{"displayName":"Bad","serviceUrl":"https://backend","apiVersion":"v1","apiVersionSetId":"/missing"}}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/versioned"+apiQuery, "", http.StatusNoContent)
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"description":"failed activation"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
	assertRoutedStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
}

func TestAPIVersionSetDocumentFallbacks(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	versionSet := model.APIVersionSet{ServiceID: serviceModel().ID(), Name: "legacy", DisplayName: "Legacy", VersioningScheme: "Segment"}
	if _, err := st.UpsertAPIVersionSet(versionSet); err != nil {
		t.Fatal(err)
	}
	path := basePath + "/apiVersionSets/legacy" + apiQuery
	response := request(t, handler, http.MethodPatch, path, `{"properties":{"description":"hydrated"}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"description":"hydrated"`) {
		t.Fatalf("legacy version-set PATCH = %d %s", response.Code, response.Body.String())
	}
	response = request(t, handler, http.MethodPatch, path, `{"properties":{"versionQueryName":null}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"versionQueryName":""`) {
		t.Fatalf("legacy version-set null query name = %d %s", response.Code, response.Body.String())
	}

	wire := apiVersionSetWire(model.APIVersionSet{Name: "invalid", Document: map[string]any{"properties": "invalid"}})
	if _, ok := wire["properties"].(map[string]any); !ok {
		t.Fatalf("version-set wire properties = %#v", wire["properties"])
	}
}

func TestNamedValueLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	collection := basePath + "/namedValues" + apiQuery
	path := basePath + "/namedValues/token" + apiQuery
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Token"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Invalid name","value":"value"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"value":"root-secret","customRoot":{"retained":true},"properties":{"displayName":"Token","value":"value","secret":true,"tags":["auth"],"customMetadata":{"keep":"one","remove":"old"}}}`, http.StatusCreated)
	for _, test := range []struct {
		filter string
		count  string
	}{
		{"tags/any(t: t eq 'auth')", `"count":1`},
		{"tags/all(t: t eq 'auth')", `"count":1`},
		{"tags/all(t: t ne 'auth')", `"count":0`},
	} {
		query := url.Values{"api-version": {"2024-05-01"}, "$filter": {test.filter}}
		response := request(t, handler, http.MethodGet, collection+"&"+query.Encode(), "")
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.count) {
			t.Fatalf("named-value tag filter %q = %d %s", test.filter, response.Code, response.Body.String())
		}
	}
	stored, err := st.GetNamedValue(model.NamedValue{ServiceID: serviceModel().ID(), Name: "token"}.ID())
	if err != nil {
		t.Fatal(err)
	}
	if stored.Document["value"] != nil || stored.Document["properties"].(map[string]any)["value"] != nil || stored.Document["properties"].(map[string]any)["customMetadata"] == nil {
		t.Fatalf("stored named-value document = %#v", stored.Document)
	}
	response := request(t, handler, http.MethodGet, path, "")
	if strings.Contains(response.Body.String(), `"value"`) || !strings.Contains(response.Body.String(), `"secret":true`) || !strings.Contains(response.Body.String(), `"retained":true`) {
		t.Fatalf("redacted named value = %s", response.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	secret := request(t, handler, http.MethodPost, basePath+"/namedValues/token/listValue"+apiQuery, "")
	if secret.Code != http.StatusOK || !strings.Contains(secret.Body.String(), `"value":"value"`) {
		t.Fatalf("listed named value = %d %s", secret.Code, secret.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/namedValues/token/listValue"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, basePath+"/namedValues/token/refreshSecret"+apiQuery, "", http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, basePath+"/namedValues/token/unknown"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/namedValues/missing/listValue"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/namedValues/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"displayName":"Updated","value":"new","secret":false,"tags":["one","two"],"keyVault":{"secretIdentifier":"https://vault/secrets/name","identityClientId":"client"},"customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"displayName":null}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"value":null,"tags":null,"secret":null,"keyVault":{"identityClientId":null}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"keyVault":{"secretIdentifier":null}}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"keyVault":null}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, basePath+"/namedValues/token/refreshSecret"+apiQuery, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, collection, "")
	var collectionDocument map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &collectionDocument); err != nil {
		t.Fatal(err)
	}
	listedProperties := collectionDocument["value"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	if collectionDocument["count"] != float64(1) || listedProperties["value"] != nil || !strings.Contains(list.Body.String(), `"secretIdentifier":"https://vault/secrets/name"`) || !strings.Contains(list.Body.String(), `"keep":"one"`) || !strings.Contains(list.Body.String(), `"add":"two"`) || strings.Contains(list.Body.String(), `"remove"`) {
		t.Fatalf("named value list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/namedValues/token/extra/path"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"value":"activation"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
}

func TestNamedValueTagFilterGrammar(t *testing.T) {
	contractRoute := route{Tail: []string{"namedValues"}}
	resource := map[string]any{"properties": map[string]any{"tags": []any{"auth", "gateway"}}}
	for _, test := range []struct {
		filter string
		want   bool
	}{
		{"tags/any(tag: contains(tag, 'way'))", true},
		{"tags/all(tag: startswith(tag, 'a'))", false},
		{"tags/all(tag: endswith(tag, 'way') or tag eq 'auth')", true},
		{"tags/any(tag: tag eq 'missing')", false},
	} {
		predicate, err := parseFilterForRoute(test.filter, contractRoute)
		if err != nil {
			t.Fatalf("parse tag filter %q: %v", test.filter, err)
		}
		got, err := predicate(resource)
		if err != nil || got != test.want {
			t.Fatalf("tag filter %q = %v, %v; want %v", test.filter, got, err, test.want)
		}
	}
	empty := map[string]any{"properties": map[string]any{"tags": []any{}}}
	for _, test := range []struct {
		filter string
		want   bool
	}{
		{"tags/any(tag: tag eq 'auth')", false},
		{"tags/all(tag: tag eq 'auth')", true},
	} {
		predicate, err := parseFilterForRoute(test.filter, contractRoute)
		if err != nil {
			t.Fatal(err)
		}
		got, err := predicate(empty)
		if err != nil || got != test.want {
			t.Fatalf("empty tag filter %q = %v, %v; want %v", test.filter, got, err, test.want)
		}
	}
	for _, resource := range []map[string]any{
		{"properties": map[string]any{"tags": []string{"auth"}}},
		{"properties": map[string]any{"tags": []any{float64(1)}}},
		{"properties": map[string]any{}},
	} {
		predicate, err := parseFilterForRoute("tags/any(tag: contains(tag, 'auth'))", contractRoute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := predicate(resource); err == nil && resource["properties"].(map[string]any)["tags"] == nil {
			t.Fatal("missing tags unexpectedly matched")
		}
	}
	if _, err := parseFilterWithContract("tags/any(tag: tag eq 'auth')", filterContract{"tags": comparisonRule("eq")}); err == nil {
		t.Fatal("unsupported any function accepted")
	}
	for _, filter := range []string{
		"tags/any(tag tag eq 'auth')",
		"tags/any(tag: tag eq 'auth'",
		"tags/any(: tag eq 'auth')",
		"tags/any(tag: 'auth' eq 'auth')",
		"tags/any(tag: tag eq 'auth' and)",
	} {
		if _, err := parseFilterForRoute(filter, contractRoute); err == nil {
			t.Fatalf("invalid tag filter %q accepted", filter)
		}
	}
}

func TestNamedValueDocumentFallbacks(t *testing.T) {
	wire := namedValueWire(model.NamedValue{Name: "invalid", Document: map[string]any{"properties": "invalid", "value": "secret"}})
	if _, ok := wire["properties"].(map[string]any); !ok || wire["value"] != nil {
		t.Fatalf("named-value wire = %#v", wire)
	}

	handler, st := testHandler(t)
	seedService(t, st)
	value := model.NamedValue{ServiceID: serviceModel().ID(), Name: "legacy", DisplayName: "Legacy", Value: "value"}
	if _, err := st.UpsertNamedValue(value); err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPatch, basePath+"/namedValues/legacy"+apiQuery, `{"properties":{"customMetadata":{"hydrated":true}}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"hydrated":true`) || strings.Contains(response.Body.String(), `"value"`) {
		t.Fatalf("legacy named-value PATCH = %d %s", response.Code, response.Body.String())
	}
}

func TestBackendLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	collection, path := basePath+"/backends"+apiQuery, basePath+"/backends/primary"+apiQuery
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"url":"relative","protocol":"invalid"}}`, http.StatusBadRequest)
	body := `{"customRoot":{"retained":true},"properties":{"title":"Primary","description":"Backend","url":"https://backend.test/base","protocol":"http","resourceId":"/external","credentials":{"header":{"X-Key":["secret"]}},"tls":{"validateCertificateChain":false},"customMetadata":{"keep":"one","remove":"old"}}}`
	assertStatus(t, handler, http.MethodPut, path, body, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	got := request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"X-Key":["secret"]`) || !strings.Contains(got.Body.String(), `"validateCertificateChain":false`) {
		t.Fatalf("lossless backend = %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/backends/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"title":null,"description":null,"resourceId":null,"credentials":{"header":{"X-Key":null}},"tls":{"validateCertificateName":false},"customMetadata":{"add":"two","remove":null}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"url":null}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"protocol":null}}`, http.StatusBadRequest)
	got = request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"title":""`) || !strings.Contains(got.Body.String(), `"description":""`) || !strings.Contains(got.Body.String(), `"resourceId":""`) || !strings.Contains(got.Body.String(), `"retained":true`) || !strings.Contains(got.Body.String(), `"keep":"one"`) || !strings.Contains(got.Body.String(), `"add":"two"`) || !strings.Contains(got.Body.String(), `"validateCertificateName":false`) || strings.Contains(got.Body.String(), `"X-Key"`) || strings.Contains(got.Body.String(), `"remove"`) {
		t.Fatalf("patched backend = %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/backends/primary/reconnect"+apiQuery, `{}`, http.StatusAccepted)
	assertStatus(t, handler, http.MethodGet, basePath+"/backends/primary/reconnect"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, basePath+"/backends/missing/reconnect"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/backends/primary/unknown"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/backends/primary/too/deep"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"title":"Activation"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
	if properties := backendWire(model.Backend{})["properties"].(map[string]any); properties["url"] != "" {
		t.Fatalf("empty backend wire = %v", properties)
	}
}

func TestBackendDocumentFallbacks(t *testing.T) {
	wire := backendWire(model.Backend{Name: "invalid", Document: map[string]any{"properties": "invalid"}})
	if _, ok := wire["properties"].(map[string]any); !ok {
		t.Fatalf("backend wire = %#v", wire)
	}

	handler, st := testHandler(t)
	seedService(t, st)
	backend := model.Backend{ServiceID: serviceModel().ID(), Name: "legacy", Title: "Legacy", URL: "https://backend.test", Protocol: "http"}
	if _, err := st.UpsertBackend(backend); err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPatch, basePath+"/backends/legacy"+apiQuery, `{"properties":{"description":"hydrated"}}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"description":"hydrated"`) {
		t.Fatalf("legacy backend PATCH = %d %s", response.Code, response.Body.String())
	}
}

func TestCertificateLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	collection, path := basePath+"/certificates"+apiQuery, basePath+"/certificates/client"+apiQuery
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"data":"not-base64"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"data":"aW52YWxpZA==","password":"wrong"}}`, http.StatusBadRequest)
	pfx := testPKCS12(t, "password")
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"data":"`+pfx+`","password":"wrong"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"data":"root-data","password":"root-password","customRoot":{"retained":true},"properties":{"data":"`+pfx+`","password":"password","subject":"injected","thumbprint":"injected","expirationDate":"2000-01-01T00:00:00Z","customMetadata":{"keep":"one"}}}`, http.StatusCreated)
	stored, err := st.GetCertificate(model.Certificate{ServiceID: serviceModel().ID(), Name: "client"}.ID())
	if err != nil {
		t.Fatal(err)
	}
	storedProperties := stored.Document["properties"].(map[string]any)
	if stored.Document["data"] != nil || stored.Document["password"] != nil || storedProperties["data"] != nil || storedProperties["password"] != nil || storedProperties["subject"] != nil || storedProperties["thumbprint"] != nil || storedProperties["expirationDate"] != nil || storedProperties["customMetadata"] == nil {
		t.Fatalf("stored certificate document = %#v", stored.Document)
	}
	got := request(t, handler, http.MethodGet, path, "")
	if strings.Contains(got.Body.String(), pfx) || strings.Contains(got.Body.String(), "root-password") || !strings.Contains(got.Body.String(), `"subject":"CN=client.test"`) || !strings.Contains(got.Body.String(), `"thumbprint":`) || !strings.Contains(got.Body.String(), `"retained":true`) || !strings.Contains(got.Body.String(), `"keep":"one"`) {
		t.Fatalf("certificate GET = %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/certificates/client/refreshSecret"+apiQuery, "", http.StatusBadRequest)
	assertStatus(t, handler, http.MethodGet, basePath+"/certificates/client/refreshSecret"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, basePath+"/certificates/missing/refreshSecret"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/certificates/client/unknown"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/certificates/client/too/deep"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	vaultPath := basePath + "/certificates/vault" + apiQuery
	assertStatus(t, handler, http.MethodPut, vaultPath, `{"customRoot":{"vault":true},"properties":{"keyVault":{"secretIdentifier":"https://vault/secrets/client","identityClientId":"identity"},"customMetadata":{"source":"vault"}}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, basePath+"/certificates/vault/refreshSecret"+apiQuery, "", http.StatusOK)
	vault := request(t, handler, http.MethodGet, vaultPath, "")
	if !strings.Contains(vault.Body.String(), `"secretIdentifier":"https://vault/secrets/client"`) || !strings.Contains(vault.Body.String(), `"identityClientId":"identity"`) || !strings.Contains(vault.Body.String(), `"vault":true`) || strings.Contains(vault.Body.String(), `"data"`) || strings.Contains(vault.Body.String(), `"password"`) {
		t.Fatalf("vault certificate = %s", vault.Body.String())
	}
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"data":"`+pfx+`","password":"password"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
}

func TestCertificateDocumentFallback(t *testing.T) {
	wire := certificateWire(model.Certificate{Name: "invalid", Document: map[string]any{"properties": "invalid", "data": "secret", "password": "secret"}})
	if _, ok := wire["properties"].(map[string]any); !ok || wire["data"] != nil || wire["password"] != nil {
		t.Fatalf("certificate wire = %#v", wire)
	}
}

func TestAPISchemaLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","serviceUrl":"https://backend"}}`, http.StatusCreated)
	collection, path := basePath+"/apis/a/schemas"+apiQuery, basePath+"/apis/a/schemas/payload"+apiQuery
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"contentType":"invalid"}}`, http.StatusBadRequest)
	body := `{"id":"malicious","name":"malicious","type":"malicious","customRoot":{"retained":true},"properties":{"contentType":"application/vnd.oai.openapi.components+json","document":{"components":{"schemas":{"Item":{"type":"object","properties":{"id":{"type":"string"}}}}}},"customMetadata":{"owner":"sdk"}}}`
	assertStatus(t, handler, http.MethodPut, path, body, http.StatusCreated)
	got := request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"customRoot":{"retained":true}`) || !strings.Contains(got.Body.String(), `"customMetadata":{"owner":"sdk"}`) || strings.Contains(got.Body.String(), `"id":"malicious"`) {
		t.Fatalf("schema GET = %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"contentType":"application/json","document":{"definitions":{"Item":{"type":"string"}}},"replacement":true}}`, http.StatusOK)
	got = request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"definitions":{"Item":{"type":"string"}}`) || !strings.Contains(got.Body.String(), `"replacement":true`) || strings.Contains(got.Body.String(), "customRoot") {
		t.Fatalf("replaced schema GET = %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, collection, "")
	if !strings.Contains(list.Body.String(), `"count":1`) {
		t.Fatalf("schema list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/schemas/payload/extra"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
}

func TestAPISchemaDocumentFallback(t *testing.T) {
	wire := apiSchemaWire(model.APISchema{APIID: "api", Name: "schema", ContentType: "application/json", Document: map[string]any{"type": "object"}, ARMDocument: map[string]any{"properties": "invalid"}})
	properties, ok := wire["properties"].(map[string]any)
	if !ok || properties["contentType"] != "application/json" || properties["document"] == nil {
		t.Fatalf("schema wire = %#v", wire)
	}
}

func testPKCS12(t *testing.T, password string) string {
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
	return base64.StdEncoding.EncodeToString(pfx)
}

func TestProductAPIListRejectsDanglingLink(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedService(t, st)
	product, err := st.UpsertProduct(model.Product{ServiceID: serviceModel().ID(), Name: "p", DisplayName: "P"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA foreign_keys=OFF; INSERT INTO product_apis (product_id, api_id) VALUES (?, ?)`, product.ID(), serviceModel().ID()+"/apis/missing"); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p/apis"+apiQuery, "", http.StatusNotFound)
}

func TestForeignKeyStoreErrors(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","serviceUrl":"https://backend"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"S","scope":"/scope"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apiVersionSets/v"+apiQuery, `{"properties":{"displayName":"V","versioningScheme":"Segment"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/namedValues/v"+apiQuery, `{"properties":{"displayName":"V","value":"value"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/backends/v"+apiQuery, `{"properties":{"url":"https://backend","protocol":"http"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/certificates/v"+apiQuery, `{"properties":{"keyVault":{"secretIdentifier":"https://vault/secret"}}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/schemas/s"+apiQuery, `{"properties":{"contentType":"application/json","document":{}}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"method":"GET","urlTemplate":"/"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/tags/t"+apiQuery, `{"properties":{"displayName":"T"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/groups/g"+apiQuery, `{"properties":{"displayName":"G"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/policyFragments/f"+apiQuery, `{"properties":{"value":"<fragment/>"}}`, http.StatusConflict)
}

func TestServiceDeleteActivationFailure(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodDelete, basePath+apiQuery, "", http.StatusInternalServerError)
}

func TestClosedStoreWriteErrors(t *testing.T) {
	handler, st := testHandler(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, `{"location":"local","properties":{"publisherName":"Local","publisherEmail":"local@example.test"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","serviceUrl":"https://backend"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"method":"GET","urlTemplate":"/"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{"properties":{"value":"<policies/>"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/policies/policy"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, "/subscriptions/sub/providers/Microsoft.ApiManagement/service"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/operations"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/revisions"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/releases"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/releases/r"+apiQuery, `{"properties":{"apiId":"/target"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/operations/get"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/products"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p/apis"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p/apis/a"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/subscriptions"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"S","scope":"scope"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/s/listSecrets"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPost, basePath+"/subscriptions/s/regeneratePrimaryKey"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/subscriptions/s"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apiVersionSets"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apiVersionSets/v"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apiVersionSets/v"+apiQuery, `{"properties":{"displayName":"V","versioningScheme":"Segment"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apiVersionSets/v"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/namedValues"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/namedValues/v"+apiQuery, `{"properties":{"displayName":"V","value":"value"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/namedValues/v"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/backends"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/backends/v"+apiQuery, `{"properties":{"url":"https://backend","protocol":"http"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/backends/v"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/certificates"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/certificates/v"+apiQuery, `{"properties":{"keyVault":{"secretIdentifier":"https://vault/secret"}}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/certificates/v"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/schemas"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/schemas/s"+apiQuery, `{"properties":{"contentType":"application/json","document":{}}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/schemas/s"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/tags"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/tags/t"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/tags/t"+apiQuery, `{"properties":{"displayName":"T"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/tags/t"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/tags/t"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/operations/get/tags/t"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p/tags/t"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/groups"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/groups/g"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/groups/g"+apiQuery, `{"properties":{"displayName":"G"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/groups/g"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p/groups"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p/groups/g"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/groups/g/users"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/users"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/users/u/groups"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPost, basePath+"/users/u/generateSsoUrl"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPost, basePath+"/users/u/token"+apiQuery, `{}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/users/u"+apiQuery, `{"properties":{"firstName":"U","lastName":"S","email":"u@example.test"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/users/u"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/policyFragments"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/policyFragments/f"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/policyFragments/f"+apiQuery, `{"properties":{"value":"<fragment/>"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/policyFragments/f/references"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+"/policyFragments/f"+apiQuery, "", http.StatusConflict)
}

func TestServiceStoreWriteErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedService(t, st)
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_service_update BEFORE UPDATE ON services BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	body := `{"location":"local","properties":{"publisherName":"Local","publisherEmail":"local@example.test"}}`
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, body, http.StatusConflict)
	assertStatus(t, handler, http.MethodPatch, basePath+apiQuery, `{}`, http.StatusConflict)
}

func TestTagStoreErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedService(t, st)
	api, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	tagPath := basePath + "/tags/t" + apiQuery
	associationPath := basePath + "/apis/a/tags/t" + apiQuery

	if _, err := db.Exec(`CREATE TRIGGER reject_tag_write BEFORE INSERT ON tags BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, tagPath, `{"properties":{"displayName":"T"}}`, http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_tag_write`); err != nil {
		t.Fatal(err)
	}
	tag, err := st.UpsertTag(model.Tag{ServiceID: serviceModel().ID(), Name: "t", DisplayName: "T"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_tag_delete BEFORE DELETE ON tags BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, tagPath, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_tag_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_tag_link BEFORE INSERT ON resource_tags BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, associationPath, `{}`, http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_tag_link`); err != nil {
		t.Fatal(err)
	}
	if err := st.AssignTag(api.ID(), tag.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE resource_tags`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/tags"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, associationPath, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, associationPath, `{}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, associationPath, "", http.StatusConflict)
}

func TestGroupStoreErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedService(t, st)
	product, err := st.UpsertProduct(model.Product{ServiceID: serviceModel().ID(), Name: "p", DisplayName: "P"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := st.UpsertGroup(model.Group{ServiceID: serviceModel().ID(), Name: "g", DisplayName: "G", Type: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	groupPath := basePath + "/groups/g" + apiQuery
	productGroupPath := basePath + "/products/p/groups/g" + apiQuery

	if _, err := db.Exec(`CREATE TRIGGER reject_group_delete BEFORE DELETE ON groups BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, groupPath, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_group_delete; CREATE TRIGGER reject_product_group_insert BEFORE INSERT ON product_groups BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, productGroupPath, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_product_group_insert`); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkProductGroup(product.ID(), group.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_product_group_delete BEFORE DELETE ON product_groups BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, productGroupPath, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_product_group_delete; DROP TABLE product_groups`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p/groups"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, productGroupPath, "", http.StatusConflict)
}

func TestUserStoreErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedService(t, st)
	group, err := st.UpsertGroup(model.Group{ServiceID: serviceModel().ID(), Name: "g", DisplayName: "G", Type: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.UpsertUser(model.User{ServiceID: serviceModel().ID(), Name: "u", FirstName: "U", LastName: "S", Email: "u@example.test", State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	userPath := basePath + "/users/u" + apiQuery
	membership := basePath + "/groups/g/users/u" + apiQuery
	if _, err := db.Exec(`CREATE TRIGGER reject_user_write BEFORE INSERT ON users BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, userPath, `{"properties":{"firstName":"U","lastName":"S","email":"u@example.test"}}`, http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_user_write; CREATE TRIGGER reject_user_delete BEFORE DELETE ON users BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, userPath, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_user_delete; CREATE TRIGGER reject_membership_insert BEFORE INSERT ON group_users BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, membership, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_membership_insert`); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkGroupUser(group.ID(), user.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_membership_delete BEFORE DELETE ON group_users BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, membership, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_membership_delete; DROP TABLE group_users`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/groups/g/users"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodHead, membership, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/users/u/groups"+apiQuery, "", http.StatusConflict)
}

func TestPolicyFragmentStoreErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedService(t, st)
	fragment, err := st.UpsertPolicyFragment(model.PolicyFragment{ServiceID: serviceModel().ID(), Name: "f", Value: `<fragment/>`})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	path := basePath + "/policyFragments/f" + apiQuery
	if _, err := db.Exec(`CREATE TRIGGER reject_fragment_write BEFORE INSERT ON policy_fragments BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"value":"<fragment/>"}}`, http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_fragment_write; CREATE TRIGGER reject_fragment_delete BEFORE DELETE ON policy_fragments BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_fragment_delete; DROP TABLE policies`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/policyFragments/f/references"+apiQuery, "", http.StatusConflict)
	if _, err := st.GetPolicyFragment(fragment.ID()); err != nil {
		t.Fatal(err)
	}
}

func TestAbsoluteAndOperationHelpers(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://host/path", nil)
	request.Host = "host.test"
	if got := absolute(request, "/next"); got != "https://host.test/next" {
		t.Fatalf("TLS absolute = %q", got)
	}
	request.Header.Set("X-Forwarded-Proto", "custom")
	if got := absolute(request, "/next"); got != "custom://host.test/next" {
		t.Fatalf("forwarded absolute = %q", got)
	}
	recorder := httptest.NewRecorder()
	OperationStatus(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Succeeded") {
		t.Fatalf("operation = %d %s", recorder.Code, recorder.Body.String())
	}
}

func testHandler(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &Handler{Store: st, Auth: auth.AllowAll{}}, st
}

func serviceModel() model.Service {
	return model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc", Location: "local", SKUName: "Developer", SKUCapacity: 1, PublisherName: "Local", PublisherEmail: "local@example.test"}
}

func seedService(t *testing.T, st *store.Store) {
	t.Helper()
	if _, err := st.UpsertService(serviceModel()); err != nil {
		t.Fatal(err)
	}
}

func request(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer token")
	setRequiredIfMatch(req)
	handler.ServeHTTP(recorder, req)
	return recorder
}

func conditionalRequest(t *testing.T, handler http.Handler, method, path, body, header, value string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set(header, value)
	handler.ServeHTTP(recorder, request)
	return recorder
}

func assertStatus(t *testing.T, handler http.Handler, method, path, body string, want int) {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	setRequiredIfMatch(request)
	recorder := httptest.NewRecorder()
	rt, parsed := parse(split(request.URL.Path))
	if armHandler, ok := handler.(*Handler); ok && parsed && requiresIfMatch(rt, method) && (want == http.StatusNotFound || want == http.StatusConflict) {
		armHandler.routeRequest(recorder, request, rt)
	} else {
		handler.ServeHTTP(recorder, request)
	}
	if recorder.Code != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, recorder.Code, want, recorder.Body.String())
	}
}

func assertRoutedStatus(t *testing.T, handler *Handler, method, path, body string, want int) {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	recorder := httptest.NewRecorder()
	rt, ok := parse(split(request.URL.Path))
	if !ok {
		t.Fatalf("route did not parse: %s", path)
	}
	handler.routeRequest(recorder, request, rt)
	if recorder.Code != want {
		t.Fatalf("routed %s %s = %d, want %d: %s", method, path, recorder.Code, want, recorder.Body.String())
	}
}

func setRequiredIfMatch(request *http.Request) {
	if rt, ok := parse(split(request.URL.Path)); ok && requiresIfMatch(rt, request.Method) {
		request.Header.Set("If-Match", "*")
	}
}
