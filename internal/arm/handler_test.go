package arm

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const (
	basePath = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/svc"
	apiQuery = "?api-version=2024-05-01"
)

type rejectingAuth struct{}

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
			assertStatus(t, handler, test.method, test.path, "", test.want)
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
	assertStatus(t, handler, http.MethodGet, basePath+"/apis"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/missing"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","path":"a","serviceUrl":"https://backend"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a"+apiQuery, "", http.StatusOK)

	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"displayName":"Get","method":"GET","urlTemplate":"/"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, basePath+"/apis/a/operations/get"+apiQuery, `{}`, http.StatusNotFound)

	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/policies/policy"+apiQuery, "", http.StatusNotFound)
	handler.ValidatePolicy = func(string) error { return errors.New("invalid policy") }
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{"properties":{"format":"rawxml","value":"x"}}`, http.StatusBadRequest)
	handler.ValidatePolicy = nil
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{"properties":{"format":"rawxml","value":"<policies/>"}}`, http.StatusCreated)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, basePath+"/apis/a/policies/policy"+apiQuery, nil)
	request.Header.Set("Authorization", "Bearer token")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `\u003cpolicies/\u003e`) || recorder.Header().Get("ETag") == "" {
		t.Fatalf("policy GET = %d %s", recorder.Code, recorder.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/policies/missing"+apiQuery, "", http.StatusNotFound)

	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","path":"a","serviceUrl":"https://backend"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/two"+apiQuery, `{"properties":{"displayName":"Two","method":"GET","urlTemplate":"/two"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{"properties":{"value":"<policies/>"}}`, http.StatusBadRequest)
}

func TestProductAndSubscriptionBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	_, _ = st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "a", DisplayName: "A", Path: "a", ServiceURL: "https://backend"})

	assertStatus(t, handler, http.MethodGet, basePath+"/products"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p"+apiQuery, "", http.StatusNotFound)

	assertStatus(t, handler, http.MethodGet, basePath+"/subscriptions/s"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"S","scope":"`+serviceModel().ID()+`"}}`, http.StatusCreated)

	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"S","scope":"`+serviceModel().ID()+`"}}`, http.StatusBadRequest)

	secrets := subscriptionWire(model.Subscription{ServiceID: serviceModel().ID(), Name: "s", PrimaryKey: "one", SecondaryKey: "two"}, true)
	properties := secrets["properties"].(map[string]any)
	if properties["primaryKey"] != "one" || properties["secondaryKey"] != "two" {
		t.Fatalf("subscription secrets = %v", properties)
	}
}

func TestForeignKeyStoreErrors(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","serviceUrl":"https://backend"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"S"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"method":"GET","urlTemplate":"/"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusConflict)
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
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"method":"GET","urlTemplate":"/"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/policies/policy"+apiQuery, `{"properties":{"value":"<policies/>"}}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/policies/policy"+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p/apis/a"+apiQuery, `{}`, http.StatusConflict)
	assertStatus(t, handler, http.MethodDelete, basePath+apiQuery, "", http.StatusConflict)
	assertStatus(t, handler, http.MethodGet, "/subscriptions/sub/providers/Microsoft.ApiManagement/service"+apiQuery, "", http.StatusConflict)
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
	handler.ServeHTTP(recorder, req)
	return recorder
}

func assertStatus(t *testing.T, handler http.Handler, method, path, body string, want int) {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, recorder.Code, want, recorder.Body.String())
	}
}
