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
	"math/big"
	"net/http"
	"net/http/httptest"
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
	assertStatus(t, handler, http.MethodGet, basePath+"/apis"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/apis"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/missing"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","path":"a","serviceUrl":"https://backend"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"A","path":"a","serviceUrl":"https://backend","protocols":["https"],"subscriptionRequired":false}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a"+apiQuery, `{"properties":{"displayName":"Updated","path":"updated","serviceUrl":"https://updated","protocols":["http","https"],"subscriptionRequired":true}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a"+apiQuery, "", http.StatusOK)
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
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"displayName":"Get","method":"GET","urlTemplate":"/"}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/operations/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/operations/get"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/operations/get"+apiQuery, `{"properties":{"displayName":"Updated","method":"POST","urlTemplate":"/updated"}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/operations/get"+apiQuery, "", http.StatusOK)
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
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a;rev=3/operations/get"+apiQuery, "", http.StatusOK)
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
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a/releases/r"+apiQuery, `{"properties":{"apiId":"`+targetRevision3+`","notes":"Release 3"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusOK)
	assertStatus(t, handler, http.MethodHead, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusOK)
	releases := request(t, handler, http.MethodGet, basePath+"/apis/a/releases"+apiQuery, "")
	if !strings.Contains(releases.Body.String(), `"count":1`) || !strings.Contains(releases.Body.String(), `"notes":"Release 3"`) {
		t.Fatalf("API releases = %s", releases.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/releases/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/releases/r"+apiQuery, `{`, http.StatusBadRequest)
	targetRevision2 := serviceModel().ID() + "/apis/a;rev=2"
	assertStatus(t, handler, http.MethodPatch, basePath+"/apis/a/releases/r"+apiQuery, `{"properties":{"apiId":"`+targetRevision2+`","notes":"Release 2"}}`, http.StatusOK)
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
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/releases/r"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a/operations/get"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/apis/a"+apiQuery, "", http.StatusNoContent)
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
	assertStatus(t, handler, http.MethodPut, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"P","state":"notPublished","approvalRequired":true}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/products/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/products/p"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+"/products/p"+apiQuery, `{"properties":{"displayName":"Updated","state":"published","approvalRequired":false}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/p"+apiQuery, "", http.StatusOK)
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
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"S","scope":"`+serviceModel().ID()+`"}}`, http.StatusCreated)
	got := request(t, handler, http.MethodGet, basePath+"/subscriptions/s"+apiQuery, "")
	if strings.Contains(got.Body.String(), "primaryKey") || got.Header().Get("ETag") == "" {
		t.Fatalf("subscription GET leaked secrets or omitted ETag: %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodPut, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"S","scope":"`+serviceModel().ID()+`","state":"suspended","primaryKey":"primary","secondaryKey":"secondary"}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/subscriptions/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/subscriptions/s"+apiQuery, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, basePath+"/subscriptions/s"+apiQuery, `{"properties":{"displayName":"Updated","scope":"`+serviceModel().ID()+`/apis/a","state":"active","primaryKey":"primary","secondaryKey":"secondary"}}`, http.StatusOK)
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
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/p"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, basePath+"/subscriptions/s"+apiQuery, "", http.StatusNoContent)

	secrets := subscriptionWire(model.Subscription{ServiceID: serviceModel().ID(), Name: "s", PrimaryKey: "one", SecondaryKey: "two"}, true)
	properties := secrets["properties"].(map[string]any)
	if properties["primaryKey"] != "one" || properties["secondaryKey"] != "two" {
		t.Fatalf("subscription secrets = %v", properties)
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
	assertStatus(t, handler, http.MethodPut, tagPath, `{"properties":{"displayName":"Public API"}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/tags/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, tagPath, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, tagPath, `{"properties":{"displayName":"Updated"}}`, http.StatusOK)
	got := request(t, handler, http.MethodGet, tagPath, "")
	if !strings.Contains(got.Body.String(), `"displayName":"Updated"`) || got.Header().Get("ETag") == "" {
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
		if !strings.Contains(collection.Body.String(), `"count":1`) {
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
	assertStatus(t, handler, http.MethodDelete, tagPath, "", http.StatusNoContent)
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
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Versions","versioningScheme":"Header","versionHeaderName":"X-API-Version","versionQueryName":"version","description":"Header versions"}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/apiVersionSets/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"displayName":"Updated","versioningScheme":"Query","versionQueryName":"api-version","versionHeaderName":"X-Version","description":"Query versions"}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusOK)
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
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
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
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"displayName":"Token","value":"value","secret":true,"tags":["auth"]}}`, http.StatusCreated)
	response := request(t, handler, http.MethodGet, path, "")
	if strings.Contains(response.Body.String(), `"value"`) || !strings.Contains(response.Body.String(), `"secret":true`) {
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
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"displayName":"Updated","value":"new","secret":false,"tags":["one","two"],"keyVault":{"secretIdentifier":"https://vault/secrets/name","identityClientId":"client"}}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, basePath+"/namedValues/token/refreshSecret"+apiQuery, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, collection, "")
	if !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), `"secretIdentifier":"https://vault/secrets/name"`) {
		t.Fatalf("named value list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/namedValues/token/extra/path"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"value":"activation"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
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
	body := `{"properties":{"title":"Primary","description":"Backend","url":"https://backend.test/base","protocol":"http","resourceId":"/external","credentials":{"header":{"X-Key":["secret"]}},"tls":{"validateCertificateChain":false}}}`
	assertStatus(t, handler, http.MethodPut, path, body, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	got := request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"X-Key":["secret"]`) || !strings.Contains(got.Body.String(), `"validateCertificateChain":false`) {
		t.Fatalf("lossless backend = %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/backends/missing"+apiQuery, `{}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"title":"Updated","description":"Changed"}}`, http.StatusOK)
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
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	if properties := backendWire(model.Backend{})["properties"].(map[string]any); properties["url"] != "" {
		t.Fatalf("empty backend wire = %v", properties)
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
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"data":"`+pfx+`","password":"password"}}`, http.StatusCreated)
	got := request(t, handler, http.MethodGet, path, "")
	if strings.Contains(got.Body.String(), pfx) || !strings.Contains(got.Body.String(), `"subject":"CN=client.test"`) || !strings.Contains(got.Body.String(), `"thumbprint":`) {
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
	assertStatus(t, handler, http.MethodPut, vaultPath, `{"properties":{"keyVault":{"secretIdentifier":"https://vault/secrets/client","identityClientId":"identity"}}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, basePath+"/certificates/vault/refreshSecret"+apiQuery, "", http.StatusOK)
	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"data":"`+pfx+`","password":"password"}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
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
	body := `{"properties":{"contentType":"application/vnd.oai.openapi.components+json","document":{"components":{"schemas":{"Item":{"type":"object","properties":{"id":{"type":"string"}}}}}}}}`
	assertStatus(t, handler, http.MethodPut, path, body, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"contentType":"application/json","document":{"definitions":{"Item":{"type":"string"}}}}}`, http.StatusOK)
	got := request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"definitions":{"Item":{"type":"string"}}`) {
		t.Fatalf("schema GET = %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, collection, "")
	if !strings.Contains(list.Body.String(), `"count":1`) {
		t.Fatalf("schema list = %s", list.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a/schemas/payload/extra"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
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
