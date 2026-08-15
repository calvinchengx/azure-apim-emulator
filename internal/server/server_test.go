package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	testSubscription = "2fb9babf-9c3b-43d2-9c89-4cba46a6d5ed"
	testServiceID    = "/subscriptions/2fb9babf-9c3b-43d2-9c89-4cba46a6d5ed/resourceGroups/test-rg/providers/Microsoft.ApiManagement/service/emulator"
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

	for _, path := range []string{"/health", "/_emulator/clock", "/_emulator/portal/api/status", "/_emulator/portal/api/snapshot", "/_emulator/portal/api/parity", "/_emulator/portal/api/faults", "/_emulator/portal/api/diagnostics"} {
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
	diagnostics := httptest.NewRecorder()
	srv.Handler().ServeHTTP(diagnostics, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/diagnostics", nil))
	if diagnostics.Code != http.StatusOK || !strings.Contains(diagnostics.Body.String(), `"events":[]`) {
		t.Fatalf("portal diagnostics = %d %s", diagnostics.Code, diagnostics.Body.String())
	}
	if !strings.Contains(status.Body.String(), `"counts"`) || !strings.Contains(status.Body.String(), `"products"`) || !strings.Contains(status.Body.String(), `"documentations"`) {
		t.Fatalf("portal core resource counts = %s", status.Body.String())
	}
	fault := httptest.NewRecorder()
	srv.Handler().ServeHTTP(fault, httptest.NewRequest(http.MethodPost, "/_emulator/portal/api/faults", strings.NewReader(`{"service":"emulator","backend":"default","status":503,"remaining":1}`)))
	if fault.Code != http.StatusOK || !strings.Contains(fault.Body.String(), "emulator/default") {
		t.Fatalf("fault update = %d %s", fault.Code, fault.Body.String())
	}
	badFault := httptest.NewRecorder()
	srv.Handler().ServeHTTP(badFault, httptest.NewRequest(http.MethodPost, "/_emulator/portal/api/faults", strings.NewReader("{")))
	if badFault.Code != http.StatusBadRequest {
		t.Fatalf("bad fault = %d", badFault.Code)
	}
	clearFault := httptest.NewRecorder()
	srv.Handler().ServeHTTP(clearFault, httptest.NewRequest(http.MethodPost, "/_emulator/portal/api/faults", strings.NewReader(`{"service":"emulator","backend":"default","clear":true}`)))
	if clearFault.Code != http.StatusOK || strings.Contains(clearFault.Body.String(), "emulator/default") {
		t.Fatalf("fault clear = %d %s", clearFault.Code, clearFault.Body.String())
	}
	scope := "/subscriptions/test/resourceGroups/test/providers/Microsoft.ApiManagement/service/emulator/apis/portal"
	missingPolicy := httptest.NewRecorder()
	srv.Handler().ServeHTTP(missingPolicy, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), nil))
	if missingPolicy.Code != http.StatusNotFound {
		t.Fatalf("missing portal policy = %d", missingPolicy.Code)
	}
	updatedPolicy := httptest.NewRecorder()
	srv.Handler().ServeHTTP(updatedPolicy, httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader(`{"format":"rawxml","value":"<policies><inbound><base/></inbound></policies>"}`)))
	if updatedPolicy.Code != http.StatusOK || !strings.Contains(updatedPolicy.Body.String(), "rawxml") {
		t.Fatalf("portal policy update = %d %s", updatedPolicy.Code, updatedPolicy.Body.String())
	}
	readPolicy := httptest.NewRecorder()
	srv.Handler().ServeHTTP(readPolicy, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), nil))
	if readPolicy.Code != http.StatusOK || !strings.Contains(readPolicy.Body.String(), "policies") {
		t.Fatalf("portal policy read = %d %s", readPolicy.Code, readPolicy.Body.String())
	}
	portalAPI := model.API{ServiceID: model.Service{SubscriptionID: defaultSubscription, ResourceGroup: defaultResourceGroup, Name: "emulator"}.ID(), Name: "portal-api", DisplayName: "Portal API", Path: "portal", ServiceURL: "https://backend.test"}
	if _, err := srv.Store.UpsertAPI(portalAPI); err != nil {
		t.Fatal(err)
	}
	resourceURL := "/_emulator/portal/api/resource?resourceId=" + url.QueryEscape(portalAPI.ID())
	resourceRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resourceRead, httptest.NewRequest(http.MethodGet, resourceURL, nil))
	if resourceRead.Code != http.StatusOK || !strings.Contains(resourceRead.Body.String(), "Portal API") {
		t.Fatalf("portal resource read = %d %s", resourceRead.Code, resourceRead.Body.String())
	}
	resourceUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resourceUpdate, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":"Updated Portal API","path":"updated"}`)))
	if resourceUpdate.Code != http.StatusOK || !strings.Contains(resourceUpdate.Body.String(), "Updated Portal API") {
		t.Fatalf("portal resource update = %d %s", resourceUpdate.Code, resourceUpdate.Body.String())
	}
	portalProduct := model.Product{ServiceID: portalAPI.ServiceID, Name: "portal-product", DisplayName: "Portal Product", State: "notPublished"}
	if _, err := srv.Store.UpsertProduct(portalProduct); err != nil {
		t.Fatal(err)
	}
	productURL := "/_emulator/portal/api/product?resourceId=" + url.QueryEscape(portalProduct.ID())
	productRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productRead, httptest.NewRequest(http.MethodGet, productURL, nil))
	if productRead.Code != http.StatusOK || !strings.Contains(productRead.Body.String(), "Portal Product") {
		t.Fatalf("portal product read = %d %s", productRead.Code, productRead.Body.String())
	}
	productUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productUpdate, httptest.NewRequest(http.MethodPut, productURL, strings.NewReader(`{"displayName":"Updated Product","state":"published","approvalRequired":true}`)))
	if productUpdate.Code != http.StatusOK || !strings.Contains(productUpdate.Body.String(), "published") {
		t.Fatalf("portal product update = %d %s", productUpdate.Code, productUpdate.Body.String())
	}
	portalBackend := model.Backend{ServiceID: portalAPI.ServiceID, Name: "portal-backend", Title: "Portal Backend", URL: "https://backend.test", Protocol: "http"}
	if _, err := srv.Store.UpsertBackend(portalBackend); err != nil {
		t.Fatal(err)
	}
	backendURL := "/_emulator/portal/api/backend?resourceId=" + url.QueryEscape(portalBackend.ID())
	backendRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backendRead, httptest.NewRequest(http.MethodGet, backendURL, nil))
	if backendRead.Code != http.StatusOK || !strings.Contains(backendRead.Body.String(), "Portal Backend") {
		t.Fatalf("portal backend read = %d %s", backendRead.Code, backendRead.Body.String())
	}
	backendUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backendUpdate, httptest.NewRequest(http.MethodPut, backendURL, strings.NewReader(`{"title":"Updated Backend","url":"https://new-backend.test","protocol":"https","resourceId":"backend-resource","description":"updated"}`)))
	if backendUpdate.Code != http.StatusOK || !strings.Contains(backendUpdate.Body.String(), "new-backend.test") {
		t.Fatalf("portal backend update = %d %s", backendUpdate.Code, backendUpdate.Body.String())
	}
	portalNamedValue := model.NamedValue{ServiceID: portalAPI.ServiceID, Name: "portal-secret", DisplayName: "Portal Secret", Value: "initial-secret", Secret: true, Tags: []string{"ops"}}
	if _, err := srv.Store.UpsertNamedValue(portalNamedValue); err != nil {
		t.Fatal(err)
	}
	namedValueURL := "/_emulator/portal/api/named-value?resourceId=" + url.QueryEscape(portalNamedValue.ID())
	namedValueRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(namedValueRead, httptest.NewRequest(http.MethodGet, namedValueURL, nil))
	if namedValueRead.Code != http.StatusOK || strings.Contains(namedValueRead.Body.String(), "initial-secret") || !strings.Contains(namedValueRead.Body.String(), `"secret":true`) {
		t.Fatalf("portal named value redaction = %d %s", namedValueRead.Code, namedValueRead.Body.String())
	}
	namedValueUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(namedValueUpdate, httptest.NewRequest(http.MethodPut, namedValueURL, strings.NewReader(`{"value":"rotated-secret","tags":["ops","rotation"]}`)))
	if namedValueUpdate.Code != http.StatusOK || strings.Contains(namedValueUpdate.Body.String(), "rotated-secret") {
		t.Fatalf("portal named value update = %d %s", namedValueUpdate.Code, namedValueUpdate.Body.String())
	}
	portalCertificate := model.Certificate{ServiceID: portalAPI.ServiceID, Name: "portal-cert", Subject: "CN=portal", Thumbprint: "ABC123", Data: []byte("private-material"), Password: "private-password"}
	if _, err := srv.Store.UpsertCertificate(portalCertificate); err != nil {
		t.Fatal(err)
	}
	certificateURL := "/_emulator/portal/api/certificate?resourceId=" + url.QueryEscape(portalCertificate.ID())
	certificateRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(certificateRead, httptest.NewRequest(http.MethodGet, certificateURL, nil))
	if certificateRead.Code != http.StatusOK || strings.Contains(certificateRead.Body.String(), "private-material") || strings.Contains(certificateRead.Body.String(), "private-password") || !strings.Contains(certificateRead.Body.String(), `"hasData":true`) {
		t.Fatalf("portal certificate redaction = %d %s", certificateRead.Code, certificateRead.Body.String())
	}
	certificateUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(certificateUpdate, httptest.NewRequest(http.MethodPut, certificateURL, strings.NewReader(`{"subject":"CN=updated","thumbprint":"DEF456","keyVaultSecretId":"https://vault/secrets/cert","keyVaultIdentityId":"identity"}`)))
	if certificateUpdate.Code != http.StatusOK || !strings.Contains(certificateUpdate.Body.String(), "updated") {
		t.Fatalf("portal certificate update = %d %s", certificateUpdate.Code, certificateUpdate.Body.String())
	}
	portalTag := model.Tag{ServiceID: portalAPI.ServiceID, Name: "portal-tag", DisplayName: "Portal Tag"}
	if _, err := srv.Store.UpsertTag(portalTag); err != nil {
		t.Fatal(err)
	}
	tagURL := "/_emulator/portal/api/tag?resourceId=" + url.QueryEscape(portalTag.ID())
	tagRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(tagRead, httptest.NewRequest(http.MethodGet, tagURL, nil))
	if tagRead.Code != http.StatusOK || !strings.Contains(tagRead.Body.String(), "Portal Tag") {
		t.Fatalf("portal tag read = %d %s", tagRead.Code, tagRead.Body.String())
	}
	tagUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(tagUpdate, httptest.NewRequest(http.MethodPut, tagURL, strings.NewReader(`{"displayName":"Updated Tag"}`)))
	if tagUpdate.Code != http.StatusOK || !strings.Contains(tagUpdate.Body.String(), "Updated Tag") {
		t.Fatalf("portal tag update = %d %s", tagUpdate.Code, tagUpdate.Body.String())
	}
	portalGroup := model.Group{ServiceID: portalAPI.ServiceID, Name: "portal-group", DisplayName: "Portal Group", Type: "custom"}
	if _, err := srv.Store.UpsertGroup(portalGroup); err != nil {
		t.Fatal(err)
	}
	groupURL := "/_emulator/portal/api/group?resourceId=" + url.QueryEscape(portalGroup.ID())
	groupRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(groupRead, httptest.NewRequest(http.MethodGet, groupURL, nil))
	if groupRead.Code != http.StatusOK || !strings.Contains(groupRead.Body.String(), "Portal Group") {
		t.Fatalf("portal group read = %d %s", groupRead.Code, groupRead.Body.String())
	}
	groupUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(groupUpdate, httptest.NewRequest(http.MethodPut, groupURL, strings.NewReader(`{"displayName":"Updated Group","description":"updated","type":"external","externalId":"external-group"}`)))
	if groupUpdate.Code != http.StatusOK || !strings.Contains(groupUpdate.Body.String(), "Updated Group") {
		t.Fatalf("portal group update = %d %s", groupUpdate.Code, groupUpdate.Body.String())
	}
	portalSubscription := model.Subscription{ServiceID: portalAPI.ServiceID, Name: "portal-subscription", DisplayName: "Portal Subscription", Scope: portalAPI.ID(), State: "active", PrimaryKey: "primary-secret", SecondaryKey: "secondary-secret"}
	if _, err := srv.Store.UpsertSubscription(portalSubscription); err != nil {
		t.Fatal(err)
	}
	subscriptionURL := "/_emulator/portal/api/subscription?resourceId=" + url.QueryEscape(portalSubscription.ID())
	subscriptionRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(subscriptionRead, httptest.NewRequest(http.MethodGet, subscriptionURL, nil))
	if subscriptionRead.Code != http.StatusOK || strings.Contains(subscriptionRead.Body.String(), "primary-secret") || strings.Contains(subscriptionRead.Body.String(), "secondary-secret") {
		t.Fatalf("portal subscription redaction = %d %s", subscriptionRead.Code, subscriptionRead.Body.String())
	}
	subscriptionUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(subscriptionUpdate, httptest.NewRequest(http.MethodPut, subscriptionURL, strings.NewReader(`{"displayName":"Updated Subscription","state":"suspended"}`)))
	if subscriptionUpdate.Code != http.StatusOK || !strings.Contains(subscriptionUpdate.Body.String(), "suspended") {
		t.Fatalf("portal subscription update = %d %s", subscriptionUpdate.Code, subscriptionUpdate.Body.String())
	}
	portalUser := model.User{ServiceID: portalAPI.ServiceID, Name: "portal-user", FirstName: "Portal", LastName: "User", Email: "portal@example.test", State: "active", Password: "private-password", PrimaryKey: "private-primary", SecondaryKey: "private-secondary"}
	if _, err := srv.Store.UpsertUser(portalUser); err != nil {
		t.Fatal(err)
	}
	userURL := "/_emulator/portal/api/user?resourceId=" + url.QueryEscape(portalUser.ID())
	userRead := httptest.NewRecorder()
	srv.Handler().ServeHTTP(userRead, httptest.NewRequest(http.MethodGet, userURL, nil))
	if userRead.Code != http.StatusOK || strings.Contains(userRead.Body.String(), "private-password") || strings.Contains(userRead.Body.String(), "private-primary") {
		t.Fatalf("portal user redaction = %d %s", userRead.Code, userRead.Body.String())
	}
	userUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(userUpdate, httptest.NewRequest(http.MethodPut, userURL, strings.NewReader(`{"firstName":"Updated","email":"updated@example.test","state":"blocked","note":"review"}`)))
	if userUpdate.Code != http.StatusOK || !strings.Contains(userUpdate.Body.String(), "updated@example.test") {
		t.Fatalf("portal user update = %d %s", userUpdate.Code, userUpdate.Body.String())
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/user", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/user?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, userURL, strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, userURL, strings.NewReader(`{"email":" "}`)),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal user invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	srv.portalUpsertUser = func(model.User) (model.User, error) {
		return model.User{}, errors.New("injected user persistence failure")
	}
	userStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(userStoreFailure, httptest.NewRequest(http.MethodPut, userURL, strings.NewReader(`{"state":"active"}`)))
	if userStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal user persistence failure = %d %s", userStoreFailure.Code, userStoreFailure.Body.String())
	}
	srv.portalUpsertUser = srv.Store.UpsertUser
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/subscription", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/subscription?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, subscriptionURL, strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, subscriptionURL, strings.NewReader(`{"displayName":" "}`)),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal subscription invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	srv.portalUpsertSubscription = func(model.Subscription) (model.Subscription, error) {
		return model.Subscription{}, errors.New("injected subscription persistence failure")
	}
	subscriptionStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(subscriptionStoreFailure, httptest.NewRequest(http.MethodPut, subscriptionURL, strings.NewReader(`{"state":"active"}`)))
	if subscriptionStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal subscription persistence failure = %d %s", subscriptionStoreFailure.Code, subscriptionStoreFailure.Body.String())
	}
	srv.portalUpsertSubscription = srv.Store.UpsertSubscription
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/group", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/group?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, groupURL, strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, groupURL, strings.NewReader(`{"displayName":" "}`)),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal group invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	srv.portalUpsertGroup = func(model.Group) (model.Group, error) {
		return model.Group{}, errors.New("injected group persistence failure")
	}
	groupStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(groupStoreFailure, httptest.NewRequest(http.MethodPut, groupURL, strings.NewReader(`{"displayName":"Store Failure"}`)))
	if groupStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal group persistence failure = %d %s", groupStoreFailure.Code, groupStoreFailure.Body.String())
	}
	srv.portalUpsertGroup = srv.Store.UpsertGroup
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/tag", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/tag?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, tagURL, strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, tagURL, strings.NewReader(`{"displayName":" "}`)),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal tag invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	srv.portalUpsertTag = func(model.Tag) (model.Tag, error) { return model.Tag{}, errors.New("injected tag persistence failure") }
	tagStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(tagStoreFailure, httptest.NewRequest(http.MethodPut, tagURL, strings.NewReader(`{"displayName":"Store Failure"}`)))
	if tagStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal tag persistence failure = %d %s", tagStoreFailure.Code, tagStoreFailure.Body.String())
	}
	srv.portalUpsertTag = srv.Store.UpsertTag
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/certificate", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/certificate?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, certificateURL, strings.NewReader("{")),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal certificate invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	srv.portalUpsertCertificate = func(model.Certificate) (model.Certificate, error) {
		return model.Certificate{}, errors.New("injected certificate persistence failure")
	}
	certificateStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(certificateStoreFailure, httptest.NewRequest(http.MethodPut, certificateURL, strings.NewReader(`{"subject":"Store Failure"}`)))
	if certificateStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal certificate persistence failure = %d %s", certificateStoreFailure.Code, certificateStoreFailure.Body.String())
	}
	srv.portalUpsertCertificate = srv.Store.UpsertCertificate
	namedValuePublic := httptest.NewRecorder()
	srv.Handler().ServeHTTP(namedValuePublic, httptest.NewRequest(http.MethodPut, namedValueURL, strings.NewReader(`{"displayName":"Public Value","secret":false}`)))
	if namedValuePublic.Code != http.StatusOK || !strings.Contains(namedValuePublic.Body.String(), "rotated-secret") {
		t.Fatalf("portal named value public update = %d %s", namedValuePublic.Code, namedValuePublic.Body.String())
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/named-value", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/named-value?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, namedValueURL, strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, namedValueURL, strings.NewReader(`{"displayName":" "}`)),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal named value invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	srv.portalUpsertNamedValue = func(model.NamedValue) (model.NamedValue, error) {
		return model.NamedValue{}, errors.New("injected named value persistence failure")
	}
	namedValueStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(namedValueStoreFailure, httptest.NewRequest(http.MethodPut, namedValueURL, strings.NewReader(`{"value":"store-failure"}`)))
	if namedValueStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal named value persistence failure = %d %s", namedValueStoreFailure.Code, namedValueStoreFailure.Body.String())
	}
	srv.portalUpsertNamedValue = srv.Store.UpsertNamedValue
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/backend", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/backend?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, backendURL, strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, backendURL, strings.NewReader(`{"title":"","url":""}`)),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal backend invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	srv.portalUpsertBackend = func(model.Backend) (model.Backend, error) {
		return model.Backend{}, errors.New("injected backend persistence failure")
	}
	backendStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backendStoreFailure, httptest.NewRequest(http.MethodPut, backendURL, strings.NewReader(`{"title":"Store Failure"}`)))
	if backendStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal backend persistence failure = %d %s", backendStoreFailure.Code, backendStoreFailure.Body.String())
	}
	srv.portalUpsertBackend = srv.Store.UpsertBackend
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/product", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/product?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, productURL, strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, productURL, strings.NewReader(`{"displayName":" "}`)),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal product invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	fullResourceUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(fullResourceUpdate, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":"Full Portal API","path":"full","serviceUrl":"https://new-backend.test","subscriptionRequired":true}`)))
	if fullResourceUpdate.Code != http.StatusOK || !strings.Contains(fullResourceUpdate.Body.String(), "new-backend.test") {
		t.Fatalf("full portal resource update = %d %s", fullResourceUpdate.Code, fullResourceUpdate.Body.String())
	}
	if _, err := srv.Store.UpsertPolicy(model.Policy{ScopeID: portalAPI.ID(), Value: "<invalid>"}); err != nil {
		t.Fatal(err)
	}
	activationResourceUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(activationResourceUpdate, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":"Activation Failure"}`)))
	if activationResourceUpdate.Code != http.StatusBadRequest {
		t.Fatalf("portal resource activation failure = %d %s", activationResourceUpdate.Code, activationResourceUpdate.Body.String())
	}
	productActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productActivationFailure, httptest.NewRequest(http.MethodPut, productURL, strings.NewReader(`{"state":"published"}`)))
	if productActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal product activation failure = %d %s", productActivationFailure.Code, productActivationFailure.Body.String())
	}
	userActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(userActivationFailure, httptest.NewRequest(http.MethodPut, userURL, strings.NewReader(`{"state":"blocked"}`)))
	if userActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal user activation failure = %d %s", userActivationFailure.Code, userActivationFailure.Body.String())
	}
	subscriptionActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(subscriptionActivationFailure, httptest.NewRequest(http.MethodPut, subscriptionURL, strings.NewReader(`{"state":"active"}`)))
	if subscriptionActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal subscription activation failure = %d %s", subscriptionActivationFailure.Code, subscriptionActivationFailure.Body.String())
	}
	groupActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(groupActivationFailure, httptest.NewRequest(http.MethodPut, groupURL, strings.NewReader(`{"displayName":"Activation Failure"}`)))
	if groupActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal group activation failure = %d %s", groupActivationFailure.Code, groupActivationFailure.Body.String())
	}
	tagActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(tagActivationFailure, httptest.NewRequest(http.MethodPut, tagURL, strings.NewReader(`{"displayName":"Activation Failure"}`)))
	if tagActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal tag activation failure = %d %s", tagActivationFailure.Code, tagActivationFailure.Body.String())
	}
	certificateActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(certificateActivationFailure, httptest.NewRequest(http.MethodPut, certificateURL, strings.NewReader(`{"subject":"Activation Failure"}`)))
	if certificateActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal certificate activation failure = %d %s", certificateActivationFailure.Code, certificateActivationFailure.Body.String())
	}
	namedValueActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(namedValueActivationFailure, httptest.NewRequest(http.MethodPut, namedValueURL, strings.NewReader(`{"value":"activation-failure"}`)))
	if namedValueActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal named value activation failure = %d %s", namedValueActivationFailure.Code, namedValueActivationFailure.Body.String())
	}
	backendActivationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backendActivationFailure, httptest.NewRequest(http.MethodPut, backendURL, strings.NewReader(`{"title":"Activation Failure"}`)))
	if backendActivationFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal backend activation failure = %d %s", backendActivationFailure.Code, backendActivationFailure.Body.String())
	}
	srv.portalUpsertProduct = func(model.Product) (model.Product, error) {
		return model.Product{}, errors.New("injected product persistence failure")
	}
	productStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productStoreFailure, httptest.NewRequest(http.MethodPut, productURL, strings.NewReader(`{"state":"published"}`)))
	if productStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal product persistence failure = %d %s", productStoreFailure.Code, productStoreFailure.Body.String())
	}
	srv.portalUpsertProduct = srv.Store.UpsertProduct
	srv.portalUpsertAPI = func(model.API) (model.API, error) { return model.API{}, errors.New("injected API persistence failure") }
	apiStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(apiStoreFailure, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":"Store Failure"}`)))
	if apiStoreFailure.Code != http.StatusBadRequest {
		t.Fatalf("portal API persistence failure = %d %s", apiStoreFailure.Code, apiStoreFailure.Body.String())
	}
	srv.portalUpsertAPI = srv.Store.UpsertAPI
	emptyUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(emptyUpdate, httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader(`{"displayName":" "}`)))
	if emptyUpdate.Code != http.StatusBadRequest {
		t.Fatalf("empty portal resource name = %d %s", emptyUpdate.Code, emptyUpdate.Body.String())
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/resource", nil),
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/resource?resourceId=/missing", nil),
		httptest.NewRequest(http.MethodPut, resourceURL, strings.NewReader("{")),
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
			t.Fatalf("portal resource invalid = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/policy", nil),
		httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader("{")),
		httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader(`{"value":"<broken>"}`)),
	} {
		badPolicy := httptest.NewRecorder()
		srv.Handler().ServeHTTP(badPolicy, request)
		if badPolicy.Code != http.StatusBadRequest {
			t.Fatalf("bad portal policy = %d %s", badPolicy.Code, badPolicy.Body.String())
		}
	}
	if _, err := srv.Store.UpsertPolicy(model.Policy{ScopeID: "/invalid-policy", Value: "<broken/>"}); err != nil {
		t.Fatal(err)
	}
	activationFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(activationFailure, httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader(`{"format":"rawxml","value":"<policies/>"}`)))
	if activationFailure.Code != http.StatusBadRequest {
		t.Fatalf("activation failure = %d %s", activationFailure.Code, activationFailure.Body.String())
	}
	portal := httptest.NewRecorder()
	srv.Handler().ServeHTTP(portal, httptest.NewRequest(http.MethodGet, "/_emulator/portal/", nil))
	if portal.Code != http.StatusOK || !strings.Contains(portal.Body.String(), "Azure APIM Emulator") || !strings.Contains(portal.Body.String(), "Diagnostic Events") || !strings.Contains(portal.Header().Get("Content-Type"), "text/html") {
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
	if err := srv.Store.Close(); err != nil {
		t.Fatal(err)
	}
	updateStoreFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(updateStoreFailure, httptest.NewRequest(http.MethodPut, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), strings.NewReader(`{"format":"rawxml","value":"<policies/>"}`)))
	if updateStoreFailure.Code != http.StatusInternalServerError {
		t.Fatalf("update store failure = %d %s", updateStoreFailure.Code, updateStoreFailure.Body.String())
	}
	storeFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(storeFailure, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/policy?scopeId="+url.QueryEscape(scope), nil))
	if storeFailure.Code != http.StatusInternalServerError {
		t.Fatalf("store failure = %d %s", storeFailure.Code, storeFailure.Body.String())
	}
	resourceFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resourceFailure, httptest.NewRequest(http.MethodGet, resourceURL, nil))
	if resourceFailure.Code != http.StatusInternalServerError {
		t.Fatalf("resource store failure = %d %s", resourceFailure.Code, resourceFailure.Body.String())
	}
	productFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(productFailure, httptest.NewRequest(http.MethodGet, productURL, nil))
	if productFailure.Code != http.StatusInternalServerError {
		t.Fatalf("product store failure = %d %s", productFailure.Code, productFailure.Body.String())
	}
	backendFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backendFailure, httptest.NewRequest(http.MethodGet, backendURL, nil))
	if backendFailure.Code != http.StatusInternalServerError {
		t.Fatalf("backend store failure = %d %s", backendFailure.Code, backendFailure.Body.String())
	}
	namedValueFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(namedValueFailure, httptest.NewRequest(http.MethodGet, namedValueURL, nil))
	if namedValueFailure.Code != http.StatusInternalServerError {
		t.Fatalf("named value store failure = %d %s", namedValueFailure.Code, namedValueFailure.Body.String())
	}
	certificateFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(certificateFailure, httptest.NewRequest(http.MethodGet, certificateURL, nil))
	if certificateFailure.Code != http.StatusInternalServerError {
		t.Fatalf("certificate store failure = %d %s", certificateFailure.Code, certificateFailure.Body.String())
	}
	tagFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(tagFailure, httptest.NewRequest(http.MethodGet, tagURL, nil))
	if tagFailure.Code != http.StatusInternalServerError {
		t.Fatalf("tag store failure = %d %s", tagFailure.Code, tagFailure.Body.String())
	}
	groupFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(groupFailure, httptest.NewRequest(http.MethodGet, groupURL, nil))
	if groupFailure.Code != http.StatusInternalServerError {
		t.Fatalf("group store failure = %d %s", groupFailure.Code, groupFailure.Body.String())
	}
	subscriptionFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(subscriptionFailure, httptest.NewRequest(http.MethodGet, subscriptionURL, nil))
	if subscriptionFailure.Code != http.StatusInternalServerError {
		t.Fatalf("subscription store failure = %d %s", subscriptionFailure.Code, subscriptionFailure.Body.String())
	}
	userFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(userFailure, httptest.NewRequest(http.MethodGet, userURL, nil))
	if userFailure.Code != http.StatusInternalServerError {
		t.Fatalf("user store failure = %d %s", userFailure.Code, userFailure.Body.String())
	}
	diagnosticFailure := httptest.NewRecorder()
	srv.Handler().ServeHTTP(diagnosticFailure, httptest.NewRequest(http.MethodGet, "/_emulator/portal/api/diagnostics", nil))
	if diagnosticFailure.Code != http.StatusInternalServerError {
		t.Fatalf("diagnostic store failure = %d %s", diagnosticFailure.Code, diagnosticFailure.Body.String())
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
