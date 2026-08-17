package arm

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

const providerBody = `{"properties":{"displayName":"GitHub","identityProvider":"oauth2","oauth2":{"tokenEndpoint":"https://idp.test/token","authorizationEndpoint":"https://idp.test/auth","grantTypes":{"authorizationCode":{"clientId":"cid","clientSecret":"shhh","scopes":"repo"}}}}}`

func seedProvider(t *testing.T, handler *Handler) string {
	t.Helper()
	path := basePath + "/authorizationProviders/github" + apiQuery
	assertStatus(t, handler, http.MethodPut, path, providerBody, http.StatusCreated)
	return path
}

func TestAuthorizationProviderLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	collection := basePath + "/authorizationProviders" + apiQuery
	path := seedProvider(t, handler)

	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)

	// identityProvider names WHICH SaaS this is; without it the resource
	// describes nothing.
	assertStatus(t, handler, http.MethodPut, basePath+"/authorizationProviders/bare"+apiQuery,
		`{"properties":{"displayName":"bare"}}`, http.StatusBadRequest)

	got := request(t, handler, http.MethodGet, path, "")
	// The client secret is write-only. A management plane that read it back
	// would be a way to exfiltrate a credential the caller was never given.
	if strings.Contains(got.Body.String(), "shhh") {
		t.Fatalf("the client secret was echoed: %s", got.Body.String())
	}
	if !strings.Contains(got.Body.String(), `"clientId":"cid"`) {
		t.Fatalf("non-secret configuration must survive: %s", got.Body.String())
	}
	if !strings.Contains(got.Body.String(), `"identityProvider":"oauth2"`) {
		t.Fatalf("provider GET = %s", got.Body.String())
	}

	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"displayName":"Renamed"}}`, http.StatusOK)
	if body := request(t, handler, http.MethodGet, path, "").Body.String(); !strings.Contains(body, "Renamed") {
		t.Fatalf("PATCH = %s", body)
	}
	assertStatus(t, handler, http.MethodPatch, basePath+"/authorizationProviders/absent"+apiQuery, `{"properties":{}}`, http.StatusNotFound)

	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
}

func TestAuthorizationLifecycleAndConsentState(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	collection := basePath + "/authorizationProviders/github/authorizations" + apiQuery
	code := basePath + "/authorizationProviders/github/authorizations/user" + apiQuery
	machine := basePath + "/authorizationProviders/github/authorizations/machine" + apiQuery

	// A credential under a provider that does not exist must not be creatable:
	// a typo would otherwise produce a credential nobody configured.
	assertStatus(t, handler, http.MethodPut, basePath+"/authorizationProviders/absent/authorizations/x"+apiQuery,
		`{"properties":{"authorizationType":"OAuth2","oauth2grantType":"ClientCredentials"}}`, http.StatusNotFound)

	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, code, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, code, `{"properties":{"oauth2grantType":"Password"}}`, http.StatusBadRequest)

	// Authorization code is NOT usable until a human consents. Reporting it
	// Connected on creation would claim a credential exists that in Azure
	// does not.
	assertStatus(t, handler, http.MethodPut, code, `{"properties":{"authorizationType":"OAuth2","oauth2grantType":"AuthorizationCode"}}`, http.StatusCreated)
	body := request(t, handler, http.MethodGet, code, "").Body.String()
	if !strings.Contains(body, `"status":"Error"`) {
		t.Fatalf("a fresh authorization-code credential must not be Connected: %s", body)
	}
	if !strings.Contains(body, "consent") {
		t.Fatalf("the reason must name consent: %s", body)
	}

	// Client credentials needs no human, so it is usable immediately.
	assertStatus(t, handler, http.MethodPut, machine, `{"properties":{"authorizationType":"OAuth2","oauth2grantType":"ClientCredentials"}}`, http.StatusCreated)
	if body := request(t, handler, http.MethodGet, machine, "").Body.String(); !strings.Contains(body, `"status":"Connected"`) {
		t.Fatalf("client credentials needs no consent: %s", body)
	}

	// Tokens are never on the wire, whatever the caller PUT.
	assertStatus(t, handler, http.MethodPut, machine,
		`{"properties":{"authorizationType":"OAuth2","oauth2grantType":"ClientCredentials","accessToken":"leak","refreshToken":"leak2"}}`, http.StatusOK)
	if body := request(t, handler, http.MethodGet, machine, "").Body.String(); strings.Contains(body, "leak") {
		t.Fatalf("a token must never be returned: %s", body)
	}

	assertStatus(t, handler, http.MethodPatch, machine, `{"properties":{"authorizationType":"OAuth2"}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/authorizationProviders/github/authorizations/absent"+apiQuery, `{"properties":{}}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, machine, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, machine, "", http.StatusNoContent)

	// Deleting the provider revokes what it issued rather than orphaning it.
	assertStatus(t, handler, http.MethodDelete, basePath+"/authorizationProviders/github"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodGet, code, "", http.StatusNotFound)
}

func TestAccessPolicyLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	authorization := basePath + "/authorizationProviders/github/authorizations/user" + apiQuery
	assertStatus(t, handler, http.MethodPut, authorization, `{"properties":{"authorizationType":"OAuth2","oauth2grantType":"AuthorizationCode"}}`, http.StatusCreated)

	collection := basePath + "/authorizationProviders/github/authorizations/user/accessPolicies" + apiQuery
	path := basePath + "/authorizationProviders/github/authorizations/user/accessPolicies/dev" + apiQuery

	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)

	// An access policy exists to name a principal; without one it permits
	// nobody and silently does nothing.
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"tenantId":"t"}}`, http.StatusBadRequest)

	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"tenantId":"tenant","objectId":"principal"}}`, http.StatusCreated)
	if body := request(t, handler, http.MethodGet, path, "").Body.String(); !strings.Contains(body, `"objectId":"principal"`) {
		t.Fatalf("access policy GET = %s", body)
	}
	if body := request(t, handler, http.MethodGet, collection, "").Body.String(); !strings.Contains(body, `"count":1`) {
		t.Fatalf("access policy list = %s", body)
	}
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"tenantId":"other"}}`, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, basePath+"/authorizationProviders/github/authorizations/user/accessPolicies/absent"+apiQuery, `{"properties":{}}`, http.StatusNotFound)

	// Policies under a credential that does not exist are not addressable.
	assertStatus(t, handler, http.MethodGet, basePath+"/authorizationProviders/github/authorizations/absent/accessPolicies"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/authorizationProviders/github/authorizations/absent/accessPolicies/x"+apiQuery, "", http.StatusNotFound)

	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
}

func TestConsentActions(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	code := basePath + "/authorizationProviders/github/authorizations/user" + apiQuery
	machine := basePath + "/authorizationProviders/github/authorizations/machine" + apiQuery
	assertStatus(t, handler, http.MethodPut, code, `{"properties":{"authorizationType":"OAuth2","oauth2grantType":"AuthorizationCode"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, machine, `{"properties":{"authorizationType":"OAuth2","oauth2grantType":"ClientCredentials"}}`, http.StatusCreated)

	links := basePath + "/authorizationProviders/github/authorizations/user/getLoginLinks" + apiQuery
	confirm := basePath + "/authorizationProviders/github/authorizations/user/confirmConsentCode" + apiQuery

	assertStatus(t, handler, http.MethodGet, links, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, basePath+"/authorizationProviders/github/authorizations/user/nonsense"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/authorizationProviders/github/authorizations/absent/getLoginLinks"+apiQuery, "", http.StatusNotFound)

	// Consent applies to the authorization-code grant only; a machine
	// credential has no user to ask.
	assertStatus(t, handler, http.MethodPost, basePath+"/authorizationProviders/github/authorizations/machine/getLoginLinks"+apiQuery, "", http.StatusBadRequest)

	// Without the hooks the handler must refuse rather than pretend.
	assertStatus(t, handler, http.MethodPost, links, "{}", http.StatusBadRequest)

	handler.LoginLink = func(providerID, authorizationID, redirect string) (string, error) {
		return "https://idp.test/auth?state=" + authorizationID, nil
	}
	got := request(t, handler, http.MethodPost, links, `{"postLoginRedirectUrl":"https://back.test/"}`)
	if !strings.Contains(got.Body.String(), "loginLink") || !strings.Contains(got.Body.String(), "state=") {
		t.Fatalf("getLoginLinks = %s", got.Body.String())
	}

	assertStatus(t, handler, http.MethodPost, confirm, `{}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, confirm, `{`, http.StatusBadRequest)

	// A refused code records WHY on the credential, so an operator reads the
	// provider's own refusal instead of reproducing the exchange.
	handler.ConfirmConsent = func(string, string, string) error { return errors.New("invalid_grant: code is expired") }
	assertStatus(t, handler, http.MethodPost, confirm, `{"consentCode":"bad"}`, http.StatusBadRequest)
	if body := request(t, handler, http.MethodGet, code, "").Body.String(); !strings.Contains(body, "invalid_grant") {
		t.Fatalf("the refusal must be recorded on the credential: %s", body)
	}

	handler.ConfirmConsent = func(string, string, string) error { return nil }
	confirmed := request(t, handler, http.MethodPost, confirm, `{"consentCode":"good"}`)
	if !strings.Contains(confirmed.Body.String(), `"status":"Connected"`) {
		t.Fatalf("a redeemed code must connect the credential: %s", confirmed.Body.String())
	}
	if strings.Contains(confirmed.Body.String(), `"error"`) {
		t.Fatalf("a connected credential must not keep its old error: %s", confirmed.Body.String())
	}
}

func TestAuthorizationProviderRoutingEdges(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	for _, path := range []string{
		basePath + "/authorizationProviders/github/nonsense" + apiQuery,
		basePath + "/authorizationProviders/github/authorizations/user/accessPolicies/dev/extra" + apiQuery,
	} {
		assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	}
}

func TestGrantTypeValidation(t *testing.T) {
	for _, value := range []string{"AuthorizationCode", "authorizationcode", "ClientCredentials", "CLIENTCREDENTIALS"} {
		if !validGrantType(value) {
			t.Errorf("%q is a valid grant type", value)
		}
	}
	for _, value := range []string{"", "password", "implicit"} {
		if validGrantType(value) {
			t.Errorf("%q is not a grant type credential manager supports", value)
		}
	}
}

// A stored document whose properties are not an object must still render.
func TestCredentialWireHandlesOddDocuments(t *testing.T) {
	odd := map[string]any{"properties": "not an object"}
	if wire := authorizationProviderWire(model.AuthorizationProvider{ServiceID: "/s", Name: "p", Document: odd}); wire["type"] != "Microsoft.ApiManagement/service/authorizationProviders" {
		t.Fatalf("provider wire = %v", wire)
	}
	if wire := authorizationWire(model.Authorization{ProviderID: "/s/authorizationProviders/p", Name: "a", Document: odd}); wire["type"] != "Microsoft.ApiManagement/service/authorizationProviders/authorizations" {
		t.Fatalf("authorization wire = %v", wire)
	}
	if wire := accessPolicyWire(model.AuthorizationAccessPolicy{AuthorizationID: "/s/authorizationProviders/p/authorizations/a", Name: "ap", Document: odd}); wire["type"] != "Microsoft.ApiManagement/service/authorizationProviders/authorizations/accessPolicies" {
		t.Fatalf("access policy wire = %v", wire)
	}
	// Secret redaction must survive a grant map holding non-objects.
	grants := map[string]any{"authorizationCode": "not an object", "clientCredentials": map[string]any{"clientSecret": "x"}}
	redactGrantSecrets(grants)
	if grant, _ := grants["clientCredentials"].(map[string]any); grant["clientSecret"] != nil {
		t.Fatal("the secret must be removed")
	}
}

// A store failure must be reported, not read as "this service has no
// providers": the two are different answers and a caller acts differently on
// each. Driven through the handlers directly, because request dispatch reads
// the service first and would fail there.
func TestCredentialManagerStoreFailuresAreReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	handler.LoginLink = func(string, string, string) (string, error) { return "https://idp.test/auth", nil }
	handler.ConfirmConsent = func(string, string, string) error { return nil }
	providerID := serviceModel().ID() + "/authorizationProviders/idp"
	authorizationID := providerID + "/authorizations/cred"
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	body := func(payload string) *http.Request {
		request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		return request
	}

	cases := []struct {
		name string
		run  func(*httptest.ResponseRecorder)
	}{
		{"provider collection", func(w *httptest.ResponseRecorder) {
			handler.authorizationProviderCollection(w, httptest.NewRequest(http.MethodGet, "/", nil), serviceModel().ID())
		}},
		{"provider get", func(w *httptest.ResponseRecorder) {
			handler.authorizationProviderResource(w, httptest.NewRequest(http.MethodGet, "/", nil), model.AuthorizationProvider{ServiceID: serviceModel().ID(), Name: "idp"})
		}},
		{"provider put", func(w *httptest.ResponseRecorder) {
			handler.authorizationProviderResource(w, body(`{"properties":{"identityProvider":"oauth2"}}`), model.AuthorizationProvider{ServiceID: serviceModel().ID(), Name: "idp"})
		}},
		{"provider delete", func(w *httptest.ResponseRecorder) {
			handler.authorizationProviderResource(w, httptest.NewRequest(http.MethodDelete, "/", nil), model.AuthorizationProvider{ServiceID: serviceModel().ID(), Name: "idp"})
		}},
		{"authorization collection", func(w *httptest.ResponseRecorder) {
			handler.authorizationCollection(w, httptest.NewRequest(http.MethodGet, "/", nil), providerID)
		}},
		{"authorization get", func(w *httptest.ResponseRecorder) {
			handler.authorizationResource(w, httptest.NewRequest(http.MethodGet, "/", nil), model.Authorization{ProviderID: providerID, Name: "cred"})
		}},
		{"authorization put", func(w *httptest.ResponseRecorder) {
			handler.authorizationResource(w, body(`{"properties":{"oauth2grantType":"ClientCredentials"}}`), model.Authorization{ProviderID: providerID, Name: "cred"})
		}},
		{"authorization delete", func(w *httptest.ResponseRecorder) {
			handler.authorizationResource(w, httptest.NewRequest(http.MethodDelete, "/", nil), model.Authorization{ProviderID: providerID, Name: "cred"})
		}},
		{"access policy collection", func(w *httptest.ResponseRecorder) {
			handler.accessPolicyCollection(w, httptest.NewRequest(http.MethodGet, "/", nil), authorizationID)
		}},
		{"access policy get", func(w *httptest.ResponseRecorder) {
			handler.accessPolicyResource(w, httptest.NewRequest(http.MethodGet, "/", nil), model.AuthorizationAccessPolicy{AuthorizationID: authorizationID, Name: "dev"})
		}},
		{"access policy put", func(w *httptest.ResponseRecorder) {
			handler.accessPolicyResource(w, body(`{"properties":{"objectId":"p"}}`), model.AuthorizationAccessPolicy{AuthorizationID: authorizationID, Name: "dev"})
		}},
		{"access policy delete", func(w *httptest.ResponseRecorder) {
			handler.accessPolicyResource(w, httptest.NewRequest(http.MethodDelete, "/", nil), model.AuthorizationAccessPolicy{AuthorizationID: authorizationID, Name: "dev"})
		}},
		{"consent action", func(w *httptest.ResponseRecorder) {
			handler.authorizationAction(w, httptest.NewRequest(http.MethodPost, "/", nil), model.Authorization{ProviderID: providerID, Name: "cred"}, "getLoginLinks")
		}},
	}
	for _, test := range cases {
		recorder := httptest.NewRecorder()
		test.run(recorder)
		if recorder.Code < 400 {
			t.Errorf("%s against a failed store returned %d", test.name, recorder.Code)
		}
	}
}

// PATCH on a resource whose read fails for a reason OTHER than absence must
// report the failure rather than 404, which would say the resource is gone.
func TestCredentialManagerMethodsAndPatchOnBrokenStore(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, run := range []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) {
			handler.authorizationProviderCollection(w, httptest.NewRequest(http.MethodPost, "/", nil), "svc")
		},
		func(w *httptest.ResponseRecorder) {
			handler.authorizationCollection(w, httptest.NewRequest(http.MethodPost, "/", nil), "p")
		},
		func(w *httptest.ResponseRecorder) {
			handler.accessPolicyCollection(w, httptest.NewRequest(http.MethodPost, "/", nil), "a")
		},
	} {
		recorder := httptest.NewRecorder()
		run(recorder)
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Errorf("a non-GET collection returned %d, want 405", recorder.Code)
		}
	}
}

// The remaining branches: successful list bodies, method rejection on the
// consent action, and the two writes inside confirmConsentCode.
func TestCredentialManagerRemainingBranches(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	authorization := basePath + "/authorizationProviders/github/authorizations/user" + apiQuery
	assertStatus(t, handler, http.MethodPut, authorization,
		`{"properties":{"authorizationType":"OAuth2","oauth2grantType":"AuthorizationCode"}}`, http.StatusCreated)

	// A non-empty credential list renders each entry.
	list := request(t, handler, http.MethodGet, basePath+"/authorizationProviders/github/authorizations"+apiQuery, "")
	if !strings.Contains(list.Body.String(), `"count":1`) || !strings.Contains(list.Body.String(), "AuthorizationCode") {
		t.Fatalf("authorization list = %s", list.Body.String())
	}
	// And so does a non-empty provider list.
	providers := request(t, handler, http.MethodGet, basePath+"/authorizationProviders"+apiQuery, "")
	if !strings.Contains(providers.Body.String(), `"count":1`) {
		t.Fatalf("provider list = %s", providers.Body.String())
	}

	// An unsupported method on a credential is rejected rather than ignored.
	assertStatus(t, handler, http.MethodOptions, authorization, "", http.StatusMethodNotAllowed)

	// A malformed consent body is refused before any exchange is attempted.
	handler.LoginLink = func(string, string, string) (string, error) { return "https://idp.test/auth", nil }
	handler.ConfirmConsent = func(string, string, string) error { return nil }
	confirm := basePath + "/authorizationProviders/github/authorizations/user/confirmConsentCode" + apiQuery
	assertStatus(t, handler, http.MethodPost, confirm, `not json`, http.StatusBadRequest)

	// A login-link builder that fails reports the reason rather than returning
	// an empty link a person would click into nothing.
	handler.LoginLink = func(string, string, string) (string, error) { return "", errors.New("no authorization endpoint") }
	links := basePath + "/authorizationProviders/github/authorizations/user/getLoginLinks" + apiQuery
	got := request(t, handler, http.MethodPost, links, "{}")
	if got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "authorization endpoint") {
		t.Fatalf("a failing login link = %d %s", got.Code, got.Body.String())
	}
}

// The write can fail even when the read succeeded: a parent that does not exist
// violates the foreign key. Reported rather than answered 201, which would tell
// the caller a credential exists when none was stored. Driven through the
// handlers directly, because routing checks the parent first.
func TestCredentialManagerWriteFailuresAreReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	_ = st
	put := func(payload string) *http.Request {
		request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		return request
	}

	recorder := httptest.NewRecorder()
	handler.authorizationProviderResource(recorder, put(`{"properties":{"identityProvider":"oauth2"}}`),
		model.AuthorizationProvider{ServiceID: serviceModel().ID() + "-absent", Name: "idp"})
	if recorder.Code < 400 {
		t.Errorf("a provider under a missing service returned %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	handler.authorizationResource(recorder, put(`{"properties":{"authorizationType":"OAuth2","oauth2grantType":"ClientCredentials"}}`),
		model.Authorization{ProviderID: serviceModel().ID() + "/authorizationProviders/absent", Name: "cred"})
	if recorder.Code < 400 {
		t.Errorf("a credential under a missing provider returned %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	handler.accessPolicyResource(recorder, put(`{"properties":{"objectId":"principal"}}`),
		model.AuthorizationAccessPolicy{AuthorizationID: serviceModel().ID() + "/authorizationProviders/p/authorizations/absent", Name: "dev"})
	if recorder.Code < 400 {
		t.Errorf("a policy under a missing credential returned %d", recorder.Code)
	}
}

// confirmConsentCode records the provider's refusal on the credential. If that
// write itself fails, the failure must surface rather than be reported as a
// plain validation error, which would hide a broken store.
func TestConfirmConsentRecordFailureIsReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	authorization := basePath + "/authorizationProviders/github/authorizations/user" + apiQuery
	assertStatus(t, handler, http.MethodPut, authorization,
		`{"properties":{"authorizationType":"OAuth2","oauth2grantType":"AuthorizationCode"}}`, http.StatusCreated)

	handler.LoginLink = func(string, string, string) (string, error) { return "https://idp.test/auth", nil }
	handler.ConfirmConsent = func(string, string, string) error { return errors.New("invalid_grant") }
	confirm := basePath + "/authorizationProviders/github/authorizations/user/confirmConsentCode" + apiQuery

	// Close the store AFTER the credential exists, so the read inside the
	// action succeeds from nothing and the write is what breaks.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	got := request(t, handler, http.MethodPost, confirm, `{"consentCode":"c"}`)
	if got.Code < 400 {
		t.Fatalf("a failed store write returned %d", got.Code)
	}

	// And the success path's write failure too.
	handler2, st2 := testHandler(t)
	seedService(t, st2)
	seedProvider(t, handler2)
	assertStatus(t, handler2, http.MethodPut, authorization,
		`{"properties":{"authorizationType":"OAuth2","oauth2grantType":"AuthorizationCode"}}`, http.StatusCreated)
	handler2.LoginLink = func(string, string, string) (string, error) { return "x", nil }
	handler2.ConfirmConsent = func(string, string, string) error { return nil }
	if err := st2.Close(); err != nil {
		t.Fatal(err)
	}
	if got := request(t, handler2, http.MethodPost, confirm, `{"consentCode":"c"}`); got.Code < 400 {
		t.Fatalf("a failed connect write returned %d", got.Code)
	}
}

// A path under a credential that names something other than accessPolicies is
// a resource that does not exist.
func TestAuthorizationRouteRejectsUnknownSubresources(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	assertStatus(t, handler, http.MethodGet,
		basePath+"/authorizationProviders/github/authorizations/user/nonsense/child"+apiQuery, "", http.StatusNotFound)
}

// The consent outcome must be PERSISTED, and a failed write must stop the
// caller rather than let it answer as though the state had been saved.
func TestRecordAuthorizationStatus(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	authorization := model.Authorization{
		ProviderID:        serviceModel().ID() + "/authorizationProviders/github",
		Name:              "user",
		AuthorizationType: "OAuth2", OAuth2GrantType: "AuthorizationCode",
	}
	if _, err := st.UpsertAuthorization(authorization); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	got, ok := handler.recordAuthorizationStatus(recorder, authorization, "Connected", "")
	if !ok || got.Status != "Connected" || got.ErrorMsg != "" {
		t.Fatalf("recording success = %+v ok=%v", got, ok)
	}
	recorder = httptest.NewRecorder()
	got, ok = handler.recordAuthorizationStatus(recorder, authorization, "Error", "invalid_grant")
	if !ok || got.Status != "Error" || got.ErrorMsg != "invalid_grant" {
		t.Fatalf("recording a refusal = %+v ok=%v", got, ok)
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	if _, ok := handler.recordAuthorizationStatus(recorder, authorization, "Connected", ""); ok {
		t.Fatal("a failed write must be reported, not treated as saved")
	}
	if recorder.Code < 400 {
		t.Fatalf("a failed write returned %d", recorder.Code)
	}
}

// The provider can be removed while a consent is in flight: the credential is
// read, the exchange is attempted, and by the time the refusal is recorded the
// parent is gone. The write then fails, and that must surface rather than be
// reported as a plain validation error.
func TestConsentRefusalRecordFailsWhenTheProviderDisappears(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	authorization := basePath + "/authorizationProviders/github/authorizations/user" + apiQuery
	assertStatus(t, handler, http.MethodPut, authorization,
		`{"properties":{"authorizationType":"OAuth2","oauth2grantType":"AuthorizationCode"}}`, http.StatusCreated)

	handler.LoginLink = func(string, string, string) (string, error) { return "x", nil }
	handler.ConfirmConsent = func(string, string, string) error {
		// The parent goes away mid-flight, which cascades the credential out
		// from under the write that is about to record the refusal.
		if err := st.DeleteAuthorizationProvider(serviceModel().ID() + "/authorizationProviders/github"); err != nil {
			t.Fatal(err)
		}
		return errors.New("invalid_grant")
	}
	confirm := basePath + "/authorizationProviders/github/authorizations/user/confirmConsentCode" + apiQuery
	got := request(t, handler, http.MethodPost, confirm, `{"consentCode":"c"}`)
	if got.Code < 400 {
		t.Fatalf("a failed refusal record returned %d: %s", got.Code, got.Body.String())
	}
}

// The mirror case: consent SUCCEEDS but the provider vanished before the
// credential could be marked Connected. Answering 200 there would report a
// working credential that was never stored.
func TestConsentSuccessRecordFailsWhenTheProviderDisappears(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedProvider(t, handler)
	authorization := basePath + "/authorizationProviders/github/authorizations/user" + apiQuery
	assertStatus(t, handler, http.MethodPut, authorization,
		`{"properties":{"authorizationType":"OAuth2","oauth2grantType":"AuthorizationCode"}}`, http.StatusCreated)

	handler.LoginLink = func(string, string, string) (string, error) { return "x", nil }
	handler.ConfirmConsent = func(string, string, string) error {
		if err := st.DeleteAuthorizationProvider(serviceModel().ID() + "/authorizationProviders/github"); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	confirm := basePath + "/authorizationProviders/github/authorizations/user/confirmConsentCode" + apiQuery
	got := request(t, handler, http.MethodPost, confirm, `{"consentCode":"c"}`)
	if got.Code < 400 {
		t.Fatalf("a failed connect record returned %d: %s", got.Code, got.Body.String())
	}
	if strings.Contains(got.Body.String(), "Connected") {
		t.Fatalf("a credential that was not stored must not be reported Connected: %s", got.Body.String())
	}
}
