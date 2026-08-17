package gateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/credential"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const emulatorServiceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator"

func credentialStore(t *testing.T, grant string) *store.Store {
	t.Helper()
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAuthorizationProvider(model.AuthorizationProvider{
		ServiceID: emulatorServiceID, Name: "idp", DisplayName: "IdP", IdentityProvider: "oauth2",
		Document: map[string]any{"properties": map[string]any{"oauth2": map[string]any{
			"tokenEndpoint":         "https://idp.test/token",
			"authorizationEndpoint": "https://idp.test/auth",
			"grantTypes": map[string]any{"clientCredentials": map[string]any{
				"clientId": "cid", "clientSecret": "secret", "scopes": "api.read",
			}},
		}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAuthorization(model.Authorization{
		ProviderID: emulatorServiceID + "/authorizationProviders/idp", Name: "cred",
		AuthorizationType: "OAuth2", OAuth2GrantType: grant, Status: "Connected",
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func tokenRuntime(body string, status int, calls *int) *Runtime {
	return New("emulator", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls != nil {
			*calls++
		}
		code := status
		if code == 0 {
			code = http.StatusOK
		}
		return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
}

func TestFetchCredentialObtainsAndCachesAToken(t *testing.T) {
	st := credentialStore(t, "ClientCredentials")
	calls := 0
	runtime := tokenRuntime(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"scope":"api.read"}`, 200, &calls)

	got, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "cred")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "at" || got.ClientID != "cid" || got.Scopes != "api.read" {
		t.Fatalf("context = %+v", got)
	}
	if got.ExpiresIn <= 0 {
		t.Fatalf("ExpiresIn = %d", got.ExpiresIn)
	}

	// A token per request would double every API call and burn provider rate
	// limits, so a live token is reused.
	if _, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "cred"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("token requests = %d, want the second call served from cache", calls)
	}

	// Forget is what makes a reconnected or deleted credential stop being
	// served from memory.
	runtime.credentials.Forget(emulatorServiceID + "/authorizationProviders/idp/authorizations/cred")
	if _, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "cred"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("token requests = %d, want a fresh one after Forget", calls)
	}
}

// An expired token is renewed rather than sent, because a token that dies
// mid-flight looks to the caller like a backend authorization failure.
func TestExpiredTokenIsReacquired(t *testing.T) {
	st := credentialStore(t, "ClientCredentials")
	calls := 0
	runtime := tokenRuntime(`{"access_token":"fresh","expires_in":3600}`, 200, &calls)
	id := emulatorServiceID + "/authorizationProviders/idp/authorizations/cred"
	runtime.credentials.put(id, credential.Token{AccessToken: "stale", ExpiresAt: time.Now().Add(-time.Minute)})

	got, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "cred")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "fresh" {
		t.Fatalf("AccessToken = %q, want the renewed one", got.AccessToken)
	}
	if calls != 1 {
		t.Fatalf("token requests = %d", calls)
	}
}

// An authorization-code credential has nothing to send until a human consents.
// Saying so beats a transport error, which would send an operator hunting the
// wrong problem.
func TestAuthorizationCodeNeedsConsentBeforeUse(t *testing.T) {
	st := credentialStore(t, "AuthorizationCode")
	runtime := tokenRuntime(`{"access_token":"never"}`, 200, nil)
	_, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "cred")
	if err == nil || !strings.Contains(err.Error(), "consent") {
		t.Fatalf("error = %v; it must name consent", err)
	}

	// Once consented, the stored refresh token is used to renew.
	id := emulatorServiceID + "/authorizationProviders/idp/authorizations/cred"
	runtime.credentials.put(id, credential.Token{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Minute)})
	got, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "cred")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "never" {
		t.Fatalf("AccessToken = %q, want the refreshed token", got.AccessToken)
	}
}

func TestFetchCredentialReportsMissingResources(t *testing.T) {
	st := credentialStore(t, "ClientCredentials")
	runtime := tokenRuntime(`{"access_token":"at"}`, 200, nil)
	if _, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "absent", "cred"); err == nil {
		t.Error("an unknown provider must be reported")
	}
	if _, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "absent"); err == nil {
		t.Error("an unknown credential must be reported")
	}
	// A provider naming a service the request did not land on must not resolve:
	// the scope comes from the route, not from the policy.
	if _, err := runtime.fetchCredential(context.Background(), st, "/subscriptions/other", "idp", "cred"); err == nil {
		t.Error("a credential in another service must not be reachable")
	}
	// A refused token request surfaces the provider's own error.
	refusing := tokenRuntime(`{"error":"invalid_client"}`, 400, nil)
	if _, err := refusing.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "cred"); err == nil {
		t.Error("a refused grant must be reported")
	}
}

func TestProviderConfigReadsTheGrantItIsGiven(t *testing.T) {
	base := func(properties map[string]any) model.AuthorizationProvider {
		return model.AuthorizationProvider{Name: "p", Document: map[string]any{"properties": properties}}
	}
	if _, err := providerConfig(base(map[string]any{})); err == nil {
		t.Error("a provider with no oauth2 block cannot be used")
	}
	if _, err := providerConfig(base(map[string]any{"oauth2": map[string]any{}})); err == nil {
		t.Error("a provider with no token endpoint cannot be used")
	}
	// The authorization-code grant's own client wins over the top-level one.
	config, err := providerConfig(base(map[string]any{"oauth2": map[string]any{
		"tokenEndpoint": "https://idp.test/token", "clientId": "outer", "scopes": "outer.scope",
		"grantTypes": map[string]any{"authorizationCode": map[string]any{
			"clientId": "inner", "clientSecret": "s", "scopes": "inner.scope",
		}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientID != "inner" || config.Scopes != "inner.scope" || config.ClientSecret != "s" {
		t.Fatalf("config = %+v", config)
	}
	// A grant entry that is not an object is skipped rather than panicking.
	config, err = providerConfig(base(map[string]any{"oauth2": map[string]any{
		"tokenEndpoint": "https://idp.test/token", "clientId": "outer",
		"grantTypes": map[string]any{"authorizationCode": "nonsense"},
	}}))
	if err != nil || config.ClientID != "outer" {
		t.Fatalf("config = %+v %v", config, err)
	}
}

// The refresh token is deliberately absent from what a policy can read: an
// expression that could export it would export a long-lived grant, which is the
// one thing credential manager exists to prevent.
func TestAuthorizationContextWithholdsTheRefreshToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	got := authorizationContext(
		credential.Provider{ClientID: "cid", Scopes: "configured"},
		credential.Token{AccessToken: "at", RefreshToken: "SECRET", ExpiresAt: now.Add(time.Hour)},
		now,
	)
	if got.AccessToken != "at" || got.ClientID != "cid" {
		t.Fatalf("context = %+v", got)
	}
	if strings.Contains(got.Scopes, "SECRET") || got.AccessToken == "SECRET" {
		t.Fatal("the refresh token must never reach a policy")
	}
	if got.ExpiresIn != 3600 {
		t.Fatalf("ExpiresIn = %d", got.ExpiresIn)
	}
	// The token's own scopes win; the configured ones are the fallback.
	scoped := authorizationContext(credential.Provider{Scopes: "configured"}, credential.Token{Scopes: "granted"}, now)
	if scoped.Scopes != "granted" {
		t.Fatalf("Scopes = %q", scoped.Scopes)
	}
	// A token already past its expiry reports no remaining lifetime rather than
	// a negative one, which a policy comparing against zero would misread.
	past := authorizationContext(credential.Provider{}, credential.Token{ExpiresAt: now.Add(-time.Hour)}, now)
	if past.ExpiresIn != 0 {
		t.Fatalf("ExpiresIn = %d, want 0 for an expired token", past.ExpiresIn)
	}
}

func TestCredentialFetcherRequiresAStore(t *testing.T) {
	runtime := New("emulator", &http.Client{})
	fetch := runtime.credentialFetcher(httpRequest(), emulatorServiceID)
	if _, err := fetch("idp", "cred"); err == nil {
		t.Fatal("with no store attached the fetcher must report it rather than return an empty credential")
	}
}

func httpRequest() *http.Request {
	request, _ := http.NewRequest(http.MethodGet, "http://gateway/", nil)
	return request
}

func TestConsentHelpersUseTheProviderConfiguration(t *testing.T) {
	st := credentialStore(t, "AuthorizationCode")
	runtime := tokenRuntime(`{"access_token":"at","refresh_token":"rt","expires_in":600}`, 200, nil)
	providerID := emulatorServiceID + "/authorizationProviders/idp"
	authorizationID := providerID + "/authorizations/cred"

	link, err := runtime.CredentialLoginLink(st, providerID, authorizationID, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "https://idp.test/auth") {
		t.Fatalf("loginLink = %q", link)
	}
	// The authorization ID is the state, so a code obtained for one credential
	// cannot be redeemed into another.
	if !strings.Contains(link, "state=") || !strings.Contains(link, "cred") {
		t.Fatalf("the login link must bind the credential through state: %q", link)
	}
	if _, err := runtime.CredentialLoginLink(st, providerID+"-absent", authorizationID, ""); err == nil {
		t.Error("an unknown provider must be reported")
	}

	if err := runtime.CredentialConfirmConsent(st, providerID, authorizationID, "the-code"); err != nil {
		t.Fatal(err)
	}
	if token, ok := runtime.credentials.get(authorizationID); !ok || token.RefreshToken != "rt" {
		t.Fatalf("the refresh token must be retained for renewal, got %+v ok=%v", token, ok)
	}
	if err := runtime.CredentialConfirmConsent(st, providerID+"-absent", authorizationID, "c"); err == nil {
		t.Error("redeeming against an unknown provider must be reported")
	}

	// Without a refresh token the credential works once and then fails at an
	// unpredictable later moment, so it is refused now with the reason named.
	once := tokenRuntime(`{"access_token":"at","expires_in":600}`, 200, nil)
	err = once.CredentialConfirmConsent(st, providerID, authorizationID, "the-code")
	if err == nil || !strings.Contains(err.Error(), "offline access") {
		t.Fatalf("error = %v; it must name the missing offline access", err)
	}
}

// The default client exists so a runtime constructed without one still has a
// timeout rather than hanging on a wedged provider.
func TestCredentialClientAlwaysHasATimeout(t *testing.T) {
	runtime := &Runtime{}
	if client := runtime.credentialClient(); client == nil || client.Timeout == 0 {
		t.Fatal("a runtime with no client must still get a bounded one")
	}
	configured := New("emulator", &http.Client{Timeout: 5 * time.Second})
	if configured.credentialClient().Timeout != 5*time.Second {
		t.Fatal("a configured client must be used as-is")
	}
}

func TestConsentHelpersReportBrokenProviders(t *testing.T) {
	st := credentialStore(t, "AuthorizationCode")
	runtime := tokenRuntime(`{"access_token":"at","refresh_token":"rt"}`, 200, nil)
	providerID := emulatorServiceID + "/authorizationProviders/idp"

	// A provider whose oauth2 block is missing cannot build a link or redeem.
	if _, err := st.UpsertAuthorizationProvider(model.AuthorizationProvider{
		ServiceID: emulatorServiceID, Name: "bare", IdentityProvider: "oauth2",
		Document: map[string]any{"properties": map[string]any{}},
	}); err != nil {
		t.Fatal(err)
	}
	bare := emulatorServiceID + "/authorizationProviders/bare"
	if _, err := runtime.CredentialLoginLink(st, bare, bare+"/authorizations/x", ""); err == nil {
		t.Error("a provider with no oauth2 configuration cannot build a login link")
	}
	if err := runtime.CredentialConfirmConsent(st, bare, bare+"/authorizations/x", "c"); err == nil {
		t.Error("a provider with no oauth2 configuration cannot redeem a code")
	}

	// A refused exchange surfaces the provider's error rather than connecting.
	refusing := tokenRuntime(`{"error":"invalid_grant"}`, 400, nil)
	if err := refusing.CredentialConfirmConsent(st, providerID, providerID+"/authorizations/cred", "c"); err == nil {
		t.Error("a refused code must be reported")
	}
}

// The fetcher resolves through the attached store, which is what binds a policy
// to the service the request landed on.
func TestCredentialFetcherResolvesThroughTheAttachedStore(t *testing.T) {
	st := credentialStore(t, "ClientCredentials")
	runtime := tokenRuntime(`{"access_token":"at","expires_in":600}`, 200, nil)
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	got, err := runtime.credentialFetcher(httpRequest(), emulatorServiceID)("idp", "cred")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "at" {
		t.Fatalf("AccessToken = %q", got.AccessToken)
	}
}

// A provider whose stored configuration cannot be read fails the fetch rather
// than returning an empty credential a policy would attach as "Bearer ".
func TestFetchCredentialRejectsAnUnusableProvider(t *testing.T) {
	st := credentialStore(t, "ClientCredentials")
	if _, err := st.UpsertAuthorizationProvider(model.AuthorizationProvider{
		ServiceID: emulatorServiceID, Name: "idp", IdentityProvider: "oauth2",
		Document: map[string]any{"properties": map[string]any{}},
	}); err != nil {
		t.Fatal(err)
	}
	runtime := tokenRuntime(`{"access_token":"at"}`, 200, nil)
	if _, err := runtime.fetchCredential(context.Background(), st, emulatorServiceID, "idp", "cred"); err == nil {
		t.Fatal("a provider with no oauth2 configuration must fail the fetch")
	}
}
