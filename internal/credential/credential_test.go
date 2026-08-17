package credential

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type recordingExchanger struct {
	forms    []url.Values
	status   int
	body     string
	failWith error
}

func (r *recordingExchanger) Do(request *http.Request) (*http.Response, error) {
	if r.failWith != nil {
		return nil, r.failWith
	}
	raw, _ := io.ReadAll(request.Body)
	form, _ := url.ParseQuery(string(raw))
	r.forms = append(r.forms, form)
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(r.body)),
	}, nil
}

func testProvider() Provider {
	return Provider{
		TokenEndpoint:         "https://idp.test/token",
		AuthorizationEndpoint: "https://idp.test/auth",
		ClientID:              "client", ClientSecret: "secret", Scopes: "api.read offline_access",
	}
}

func TestClientCredentialsSendsScopeAndParsesTheToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	exchanger := &recordingExchanger{body: `{"access_token":"at","token_type":"Bearer","expires_in":3600,"scope":"api.read"}`}
	token, err := ClientCredentials(context.Background(), exchanger, testProvider(), now)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "at" || token.TokenType != "Bearer" || token.Scopes != "api.read" {
		t.Fatalf("token = %+v", token)
	}
	if !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v", token.ExpiresAt)
	}
	form := exchanger.forms[0]
	if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != "client" || form.Get("client_secret") != "secret" {
		t.Fatalf("form = %v", form)
	}
	// scope is a valid parameter for THIS grant.
	if form.Get("scope") != "api.read offline_access" {
		t.Fatalf("client_credentials must carry scope, got %q", form.Get("scope"))
	}
}

// RFC 6749 defines no scope parameter for an authorization-code exchange: the
// scope comes from the code. Sending it anyway is not cosmetic; a real
// authorization server is entitled to treat the request differently.
func TestCodeExchangeAndRefreshDoNotSendScope(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	exchanger := &recordingExchanger{body: `{"access_token":"at","refresh_token":"rt","expires_in":600}`}
	if _, err := ExchangeCode(context.Background(), exchanger, testProvider(), "the-code", "https://redirect.test/cb", now); err != nil {
		t.Fatal(err)
	}
	form := exchanger.forms[0]
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "the-code" {
		t.Fatalf("form = %v", form)
	}
	if form.Get("redirect_uri") != "https://redirect.test/cb" {
		t.Fatalf("redirect_uri must match the one used at authorize time, got %q", form.Get("redirect_uri"))
	}
	if form.Has("scope") {
		t.Fatalf("authorization_code must not carry scope, got %q", form.Get("scope"))
	}

	exchanger.forms = nil
	if _, err := Refresh(context.Background(), exchanger, testProvider(), "old-rt", now); err != nil {
		t.Fatal(err)
	}
	// On refresh, scope may only NARROW; sending the configured scopes could
	// silently change the grant, so it is omitted.
	if exchanger.forms[0].Has("scope") {
		t.Fatal("refresh_token must not carry the configured scope")
	}
}

// A provider that does not rotate refresh tokens omits it from the reply.
// Dropping the old one would make the credential single-use.
func TestRefreshCarriesTheOldRefreshTokenForward(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	kept := &recordingExchanger{body: `{"access_token":"new","expires_in":600}`}
	token, err := Refresh(context.Background(), kept, testProvider(), "old-rt", now)
	if err != nil {
		t.Fatal(err)
	}
	if token.RefreshToken != "old-rt" {
		t.Fatalf("RefreshToken = %q; a provider that does not rotate must not cost us the credential", token.RefreshToken)
	}
	rotated := &recordingExchanger{body: `{"access_token":"new","refresh_token":"fresh","expires_in":600}`}
	token, err = Refresh(context.Background(), rotated, testProvider(), "old-rt", now)
	if err != nil || token.RefreshToken != "fresh" {
		t.Fatalf("a rotated refresh token must replace the old one, got %q %v", token.RefreshToken, err)
	}
}

func TestTokenRequestsSurfaceProviderErrors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// The provider's own code is preserved: invalid_grant and invalid_client
	// need different fixes, and collapsing them to "failed" loses that.
	refused := &recordingExchanger{status: 400, body: `{"error":"invalid_grant","error_description":"code is expired"}`}
	_, err := ExchangeCode(context.Background(), refused, testProvider(), "c", "r", now)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") || !strings.Contains(err.Error(), "code is expired") {
		t.Fatalf("error = %v", err)
	}

	for name, exchanger := range map[string]*recordingExchanger{
		"transport failure": {failWith: errors.New("dial refused")},
		"not JSON":          {body: "<html>"},
		"no access token":   {body: `{"token_type":"Bearer"}`},
		"error status":      {status: 500, body: `{}`},
	} {
		if _, err := ClientCredentials(context.Background(), exchanger, testProvider(), now); err == nil {
			t.Errorf("%s must be reported", name)
		}
	}

	// A provider with no token endpoint cannot be used at all.
	if _, err := ClientCredentials(context.Background(), &recordingExchanger{}, Provider{}, now); err == nil {
		t.Error("a provider with no token endpoint must fail")
	}
	// An endpoint the http package cannot parse fails at construction.
	if _, err := ClientCredentials(context.Background(), &recordingExchanger{}, Provider{TokenEndpoint: "://nope"}, now); err == nil {
		t.Error("an unparseable token endpoint must fail")
	}
}

// expires_in is a number per RFC 6749 and a string in several real providers.
func TestExpiresInAcceptsBothEncodings(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for body, want := range map[string]bool{
		`{"access_token":"a","expires_in":60}`:   true,
		`{"access_token":"a","expires_in":"60"}`: true,
		`{"access_token":"a"}`:                   false,
	} {
		token, err := ClientCredentials(context.Background(), &recordingExchanger{body: body}, testProvider(), now)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if got := !token.ExpiresAt.IsZero(); got != want {
			t.Errorf("%s: ExpiresAt set = %v, want %v", body, got, want)
		}
	}
	// A lifetime that is neither a number nor numeric text fails the exchange
	// outright. A token whose expiry we cannot determine cannot be refreshed at
	// the right moment, and pretending it has no expiry would defer the failure
	// to an unpredictable later request against the backend.
	if _, err := ClientCredentials(context.Background(), &recordingExchanger{body: `{"access_token":"a","expires_in":"soon"}`}, testProvider(), now); err == nil {
		t.Fatal("a malformed expires_in must fail the exchange rather than be ignored")
	}

	// A missing token_type defaults to Bearer rather than being sent empty,
	// which would produce a header of "  <token>".
	token, _ := ClientCredentials(context.Background(), &recordingExchanger{body: `{"access_token":"a"}`}, testProvider(), now)
	if token.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q", token.TokenType)
	}
}

// The skew matters: a token that expires mid-flight fails the backend call, and
// the caller cannot tell that from a real authorization failure.
func TestExpiredRenewsEarly(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if (Token{}).Expired(now) {
		t.Fatal("a token with no expiry never expires")
	}
	if (Token{ExpiresAt: now.Add(time.Hour)}).Expired(now) {
		t.Fatal("a token valid for an hour is not expired")
	}
	if !(Token{ExpiresAt: now.Add(10 * time.Second)}).Expired(now) {
		t.Fatal("a token expiring inside the skew must be renewed early")
	}
	if !(Token{ExpiresAt: now.Add(-time.Second)}).Expired(now) {
		t.Fatal("an expired token is expired")
	}
}

func TestLoginLinkBuildsAConsentURL(t *testing.T) {
	link, err := LoginLink(testProvider(), "https://redirect.test/cb", "state-value")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("response_type") != "code" || query.Get("client_id") != "client" {
		t.Fatalf("query = %v", query)
	}
	if query.Get("redirect_uri") != "https://redirect.test/cb" || query.Get("state") != "state-value" {
		t.Fatalf("query = %v", query)
	}
	// OIDC ignores offline_access unless consent is requested, so a provider
	// that follows the spec issues no refresh token without this and the
	// credential works exactly once.
	if query.Get("prompt") != "consent" {
		t.Fatalf("offline_access was requested, so prompt=consent is required; got %q", query.Get("prompt"))
	}

	// Without offline_access, forcing re-consent every login would be its own
	// defect, so prompt is left off.
	plain := testProvider()
	plain.Scopes = "api.read"
	link, _ = LoginLink(plain, "https://redirect.test/cb", "")
	parsed, _ = url.Parse(link)
	if parsed.Query().Has("prompt") {
		t.Fatal("prompt=consent must not be forced when offline access was not requested")
	}
	if parsed.Query().Has("state") {
		t.Fatal("an empty state must be omitted rather than sent blank")
	}

	if _, err := LoginLink(Provider{}, "r", "s"); err == nil {
		t.Error("a provider with no authorization endpoint cannot build a login link")
	}
	if _, err := LoginLink(Provider{AuthorizationEndpoint: "://nope"}, "r", "s"); err == nil {
		t.Error("an unparseable authorization endpoint must fail")
	}
}

// An oversized token response is refused rather than read into memory.
func TestOversizedTokenResponseIsBounded(t *testing.T) {
	huge := &recordingExchanger{body: `{"access_token":"` + strings.Repeat("x", maxTokenResponseBytes) + `"}`}
	token, err := ClientCredentials(context.Background(), huge, testProvider(), time.Now())
	if err == nil && len(token.AccessToken) >= maxTokenResponseBytes {
		t.Fatal("the response must be bounded")
	}
}

// A refresh that the provider refuses must surface, not fall back to the old
// token: continuing with a credential the provider has revoked would send a
// dead token to the backend and read as a backend authorization bug.
func TestRefreshFailurePropagates(t *testing.T) {
	refused := &recordingExchanger{status: 400, body: `{"error":"invalid_grant"}`}
	if _, err := Refresh(context.Background(), refused, testProvider(), "rt", time.Unix(1, 0)); err == nil {
		t.Fatal("a refused refresh must be reported")
	}
}

// The request body is form-encoded with the documented content type; a provider
// reading it as JSON would see nothing.
func TestTokenRequestUsesFormEncoding(t *testing.T) {
	var seen *http.Request
	capture := exchangerFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"a"}`))}, nil
	})
	if _, err := ClientCredentials(context.Background(), capture, testProvider(), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if got := seen.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := seen.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept = %q", got)
	}
	if seen.Method != http.MethodPost {
		t.Fatalf("method = %s", seen.Method)
	}
}

type exchangerFunc func(*http.Request) (*http.Response, error)

func (f exchangerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// A provider with no secret (public client, PKCE-style) must not send an empty
// client_secret, which some servers reject outright.
func TestPublicClientOmitsTheSecret(t *testing.T) {
	provider := testProvider()
	provider.ClientSecret = ""
	exchanger := &recordingExchanger{body: `{"access_token":"a"}`}
	if _, err := ClientCredentials(context.Background(), exchanger, provider, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if exchanger.forms[0].Has("client_secret") {
		t.Fatal("an empty client_secret must be omitted, not sent blank")
	}
}

// A response whose body fails mid-read must be reported rather than parsed as a
// truncated token, which could yield a plausible-looking but wrong credential.
func TestUnreadableTokenResponseIsReported(t *testing.T) {
	broken := exchangerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(failingReader{})}, nil
	})
	if _, err := ClientCredentials(context.Background(), broken, testProvider(), time.Unix(1, 0)); err == nil {
		t.Fatal("a body that fails mid-read must be reported")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
