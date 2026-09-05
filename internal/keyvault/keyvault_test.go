package keyvault

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPGetSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api-version") != "7.4" {
			t.Fatalf("api-version = %q", r.URL.Query().Get("api-version"))
		}
		switch r.URL.Path {
		case "/secrets/name":
			_, _ = io.WriteString(w, `{"value":"current","contentType":"text/plain","id":"https://vault/secrets/name/v1"}`)
		case "/secrets/name/v2":
			_, _ = io.WriteString(w, `{"value":"versioned","id":"https://vault/secrets/name/v2"}`)
		case "/secrets/empty":
			_, _ = io.WriteString(w, `{"value":""}`)
		case "/secrets/broken":
			_, _ = io.WriteString(w, `{`)
		case "/secrets/missing":
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"code":"SecretNotFound","message":"missing"}}`)
		case "/secrets/denied":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"message":"no access"}}`)
		case "/secrets/unauth":
			w.WriteHeader(http.StatusUnauthorized)
		case "/secrets/slow":
			w.WriteHeader(http.StatusGatewayTimeout)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client := HTTP{Client: server.Client()}

	got, err := client.GetSecret(context.Background(), server.URL+"/secrets/name")
	if err != nil || got.Value != "current" || got.ContentType != "text/plain" || got.ID == "" {
		t.Fatalf("current secret = %+v, %v", got, err)
	}
	got, err = client.GetSecret(context.Background(), server.URL+"/secrets/name/v2?api-version=7.4")
	if err != nil || got.Value != "versioned" {
		t.Fatalf("versioned secret = %+v, %v", got, err)
	}
	if _, err := client.GetSecret(context.Background(), server.URL+"/secrets/empty"); err == nil {
		t.Fatal("empty secret accepted")
	}
	if _, err := client.GetSecret(context.Background(), server.URL+"/secrets/broken"); err == nil {
		t.Fatal("malformed secret accepted")
	}
	if _, err := client.GetSecret(context.Background(), "not-a-url"); classifyCode(err) != "Error" {
		t.Fatalf("invalid identifier = %v", err)
	}
	if _, err := client.GetSecret(context.Background(), "http://%"); classifyCode(err) != "Error" {
		t.Fatalf("parse identifier = %v", err)
	}
	if _, err := client.GetSecret(context.Background(), server.URL+"/keys/name"); err == nil {
		t.Fatal("key identifier accepted")
	}
	if _, err := client.GetSecret(context.Background(), server.URL+"/secrets/missing"); classifyCode(err) != "NotFound" {
		t.Fatalf("missing secret = %v", err)
	}
	if _, err := client.GetSecret(context.Background(), server.URL+"/secrets/denied"); classifyCode(err) != "Forbidden" {
		t.Fatalf("denied secret = %v", err)
	}
	if _, err := client.GetSecret(context.Background(), server.URL+"/secrets/unauth"); classifyCode(err) != "Unauthorized" {
		t.Fatalf("unauth secret = %v", err)
	}
	if _, err := client.GetSecret(context.Background(), server.URL+"/secrets/slow"); classifyCode(err) != "Timeout" {
		t.Fatalf("timeout secret = %v", err)
	}
	if _, err := client.GetSecret(context.Background(), server.URL+"/secrets/other"); classifyCode(err) != "Error" {
		t.Fatalf("other secret = %v", err)
	}
}

func TestHTTPGetSecretTransportAndDefaultClient(t *testing.T) {
	client := HTTP{Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	})}}
	if _, err := client.GetSecret(context.Background(), "https://vault.test/secrets/name"); err == nil || classifyCode(err) != "Error" {
		t.Fatalf("transport error = %v", err)
	}
	reader := HTTP{Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errReader{}), Header: make(http.Header)}, nil
	})}}
	if _, err := reader.GetSecret(context.Background(), "https://vault.test/secrets/name"); err == nil {
		t.Fatal("body read error accepted")
	}
	timeout := HTTP{Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusRequestTimeout, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}}
	if _, err := timeout.GetSecret(context.Background(), "https://vault.test/secrets/name"); classifyCode(err) != "Timeout" {
		t.Fatalf("request timeout = %v", err)
	}
	if _, err := (HTTP{}).GetSecret(context.Background(), "https://127.0.0.1:1/secrets/name"); err == nil {
		t.Fatal("default client request succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (HTTP{Client: http.DefaultClient}).GetSecret(ctx, "https://vault.test/secrets/name"); err == nil {
		t.Fatal("canceled request succeeded")
	}
}

func classifyCode(err error) string {
	code, _ := Classify(err)
	return code
}

func TestHTTPGetSecretRequestBuildFailure(t *testing.T) {
	original := newHTTPRequest
	t.Cleanup(func() { newHTTPRequest = original })
	newHTTPRequest = func(context.Context, string, string, io.Reader) (*http.Request, error) {
		return nil, errors.New("build failed")
	}
	if _, err := (HTTP{Client: http.DefaultClient}).GetSecret(context.Background(), "https://vault.test/secrets/name"); err == nil {
		t.Fatal("request build failure accepted")
	}
}

func TestHTTPGetSecretChallenge(t *testing.T) {
	var seenAuth string
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/secrets/name" && r.Header.Get("Authorization") == "":
			w.Header().Set("WWW-Authenticate", `Bearer authorization="https://identity.example/oauth2/token", resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/secrets/name" && r.Header.Get("Authorization") == "Bearer vault-token":
			seenAuth = r.Header.Get("Authorization")
			_, _ = io.WriteString(w, `{"value":"protected"}`)
		case r.URL.Path == "/secrets/name":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/secrets/quoted":
			w.Header().Set("WWW-Authenticate", `Bearer authorization="https://identity.example/a,b", resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer vault.Close()
	client := HTTP{Client: vault.Client(), AcquireToken: func(_ context.Context, resource, authorization string) (string, error) {
		if resource != "https://vault.azure.net" || authorization != "https://identity.example/oauth2/token" {
			t.Fatalf("challenge = %q %q", resource, authorization)
		}
		return "vault-token", nil
	}}
	got, err := client.GetSecret(context.Background(), vault.URL+"/secrets/name")
	if err != nil || got.Value != "protected" || seenAuth != "Bearer vault-token" {
		t.Fatalf("challenged secret = %+v %q %v", got, seenAuth, err)
	}
	if _, err := (HTTP{Client: vault.Client(), AcquireToken: func(context.Context, string, string) (string, error) {
		return "", errors.New("identity down")
	}}).GetSecret(context.Background(), vault.URL+"/secrets/name"); classifyCode(err) != "Unauthorized" {
		t.Fatalf("token error = %v", err)
	}
	if _, err := (HTTP{Client: vault.Client(), AcquireToken: func(context.Context, string, string) (string, error) {
		return "   ", nil
	}}).GetSecret(context.Background(), vault.URL+"/secrets/name"); classifyCode(err) != "Unauthorized" {
		t.Fatalf("empty token = %v", err)
	}
	if _, err := (HTTP{Client: vault.Client(), AcquireToken: func(context.Context, string, string) (string, error) {
		return "other", nil
	}}).GetSecret(context.Background(), vault.URL+"/secrets/name"); classifyCode(err) != "Unauthorized" {
		t.Fatalf("retry unauthorized = %v", err)
	}
	quoted := HTTP{Client: vault.Client(), AcquireToken: func(_ context.Context, _, authorization string) (string, error) {
		if authorization != "https://identity.example/a,b" {
			t.Fatalf("quoted authorization = %q", authorization)
		}
		return "", errors.New("stop")
	}}
	if _, err := quoted.GetSecret(context.Background(), vault.URL+"/secrets/quoted"); classifyCode(err) != "Unauthorized" {
		t.Fatalf("quoted challenge = %v", err)
	}
	if got := parseBearerChallenge(`Bearer authorization_uri="https://login.example", resource_id="https://vault.azure.net", ignored`); got.authorization != "https://login.example" || got.resource != "https://vault.azure.net" {
		t.Fatalf("alias challenge = %+v", got)
	}
	if got := parseBearerChallenge(""); got != (bearerChallenge{}) {
		t.Fatalf("empty challenge = %+v", got)
	}
	if got := parseBearerChallenge(`Basic realm="vault"`); got != (bearerChallenge{}) {
		t.Fatalf("non-bearer challenge = %+v", got)
	}

	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" || r.URL.Query().Get("api-version") != "2018-02-01" || r.URL.Query().Get("resource") != "https://vault.azure.net" {
			t.Fatalf("imds request = %s %v", r.URL.String(), r.Header)
		}
		switch r.URL.Path {
		case "/metadata/identity/oauth2/token":
			_, _ = io.WriteString(w, `{"access_token":"imds-token"}`)
		case "/oauth2/token":
			_, _ = io.WriteString(w, `{"access_token":"path-token"}`)
		case "/empty/oauth2/token":
			_, _ = io.WriteString(w, `{"access_token":""}`)
		case "/broken/oauth2/token":
			_, _ = io.WriteString(w, `{`)
		case "/denied/oauth2/token":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer identity.Close()
	imdsVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer imds-token" {
			_, _ = io.WriteString(w, `{"value":"imds"}`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer authorization="`+identity.URL+`", resource="https://vault.azure.net"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer imdsVault.Close()
	got, err = (HTTP{Client: imdsVault.Client()}).GetSecret(context.Background(), imdsVault.URL+"/secrets/name")
	if err != nil || got.Value != "imds" {
		t.Fatalf("imds secret = %+v, %v", got, err)
	}
	if token, err := acquireManagedIdentityToken(context.Background(), identity.Client(), "https://vault.azure.net", identity.URL+"/oauth2/token"); err != nil || token != "path-token" {
		t.Fatalf("path token = %q %v", token, err)
	}
	if _, err := acquireManagedIdentityToken(context.Background(), identity.Client(), "https://vault.azure.net", identity.URL+"/empty/oauth2/token"); classifyCode(err) != "Unauthorized" {
		t.Fatalf("empty imds = %v", err)
	}
	if _, err := acquireManagedIdentityToken(context.Background(), identity.Client(), "https://vault.azure.net", identity.URL+"/broken/oauth2/token"); err == nil {
		t.Fatal("broken imds accepted")
	}
	if _, err := acquireManagedIdentityToken(context.Background(), identity.Client(), "https://vault.azure.net", identity.URL+"/denied/oauth2/token"); classifyCode(err) != "Forbidden" {
		t.Fatalf("denied imds = %v", err)
	}
	if _, err := acquireManagedIdentityToken(context.Background(), nil, "https://vault.azure.net", "not-a-url"); classifyCode(err) != "Unauthorized" {
		t.Fatalf("invalid authorization = %v", err)
	}
	if _, err := acquireManagedIdentityToken(context.Background(), nil, "https://vault.azure.net", "https://127.0.0.1:1"); err == nil {
		t.Fatal("default imds client succeeded")
	}
	if _, err := acquireManagedIdentityToken(context.Background(), &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	})}, "https://vault.azure.net", "https://identity.test"); err == nil {
		t.Fatal("imds transport error accepted")
	}
	if _, err := acquireManagedIdentityToken(context.Background(), &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errReader{}), Header: make(http.Header)}, nil
	})}, "https://vault.azure.net", "https://identity.test"); err == nil {
		t.Fatal("imds body read accepted")
	}
	original := newHTTPRequest
	t.Cleanup(func() { newHTTPRequest = original })
	newHTTPRequest = func(context.Context, string, string, io.Reader) (*http.Request, error) {
		return nil, errors.New("build failed")
	}
	if _, err := acquireManagedIdentityToken(context.Background(), identity.Client(), "https://vault.azure.net", identity.URL); err == nil {
		t.Fatal("imds request build accepted")
	}
}

func TestClassify(t *testing.T) {
	if code, message := Classify(nil); code != "Success" || message != "" {
		t.Fatalf("nil classify = %s %q", code, message)
	}
	if code, message := Classify(&StatusError{}); code != "Error" || message != "" {
		t.Fatalf("empty status classify = %s %q", code, message)
	}
	if (*StatusError)(nil).Error() != "" {
		t.Fatal("nil status error message")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// A vault that challenges, and an authority that answers with client
// credentials. The two are one server so the test can assert that the token
// the authority minted is the one the vault was shown.
func challengingVault(t *testing.T, tokenBody string, tokenStatus int) (*httptest.Server, *[]url.Values) {
	t.Helper()
	var grants []url.Values
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = r.ParseForm()
			grants = append(grants, r.PostForm)
			w.WriteHeader(tokenStatus)
			_, _ = io.WriteString(w, tokenBody)
		case r.Header.Get("Authorization") == "":
			// The authority is this same server, so the challenge points at it.
			w.Header().Set("WWW-Authenticate",
				`Bearer authorization="`+server.URL+`/tenant", resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"code":"Unauthorized","message":"missing token"}}`)
		case r.Header.Get("Authorization") != "Bearer minted-token":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":"Forbidden","message":"wrong token"}}`)
		default:
			_, _ = io.WriteString(w, `{"value":"through-the-challenge","id":"https://vault/secrets/s/v1"}`)
		}
	})
	server.Start()
	t.Cleanup(server.Close)
	return server, &grants
}

func TestClientCredentialsAnswerTheChallenge(t *testing.T) {
	// The path this exists for. Measured against azure-keyvault-emulator: with
	// no credentials the IMDS approximation reaches entra's operator portal and
	// the retrieval dies on `<!doctype html>`.
	server, grants := challengingVault(t, `{"access_token":"minted-token"}`, http.StatusOK)
	retriever := HTTP{Client: server.Client(), ClientID: "app", ClientSecret: "secret"}
	secret, err := retriever.GetSecret(context.Background(), server.URL+"/secrets/s")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if secret.Value != "through-the-challenge" {
		t.Errorf("value = %q", secret.Value)
	}
	if len(*grants) != 1 {
		t.Fatalf("token requests = %d, want 1", len(*grants))
	}
	form := (*grants)[0]
	// The scope is the resource the CHALLENGE named, not one we chose, and it
	// carries the /.default suffix the v2.0 endpoint requires.
	for field, want := range map[string]string{
		"grant_type": "client_credentials", "client_id": "app",
		"client_secret": "secret", "scope": "https://vault.azure.net/.default",
	} {
		if form.Get(field) != want {
			t.Errorf("%s = %q, want %q", field, form.Get(field), want)
		}
	}
}

func TestAnInjectedAcquireTokenStillWins(t *testing.T) {
	// Ordering matters: the tests that predate the credentials inject
	// AcquireToken, and must keep working unchanged.
	server, grants := challengingVault(t, `{"access_token":"minted-token"}`, http.StatusOK)
	retriever := HTTP{
		Client: server.Client(), ClientID: "app", ClientSecret: "secret",
		AcquireToken: func(context.Context, string, string) (string, error) { return "minted-token", nil },
	}
	if _, err := retriever.GetSecret(context.Background(), server.URL+"/secrets/s"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if len(*grants) != 0 {
		t.Errorf("the token endpoint was called %d times despite an injected AcquireToken", len(*grants))
	}
}

func TestClientCredentialsFailures(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		body   string
		status int
		want   string
	}{
		{"the authority refuses", `{"error":"invalid_client"}`, http.StatusUnauthorized, "invalid_client"},
		// The exact shape of the defect: a catch-all answering 200 with HTML.
		{"the authority answers HTML", `<!doctype html><html></html>`, http.StatusOK, "did not return JSON"},
		{"the authority answers no token", `{"token_type":"Bearer"}`, http.StatusOK, "no access_token"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server, _ := challengingVault(t, testCase.body, testCase.status)
			retriever := HTTP{Client: server.Client(), ClientID: "app", ClientSecret: "secret"}
			_, err := retriever.GetSecret(context.Background(), server.URL+"/secrets/s")
			if err == nil {
				t.Fatal("expected a failure")
			}
			code, message := Classify(err)
			if code != "Unauthorized" {
				t.Errorf("classified %q, want Unauthorized", code)
			}
			if !strings.Contains(message, testCase.want) {
				t.Errorf("message = %q, want it to mention %q", message, testCase.want)
			}
		})
	}
}

func TestClientCredentialsTokenURL(t *testing.T) {
	for _, testCase := range []struct{ name, authority, want string }{
		{"a bare authority gains the token path", "https://sts.test/tenant", "https://sts.test/tenant/oauth2/v2.0/token"},
		{"a trailing slash does not double up", "https://sts.test/tenant/", "https://sts.test/tenant/oauth2/v2.0/token"},
		{"an authority that already names the endpoint is left alone", "https://sts.test/tenant/oauth2/v2.0/token", "https://sts.test/tenant/oauth2/v2.0/token"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := clientCredentialsTokenURL(testCase.authority)
			if err != nil || got != testCase.want {
				t.Errorf("= %q, %v; want %q", got, err, testCase.want)
			}
		})
	}
	if _, err := clientCredentialsTokenURL("not-a-url"); err == nil {
		t.Error("a relative authority must be refused")
	}
}

func TestDefaultScope(t *testing.T) {
	for authority, want := range map[string]string{
		"https://vault.azure.net":          "https://vault.azure.net/.default",
		"https://vault.azure.net/":         "https://vault.azure.net/.default",
		"https://vault.azure.net/.default": "https://vault.azure.net/.default",
		"":                                 "",
	} {
		if got := defaultScope(authority); got != want {
			t.Errorf("defaultScope(%q) = %q, want %q", authority, got, want)
		}
	}
}

func TestClientCredentialsUsesTheDefaultClient(t *testing.T) {
	// Plain HTTP so http.DefaultClient can reach it: the point is the nil-Client
	// branch, not TLS.
	server, grants := challengingVault(t, `{"access_token":"minted-token"}`, http.StatusOK)
	retriever := HTTP{ClientID: "app", ClientSecret: "secret"}
	if _, err := retriever.GetSecret(context.Background(), server.URL+"/secrets/s"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if len(*grants) != 1 {
		t.Errorf("token requests = %d, want 1", len(*grants))
	}
}

func TestClientCredentialsTransportFailures(t *testing.T) {
	challenge := func() *http.Response {
		header := make(http.Header)
		header.Set("WWW-Authenticate", `Bearer authorization="https://sts.test/tenant", resource="https://vault.azure.net"`)
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("{}")), Header: header}
	}
	token := func(handle func() (*http.Response, error)) HTTP {
		return HTTP{ClientID: "app", ClientSecret: "secret", Client: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "oauth2") {
					return handle()
				}
				return challenge(), nil
			}),
		}}
	}

	unreachable := token(func() (*http.Response, error) { return nil, errors.New("dial failed") })
	if _, err := unreachable.GetSecret(context.Background(), "https://vault.test/secrets/s"); err == nil {
		t.Error("an unreachable authority was accepted")
	}

	unreadable := token(func() (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errReader{}), Header: make(http.Header)}, nil
	})
	if _, err := unreadable.GetSecret(context.Background(), "https://vault.test/secrets/s"); err == nil {
		t.Error("an unreadable token response was accepted")
	}
}

func TestClientCredentialsRejectsARelativeAuthority(t *testing.T) {
	// A challenge naming something that is not an absolute URL. The retrieval
	// must say so rather than construct a request against nothing.
	retriever := HTTP{ClientID: "app", ClientSecret: "secret", Client: &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			header := make(http.Header)
			header.Set("WWW-Authenticate", `Bearer authorization="tenant-only", resource="https://vault.azure.net"`)
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("{}")), Header: header}, nil
		}),
	}}
	_, err := retriever.GetSecret(context.Background(), "https://vault.test/secrets/s")
	code, message := Classify(err)
	if code != "Unauthorized" || !strings.Contains(message, "absolute URL") {
		t.Errorf("classified (%s, %s), want Unauthorized about an absolute URL", code, message)
	}
}

func TestClientCredentialsRequestBuildFailure(t *testing.T) {
	original := newHTTPRequest
	t.Cleanup(func() { newHTTPRequest = original })
	// Only the token POST fails; the vault GET must still reach its challenge.
	newHTTPRequest = func(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
		if method == http.MethodPost {
			return nil, errors.New("build failed")
		}
		return original(ctx, method, url, body)
	}
	retriever := HTTP{ClientID: "app", ClientSecret: "secret", Client: &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			header := make(http.Header)
			header.Set("WWW-Authenticate", `Bearer authorization="https://sts.test/tenant", resource="https://vault.azure.net"`)
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("{}")), Header: header}, nil
		}),
	}}
	if _, err := retriever.GetSecret(context.Background(), "https://vault.test/secrets/s"); err == nil {
		t.Fatal("a token request that could not be built was accepted")
	}
}
