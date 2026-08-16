package keyvault

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
