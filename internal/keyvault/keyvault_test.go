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
