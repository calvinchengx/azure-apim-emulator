package gateway

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

// failingConn accepts a dial and then refuses every write, which is how a
// backend that dies between accept and handshake presents.
type failingConn struct{ net.Conn }

func (failingConn) Write([]byte) (int, error) { return 0, errors.New("upstream write failed") }
func (failingConn) Close() error              { return nil }

func TestWebSocketHandshakeWriteFailureIsAGatewayError(t *testing.T) {
	original := websocketDialer
	websocketDialer = func(*url.URL) (net.Conn, error) { return failingConn{}, nil }
	defer func() { websocketDialer = original }()

	runtime := New("emulator", nil)
	route := &Route{
		API:        model.API{Name: "socket", Path: "socket", ServiceURL: "http://backend.test"},
		Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}},
	}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Name: "emulator", Routes: []*Route{route}}}})
	request := httptest.NewRequest(http.MethodGet, "/socket", nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", recorder.Code)
	}
}

// hijackRefuser is a ResponseWriter that claims to be hijackable and is not.
type hijackRefuser struct{ http.ResponseWriter }

func (hijackRefuser) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("hijack refused")
}

func TestWebSocketHijackFailuresAreGatewayErrors(t *testing.T) {
	accepted := make(chan string, 1)
	backendURL := rawWebSocketBackend(t, "", accepted)
	runtime := New("emulator", nil)
	route := &Route{
		API:        model.API{Name: "socket", Path: "socket", ServiceURL: backendURL},
		Operations: []model.Operation{{Method: http.MethodGet, URLTemplate: "/"}},
	}
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Name: "emulator", Routes: []*Route{route}}}})

	// NOT the "no hijacker" branch, though it looks like it: the runtime wraps
	// the ResponseWriter in a type that DOES implement http.Hijacker, so the
	// assertion succeeds and the Hijack call underneath fails. Measured, after
	// coverage showed the branch this was meant to reach was never taken.
	request := httptest.NewRequest(http.MethodGet, "/socket", nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("no hijacker: status = %d, want 500", recorder.Code)
	}

	// And one that is, but refuses.
	accepted2 := make(chan string, 1)
	backendURL2 := rawWebSocketBackend(t, "", accepted2)
	route.API.ServiceURL = backendURL2
	runtime.current.Store(&Snapshot{Services: map[string]*Service{"emulator": {Name: "emulator", Routes: []*Route{route}}}})
	refuser := hijackRefuser{httptest.NewRecorder()}
	runtime.ServeHTTP(refuser, request)
	if got := refuser.ResponseWriter.(*httptest.ResponseRecorder).Code; got != http.StatusInternalServerError {
		t.Fatalf("hijack refused: status = %d, want 500", got)
	}
}

func TestWebSocketDialTarget(t *testing.T) {
	// The default ports are a rule, not an accident: a backend named without a
	// port must reach 80 or 443 by scheme, and a wss backend must be verified
	// against the name it was addressed by rather than whatever it presents.
	for _, testCase := range []struct {
		name       string
		raw        string
		wantAddr   string
		wantTLS    bool
		wantServer string
	}{
		{"ws keeps an explicit port", "ws://backend.test:8080/x", "backend.test:8080", false, ""},
		{"ws defaults to 80", "ws://backend.test/x", "backend.test:80", false, ""},
		{"wss keeps an explicit port", "wss://backend.test:8443/x", "backend.test:8443", true, "backend.test"},
		{"wss defaults to 443", "wss://backend.test/x", "backend.test:443", true, "backend.test"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := url.Parse(testCase.raw)
			if err != nil {
				t.Fatal(err)
			}
			address, tlsConfig := websocketDialTarget(parsed)
			if address != testCase.wantAddr {
				t.Errorf("address = %q, want %q", address, testCase.wantAddr)
			}
			if (tlsConfig != nil) != testCase.wantTLS {
				t.Fatalf("tls = %v, want %v", tlsConfig != nil, testCase.wantTLS)
			}
			if tlsConfig != nil && tlsConfig.ServerName != testCase.wantServer {
				t.Errorf("ServerName = %q, want %q", tlsConfig.ServerName, testCase.wantServer)
			}
		})
	}
}

func TestWebSocketDialUsesTLSForWSS(t *testing.T) {
	// Nothing is listening; the point is that the wss branch takes the TLS dial.
	parsed, err := url.Parse("wss://127.0.0.1:1/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialWebSocketBackend(parsed); err == nil {
		t.Fatal("expected the dial to fail")
	}
}

func TestWebSocketWriterWithoutHijackerIsAGatewayError(t *testing.T) {
	// Reached by calling the tunnel directly, because every ResponseWriter that
	// arrives through ServeHTTP is wrapped in one that implements Hijacker. The
	// branch stays because that wrapping is not this function's to assume.
	seen := make(chan string, 1)
	backendURL := rawWebSocketBackend(t, "", seen)
	runtime := New("emulator", nil)
	request := httptest.NewRequest(http.MethodGet, "/socket", nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	recorder := httptest.NewRecorder()
	runtime.serveWebSocket(recorder, request, backendURL, "/")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "could not be taken over") {
		t.Errorf("body = %s", recorder.Body.String())
	}
}
