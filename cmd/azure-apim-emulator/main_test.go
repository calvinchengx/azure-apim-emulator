package main

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/tlscert"
)

func TestMainReportsRunError(t *testing.T) {
	oldArgs, oldFatal := os.Args, fatal
	t.Cleanup(func() {
		os.Args = oldArgs
		fatal = oldFatal
	})
	os.Args = []string{"azure-apim-emulator", "-bad-flag"}
	var reported error
	fatal = func(values ...any) {
		reported, _ = values[0].(error)
	}
	main()
	if reported == nil {
		t.Fatal("main did not report run error")
	}
}

func TestRunVersionAndArgumentErrors(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-bad-flag"}); err == nil {
		t.Fatal("invalid flag succeeded")
	}
	if err := run([]string{"-default-service", ""}); err == nil {
		t.Fatal("invalid config succeeded")
	}

	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-disable-auth", "-data-dir", filepath.Join(file, "child")}); err == nil {
		t.Fatal("invalid data directory succeeded")
	}
	corruptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(corruptDir, "azure-apim-emulator.db"), []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-disable-auth", "-data-dir", corruptDir}); err == nil {
		t.Fatal("corrupt database succeeded")
	}
}

func TestRunStartupPaths(t *testing.T) {
	oldListen, oldServe, oldLoad := listen, serve, loadCertificate
	t.Cleanup(func() {
		listen = oldListen
		serve = oldServe
		loadCertificate = oldLoad
	})

	wantListen := errors.New("listen failed")
	listen = func(string, string) (net.Listener, error) { return nil, wantListen }
	if err := run([]string{"-disable-tls", "-disable-auth", "-data-dir", ""}); !errors.Is(err, wantListen) {
		t.Fatalf("listen error = %v", err)
	}

	listen = func(string, string) (net.Listener, error) { return newStubListener(), nil }
	wantTLS := errors.New("TLS failed")
	loadCertificate = func(string) (tls.Certificate, error) { return tls.Certificate{}, wantTLS }
	if err := run([]string{"-disable-auth", "-data-dir", ""}); !errors.Is(err, wantTLS) {
		t.Fatalf("TLS error = %v", err)
	}

	wantServe := errors.New("serve stopped")
	var sawTLS bool
	var rawListener net.Listener
	listen = func(string, string) (net.Listener, error) {
		rawListener = newStubListener()
		return rawListener, nil
	}
	loadCertificate = tlscert.Load
	serve = func(listener net.Listener, handler http.Handler) error {
		sawTLS = listener != rawListener
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("health status = %d", recorder.Code)
		}
		return wantServe
	}
	if err := run([]string{"-disable-auth", "-data-dir", ""}); !errors.Is(err, wantServe) || !sawTLS {
		t.Fatalf("TLS run = %v, TLS listener = %v", err, sawTLS)
	}

	sawTLS = true
	if err := run([]string{"-disable-tls", "-disable-auth", "-data-dir", ""}); !errors.Is(err, wantServe) || sawTLS {
		t.Fatalf("HTTP run = %v, TLS listener = %v", err, sawTLS)
	}
}

func TestHealthcheck(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				t.Fatalf("path = %q", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		})
		var server *httptest.Server
		if useTLS {
			server = httptest.NewTLSServer(handler)
		} else {
			server = httptest.NewServer(handler)
		}
		addr := strings.TrimPrefix(strings.TrimPrefix(server.URL, "http://"), "https://")
		if err := healthcheck(addr); err != nil {
			t.Fatalf("healthcheck TLS=%v: %v", useTLS, err)
		}
		if !useTLS {
			t.Setenv("APIM_ADDR", addr)
			if err := run([]string{"healthcheck"}); err != nil {
				t.Fatalf("run healthcheck: %v", err)
			}
		}
		server.Close()
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	addr := strings.TrimPrefix(bad.URL, "http://")
	if err := healthcheck(addr); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("non-OK error = %v", err)
	}
	bad.Close()

	if err := healthcheck("invalid"); err == nil {
		t.Fatal("invalid address succeeded")
	}
	emptyHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	_, port, err := net.SplitHostPort(strings.TrimPrefix(emptyHost.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(":" + port); err != nil {
		t.Fatalf("empty host healthcheck: %v", err)
	}
	emptyHost.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := listener.Addr().String()
	_ = listener.Close()
	if err := healthcheck(closedAddr); err == nil {
		t.Fatal("unreachable healthcheck succeeded")
	}
}

type stubListener struct {
	closed bool
}

func newStubListener() *stubListener { return &stubListener{} }

func (l *stubListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (l *stubListener) Close() error {
	l.closed = true
	return nil
}
func (l *stubListener) Addr() net.Addr { return stubAddr("127.0.0.1:8445") }

type stubAddr string

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return string(a) }
