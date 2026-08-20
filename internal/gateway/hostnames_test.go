package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// A hostname configured to negotiate a client certificate refuses a request
// that presents none. In Azure that refusal happens in the TLS handshake, so no
// policy ever sees the request; refusing before the plan runs is the nearest
// truthful equivalent.
func TestNegotiateClientCertificateRefusesAnUnauthenticatedRequest(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	service, err := st.UpsertService(model.Service{
		SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local",
		Document: map[string]any{"properties": map[string]any{"hostnameConfigurations": []any{
			map[string]any{"type": "Proxy", "hostName": "Secure.Contoso.Test", "negotiateClientCertificate": true},
			map[string]any{"type": "Proxy", "hostName": "open.contoso.test"},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "echo", DisplayName: "Echo", Path: "echo", ServiceURL: backend.URL, IsCurrent: true})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: http.MethodGet, URLTemplate: "/"})
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}

	on := func(host string, presented bool) int {
		request := httptest.NewRequest(http.MethodGet, "/echo", nil)
		request.Host = host
		if presented {
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
		}
		recorder := httptest.NewRecorder()
		runtime.ServeHTTP(recorder, request)
		return recorder.Code
	}

	// Matched case-insensitively and with the port stripped, like every other
	// host lookup here.
	if code := on("secure.contoso.test:8443", false); code != http.StatusForbidden {
		t.Fatalf("an unauthenticated request on a client-certificate hostname = %d", code)
	}
	if code := on("secure.contoso.test", true); code != http.StatusNoContent {
		t.Fatalf("a request presenting a certificate = %d", code)
	}
	// A hostname that does not demand one is unaffected, which is what keeps
	// this from being a service-wide switch.
	if code := on("open.contoso.test", false); code != http.StatusNoContent {
		t.Fatalf("a hostname without the setting refused a request: %d", code)
	}
	// And so is the service's own front door.
	if code := on("emulator.azure-api.localhost", false); code != http.StatusNoContent {
		t.Fatalf("the service front door refused a request: %d", code)
	}
}

func TestClientCertificateHostsProjection(t *testing.T) {
	hosts := clientCertificateHosts(map[string]any{"properties": map[string]any{"hostnameConfigurations": []any{
		map[string]any{"hostName": " Mixed.Case.Test ", "negotiateClientCertificate": true},
		map[string]any{"hostName": "plain.test", "negotiateClientCertificate": false},
		map[string]any{"hostName": "", "negotiateClientCertificate": true},
		map[string]any{"negotiateClientCertificate": true},
		"not an object",
	}}})
	if len(hosts) != 1 || !hosts["mixed.case.test"] {
		t.Fatalf("hosts = %v", hosts)
	}
	// A service with no configurations at all costs nothing at request time.
	if len(clientCertificateHosts(map[string]any{})) != 0 {
		t.Fatal("an empty document produced hosts")
	}
}
