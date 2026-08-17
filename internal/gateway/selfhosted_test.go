package gateway

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// A self-hosted gateway serves only the APIs associated with it. The property
// under test is the ABSENCE: an unassociated API must not be reachable on the
// gateway's hostname even though it is reachable on the service's own, because
// that absence is the entire reason the association exists.
func TestSelfHostedGatewayServesOnlyAssociatedAPIs(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pets", "orders"} {
		api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: name, DisplayName: name, Path: name, ServiceURL: "https://backend.test", IsCurrent: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "list", DisplayName: "list", Method: http.MethodGet, URLTemplate: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	gateway, err := st.UpsertGateway(model.Gateway{ServiceID: service.ID(), Name: "edge", LocationName: "on-prem"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertGatewayHostnameConfiguration(model.GatewayHostnameConfiguration{
		GatewayID: gateway.ID(), Name: "primary", Hostname: "Edge.Example.Test",
	}); err != nil {
		t.Fatal(err)
	}
	// Associated by logical ID, and only one of the two.
	if err := st.AttachGatewayAPI(gateway.ID(), service.ID()+"/apis/pets"); err != nil {
		t.Fatal(err)
	}
	// A dangling association is dropped rather than failing the activation: an
	// API can be associated and then have its current revision removed, and one
	// broken link must not take the whole service off the air.
	if err := st.AttachGatewayAPI(gateway.ID(), service.ID()+"/apis/ghost"); err != nil {
		t.Fatal(err)
	}

	runtime := New("emulator", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}

	onGateway := func(path string) *http.Request {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		// Matched case-insensitively and with the port stripped, the way every
		// other host lookup in this gateway works.
		request.Host = "edge.example.test:8443"
		return request
	}
	assertGatewayStatus(t, runtime, onGateway("/pets"), http.StatusNoContent)
	assertGatewayStatus(t, runtime, onGateway("/orders"), http.StatusNotFound)

	// Both remain reachable on the service's own front door: associating an API
	// with a gateway grants access there, it does not withdraw it here.
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/pets", nil), http.StatusNoContent)
	assertGatewayStatus(t, runtime, httptest.NewRequest(http.MethodGet, "/orders", nil), http.StatusNoContent)

	// Removing the association takes the API off the gateway on the next
	// activation, which is what makes the link a runtime decision.
	if err := st.DetachGatewayAPI(gateway.ID(), service.ID()+"/apis/pets"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(st, false); err != nil {
		t.Fatal(err)
	}
	assertGatewayStatus(t, runtime, onGateway("/pets"), http.StatusNotFound)
}

// A hostname configured on both the service and one of its gateways keeps
// answering as the service, which is how it behaved before gateways were
// routable at all.
func TestServiceHostnameWinsOverGatewayHostname(t *testing.T) {
	snapshot := &Snapshot{Services: map[string]*Service{
		"alpha": {Name: "alpha", Hostnames: map[string]bool{"shared.example.test": true}},
		"beta": {Name: "beta", Gateways: []*SelfHostedGateway{
			{Name: "edge", Hostnames: map[string]bool{"shared.example.test": true}},
		}},
	}}
	if name, selfHosted := serviceForHost(snapshot, "shared.example.test", "fallback"); name != "alpha" || selfHosted != nil {
		t.Fatalf("shared hostname = %q %v", name, selfHosted)
	}
}

// Activation reports a store it cannot read rather than publishing a snapshot
// in which every gateway silently has no hostnames and no APIs.
func TestSelfHostedGatewayLoadFailuresStopActivation(t *testing.T) {
	for _, table := range []string{"gateways", "gateway_hostname_configurations", "gateway_apis"} {
		t.Run(table, func(t *testing.T) {
			dir := t.TempDir()
			st, err := store.Open(dir, clock.New())
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.UpsertGateway(model.Gateway{ServiceID: service.ID(), Name: "edge", LocationName: "on-prem"}); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("DROP TABLE " + table); err != nil {
				t.Fatal(err)
			}
			if err := New("emulator", nil).Activate(st, false); err == nil {
				t.Fatalf("activation succeeded with %s missing", table)
			}
		})
	}
}
