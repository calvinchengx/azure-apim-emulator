package store

import (
	"errors"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

func TestPrivateEndpointConnectionLifecycle(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := st.UpsertPrivateEndpointConnection(model.PrivateEndpointConnection{
		ServiceID: service.ID(), Name: "from-vnet", Status: "Pending",
		EndpointID: "/subscriptions/other/providers/Microsoft.Network/privateEndpoints/pe",
		Document:   map[string]any{"properties": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetPrivateEndpointConnection(connection.ID())
	if err != nil || got.Status != "Pending" || got.EndpointID == "" {
		t.Fatalf("get = %#v, %v", got, err)
	}
	if _, err := st.GetPrivateEndpointConnection("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing connection = %v", err)
	}
	if values, err := st.ListPrivateEndpointConnections(service.ID()); err != nil || len(values) != 1 {
		t.Fatalf("list = %#v, %v", values, err)
	}
	if _, err := st.UpsertPrivateEndpointConnection(model.PrivateEndpointConnection{
		ServiceID: service.ID(), Name: "bad", Document: map[string]any{"x": make(chan int)},
	}); err == nil {
		t.Fatal("an unmarshalable document was accepted")
	}
	if err := st.DeletePrivateEndpointConnection(connection.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePrivateEndpointConnection(connection.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

// Deleting a service takes its connections with it: a connection to a service
// that no longer exists is a dangling grant.
func TestDeleteServiceCascadesToPrivateEndpointConnections(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	connection, err := st.UpsertPrivateEndpointConnection(model.PrivateEndpointConnection{
		ServiceID: service.ID(), Name: "from-vnet", Status: "Approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteService(service.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetPrivateEndpointConnection(connection.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a connection outlived its service: %v", err)
	}
}
