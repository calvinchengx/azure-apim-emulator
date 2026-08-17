package store

import (
	"errors"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

func gatewayStore(t *testing.T) (*Store, model.Service) {
	t.Helper()
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	return st, service
}

func TestGatewayLifecycle(t *testing.T) {
	st, service := gatewayStore(t)
	gateway, err := st.UpsertGateway(model.Gateway{
		ServiceID: service.ID(), Name: "edge", LocationName: "on-prem", Description: "lab",
		PrimaryKey: "primary", SecondaryKey: "secondary", Document: map[string]any{"properties": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetGateway(gateway.ID())
	if err != nil || got.LocationName != "on-prem" || got.PrimaryKey != "primary" {
		t.Fatalf("get gateway = %#v, %v", got, err)
	}
	if _, err := st.GetGateway("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing gateway = %v", err)
	}
	values, err := st.ListGateways(service.ID())
	if err != nil || len(values) != 1 {
		t.Fatalf("list gateways = %#v, %v", values, err)
	}
	if _, err := st.UpsertGateway(model.Gateway{ServiceID: service.ID(), Name: "bad", Document: map[string]any{"x": make(chan int)}}); err == nil {
		t.Fatal("an unmarshalable document was accepted")
	}
	if err := st.DeleteGateway(gateway.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteGateway(gateway.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

// A gateway's contents do not outlive its registration: deleting the gateway is
// what takes it out of service, so nothing it was configured with may survive.
func TestDeleteGatewayCascades(t *testing.T) {
	st, service := gatewayStore(t)
	gateway, err := st.UpsertGateway(model.Gateway{ServiceID: service.ID(), Name: "edge", LocationName: "on-prem"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AttachGatewayAPI(gateway.ID(), service.ID()+"/apis/echo"); err != nil {
		t.Fatal(err)
	}
	hostname, err := st.UpsertGatewayHostnameConfiguration(model.GatewayHostnameConfiguration{
		GatewayID: gateway.ID(), Name: "primary", Hostname: "edge.example.test", HTTP2Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := st.UpsertGatewayCertificateAuthority(model.GatewayCertificateAuthority{
		GatewayID: gateway.ID(), Name: "root", IsTrusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteGateway(gateway.ID()); err != nil {
		t.Fatal(err)
	}
	if ids, err := st.ListGatewayAPIs(gateway.ID()); err != nil || len(ids) != 0 {
		t.Fatalf("associations survived the gateway: %#v, %v", ids, err)
	}
	if _, err := st.GetGatewayHostnameConfiguration(hostname.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("hostname survived the gateway: %v", err)
	}
	if _, err := st.GetGatewayCertificateAuthority(authority.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("certificate authority survived the gateway: %v", err)
	}
}

func TestGatewayAPIAssociations(t *testing.T) {
	st, service := gatewayStore(t)
	gateway, err := st.UpsertGateway(model.Gateway{ServiceID: service.ID(), Name: "edge", LocationName: "on-prem"})
	if err != nil {
		t.Fatal(err)
	}
	apiID := service.ID() + "/apis/echo"
	if err := st.AttachGatewayAPI(gateway.ID(), apiID); err != nil {
		t.Fatal(err)
	}
	// Attaching twice is not an error: the association either exists or it does
	// not, and a repeated PUT of the same link is the same state.
	if err := st.AttachGatewayAPI(gateway.ID(), apiID); err != nil {
		t.Fatal(err)
	}
	ids, err := st.ListGatewayAPIs(gateway.ID())
	if err != nil || len(ids) != 1 || ids[0] != apiID {
		t.Fatalf("list associations = %#v, %v", ids, err)
	}
	attached, err := st.GatewayAPIAttached(gateway.ID(), apiID)
	if err != nil || !attached {
		t.Fatalf("attached = %v, %v", attached, err)
	}
	if attached, err := st.GatewayAPIAttached(gateway.ID(), service.ID()+"/apis/other"); err != nil || attached {
		t.Fatalf("unassociated API reported attached = %v, %v", attached, err)
	}
	if err := st.DetachGatewayAPI(gateway.ID(), apiID); err != nil {
		t.Fatal(err)
	}
	// Removing a link that was never made is a 404, not a success: a caller
	// that deletes something it never created should learn that.
	if err := st.DetachGatewayAPI(gateway.ID(), apiID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second detach = %v", err)
	}
}

func TestGatewayHostnameAndCertificateAuthorityLifecycle(t *testing.T) {
	st, service := gatewayStore(t)
	gateway, err := st.UpsertGateway(model.Gateway{ServiceID: service.ID(), Name: "edge", LocationName: "on-prem"})
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := st.UpsertGatewayHostnameConfiguration(model.GatewayHostnameConfiguration{
		GatewayID: gateway.ID(), Name: "primary", Hostname: "edge.example.test",
		CertificateID: "cert", NegotiateClientCertificate: true, TLS10Enabled: true, TLS11Enabled: true, HTTP2Enabled: true,
		Document: map[string]any{"properties": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetGatewayHostnameConfiguration(hostname.ID())
	if err != nil || got.Hostname != "edge.example.test" || !got.HTTP2Enabled || !got.NegotiateClientCertificate {
		t.Fatalf("get hostname = %#v, %v", got, err)
	}
	if _, err := st.GetGatewayHostnameConfiguration("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing hostname = %v", err)
	}
	if values, err := st.ListGatewayHostnameConfigurations(gateway.ID()); err != nil || len(values) != 1 {
		t.Fatalf("list hostnames = %#v, %v", values, err)
	}
	if _, err := st.UpsertGatewayHostnameConfiguration(model.GatewayHostnameConfiguration{
		GatewayID: gateway.ID(), Name: "bad", Document: map[string]any{"x": make(chan int)},
	}); err == nil {
		t.Fatal("an unmarshalable hostname document was accepted")
	}
	if err := st.DeleteGatewayHostnameConfiguration(hostname.ID()); err != nil {
		t.Fatal(err)
	}

	authority, err := st.UpsertGatewayCertificateAuthority(model.GatewayCertificateAuthority{
		GatewayID: gateway.ID(), Name: "root", IsTrusted: true, Document: map[string]any{"properties": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetGatewayCertificateAuthority(authority.ID()); err != nil || !got.IsTrusted {
		t.Fatalf("get certificate authority = %#v, %v", got, err)
	}
	if _, err := st.GetGatewayCertificateAuthority("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing certificate authority = %v", err)
	}
	if values, err := st.ListGatewayCertificateAuthorities(gateway.ID()); err != nil || len(values) != 1 {
		t.Fatalf("list certificate authorities = %#v, %v", values, err)
	}
	if _, err := st.UpsertGatewayCertificateAuthority(model.GatewayCertificateAuthority{
		GatewayID: gateway.ID(), Name: "bad", Document: map[string]any{"x": make(chan int)},
	}); err == nil {
		t.Fatal("an unmarshalable certificate-authority document was accepted")
	}
	if err := st.DeleteGatewayCertificateAuthority(authority.ID()); err != nil {
		t.Fatal(err)
	}
}

// `managed` is the built-in gateway every service already has. A registration
// under that name would be a second thing answering to the name of the first.
func TestGatewayNameReserved(t *testing.T) {
	if !GatewayNameReserved("managed") || !GatewayNameReserved("MANAGED") {
		t.Fatal("the built-in gateway name was not reserved")
	}
	if GatewayNameReserved("edge") {
		t.Fatal("an ordinary gateway name was reserved")
	}
}
