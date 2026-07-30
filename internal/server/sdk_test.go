package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	entra "github.com/calvinchengx/entra-emulator/emulator"

	"github.com/calvinchengx/azure-apim-emulator/internal/config"
)

type staticCredential struct{}

func (staticCredential) GetToken(context.Context, azpolicy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "sdk-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestGoManagementSDKCreatesAPI(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer backend.Close()
	srv := newTestServer(t, false, backend.Client())
	front := httptest.NewTLSServer(srv.Handler())
	defer front.Close()

	configuration := cloud.Configuration{
		ActiveDirectoryAuthorityHost: "https://login.microsoftonline.com/",
		Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: front.URL, Audience: "https://management.azure.com"},
		},
	}
	options := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{Cloud: configuration, Transport: front.Client()}}
	client, err := armapimanagement.NewAPIClient(defaultSubscription, staticCredential{}, options)
	if err != nil {
		t.Fatal(err)
	}
	displayName, path, serviceURL, required := "SDK API", "sdk", backend.URL, false
	protocol := armapimanagement.ProtocolHTTPS
	poller, err := client.BeginCreateOrUpdate(context.Background(), defaultResourceGroup, "emulator", "sdk-api", armapimanagement.APICreateOrUpdateParameter{
		Properties: &armapimanagement.APICreateOrUpdateProperties{
			DisplayName: &displayName, Path: &path, ServiceURL: &serviceURL,
			Protocols: []*armapimanagement.Protocol{&protocol}, SubscriptionRequired: &required,
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := poller.PollUntilDone(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Name == nil || *result.Name != "sdk-api" {
		t.Fatalf("SDK response name = %v", result.Name)
	}
}

func TestGoManagementSDKAuthenticatesThroughEntraEmulator(t *testing.T) {
	identity := entra.StartT(t, entra.WithTLS())
	cfg := &config.Config{
		Addr: ":0", DefaultService: "emulator", Location: "local", DisableTLS: true,
		EntraIssuer: identity.Issuer, EntraJWKSURL: identity.JWKSURL(),
	}
	srv, err := New(cfg, nil, http.DefaultClient, identity.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	front := httptest.NewTLSServer(srv.Handler())
	defer front.Close()

	credential, err := azidentity.NewClientSecretCredential(identity.TenantID, entra.DaemonClientID, entra.DaemonSecret, &azidentity.ClientSecretCredentialOptions{
		DisableInstanceDiscovery: true,
		ClientOptions: azcore.ClientOptions{
			Transport: identity.HTTPClient(),
			Cloud:     cloud.Configuration{ActiveDirectoryAuthorityHost: identity.Origin, Services: map[cloud.ServiceName]cloud.ServiceConfiguration{}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration := cloud.Configuration{
		ActiveDirectoryAuthorityHost: identity.Origin,
		Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: front.URL, Audience: "https://management.azure.com"},
		},
	}
	client, err := armapimanagement.NewAPIClient(defaultSubscription, credential, &arm.ClientOptions{ClientOptions: azcore.ClientOptions{Cloud: configuration, Transport: front.Client()}})
	if err != nil {
		t.Fatal(err)
	}
	displayName, path, serviceURL, required := "Authenticated SDK API", "authenticated", "http://127.0.0.1:1", false
	protocol := armapimanagement.ProtocolHTTPS
	poller, err := client.BeginCreateOrUpdate(context.Background(), defaultResourceGroup, "emulator", "authenticated-api", armapimanagement.APICreateOrUpdateParameter{
		Properties: &armapimanagement.APICreateOrUpdateProperties{DisplayName: &displayName, Path: &path, ServiceURL: &serviceURL, Protocols: []*armapimanagement.Protocol{&protocol}, SubscriptionRequired: &required},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := poller.PollUntilDone(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Name == nil || *result.Name != "authenticated-api" {
		t.Fatalf("SDK response name = %v", result.Name)
	}
}
