package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestGoManagementSDKConfiguresProtectedGateway(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Named") != "go-sdk-named-value" {
			t.Errorf("named-value policy header = %q", r.Header.Get("X-Named"))
		}
		_, _ = w.Write([]byte("go-sdk-backend"))
	}))
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
	credential := staticCredential{}
	ctx := context.Background()

	serviceClient, err := armapimanagement.NewServiceClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	location, publisherName, publisherEmail := "local", "Go SDK", "go@example.test"
	capacity, sku := int32(1), armapimanagement.SKUTypeDeveloper
	servicePoller, err := serviceClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", armapimanagement.ServiceResource{
		Location: &location,
		SKU:      &armapimanagement.ServiceSKUProperties{Name: &sku, Capacity: &capacity},
		Properties: &armapimanagement.ServiceProperties{
			PublisherName: &publisherName, PublisherEmail: &publisherEmail,
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := servicePoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}

	namedValueClient, err := armapimanagement.NewNamedValueClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	namedValueDisplayName, namedValueContent := "GatewayHeader", "initial"
	namedValueSecret := true
	namedValuePoller, err := namedValueClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "gateway-header", armapimanagement.NamedValueCreateContract{
		Properties: &armapimanagement.NamedValueCreateContractProperties{DisplayName: &namedValueDisplayName, Value: &namedValueContent, Secret: &namedValueSecret},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := namedValuePoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	gotNamedValue, err := namedValueClient.Get(ctx, defaultResourceGroup, "emulator", "gateway-header", nil)
	if err != nil || gotNamedValue.Properties == nil || gotNamedValue.Properties.Value != nil || gotNamedValue.Properties.Secret == nil || !*gotNamedValue.Properties.Secret {
		t.Fatalf("named value GET = %+v, %v", gotNamedValue, err)
	}
	if entityTag, err := namedValueClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "gateway-header", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("named value ETag = %+v, %v", entityTag, err)
	}
	namedValuePage, err := namedValueClient.NewListByServicePager(defaultResourceGroup, "emulator", nil).NextPage(ctx)
	if err != nil || len(namedValuePage.Value) != 1 {
		t.Fatalf("named value page = %+v, %v", namedValuePage, err)
	}
	listedValue, err := namedValueClient.ListValue(ctx, defaultResourceGroup, "emulator", "gateway-header", nil)
	if err != nil || listedValue.Value == nil || *listedValue.Value != namedValueContent {
		t.Fatalf("named value secret = %+v, %v", listedValue, err)
	}
	namedValueContent = "go-sdk-named-value"
	updatePoller, err := namedValueClient.BeginUpdate(ctx, defaultResourceGroup, "emulator", "gateway-header", "*", armapimanagement.NamedValueUpdateParameters{
		Properties: &armapimanagement.NamedValueUpdateParameterProperties{Value: &namedValueContent},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updatePoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	temporaryDisplayName, temporaryValue := "Temporary", "temporary"
	temporaryPoller, err := namedValueClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "temporary", armapimanagement.NamedValueCreateContract{
		Properties: &armapimanagement.NamedValueCreateContractProperties{DisplayName: &temporaryDisplayName, Value: &temporaryValue},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := temporaryPoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := namedValueClient.Delete(ctx, defaultResourceGroup, "emulator", "temporary", "*", nil); err != nil {
		t.Fatal(err)
	}

	backendClient, err := armapimanagement.NewBackendClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	backendTitle, backendDescription := "Go SDK backend", "Created by the Go SDK"
	backendProtocol := armapimanagement.BackendProtocolHTTP
	createdBackend, err := backendClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-backend", armapimanagement.BackendContract{
		Properties: &armapimanagement.BackendContractProperties{Title: &backendTitle, Description: &backendDescription, URL: &backend.URL, Protocol: &backendProtocol},
	}, nil)
	if err != nil || createdBackend.ID == nil {
		t.Fatalf("backend create = %+v, %v", createdBackend, err)
	}
	gotBackend, err := backendClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-backend", nil)
	if err != nil || gotBackend.Properties == nil || gotBackend.Properties.URL == nil || *gotBackend.Properties.URL != backend.URL {
		t.Fatalf("backend GET = %+v, %v", gotBackend, err)
	}
	if entityTag, err := backendClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-backend", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("backend ETag = %+v, %v", entityTag, err)
	}
	backendPage, err := backendClient.NewListByServicePager(defaultResourceGroup, "emulator", nil).NextPage(ctx)
	if err != nil || len(backendPage.Value) != 1 {
		t.Fatalf("backend page = %+v, %v", backendPage, err)
	}
	backendDescription = "Updated by the Go SDK"
	if _, err := backendClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-backend", "*", armapimanagement.BackendUpdateParameters{
		Properties: &armapimanagement.BackendUpdateParameterProperties{Description: &backendDescription},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := backendClient.Reconnect(ctx, defaultResourceGroup, "emulator", "go-sdk-backend", nil); err != nil {
		t.Fatal(err)
	}
	temporaryBackendTitle := "Temporary"
	if _, err := backendClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "temporary", armapimanagement.BackendContract{
		Properties: &armapimanagement.BackendContractProperties{Title: &temporaryBackendTitle, URL: &backend.URL, Protocol: &backendProtocol},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := backendClient.Delete(ctx, defaultResourceGroup, "emulator", "temporary", "*", nil); err != nil {
		t.Fatal(err)
	}

	apiClient, err := armapimanagement.NewAPIClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	versionSetClient, err := armapimanagement.NewAPIVersionSetClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	versionSetDisplayName := "Go SDK versions"
	versioningScheme := armapimanagement.VersioningSchemeSegment
	versionSet, err := versionSetClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-versions", armapimanagement.APIVersionSetContract{
		Properties: &armapimanagement.APIVersionSetContractProperties{DisplayName: &versionSetDisplayName, VersioningScheme: &versioningScheme},
	}, nil)
	if err != nil || versionSet.ID == nil {
		t.Fatalf("API version set = %+v, %v", versionSet, err)
	}
	versionSetID := *versionSet.ID
	versionSetPager := versionSetClient.NewListByServicePager(defaultResourceGroup, "emulator", nil)
	versionSetPage, err := versionSetPager.NextPage(ctx)
	if err != nil || len(versionSetPage.Value) != 1 {
		t.Fatalf("API version-set page = %+v, %v", versionSetPage, err)
	}
	if gotVersionSet, err := versionSetClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-versions", nil); err != nil || gotVersionSet.Properties == nil || gotVersionSet.Properties.VersioningScheme == nil || *gotVersionSet.Properties.VersioningScheme != versioningScheme {
		t.Fatalf("API version-set GET = %+v, %v", gotVersionSet, err)
	}
	if entityTag, err := versionSetClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-versions", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("API version-set ETag = %+v, %v", entityTag, err)
	}
	versionSetDescription := "Versioned by path segment"
	if _, err := versionSetClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-versions", "*", armapimanagement.APIVersionSetUpdateParameters{
		Properties: &armapimanagement.APIVersionSetUpdateParametersProperties{Description: &versionSetDescription},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := versionSetClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "temporary-versions", armapimanagement.APIVersionSetContract{
		Properties: &armapimanagement.APIVersionSetContractProperties{DisplayName: &versionSetDisplayName, VersioningScheme: &versioningScheme},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := versionSetClient.Delete(ctx, defaultResourceGroup, "emulator", "temporary-versions", "*", nil); err != nil {
		t.Fatal(err)
	}
	displayName, path, required := "Go protected API", "go-sdk-full", true
	apiVersion := "v1"
	protocol := armapimanagement.ProtocolHTTPS
	apiPoller, err := apiClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", armapimanagement.APICreateOrUpdateParameter{
		Properties: &armapimanagement.APICreateOrUpdateProperties{
			DisplayName: &displayName, Path: &path, ServiceURL: &backend.URL,
			Protocols: []*armapimanagement.Protocol{&protocol}, SubscriptionRequired: &required,
			APIVersion: &apiVersion, APIVersionSetID: &versionSetID,
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apiPoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	revisionClient, err := armapimanagement.NewAPIRevisionClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	revisionPager := revisionClient.NewListByServicePager(defaultResourceGroup, "emulator", "go-sdk-full", nil)
	revisionPage, err := revisionPager.NextPage(ctx)
	if err != nil || len(revisionPage.Value) != 1 || revisionPage.Value[0].APIRevision == nil || *revisionPage.Value[0].APIRevision != "1" || revisionPage.Value[0].IsCurrent == nil || !*revisionPage.Value[0].IsCurrent {
		t.Fatalf("API revision page = %+v, %v", revisionPage, err)
	}

	operationClient, err := armapimanagement.NewAPIOperationClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	method, template := http.MethodGet, "/items"
	if _, err := operationClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "get", armapimanagement.OperationContract{
		Properties: &armapimanagement.OperationContractProperties{DisplayName: &displayName, Method: &method, URLTemplate: &template},
	}, nil); err != nil {
		t.Fatal(err)
	}
	apiPolicyClient, err := armapimanagement.NewAPIPolicyClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	policyValue := `<policies><inbound><set-header name="X-Named" exists-action="override"><value>{{GatewayHeader}}</value></set-header><set-backend-service backend-id="go-sdk-backend" /></inbound><backend><base /></backend><outbound /><on-error /></policies>`
	policyFormat := armapimanagement.PolicyContentFormatRawxml
	if _, err := apiPolicyClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", armapimanagement.PolicyIDNamePolicy, armapimanagement.PolicyContract{
		Properties: &armapimanagement.PolicyContractProperties{Value: &policyValue, Format: &policyFormat},
	}, nil); err != nil {
		t.Fatal(err)
	}
	revision, revisionDescription := "2", "Go SDK cloned revision"
	sourceAPIID := "/subscriptions/" + defaultSubscription + "/resourceGroups/" + defaultResourceGroup + "/providers/Microsoft.ApiManagement/service/emulator/apis/go-sdk-full;rev=1"
	revisionPoller, err := apiClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", armapimanagement.APICreateOrUpdateParameter{
		Properties: &armapimanagement.APICreateOrUpdateProperties{
			SourceAPIID: &sourceAPIID, APIRevision: &revision, APIRevisionDescription: &revisionDescription,
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revisionPoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	clonedOperation, err := operationClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "get", nil)
	if err != nil || clonedOperation.Properties == nil || clonedOperation.Properties.Method == nil || *clonedOperation.Properties.Method != method {
		t.Fatalf("cloned revision operation = %+v, %v", clonedOperation, err)
	}
	revisionPager = revisionClient.NewListByServicePager(defaultResourceGroup, "emulator", "go-sdk-full", nil)
	revisionPage, err = revisionPager.NextPage(ctx)
	if err != nil || len(revisionPage.Value) != 2 {
		t.Fatalf("cloned revision page = %+v, %v", revisionPage, err)
	}
	releaseClient, err := armapimanagement.NewAPIReleaseClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	targetAPIID, releaseNotes := strings.TrimSuffix(sourceAPIID, ";rev=1")+";rev=2", "Promote revision 2"
	createdRelease, err := releaseClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "release-2", armapimanagement.APIReleaseContract{
		Properties: &armapimanagement.APIReleaseContractProperties{APIID: &targetAPIID, Notes: &releaseNotes},
	}, nil)
	if err != nil || createdRelease.Properties == nil || createdRelease.Properties.APIID == nil || *createdRelease.Properties.APIID != targetAPIID {
		t.Fatalf("created API release = %+v, %v", createdRelease, err)
	}
	gotRelease, err := releaseClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "release-2", nil)
	if err != nil || gotRelease.Properties == nil || gotRelease.Properties.Notes == nil || *gotRelease.Properties.Notes != releaseNotes {
		t.Fatalf("API release GET = %+v, %v", gotRelease, err)
	}
	if entityTag, err := releaseClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "release-2", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("API release ETag = %+v, %v", entityTag, err)
	}
	releasePager := releaseClient.NewListByServicePager(defaultResourceGroup, "emulator", "go-sdk-full", nil)
	releasePage, err := releasePager.NextPage(ctx)
	if err != nil || len(releasePage.Value) != 1 {
		t.Fatalf("API release page = %+v, %v", releasePage, err)
	}

	subscriptionClient, err := armapimanagement.NewSubscriptionClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	scope := "/subscriptions/" + defaultSubscription + "/resourceGroups/" + defaultResourceGroup + "/providers/Microsoft.ApiManagement/service/emulator/apis/go-sdk-full"
	primary, secondary, subscriptionName := "go-sdk-key", "go-sdk-secondary", "Go SDK subscription"
	state := armapimanagement.SubscriptionStateActive
	if _, err := subscriptionClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-subscription", armapimanagement.SubscriptionCreateParameters{
		Properties: &armapimanagement.SubscriptionCreateParameterProperties{
			DisplayName: &subscriptionName, Scope: &scope, State: &state, PrimaryKey: &primary, SecondaryKey: &secondary,
		},
	}, nil); err != nil {
		t.Fatal(err)
	}
	secrets, err := subscriptionClient.ListSecrets(ctx, defaultResourceGroup, "emulator", "go-sdk-subscription", nil)
	if err != nil || secrets.PrimaryKey == nil || *secrets.PrimaryKey != primary || secrets.SecondaryKey == nil || *secrets.SecondaryKey != secondary {
		t.Fatalf("subscription secrets = %+v, %v", secrets, err)
	}
	if _, err := subscriptionClient.RegeneratePrimaryKey(ctx, defaultResourceGroup, "emulator", "go-sdk-subscription", nil); err != nil {
		t.Fatal(err)
	}
	rotated, err := subscriptionClient.ListSecrets(ctx, defaultResourceGroup, "emulator", "go-sdk-subscription", nil)
	if err != nil || rotated.PrimaryKey == nil || *rotated.PrimaryKey == primary || rotated.SecondaryKey == nil || *rotated.SecondaryKey != secondary {
		t.Fatalf("rotated subscription secrets = %+v, %v", rotated, err)
	}
	request, _ := http.NewRequest(http.MethodGet, front.URL+"/go-sdk-full/v1/items", nil)
	request.Header.Set("Ocp-Apim-Subscription-Key", primary)
	response, err := front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("retired subscription key status = %d", response.StatusCode)
	}
	primary = *rotated.PrimaryKey

	request, _ = http.NewRequest(http.MethodGet, front.URL+"/go-sdk-full/v1/items", nil)
	request.Header.Set("Ocp-Apim-Subscription-Key", primary)
	response, err = front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "go-sdk-backend" {
		t.Fatalf("gateway = %d %q", response.StatusCode, body)
	}
	updatedNotes := "Updated release notes"
	updatedRelease, err := releaseClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "release-2", "*", armapimanagement.APIReleaseContract{
		Properties: &armapimanagement.APIReleaseContractProperties{Notes: &updatedNotes},
	}, nil)
	if err != nil || updatedRelease.Properties == nil || updatedRelease.Properties.Notes == nil || *updatedRelease.Properties.Notes != updatedNotes {
		t.Fatalf("updated API release = %+v, %v", updatedRelease, err)
	}
	if _, err := releaseClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "release-2", "*", nil); err != nil {
		t.Fatal(err)
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
