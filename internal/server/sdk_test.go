package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
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
	"software.sslmate.com/src/go-pkcs12"
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
	importBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("imported-backend"))
	}))
	defer importBackend.Close()
	linkedDefinition := ""
	importSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(linkedDefinition))
	}))
	defer importSource.Close()
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Named") != "go-sdk-named-value" {
			t.Errorf("named-value policy header = %q", r.Header.Get("X-Named"))
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Error("backend request did not present the SDK-created client certificate")
		}
		_, _ = w.Write([]byte("go-sdk-backend"))
	}))
	backend.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	backend.StartTLS()
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
	entityTag, err := namedValueClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "gateway-header", nil)
	if err != nil || entityTag.ETag == nil {
		t.Fatalf("named value ETag = %+v, %v", entityTag, err)
	}
	staleNamedValueETag := *entityTag.ETag
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
	if gotNamedValue, err := namedValueClient.Get(ctx, defaultResourceGroup, "emulator", "gateway-header", nil); err != nil || gotNamedValue.Properties == nil || gotNamedValue.Properties.Value != nil || gotNamedValue.Properties.DisplayName == nil || *gotNamedValue.Properties.DisplayName != namedValueDisplayName {
		t.Fatalf("updated named value GET = %+v, %v", gotNamedValue, err)
	}
	if listedValue, err := namedValueClient.ListValue(ctx, defaultResourceGroup, "emulator", "gateway-header", nil); err != nil || listedValue.Value == nil || *listedValue.Value != namedValueContent {
		t.Fatalf("updated named value secret = %+v, %v", listedValue, err)
	}
	_, err = namedValueClient.BeginUpdate(ctx, defaultResourceGroup, "emulator", "gateway-header", staleNamedValueETag, armapimanagement.NamedValueUpdateParameters{
		Properties: &armapimanagement.NamedValueUpdateParameterProperties{Value: &namedValueContent},
	}, nil)
	var responseError *azcore.ResponseError
	if !errors.As(err, &responseError) || responseError.StatusCode != http.StatusPreconditionFailed || responseError.ErrorCode != "PreconditionFailed" || responseError.RawResponse.Header.Get("x-ms-error-code") != "PreconditionFailed" {
		t.Fatalf("stale named value update error = %#v", err)
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

	certificateClient, err := armapimanagement.NewCertificateClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	certificateData, certificatePassword := serverTestPKCS12(t, "password"), "password"
	createdCertificate, err := certificateClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-client", armapimanagement.CertificateCreateOrUpdateParameters{
		Properties: &armapimanagement.CertificateCreateOrUpdateProperties{Data: &certificateData, Password: &certificatePassword},
	}, nil)
	if err != nil || createdCertificate.ID == nil || createdCertificate.Properties == nil || createdCertificate.Properties.Thumbprint == nil {
		t.Fatalf("certificate create = %+v, %v", createdCertificate, err)
	}
	certificateID := *createdCertificate.ID
	gotCertificate, err := certificateClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-client", nil)
	if err != nil || gotCertificate.Properties == nil || gotCertificate.Properties.Subject == nil {
		t.Fatalf("certificate GET = %+v, %v", gotCertificate, err)
	}
	if entityTag, err := certificateClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-client", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("certificate ETag = %+v, %v", entityTag, err)
	}
	certificatePage, err := certificateClient.NewListByServicePager(defaultResourceGroup, "emulator", nil).NextPage(ctx)
	if err != nil || len(certificatePage.Value) != 1 {
		t.Fatalf("certificate page = %+v, %v", certificatePage, err)
	}
	if _, err := certificateClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "temporary", armapimanagement.CertificateCreateOrUpdateParameters{Properties: &armapimanagement.CertificateCreateOrUpdateProperties{Data: &certificateData, Password: &certificatePassword}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := certificateClient.Delete(ctx, defaultResourceGroup, "emulator", "temporary", "*", nil); err != nil {
		t.Fatal(err)
	}
	vaultSecretID := "https://vault.test/secrets/client"
	if _, err := certificateClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "vault-client", armapimanagement.CertificateCreateOrUpdateParameters{Properties: &armapimanagement.CertificateCreateOrUpdateProperties{KeyVault: &armapimanagement.KeyVaultContractCreateProperties{SecretIdentifier: &vaultSecretID}}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := certificateClient.RefreshSecret(ctx, defaultResourceGroup, "emulator", "vault-client", nil); err != nil {
		t.Fatal(err)
	}
	if gotVaultCertificate, err := certificateClient.Get(ctx, defaultResourceGroup, "emulator", "vault-client", nil); err != nil || gotVaultCertificate.Properties == nil || gotVaultCertificate.Properties.KeyVault == nil || gotVaultCertificate.Properties.KeyVault.SecretIdentifier == nil || *gotVaultCertificate.Properties.KeyVault.SecretIdentifier != vaultSecretID {
		t.Fatalf("vault certificate GET = %+v, %v", gotVaultCertificate, err)
	}

	backendClient, err := armapimanagement.NewBackendClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	backendTitle, backendDescription := "Go SDK backend", "Created by the Go SDK"
	backendProtocol := armapimanagement.BackendProtocolHTTP
	createdBackend, err := backendClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-backend", armapimanagement.BackendContract{
		Properties: &armapimanagement.BackendContractProperties{Title: &backendTitle, Description: &backendDescription, URL: &backend.URL, Protocol: &backendProtocol, Credentials: &armapimanagement.BackendCredentialsContract{CertificateIDs: []*string{&certificateID}}},
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
	if gotBackend, err := backendClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-backend", nil); err != nil || gotBackend.Properties == nil || gotBackend.Properties.Description == nil || *gotBackend.Properties.Description != backendDescription || gotBackend.Properties.Credentials == nil || len(gotBackend.Properties.Credentials.CertificateIDs) != 1 {
		t.Fatalf("updated backend GET = %+v, %v", gotBackend, err)
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
	if gotVersionSet, err := versionSetClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-versions", nil); err != nil || gotVersionSet.Properties == nil || gotVersionSet.Properties.Description == nil || *gotVersionSet.Properties.Description != versionSetDescription {
		t.Fatalf("API version-set description = %+v, %v", gotVersionSet, err)
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
	apiDescription := "Created through the official Go SDK"
	apiVersion := "v1"
	protocol := armapimanagement.ProtocolHTTPS
	apiPoller, err := apiClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", armapimanagement.APICreateOrUpdateParameter{
		Properties: &armapimanagement.APICreateOrUpdateProperties{
			DisplayName: &displayName, Path: &path, ServiceURL: &backend.URL,
			Protocols: []*armapimanagement.Protocol{&protocol}, SubscriptionRequired: &required,
			APIVersion: &apiVersion, APIVersionSetID: &versionSetID, Description: &apiDescription,
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apiPoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	gotAPI, err := apiClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full", nil)
	if err != nil || gotAPI.Properties == nil || gotAPI.Properties.Description == nil || *gotAPI.Properties.Description != apiDescription {
		t.Fatalf("lossless API GET = %+v, %v", gotAPI, err)
	}
	apiDescription = "Patched through the official Go SDK"
	updatedAPI, err := apiClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "*", armapimanagement.APIUpdateContract{
		Properties: &armapimanagement.APIContractUpdateProperties{Description: &apiDescription},
	}, nil)
	if err != nil || updatedAPI.Properties == nil || updatedAPI.Properties.Description == nil || *updatedAPI.Properties.Description != apiDescription {
		t.Fatalf("lossless API update = %+v, %v", updatedAPI, err)
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
	operationDescription := "Retained operation metadata"
	if _, err := operationClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "get", armapimanagement.OperationContract{
		Properties: &armapimanagement.OperationContractProperties{DisplayName: &displayName, Method: &method, URLTemplate: &template, Description: &operationDescription},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if gotOperation, err := operationClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "get", nil); err != nil || gotOperation.Properties == nil || gotOperation.Properties.Description == nil || *gotOperation.Properties.Description != operationDescription {
		t.Fatalf("lossless operation GET = %+v, %v", gotOperation, err)
	}
	importedPath, importedRequired := "go-sdk-imported", false
	importFormat := armapimanagement.ContentFormatOpenapiJSON
	importValue := `{"openapi":"3.0.3","info":{"title":"Go SDK imported API"},"servers":[{"url":"` + importBackend.URL + `"}],"paths":{"/items":{"get":{"operationId":"importedGet","summary":"Imported GET","responses":{"200":{"description":"OK"}}}}}}`
	importPoller, err := apiClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-imported", armapimanagement.APICreateOrUpdateParameter{Properties: &armapimanagement.APICreateOrUpdateProperties{
		Path: &importedPath, Format: &importFormat, Value: &importValue, SubscriptionRequired: &importedRequired,
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	importedAPI, err := importPoller.PollUntilDone(ctx, nil)
	if err != nil || importedAPI.Properties == nil || importedAPI.Properties.DisplayName == nil || *importedAPI.Properties.DisplayName != "Go SDK imported API" {
		t.Fatalf("SDK OpenAPI import = %+v, %v", importedAPI, err)
	}
	if importedOperation, err := operationClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-imported", "importedGet", nil); err != nil || importedOperation.Properties == nil || importedOperation.Properties.Method == nil || *importedOperation.Properties.Method != http.MethodGet {
		t.Fatalf("SDK imported operation = %+v, %v", importedOperation, err)
	}
	linkedDefinition = `{"openapi":"3.1.0","info":{"title":"Go SDK linked API"},"servers":[{"url":"` + importBackend.URL + `"}],"paths":{"/linked":{"post":{"operationId":"linkedPost","responses":{"200":{"description":"OK"}}}}}}`
	linkedFormat, linkedValue := armapimanagement.ContentFormatOpenapiJSONLink, importSource.URL
	linkedPoller, err := apiClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-imported", armapimanagement.APICreateOrUpdateParameter{Properties: &armapimanagement.APICreateOrUpdateProperties{
		Path: &importedPath, Format: &linkedFormat, Value: &linkedValue, SubscriptionRequired: &importedRequired,
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linkedPoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if linkedOperation, err := operationClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-imported", "linkedPost", nil); err != nil || linkedOperation.Properties == nil || linkedOperation.Properties.URLTemplate == nil || *linkedOperation.Properties.URLTemplate != "/linked" {
		t.Fatalf("SDK linked operation = %+v, %v", linkedOperation, err)
	}
	if _, err := operationClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-imported", "importedGet", nil); err == nil {
		t.Fatal("linked import retained the replaced operation")
	}
	importedRequest, _ := http.NewRequest(http.MethodPost, front.URL+"/go-sdk-imported/linked", nil)
	importedResponse, err := front.Client().Do(importedRequest)
	if err != nil {
		t.Fatal(err)
	}
	importedBody, _ := io.ReadAll(importedResponse.Body)
	importedResponse.Body.Close()
	if importedResponse.StatusCode != http.StatusOK || string(importedBody) != "imported-backend" {
		t.Fatalf("imported gateway = %d %q", importedResponse.StatusCode, importedBody)
	}
	exportClient, err := armapimanagement.NewAPIExportClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := exportClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-imported", armapimanagement.ExportFormatOpenapiJSON, armapimanagement.ExportAPITrue, nil)
	if err != nil || exported.Value == nil || exported.Value.Link == nil || exported.ExportResultFormat == nil {
		t.Fatalf("SDK API export = %+v, %v", exported, err)
	}
	exportResponse, err := front.Client().Get(*exported.Value.Link)
	if err != nil {
		t.Fatal(err)
	}
	exportBody, _ := io.ReadAll(exportResponse.Body)
	exportResponse.Body.Close()
	if exportResponse.StatusCode != http.StatusOK || !strings.Contains(string(exportBody), `"operationId":"linkedPost"`) {
		t.Fatalf("SDK API export download = %d %s", exportResponse.StatusCode, exportBody)
	}
	productClient, err := armapimanagement.NewProductClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	productDisplayName, productDescription, productTerms := "Go SDK product", "SDK product description", "SDK product terms"
	productSubscriptionRequired := false
	productLimit := int32(2)
	createdProduct, err := productClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-product", armapimanagement.ProductContract{
		Properties: &armapimanagement.ProductContractProperties{DisplayName: &productDisplayName, Description: &productDescription, Terms: &productTerms, SubscriptionRequired: &productSubscriptionRequired, SubscriptionsLimit: &productLimit},
	}, nil)
	if err != nil || createdProduct.Properties == nil || createdProduct.Properties.State == nil || *createdProduct.Properties.State != armapimanagement.ProductStateNotPublished {
		t.Fatalf("product create/default state = %+v, %v", createdProduct, err)
	}
	gotProduct, err := productClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-product", nil)
	if err != nil || gotProduct.Properties == nil || gotProduct.Properties.Description == nil || *gotProduct.Properties.Description != productDescription || gotProduct.Properties.Terms == nil || *gotProduct.Properties.Terms != productTerms || gotProduct.Properties.SubscriptionsLimit == nil || *gotProduct.Properties.SubscriptionsLimit != productLimit {
		t.Fatalf("lossless product GET = %+v, %v", gotProduct, err)
	}
	groupClient, err := armapimanagement.NewGroupClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	groupDisplayName, groupDescription := "Go SDK partners", "Created by the Go SDK"
	groupType := armapimanagement.GroupTypeCustom
	createdGroup, err := groupClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-partners", armapimanagement.GroupCreateParameters{
		Properties: &armapimanagement.GroupCreateParametersProperties{DisplayName: &groupDisplayName, Description: &groupDescription, Type: &groupType},
	}, nil)
	if err != nil || createdGroup.Properties == nil || createdGroup.Properties.BuiltIn == nil || *createdGroup.Properties.BuiltIn {
		t.Fatalf("group create = %+v, %v", createdGroup, err)
	}
	groupDescription = "Updated by the Go SDK"
	updatedGroup, err := groupClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-partners", "*", armapimanagement.GroupUpdateParameters{
		Properties: &armapimanagement.GroupUpdateParametersProperties{Description: &groupDescription},
	}, nil)
	if err != nil || updatedGroup.Properties == nil || updatedGroup.Properties.Description == nil || *updatedGroup.Properties.Description != groupDescription {
		t.Fatalf("group update = %+v, %v", updatedGroup, err)
	}
	if gotGroup, err := groupClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-partners", nil); err != nil || gotGroup.Properties == nil || gotGroup.Properties.DisplayName == nil || *gotGroup.Properties.DisplayName != groupDisplayName {
		t.Fatalf("group GET = %+v, %v", gotGroup, err)
	}
	if entityTag, err := groupClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-partners", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("group ETag = %+v, %v", entityTag, err)
	}
	if page, err := groupClient.NewListByServicePager(defaultResourceGroup, "emulator", nil).NextPage(ctx); err != nil || len(page.Value) != 4 {
		t.Fatalf("group service page = %+v, %v", page, err)
	}
	temporaryGroupName := "Temporary group"
	if _, err := groupClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "temporary", armapimanagement.GroupCreateParameters{Properties: &armapimanagement.GroupCreateParametersProperties{DisplayName: &temporaryGroupName}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := groupClient.Delete(ctx, defaultResourceGroup, "emulator", "temporary", "*", nil); err != nil {
		t.Fatal(err)
	}
	productGroupClient, err := armapimanagement.NewProductGroupClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	if linkedGroup, err := productGroupClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-partners", nil); err != nil || linkedGroup.Name == nil || *linkedGroup.Name != "go-sdk-partners" {
		t.Fatalf("product group create = %+v, %v", linkedGroup, err)
	}
	if _, err := productGroupClient.CheckEntityExists(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-partners", nil); err != nil {
		t.Fatal(err)
	}
	if page, err := productGroupClient.NewListByProductPager(defaultResourceGroup, "emulator", "go-sdk-product", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("product group page = %+v, %v", page, err)
	}
	if _, err := productGroupClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-partners", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := productGroupClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-partners", nil); err != nil {
		t.Fatal(err)
	}
	userClient, err := armapimanagement.NewUserClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	firstName, lastName, email, password := "Go", "Developer", "go-developer@example.test", "local-password"
	userState := armapimanagement.UserStateActive
	identityProvider, identityID := "Azure", "go-object"
	createdUser, err := userClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-user", armapimanagement.UserCreateParameters{
		Properties: &armapimanagement.UserCreateParameterProperties{FirstName: &firstName, LastName: &lastName, Email: &email, Password: &password, State: &userState, Identities: []*armapimanagement.UserIdentityContract{{Provider: &identityProvider, ID: &identityID}}},
	}, nil)
	if err != nil || createdUser.Properties == nil || createdUser.Properties.RegistrationDate == nil || createdUser.Properties.Email == nil || *createdUser.Properties.Email != email {
		t.Fatalf("user create = %+v, %v", createdUser, err)
	}
	userNote := "Updated by the Go SDK"
	updatedUser, err := userClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-user", "*", armapimanagement.UserUpdateParameters{
		Properties: &armapimanagement.UserUpdateParametersProperties{Note: &userNote},
	}, nil)
	if err != nil || updatedUser.Properties == nil || updatedUser.Properties.Note == nil || *updatedUser.Properties.Note != userNote {
		t.Fatalf("user update = %+v, %v", updatedUser, err)
	}
	if gotUser, err := userClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-user", nil); err != nil || gotUser.Properties == nil || gotUser.Properties.Note == nil || *gotUser.Properties.Note != userNote || len(gotUser.Properties.Identities) != 1 || gotUser.Properties.Identities[0].ID == nil || *gotUser.Properties.Identities[0].ID != identityID {
		t.Fatalf("user GET = %+v, %v", gotUser, err)
	}
	if entityTag, err := userClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-user", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("user ETag = %+v, %v", entityTag, err)
	}
	if page, err := userClient.NewListByServicePager(defaultResourceGroup, "emulator", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("user service page = %+v, %v", page, err)
	}
	if sso, err := userClient.GenerateSsoURL(ctx, defaultResourceGroup, "emulator", "go-sdk-user", nil); err != nil || sso.Value == nil || !strings.Contains(*sso.Value, "signin-sso") {
		t.Fatalf("user SSO URL = %+v, %v", sso, err)
	}
	tokenExpiry := time.Now().Add(time.Hour).UTC()
	keyType := armapimanagement.KeyTypeSecondary
	if token, err := userClient.GetSharedAccessToken(ctx, defaultResourceGroup, "emulator", "go-sdk-user", armapimanagement.UserTokenParameters{Properties: &armapimanagement.UserTokenParameterProperties{Expiry: &tokenExpiry, KeyType: &keyType}}, nil); err != nil || token.Value == nil || !strings.Contains(*token.Value, "skn=secondary") {
		t.Fatalf("user shared-access token = %+v, %v", token, err)
	}
	temporaryEmail := "temporary@example.test"
	if _, err := userClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "temporary", armapimanagement.UserCreateParameters{Properties: &armapimanagement.UserCreateParameterProperties{FirstName: &firstName, LastName: &lastName, Email: &temporaryEmail}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := userClient.Delete(ctx, defaultResourceGroup, "emulator", "temporary", "*", nil); err != nil {
		t.Fatal(err)
	}
	groupUserClient, err := armapimanagement.NewGroupUserClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	if linkedUser, err := groupUserClient.Create(ctx, defaultResourceGroup, "emulator", "go-sdk-partners", "go-sdk-user", nil); err != nil || linkedUser.Name == nil || *linkedUser.Name != "go-sdk-user" {
		t.Fatalf("group user create = %+v, %v", linkedUser, err)
	}
	if _, err := groupUserClient.CheckEntityExists(ctx, defaultResourceGroup, "emulator", "go-sdk-partners", "go-sdk-user", nil); err != nil {
		t.Fatal(err)
	}
	if page, err := groupUserClient.NewListPager(defaultResourceGroup, "emulator", "go-sdk-partners", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("group user page = %+v, %v", page, err)
	}
	userGroupClient, err := armapimanagement.NewUserGroupClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	if page, err := userGroupClient.NewListPager(defaultResourceGroup, "emulator", "go-sdk-user", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("user group page = %+v, %v", page, err)
	}
	if _, err := groupUserClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-partners", "go-sdk-user", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := groupUserClient.Create(ctx, defaultResourceGroup, "emulator", "go-sdk-partners", "go-sdk-user", nil); err != nil {
		t.Fatal(err)
	}
	tagClient, err := armapimanagement.NewTagClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	tagDisplayName := "Go SDK tag"
	createdTag, err := tagClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-tag", armapimanagement.TagCreateUpdateParameters{
		Properties: &armapimanagement.TagContractProperties{DisplayName: &tagDisplayName},
	}, nil)
	if err != nil || createdTag.Properties == nil || createdTag.Properties.DisplayName == nil || *createdTag.Properties.DisplayName != tagDisplayName {
		t.Fatalf("tag create = %+v, %v", createdTag, err)
	}
	tagDisplayName = "Updated Go SDK tag"
	updatedTag, err := tagClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-tag", "*", armapimanagement.TagCreateUpdateParameters{
		Properties: &armapimanagement.TagContractProperties{DisplayName: &tagDisplayName},
	}, nil)
	if err != nil || updatedTag.Properties == nil || updatedTag.Properties.DisplayName == nil || *updatedTag.Properties.DisplayName != tagDisplayName {
		t.Fatalf("tag update = %+v, %v", updatedTag, err)
	}
	if gotTag, err := tagClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-tag", nil); err != nil || gotTag.Properties == nil || gotTag.Properties.DisplayName == nil || *gotTag.Properties.DisplayName != tagDisplayName {
		t.Fatalf("tag GET = %+v, %v", gotTag, err)
	}
	if entityTag, err := tagClient.GetEntityState(ctx, defaultResourceGroup, "emulator", "go-sdk-tag", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("tag ETag = %+v, %v", entityTag, err)
	}
	if page, err := tagClient.NewListByServicePager(defaultResourceGroup, "emulator", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("tag service page = %+v, %v", page, err)
	}
	temporaryTagName := "Temporary tag"
	if _, err := tagClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "temporary", armapimanagement.TagCreateUpdateParameters{Properties: &armapimanagement.TagContractProperties{DisplayName: &temporaryTagName}}, nil); err != nil {
		t.Fatal(err)
	}
	filter, top := "endswith(displayName, 'tag')", int32(1)
	tagPager := tagClient.NewListByServicePager(defaultResourceGroup, "emulator", &armapimanagement.TagClientListByServiceOptions{Filter: &filter, Top: &top})
	firstTagPage, err := tagPager.NextPage(ctx)
	if err != nil || len(firstTagPage.Value) != 1 || firstTagPage.Count == nil || *firstTagPage.Count != 2 || !tagPager.More() {
		t.Fatalf("filtered first tag page = %+v, more=%v, %v", firstTagPage, tagPager.More(), err)
	}
	secondTagPage, err := tagPager.NextPage(ctx)
	if err != nil || len(secondTagPage.Value) != 1 || tagPager.More() {
		t.Fatalf("filtered second tag page = %+v, more=%v, %v", secondTagPage, tagPager.More(), err)
	}
	if _, err := tagClient.Delete(ctx, defaultResourceGroup, "emulator", "temporary", "*", nil); err != nil {
		t.Fatal(err)
	}

	if _, err := tagClient.AssignToAPI(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}
	if gotTag, err := tagClient.GetByAPI(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-tag", nil); err != nil || gotTag.Name == nil || *gotTag.Name != "go-sdk-tag" {
		t.Fatalf("API tag = %+v, %v", gotTag, err)
	}
	if entityTag, err := tagClient.GetEntityStateByAPI(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-tag", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("API tag ETag = %+v, %v", entityTag, err)
	}
	if page, err := tagClient.NewListByAPIPager(defaultResourceGroup, "emulator", "go-sdk-full", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("API tag page = %+v, %v", page, err)
	}
	if _, err := tagClient.DetachFromAPI(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tagClient.AssignToAPI(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}

	if _, err := tagClient.AssignToOperation(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "get", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}
	if gotTag, err := tagClient.GetByOperation(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "get", "go-sdk-tag", nil); err != nil || gotTag.Name == nil || *gotTag.Name != "go-sdk-tag" {
		t.Fatalf("operation tag = %+v, %v", gotTag, err)
	}
	if entityTag, err := tagClient.GetEntityStateByOperation(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "get", "go-sdk-tag", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("operation tag ETag = %+v, %v", entityTag, err)
	}
	if page, err := tagClient.NewListByOperationPager(defaultResourceGroup, "emulator", "go-sdk-full", "get", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("operation tag page = %+v, %v", page, err)
	}
	if _, err := tagClient.DetachFromOperation(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "get", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tagClient.AssignToOperation(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "get", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}

	if _, err := tagClient.AssignToProduct(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}
	if gotTag, err := tagClient.GetByProduct(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-tag", nil); err != nil || gotTag.Name == nil || *gotTag.Name != "go-sdk-tag" {
		t.Fatalf("product tag = %+v, %v", gotTag, err)
	}
	if entityTag, err := tagClient.GetEntityStateByProduct(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-tag", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("product tag ETag = %+v, %v", entityTag, err)
	}
	if page, err := tagClient.NewListByProductPager(defaultResourceGroup, "emulator", "go-sdk-product", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("product tag page = %+v, %v", page, err)
	}
	if _, err := tagClient.DetachFromProduct(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tagClient.AssignToProduct(ctx, defaultResourceGroup, "emulator", "go-sdk-product", "go-sdk-tag", nil); err != nil {
		t.Fatal(err)
	}
	schemaClient, err := armapimanagement.NewAPISchemaClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	schemaContentType := "application/vnd.oai.openapi.components+json"
	schemaPoller, err := schemaClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "components", armapimanagement.SchemaContract{
		Properties: &armapimanagement.SchemaContractProperties{ContentType: &schemaContentType, Document: &armapimanagement.SchemaDocumentProperties{Components: map[string]any{"schemas": map[string]any{"Item": map[string]any{"type": "object"}}}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := schemaPoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	gotSchema, err := schemaClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "components", nil)
	if err != nil || gotSchema.Properties == nil || gotSchema.Properties.ContentType == nil || *gotSchema.Properties.ContentType != schemaContentType || gotSchema.Properties.Document == nil {
		t.Fatalf("schema GET = %+v, %v", gotSchema, err)
	}
	components, ok := gotSchema.Properties.Document.Components.(map[string]any)
	if !ok || components["schemas"] == nil {
		t.Fatalf("schema document = %#v", gotSchema.Properties.Document.Components)
	}
	if entityTag, err := schemaClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "components", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("schema ETag = %+v, %v", entityTag, err)
	}
	schemaPage, err := schemaClient.NewListByAPIPager(defaultResourceGroup, "emulator", "go-sdk-full", nil).NextPage(ctx)
	if err != nil || len(schemaPage.Value) != 1 {
		t.Fatalf("schema page = %+v, %v", schemaPage, err)
	}
	temporarySchemaValue := `<schema xmlns="http://www.w3.org/2001/XMLSchema" />`
	temporarySchemaType := "application/vnd.ms-azure-apim.xsd+xml"
	temporarySchemaPoller, err := schemaClient.BeginCreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "temporary", armapimanagement.SchemaContract{Properties: &armapimanagement.SchemaContractProperties{ContentType: &temporarySchemaType, Document: &armapimanagement.SchemaDocumentProperties{Value: &temporarySchemaValue}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := temporarySchemaPoller.PollUntilDone(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := schemaClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "temporary", "*", nil); err != nil {
		t.Fatal(err)
	}
	loggerClient, err := armapimanagement.NewLoggerClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	loggerType := armapimanagement.LoggerTypeApplicationInsights
	loggerDescription, instrumentationKey := "Go SDK logger", "local-instrumentation-key"
	loggerBuffered := false
	createdLogger, err := loggerClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-logger", armapimanagement.LoggerContract{
		Properties: &armapimanagement.LoggerContractProperties{LoggerType: &loggerType, Description: &loggerDescription,
			IsBuffered: &loggerBuffered, Credentials: map[string]*string{"instrumentationKey": &instrumentationKey}},
	}, nil)
	if err != nil || createdLogger.ID == nil || createdLogger.Properties == nil || createdLogger.Properties.LoggerType == nil {
		t.Fatalf("logger create = %+v, %v", createdLogger, err)
	}
	loggerID := *createdLogger.ID
	if got, err := loggerClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-logger", nil); err != nil || got.Properties == nil || got.Properties.Description == nil || *got.Properties.Description != loggerDescription || got.Properties.Credentials["instrumentationKey"] == nil || *got.Properties.Credentials["instrumentationKey"] == instrumentationKey || !strings.HasPrefix(*got.Properties.Credentials["instrumentationKey"], "{{Logger-Credentials-") {
		t.Fatalf("logger GET = %+v, %v", got, err)
	}
	if entityTag, err := loggerClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-logger", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("logger ETag = %+v, %v", entityTag, err)
	}
	if page, err := loggerClient.NewListByServicePager(defaultResourceGroup, "emulator", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("logger page = %+v, %v", page, err)
	}
	updatedLoggerDescription := "Updated Go SDK logger"
	if updated, err := loggerClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-logger", "*", armapimanagement.LoggerUpdateContract{Properties: &armapimanagement.LoggerUpdateParameters{Description: &updatedLoggerDescription}}, nil); err != nil || updated.Properties == nil || updated.Properties.Description == nil || *updated.Properties.Description != updatedLoggerDescription {
		t.Fatalf("logger update = %+v, %v", updated, err)
	}
	if _, err := loggerClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "temporary", armapimanagement.LoggerContract{Properties: &armapimanagement.LoggerContractProperties{LoggerType: &loggerType}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := loggerClient.Delete(ctx, defaultResourceGroup, "emulator", "temporary", "*", nil); err != nil {
		t.Fatal(err)
	}

	diagnosticClient, err := armapimanagement.NewDiagnosticClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	alwaysLog, verbosity := armapimanagement.AlwaysLogAllErrors, armapimanagement.VerbosityInformation
	correlationProtocol, operationNameFormat := armapimanagement.HTTPCorrelationProtocolW3C, armapimanagement.OperationNameFormatURL
	samplingType, samplingPercentage, logClientIP := armapimanagement.SamplingTypeFixed, 100.0, true
	diagnosticContract := armapimanagement.DiagnosticContract{Properties: &armapimanagement.DiagnosticContractProperties{
		LoggerID: &loggerID, AlwaysLog: &alwaysLog, LogClientIP: &logClientIP, Verbosity: &verbosity,
		HTTPCorrelationProtocol: &correlationProtocol, OperationNameFormat: &operationNameFormat,
		Sampling: &armapimanagement.SamplingSettings{SamplingType: &samplingType, Percentage: &samplingPercentage},
		Frontend: &armapimanagement.PipelineDiagnosticSettings{Request: &armapimanagement.HTTPMessageDiagnostic{Headers: []*string{&displayName}}},
	}}
	createdDiagnostic, err := diagnosticClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-diagnostic", diagnosticContract, nil)
	if err != nil || createdDiagnostic.Properties == nil || createdDiagnostic.Properties.LoggerID == nil || *createdDiagnostic.Properties.LoggerID != loggerID {
		t.Fatalf("diagnostic create = %+v, %v", createdDiagnostic, err)
	}
	if got, err := diagnosticClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-diagnostic", nil); err != nil || got.Properties == nil || got.Properties.Frontend == nil || got.Properties.HTTPCorrelationProtocol == nil || *got.Properties.HTTPCorrelationProtocol != correlationProtocol || got.Properties.OperationNameFormat == nil || *got.Properties.OperationNameFormat != operationNameFormat {
		t.Fatalf("diagnostic GET = %+v, %v", got, err)
	}
	if entityTag, err := diagnosticClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-diagnostic", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("diagnostic ETag = %+v, %v", entityTag, err)
	}
	if page, err := diagnosticClient.NewListByServicePager(defaultResourceGroup, "emulator", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("diagnostic page = %+v, %v", page, err)
	}
	verbosity = armapimanagement.VerbosityVerbose
	if updated, err := diagnosticClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-diagnostic", "*", armapimanagement.DiagnosticContract{Properties: &armapimanagement.DiagnosticContractProperties{Verbosity: &verbosity}}, nil); err != nil || updated.Properties == nil || updated.Properties.Verbosity == nil || *updated.Properties.Verbosity != verbosity {
		t.Fatalf("diagnostic update = %+v, %v", updated, err)
	}

	apiDiagnosticClient, err := armapimanagement.NewAPIDiagnosticClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	createdAPIDiagnostic, err := apiDiagnosticClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-api-diagnostic", diagnosticContract, nil)
	if err != nil || createdAPIDiagnostic.Properties == nil || createdAPIDiagnostic.Properties.Sampling == nil {
		t.Fatalf("API diagnostic create = %+v, %v", createdAPIDiagnostic, err)
	}
	if got, err := apiDiagnosticClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-api-diagnostic", nil); err != nil || got.Properties == nil || got.Properties.LoggerID == nil {
		t.Fatalf("API diagnostic GET = %+v, %v", got, err)
	}
	if entityTag, err := apiDiagnosticClient.GetEntityTag(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-api-diagnostic", nil); err != nil || entityTag.ETag == nil {
		t.Fatalf("API diagnostic ETag = %+v, %v", entityTag, err)
	}
	if page, err := apiDiagnosticClient.NewListByServicePager(defaultResourceGroup, "emulator", "go-sdk-full", nil).NextPage(ctx); err != nil || len(page.Value) != 1 {
		t.Fatalf("API diagnostic page = %+v, %v", page, err)
	}
	verbosity = armapimanagement.VerbosityError
	if updated, err := apiDiagnosticClient.Update(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-api-diagnostic", "*", armapimanagement.DiagnosticContract{Properties: &armapimanagement.DiagnosticContractProperties{Verbosity: &verbosity}}, nil); err != nil || updated.Properties == nil || updated.Properties.Verbosity == nil || *updated.Properties.Verbosity != verbosity {
		t.Fatalf("API diagnostic update = %+v, %v", updated, err)
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
	if err != nil || clonedOperation.Properties == nil || clonedOperation.Properties.Method == nil || *clonedOperation.Properties.Method != method || clonedOperation.Properties.Description == nil || *clonedOperation.Properties.Description != operationDescription {
		t.Fatalf("cloned revision operation = %+v, %v", clonedOperation, err)
	}
	if clonedSchema, err := schemaClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "components", nil); err != nil || clonedSchema.Properties == nil || clonedSchema.Properties.ContentType == nil || *clonedSchema.Properties.ContentType != schemaContentType {
		t.Fatalf("cloned revision schema = %+v, %v", clonedSchema, err)
	}
	if clonedTag, err := tagClient.GetByAPI(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "go-sdk-tag", nil); err != nil || clonedTag.Name == nil || *clonedTag.Name != "go-sdk-tag" {
		t.Fatalf("cloned revision API tag = %+v, %v", clonedTag, err)
	}
	if clonedTag, err := tagClient.GetByOperation(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "get", "go-sdk-tag", nil); err != nil || clonedTag.Name == nil || *clonedTag.Name != "go-sdk-tag" {
		t.Fatalf("cloned revision operation tag = %+v, %v", clonedTag, err)
	}
	if clonedDiagnostic, err := apiDiagnosticClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "go-sdk-api-diagnostic", nil); err != nil || clonedDiagnostic.Properties == nil || clonedDiagnostic.Properties.LoggerID == nil || *clonedDiagnostic.Properties.LoggerID != loggerID {
		t.Fatalf("cloned revision API diagnostic = %+v, %v", clonedDiagnostic, err)
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
	if gotSubscription, err := subscriptionClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-subscription", nil); err != nil || gotSubscription.Properties == nil || gotSubscription.Properties.DisplayName == nil || *gotSubscription.Properties.DisplayName != subscriptionName || gotSubscription.Properties.Scope == nil || *gotSubscription.Properties.Scope != scope || gotSubscription.Properties.State == nil || *gotSubscription.Properties.State != state {
		t.Fatalf("subscription GET = %+v, %v", gotSubscription, err)
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
	if gotRelease, err := releaseClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "release-2", nil); err != nil || gotRelease.Properties == nil || gotRelease.Properties.Notes == nil || *gotRelease.Properties.Notes != updatedNotes {
		t.Fatalf("updated API release GET = %+v, %v", gotRelease, err)
	}
	if _, err := releaseClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "release-2", "*", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := loggerClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-logger", "*", nil); err == nil {
		t.Fatal("SDK deleted a referenced logger")
	}
	if _, err := apiDiagnosticClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-full", "go-sdk-api-diagnostic", "*", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := apiDiagnosticClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "go-sdk-api-diagnostic", "*", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := diagnosticClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-diagnostic", "*", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := loggerClient.Delete(ctx, defaultResourceGroup, "emulator", "go-sdk-logger", "*", nil); err != nil {
		t.Fatal(err)
	}
}

func serverTestPKCS12(t *testing.T, password string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sdk-client.test"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.Modern.Encode(key, leaf, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pfx)
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
