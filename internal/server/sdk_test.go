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
	productClient, err := armapimanagement.NewProductClient(defaultSubscription, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	productDisplayName := "Go SDK product"
	if _, err := productClient.CreateOrUpdate(ctx, defaultResourceGroup, "emulator", "go-sdk-product", armapimanagement.ProductContract{
		Properties: &armapimanagement.ProductContractProperties{DisplayName: &productDisplayName},
	}, nil); err != nil {
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
	if err != nil || gotSchema.Properties == nil || gotSchema.Properties.ContentType == nil || *gotSchema.Properties.ContentType != schemaContentType {
		t.Fatalf("schema GET = %+v, %v", gotSchema, err)
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
	if clonedSchema, err := schemaClient.Get(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "components", nil); err != nil || clonedSchema.Properties == nil || clonedSchema.Properties.ContentType == nil || *clonedSchema.Properties.ContentType != schemaContentType {
		t.Fatalf("cloned revision schema = %+v, %v", clonedSchema, err)
	}
	if clonedTag, err := tagClient.GetByAPI(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "go-sdk-tag", nil); err != nil || clonedTag.Name == nil || *clonedTag.Name != "go-sdk-tag" {
		t.Fatalf("cloned revision API tag = %+v, %v", clonedTag, err)
	}
	if clonedTag, err := tagClient.GetByOperation(ctx, defaultResourceGroup, "emulator", "go-sdk-full;rev=2", "get", "go-sdk-tag", nil); err != nil || clonedTag.Name == nil || *clonedTag.Name != "go-sdk-tag" {
		t.Fatalf("cloned revision operation tag = %+v, %v", clonedTag, err)
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
