package arm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// expiringPKCS12 builds a PFX whose validity window the caller chooses, so an
// expiry can be asserted without waiting for one.
func expiringPKCS12(t *testing.T, password string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "api.contoso.test"},
		NotBefore:    notAfter.Add(-2 * time.Hour),
		NotAfter:     notAfter,
	}
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

func servicePayloadWithHostnames(configurations string) string {
	return `{"location":"local","sku":{"name":"Developer","capacity":1},"properties":{` +
		`"publisherName":"Contoso","publisherEmail":"ops@contoso.test",` +
		`"hostnameConfigurations":[` + configurations + `]}}`
}

func hostnameConfigurations(t *testing.T, handler *Handler) []map[string]any {
	t.Helper()
	got := request(t, handler, http.MethodGet, basePath+apiQuery, "")
	var payload struct {
		Properties struct {
			HostnameConfigurations []map[string]any `json:"hostnameConfigurations"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &payload); err != nil {
		t.Fatalf("service GET = %s", got.Body.String())
	}
	return payload.Properties.HostnameConfigurations
}

// The PFX and its password are write-only; the facts inside it are exactly what
// an operator needs to read. Returning the secret would make a management read
// a way to harvest a private key.
func TestCustomDomainCertificateIsParsedAndTheSecretDropped(t *testing.T) {
	handler, _ := testHandler(t)
	password := "pfx-password"
	encoded := expiringPKCS12(t, password, time.Now().UTC().Add(365*24*time.Hour))
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, servicePayloadWithHostnames(
		`{"type":"Proxy","hostName":"api.contoso.test","encodedCertificate":"`+encoded+`","certificatePassword":"`+password+`","defaultSslBinding":true}`,
	), http.StatusCreated)

	body := request(t, handler, http.MethodGet, basePath+apiQuery, "").Body.String()
	if strings.Contains(body, password) || strings.Contains(body, encoded[:40]) {
		t.Fatalf("the certificate or its password was echoed: %s", body)
	}
	configurations := hostnameConfigurations(t, handler)
	if len(configurations) != 1 {
		t.Fatalf("hostnameConfigurations = %v", configurations)
	}
	entry := configurations[0]
	if entry["certificateSource"] != "Custom" || entry["certificateStatus"] != "Completed" {
		t.Fatalf("source/status = %v", entry)
	}
	certificate, _ := entry["certificate"].(map[string]any)
	if certificate == nil || !strings.Contains(certificate["subject"].(string), "api.contoso.test") {
		t.Fatalf("certificate = %v", entry)
	}
	if certificate["thumbprint"] == "" || certificate["expiry"] == "" {
		t.Fatalf("thumbprint or expiry missing: %v", certificate)
	}
	// Non-secret configuration survives untouched.
	if entry["defaultSslBinding"] != true || entry["hostName"] != "api.contoso.test" {
		t.Fatalf("configuration was altered: %v", entry)
	}
}

// An expired certificate parses perfectly and still cannot serve TLS. Reporting
// Completed because the bytes were readable would tell an operator the domain
// is healthy on the day it stops working.
func TestExpiredCustomDomainCertificateIsReportedFailed(t *testing.T) {
	handler, _ := testHandler(t)
	encoded := expiringPKCS12(t, "p", time.Now().UTC().Add(-time.Hour))
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, servicePayloadWithHostnames(
		`{"type":"Proxy","hostName":"expired.contoso.test","encodedCertificate":"`+encoded+`","certificatePassword":"p"}`,
	), http.StatusCreated)
	entry := hostnameConfigurations(t, handler)[0]
	if entry["certificateStatus"] != "Failed" {
		t.Fatalf("an expired certificate was reported %v", entry["certificateStatus"])
	}
	// The parsed facts are still reported: an operator needs the expiry date to
	// understand WHY it failed.
	certificate, _ := entry["certificate"].(map[string]any)
	if certificate == nil || certificate["expiry"] == "" {
		t.Fatalf("certificate facts were withheld: %v", entry)
	}
}

// One broken domain must not take a working service down with it.
func TestUnreadableCustomDomainCertificateDoesNotRefuseTheService(t *testing.T) {
	handler, _ := testHandler(t)
	good := expiringPKCS12(t, "p", time.Now().UTC().Add(24*time.Hour))
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, servicePayloadWithHostnames(
		`{"type":"Proxy","hostName":"broken.contoso.test","encodedCertificate":"not base64 at all!!","certificatePassword":"p"},`+
			`{"type":"Proxy","hostName":"wrongpassword.contoso.test","encodedCertificate":"`+good+`","certificatePassword":"wrong"},`+
			`{"type":"Proxy","hostName":"good.contoso.test","encodedCertificate":"`+good+`","certificatePassword":"p"}`,
	), http.StatusCreated)

	byHost := map[string]map[string]any{}
	for _, entry := range hostnameConfigurations(t, handler) {
		byHost[entry["hostName"].(string)] = entry
	}
	if byHost["broken.contoso.test"]["certificateStatus"] != "Failed" {
		t.Fatalf("unreadable base64 = %v", byHost["broken.contoso.test"])
	}
	if _, has := byHost["broken.contoso.test"]["certificate"]; has {
		t.Fatalf("facts were reported for a certificate that could not be read: %v", byHost["broken.contoso.test"])
	}
	if byHost["wrongpassword.contoso.test"]["certificateStatus"] != "Failed" {
		t.Fatalf("wrong password = %v", byHost["wrongpassword.contoso.test"])
	}
	// The working domain is unaffected, which is the point.
	if byHost["good.contoso.test"]["certificateStatus"] != "Completed" {
		t.Fatalf("a working domain was failed by its neighbour: %v", byHost["good.contoso.test"])
	}
}

func TestCustomDomainCertificateSources(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery, servicePayloadWithHostnames(
		`{"type":"Proxy","hostName":"vault.contoso.test","keyVaultId":"https://vault.test/secrets/domain"},`+
			`{"type":"Proxy","hostName":"managed.contoso.test"}`,
	), http.StatusCreated)
	byHost := map[string]map[string]any{}
	for _, entry := range hostnameConfigurations(t, handler) {
		byHost[entry["hostName"].(string)] = entry
	}
	// A hostname deferring to a vault is distinguishable from one carrying its
	// own PFX, which is what an operator rotating a certificate needs to know.
	if byHost["vault.contoso.test"]["certificateSource"] != "KeyVault" {
		t.Fatalf("key vault source = %v", byHost["vault.contoso.test"])
	}
	// A hostname with no certificate is served by the service's own.
	if byHost["managed.contoso.test"]["certificateSource"] != "Managed" {
		t.Fatalf("managed source = %v", byHost["managed.contoso.test"])
	}
}

// A document whose hostnameConfigurations are not a list, or whose entries are
// not objects, must not panic the resolution.
func TestHostnameResolutionToleratesMalformedDocuments(t *testing.T) {
	for _, document := range []map[string]any{
		{},
		{"properties": "scalar"},
		{"properties": map[string]any{"hostnameConfigurations": "scalar"}},
		{"properties": map[string]any{"hostnameConfigurations": []any{"scalar", 42}}},
		{"hostnameConfigurations": []any{map[string]any{"hostName": "top.level.test"}}},
	} {
		resolveHostnameCertificates(document, time.Now().UTC())
	}
	// The top-level form is resolved too, since a caller may put it there.
	top := map[string]any{"hostnameConfigurations": []any{map[string]any{"hostName": "top.level.test"}}}
	resolveHostnameCertificates(top, time.Now().UTC())
	entry := top["hostnameConfigurations"].([]any)[0].(map[string]any)
	if entry["certificateSource"] != "Managed" {
		t.Fatalf("top-level configuration = %v", entry)
	}
}

// A caller that states its own status is not overridden for a Key Vault
// hostname, because the gateway records last-known-good there.
func TestKeyVaultHostnameKeepsAStatedStatus(t *testing.T) {
	configuration := map[string]any{
		"hostName": "vault.contoso.test", "keyVaultId": "https://vault.test/secrets/x",
		"certificateStatus": "Failed",
	}
	resolveHostnameCertificate(configuration, time.Now().UTC())
	if configuration["certificateStatus"] != "Failed" {
		t.Fatalf("a stated status was overwritten: %v", configuration)
	}
}
