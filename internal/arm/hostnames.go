package arm

import (
	"encoding/base64"
	"strings"
	"time"

	certutil "github.com/calvinchengx/azure-apim-emulator/internal/certificate"
)

// Custom domains: the certificate a hostname configuration carries, and what
// the service reports back about it.
//
// A hostname configuration is where a secret and a fact live in one object. The
// PFX and its password are WRITE-ONLY -- Azure never returns them -- while the
// subject, thumbprint and expiry it contains are exactly what an operator needs
// to read. Storing the one and projecting the other is the whole job here.

// Certificate sources and statuses, spelled as Azure spells them because a
// caller compares against these strings.
const (
	certificateSourceCustom    = "Custom"
	certificateSourceKeyVault  = "KeyVault"
	certificateStatusCompleted = "Completed"
	certificateStatusFailed    = "Failed"
)

// hostnameSecrets are the fields a caller may send and must never read back.
var hostnameSecrets = []string{"encodedCertificate", "certificatePassword"}

// resolveHostnameCertificates parses each hostname configuration's certificate
// and records what it found, in place, on the service document.
//
// A certificate that will not parse is recorded as Failed rather than refused.
// That is deliberate and it is the direction Azure takes: the service still
// exists, the other hostnames still work, and the operator is told which one is
// broken. Refusing the whole PUT would take a working service down over one
// expired domain.
func resolveHostnameCertificates(document map[string]any, now time.Time) {
	for _, configuration := range hostnameConfigurationList(document) {
		resolveHostnameCertificate(configuration, now)
	}
}

func resolveHostnameCertificate(configuration map[string]any, now time.Time) {
	keyVaultID, _ := configuration["keyVaultId"].(string)
	encoded, _ := configuration["encodedCertificate"].(string)
	switch {
	case strings.TrimSpace(encoded) != "":
		configuration["certificateSource"] = certificateSourceCustom
		password, _ := configuration["certificatePassword"].(string)
		applyParsedCertificate(configuration, encoded, password, now)
	case strings.TrimSpace(keyVaultID) != "":
		// The secret is fetched by the gateway at activation, not here: this
		// handler must not reach a vault while holding the mutation lock. What
		// is recorded is that the hostname DEFERS to a vault, which is what
		// distinguishes it from one carrying its own PFX.
		configuration["certificateSource"] = certificateSourceKeyVault
		if _, stated := configuration["certificateStatus"]; !stated {
			configuration["certificateStatus"] = certificateStatusCompleted
		}
	default:
		// A hostname with no certificate at all is served by the service's own,
		// which is what Azure calls a Managed certificate.
		configuration["certificateSource"] = "Managed"
		configuration["certificateStatus"] = certificateStatusCompleted
	}
	for _, secret := range hostnameSecrets {
		delete(configuration, secret)
	}
}

// applyParsedCertificate records the facts inside a PFX, or why it could not be
// read.
func applyParsedCertificate(configuration map[string]any, encoded, password string, now time.Time) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		configuration["certificateStatus"] = certificateStatusFailed
		delete(configuration, "certificate")
		return
	}
	leaf, thumbprint, err := certutil.ParsePKCS12(data, password)
	if err != nil {
		configuration["certificateStatus"] = certificateStatusFailed
		delete(configuration, "certificate")
		return
	}
	configuration["certificate"] = map[string]any{
		"subject":    leaf.Subject.String(),
		"thumbprint": thumbprint,
		"expiry":     leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	// An expired certificate parses perfectly and still cannot serve TLS, so it
	// is reported Failed. Reporting Completed because the bytes were readable
	// would tell an operator the domain is healthy on the day it stops working.
	if now.After(leaf.NotAfter) {
		configuration["certificateStatus"] = certificateStatusFailed
		return
	}
	configuration["certificateStatus"] = certificateStatusCompleted
}

// hostnameConfigurationList returns the hostname configurations of a service
// document, from wherever the caller put them.
func hostnameConfigurationList(document map[string]any) []map[string]any {
	var values []map[string]any
	collect := func(value any) {
		entries, ok := value.([]any)
		if !ok {
			return
		}
		for _, entry := range entries {
			if configuration, ok := entry.(map[string]any); ok {
				values = append(values, configuration)
			}
		}
	}
	collect(document["hostnameConfigurations"])
	if properties, ok := document["properties"].(map[string]any); ok {
		collect(properties["hostnameConfigurations"])
	}
	return values
}
