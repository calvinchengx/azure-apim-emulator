package arm

import (
	"context"
	"encoding/base64"
	"time"

	certutil "github.com/calvinchengx/azure-apim-emulator/internal/certificate"
	"github.com/calvinchengx/azure-apim-emulator/internal/keyvault"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

func (h *Handler) secretRetriever() keyvault.Retriever {
	if h.Secrets != nil {
		return h.Secrets
	}
	client := h.KeyVaultClient
	if client == nil {
		client = h.ImportClient
	}
	return keyvault.HTTP{Client: client, AcquireToken: h.AcquireToken, ClientID: h.IdentityClientID, ClientSecret: h.IdentityClientSecret}
}

func (h *Handler) keyVaultNow() time.Time {
	if h.Store != nil && h.Store.Clock != nil {
		return time.Unix(h.Store.Clock.Now(), 0).UTC()
	}
	return time.Now().UTC()
}

func (h *Handler) refreshNamedValueSecret(ctx context.Context, value *model.NamedValue) {
	secret, err := h.secretRetriever().GetSecret(ctx, value.KeyVaultSecretID)
	value.KeyVaultStatusCode, value.KeyVaultStatusMessage = keyvault.Classify(err)
	value.KeyVaultStatusTime = h.keyVaultNow()
	if err == nil {
		value.Value = secret.Value
	}
}

func (h *Handler) refreshCertificateSecret(ctx context.Context, value *model.Certificate) {
	secret, err := h.secretRetriever().GetSecret(ctx, value.KeyVaultSecretID)
	value.KeyVaultStatusCode, value.KeyVaultStatusMessage = keyvault.Classify(err)
	value.KeyVaultStatusTime = h.keyVaultNow()
	if err != nil {
		return
	}
	data := decodeKeyVaultCertificate(secret.Value)
	leaf, thumbprint, parseErr := certutil.ParsePKCS12(data, value.Password)
	if parseErr != nil {
		value.KeyVaultStatusCode, value.KeyVaultStatusMessage = "Error", parseErr.Error()
		return
	}
	value.Data, value.Subject, value.Thumbprint, value.Expiration = data, leaf.Subject.String(), thumbprint, leaf.NotAfter.UTC()
}

func decodeKeyVaultCertificate(value string) []byte {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return []byte(value)
	}
	return data
}

func keyVaultWire(secretID, identityID, code, message string, at time.Time) map[string]any {
	result := map[string]any{"secretIdentifier": secretID, "identityClientId": identityID}
	if code == "" && message == "" && at.IsZero() {
		return result
	}
	status := map[string]any{"code": code, "message": message}
	if !at.IsZero() {
		status["timeStampUtc"] = at.UTC().Format(time.RFC3339)
	}
	result["lastStatus"] = status
	return result
}
