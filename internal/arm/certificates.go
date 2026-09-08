package arm

import (
	"errors"
	"net/http"
	"time"

	certutil "github.com/calvinchengx/azure-apim-emulator/internal/certificate"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type certificatePayload struct {
	Properties struct {
		Data     []byte  `json:"data"`
		Password *string `json:"password"`
		KeyVault *struct {
			SecretIdentifier *string `json:"secretIdentifier"`
			IdentityClientID *string `json:"identityClientId"`
		} `json:"keyVault"`
	} `json:"properties"`
}

func (h *Handler) certificate(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListCertificates(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, certificateWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested certificate resource was not found.", r.URL.Path)
		return
	}
	value := model.Certificate{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		if rt.Tail[2] != "refreshSecret" {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested certificate action was not found.", r.URL.Path)
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetCertificate(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if got.KeyVaultSecretID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "refreshSecret requires a Key Vault-backed certificate.", value.ID())
			return
		}
		h.refreshCertificateSecret(r.Context(), &got)
		updated, err := h.Store.UpsertCertificate(got)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		writeResource(w, http.StatusOK, certificateWire(updated), updated.ETag)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetCertificate(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, certificateWire(got), got.ETag)
	case http.MethodPut:
		_, existingErr := h.Store.GetCertificate(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body certificatePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		sanitizeCertificateDocument(value.Document)
		if body.Properties.Password != nil {
			value.Password = *body.Properties.Password
		}
		if body.Properties.KeyVault != nil {
			if body.Properties.KeyVault.SecretIdentifier != nil {
				value.KeyVaultSecretID = *body.Properties.KeyVault.SecretIdentifier
			}
			if body.Properties.KeyVault.IdentityClientID != nil {
				value.KeyVaultIdentityID = *body.Properties.KeyVault.IdentityClientID
			}
		}
		value.Data = body.Properties.Data
		if (len(value.Data) == 0) == (value.KeyVaultSecretID == "") {
			writeError(w, http.StatusBadRequest, "ValidationError", "exactly one of data or keyVault.secretIdentifier is required.", "properties")
			return
		}
		if len(value.Data) != 0 {
			leaf, thumbprint, err := certutil.ParsePKCS12(value.Data, value.Password)
			if err != nil {
				writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.data")
				return
			}
			value.Subject, value.Thumbprint, value.Expiration = leaf.Subject.String(), thumbprint, leaf.NotAfter.UTC()
		} else {
			h.refreshCertificateSecret(r.Context(), &value)
		}
		got, err := h.Store.UpsertCertificate(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, certificateWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteCertificate(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func sanitizeCertificateDocument(document map[string]any) {
	delete(document, "data")
	delete(document, "password")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "data")
	delete(properties, "password")
	delete(properties, "subject")
	delete(properties, "thumbprint")
	delete(properties, "expirationDate")
}

func certificateWire(v model.Certificate) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/certificates"
	delete(result, "data")
	delete(result, "password")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	for _, field := range []string{"data", "password", "subject", "thumbprint", "expirationDate", "keyVault"} {
		delete(properties, field)
	}
	if v.Subject != "" {
		properties["subject"] = v.Subject
	}
	if v.Thumbprint != "" {
		properties["thumbprint"] = v.Thumbprint
	}
	if !v.Expiration.IsZero() {
		properties["expirationDate"] = v.Expiration.UTC().Format(time.RFC3339)
	}
	if v.KeyVaultSecretID != "" {
		properties["keyVault"] = keyVaultWire(v.KeyVaultSecretID, v.KeyVaultIdentityID, v.KeyVaultStatusCode, v.KeyVaultStatusMessage, v.KeyVaultStatusTime)
	}
	return result
}
