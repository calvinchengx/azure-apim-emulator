package arm

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

var namedValueDisplayName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type namedValuePayload struct {
	Properties struct {
		DisplayName *string   `json:"displayName"`
		Value       *string   `json:"value"`
		Tags        *[]string `json:"tags"`
		Secret      *bool     `json:"secret"`
		KeyVault    *struct {
			SecretIdentifier *string `json:"secretIdentifier"`
			IdentityClientID *string `json:"identityClientId"`
		} `json:"keyVault"`
	} `json:"properties"`
}

func (h *Handler) namedValue(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListNamedValues(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, namedValueWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested named value resource was not found.", r.URL.Path)
		return
	}
	value := model.NamedValue{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		h.namedValueAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetNamedValue(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, namedValueWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetNamedValue(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body namedValuePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = namedValueWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeNamedValueDocument(value.Document)
		applyNamedValuePayload(&value, body)
		clearNullNamedValueProperties(&value, document)
		if value.DisplayName == "" || len(value.DisplayName) > 256 || !namedValueDisplayName.MatchString(value.DisplayName) ||
			(strings.TrimSpace(value.Value) == "" && value.KeyVaultSecretID == "") || len(value.Value) > 4096 {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName must be a valid named-value identifier and either value or keyVault.secretIdentifier is required.", "properties")
			return
		}
		if value.KeyVaultSecretID != "" {
			h.refreshNamedValueSecret(r.Context(), &value)
		}
		got, err := h.Store.UpsertNamedValue(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, namedValueWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteNamedValue(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func (h *Handler) namedValueAction(w http.ResponseWriter, r *http.Request, value model.NamedValue, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	got, err := h.Store.GetNamedValue(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	switch action {
	case "listValue":
		writeResource(w, http.StatusOK, map[string]any{"value": got.Value}, got.ETag)
	case "refreshSecret":
		if got.KeyVaultSecretID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "refreshSecret requires a Key Vault-backed named value.", value.ID())
			return
		}
		h.refreshNamedValueSecret(r.Context(), &got)
		updated, err := h.Store.UpsertNamedValue(got)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		writeResource(w, http.StatusOK, namedValueWire(updated), updated.ETag)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested named value action was not found.", r.URL.Path)
	}
}

func applyNamedValuePayload(value *model.NamedValue, body namedValuePayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Value != nil {
		value.Value = *body.Properties.Value
	}
	if body.Properties.Tags != nil {
		value.Tags = *body.Properties.Tags
	}
	if body.Properties.Secret != nil {
		value.Secret = *body.Properties.Secret
	}
	if body.Properties.KeyVault != nil {
		if body.Properties.KeyVault.SecretIdentifier != nil {
			value.KeyVaultSecretID = *body.Properties.KeyVault.SecretIdentifier
		}
		if body.Properties.KeyVault.IdentityClientID != nil {
			value.KeyVaultIdentityID = *body.Properties.KeyVault.IdentityClientID
		}
	}
}

func sanitizeNamedValueDocument(document map[string]any) {
	delete(document, "value")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "value")
}

func clearNullNamedValueProperties(value *model.NamedValue, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["displayName"]; present && field == nil {
		value.DisplayName = ""
	}
	if field, present := properties["value"]; present && field == nil {
		value.Value = ""
	}
	if field, present := properties["tags"]; present && field == nil {
		value.Tags = nil
	}
	if field, present := properties["secret"]; present && field == nil {
		value.Secret = false
	}
	if field, present := properties["keyVault"]; present && field == nil {
		value.KeyVaultSecretID, value.KeyVaultIdentityID = "", ""
		return
	}
	keyVault, _ := properties["keyVault"].(map[string]any)
	if field, present := keyVault["secretIdentifier"]; present && field == nil {
		value.KeyVaultSecretID = ""
	}
	if field, present := keyVault["identityClientId"]; present && field == nil {
		value.KeyVaultIdentityID = ""
	}
}

func namedValueWire(v model.NamedValue) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/namedValues"
	delete(result, "value")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "value")
	properties["displayName"], properties["secret"], properties["tags"] = v.DisplayName, v.Secret, v.Tags
	if v.KeyVaultSecretID != "" {
		properties["keyVault"] = keyVaultWire(v.KeyVaultSecretID, v.KeyVaultIdentityID, v.KeyVaultStatusCode, v.KeyVaultStatusMessage, v.KeyVaultStatusTime)
	} else {
		delete(properties, "keyVault")
	}
	return result
}
