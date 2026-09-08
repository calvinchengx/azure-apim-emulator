package arm

import (
	"errors"
	"net/http"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type openIDConnectProviderPayload struct {
	Properties struct {
		DisplayName      *string `json:"displayName"`
		Description      *string `json:"description"`
		MetadataEndpoint *string `json:"metadataEndpoint"`
		ClientID         *string `json:"clientId"`
		ClientSecret     *string `json:"clientSecret"`
	} `json:"properties"`
}

func (h *Handler) openIDConnectProvider(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListOpenIDConnectProviders(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, openIDConnectProviderWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested OpenID Connect provider resource was not found.", r.URL.Path)
		return
	}
	value := model.OpenIDConnectProvider{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		h.openIDConnectProviderAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetOpenIDConnectProvider(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, openIDConnectProviderWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetOpenIDConnectProvider(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value.Name = existing.Name
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body openIDConnectProviderPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = openIDConnectProviderWire(value)
			}
			mergeObject(value.Document, document)
			clearNullOpenIDConnectProviderProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeOpenIDConnectProviderDocument(value.Document)
		applyOpenIDConnectProviderPayload(&value, body)
		if err := validateOpenIDConnectProvider(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertOpenIDConnectProvider(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, openIDConnectProviderWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteOpenIDConnectProvider(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) openIDConnectProviderAction(w http.ResponseWriter, r *http.Request, value model.OpenIDConnectProvider, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !equal(action, "listSecrets") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested OpenID Connect provider action was not found.", r.URL.Path)
		return
	}
	got, err := h.Store.GetOpenIDConnectProvider(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	writeResource(w, http.StatusOK, map[string]any{"clientSecret": got.ClientSecret}, got.ETag)
}

func applyOpenIDConnectProviderPayload(value *model.OpenIDConnectProvider, body openIDConnectProviderPayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.MetadataEndpoint != nil {
		value.MetadataEndpoint = *body.Properties.MetadataEndpoint
	}
	if body.Properties.ClientID != nil {
		value.ClientID = *body.Properties.ClientID
	}
	if body.Properties.ClientSecret != nil {
		value.ClientSecret = *body.Properties.ClientSecret
	}
}

func clearNullOpenIDConnectProviderProperties(value *model.OpenIDConnectProvider, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["description"]; present && field == nil {
		value.Description = ""
	}
}

func validateOpenIDConnectProvider(value model.OpenIDConnectProvider, creating bool) error {
	if creating && value.DisplayName == "" {
		return errors.New("displayName is required")
	}
	if creating && value.MetadataEndpoint == "" {
		return errors.New("metadataEndpoint is required")
	}
	if creating && value.ClientID == "" {
		return errors.New("clientId is required")
	}
	if value.DisplayName == "" {
		return errors.New("displayName cannot be empty")
	}
	if len(value.DisplayName) > 50 {
		return errors.New("displayName must be at most 50 characters")
	}
	if value.MetadataEndpoint == "" {
		return errors.New("metadataEndpoint cannot be empty")
	}
	if value.ClientID == "" {
		return errors.New("clientId cannot be empty")
	}
	return nil
}

func sanitizeOpenIDConnectProviderDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

func openIDConnectProviderWire(v model.OpenIDConnectProvider) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/openidConnectProviders"
	delete(result, "clientSecret")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "clientSecret")
	properties["displayName"] = v.DisplayName
	properties["description"] = v.Description
	properties["metadataEndpoint"] = v.MetadataEndpoint
	properties["clientId"] = v.ClientID
	return result
}
