package arm

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type backendPayload struct {
	Properties struct {
		Title       *string `json:"title"`
		Description *string `json:"description"`
		URL         *string `json:"url"`
		Protocol    *string `json:"protocol"`
		ResourceID  *string `json:"resourceId"`
	} `json:"properties"`
}

func (h *Handler) backend(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListBackends(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, backendWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested backend resource was not found.", r.URL.Path)
		return
	}
	value := model.Backend{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		if rt.Tail[2] != "reconnect" {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested backend action was not found.", r.URL.Path)
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetBackend(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		w.Header().Set("ETag", got.ETag)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetBackend(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, backendWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetBackend(value.ID())
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
		var body backendPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = backendWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		applyBackendPayload(&value, body)
		clearNullBackendProperties(&value, document)
		parsedURL, urlErr := url.ParseRequestURI(value.URL)
		if value.URL == "" || urlErr != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || (value.Protocol != "http" && value.Protocol != "soap") {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.url and a valid properties.protocol are required.", "properties")
			return
		}
		got, err := h.Store.UpsertBackend(value)
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
		writeResource(w, status, backendWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteBackend(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func applyBackendPayload(value *model.Backend, body backendPayload) {
	if body.Properties.Title != nil {
		value.Title = *body.Properties.Title
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.URL != nil {
		value.URL = *body.Properties.URL
	}
	if body.Properties.Protocol != nil {
		value.Protocol = *body.Properties.Protocol
	}
	if body.Properties.ResourceID != nil {
		value.ResourceID = *body.Properties.ResourceID
	}
}

func clearNullBackendProperties(value *model.Backend, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["title"]; present && field == nil {
		value.Title = ""
	}
	if field, present := properties["description"]; present && field == nil {
		value.Description = ""
	}
	if field, present := properties["url"]; present && field == nil {
		value.URL = ""
	}
	if field, present := properties["protocol"]; present && field == nil {
		value.Protocol = ""
	}
	if field, present := properties["resourceId"]; present && field == nil {
		value.ResourceID = ""
	}
}

func backendWire(v model.Backend) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/backends"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["title"], properties["description"], properties["url"] = v.Title, v.Description, v.URL
	properties["protocol"], properties["resourceId"] = v.Protocol, v.ResourceID
	return result
}
