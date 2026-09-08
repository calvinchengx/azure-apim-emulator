package arm

import (
	"errors"
	"net/http"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) apiVersionSet(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIVersionSets(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiVersionSetWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested API version set resource was not found.", r.URL.Path)
		return
	}
	value := model.APIVersionSet{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAPIVersionSet(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, apiVersionSetWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAPIVersionSet(value.ID())
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
		var body struct {
			Properties struct {
				DisplayName       *string `json:"displayName"`
				VersioningScheme  *string `json:"versioningScheme"`
				VersionHeaderName *string `json:"versionHeaderName"`
				VersionQueryName  *string `json:"versionQueryName"`
				Description       *string `json:"description"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = apiVersionSetWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.VersioningScheme != nil {
			value.VersioningScheme = *body.Properties.VersioningScheme
		}
		if body.Properties.VersionHeaderName != nil {
			value.VersionHeaderName = *body.Properties.VersionHeaderName
		}
		if body.Properties.VersionQueryName != nil {
			value.VersionQueryName = *body.Properties.VersionQueryName
		}
		if body.Properties.Description != nil {
			value.Description = *body.Properties.Description
		}
		properties, _ := document["properties"].(map[string]any)
		if field, present := properties["versionHeaderName"]; present && field == nil {
			value.VersionHeaderName = ""
		}
		if field, present := properties["versionQueryName"]; present && field == nil {
			value.VersionQueryName = ""
		}
		if field, present := properties["description"]; present && field == nil {
			value.Description = ""
		}
		if err := validateAPIVersionSet(value); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertAPIVersionSet(value)
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
		writeResource(w, status, apiVersionSetWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPIVersionSet(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func validateAPIVersionSet(value model.APIVersionSet) error {
	if value.DisplayName == "" || (value.VersioningScheme != "Segment" && value.VersioningScheme != "Header" && value.VersioningScheme != "Query") {
		return errors.New("displayName and a valid versioningScheme are required")
	}
	if value.VersioningScheme == "Header" && value.VersionHeaderName == "" {
		return errors.New("versionHeaderName is required for Header versioning")
	}
	if value.VersioningScheme == "Query" && value.VersionQueryName == "" {
		return errors.New("versionQueryName is required for Query versioning")
	}
	return nil
}

func apiVersionSetWire(v model.APIVersionSet) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apiVersionSets"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["versioningScheme"] = v.DisplayName, v.VersioningScheme
	properties["versionHeaderName"], properties["versionQueryName"] = v.VersionHeaderName, v.VersionQueryName
	properties["description"] = v.Description
	return result
}
