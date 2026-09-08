package arm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type cachePayload struct {
	Properties struct {
		ConnectionString *string `json:"connectionString"`
		UseFromLocation  *string `json:"useFromLocation"`
		Description      *string `json:"description"`
		ResourceID       *string `json:"resourceId"`
	} `json:"properties"`
}

func (h *Handler) cache(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListCaches(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, cacheWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested cache resource was not found.", r.URL.Path)
		return
	}
	value := model.Cache{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetCache(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, cacheWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetCache(value.ID())
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
		var body cachePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = cacheWire(value)
			}
			mergeObject(value.Document, document)
			clearNullCacheProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeCacheDocument(value.Document)
		applyCachePayload(&value, body)
		if err := validateCache(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertCache(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, cacheWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteCache(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyCachePayload(value *model.Cache, body cachePayload) {
	if body.Properties.ConnectionString != nil {
		value.ConnectionString = *body.Properties.ConnectionString
	}
	if body.Properties.UseFromLocation != nil {
		value.UseFromLocation = *body.Properties.UseFromLocation
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.ResourceID != nil {
		value.ResourceID = *body.Properties.ResourceID
	}
	if strings.EqualFold(value.UseFromLocation, "default") {
		value.UseFromLocation = "default"
	}
}

func clearNullCacheProperties(value *model.Cache, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["description"]; present && field == nil {
		value.Description = ""
	}
	if field, present := properties["resourceId"]; present && field == nil {
		value.ResourceID = ""
	}
}

func validateCache(value model.Cache, creating bool) error {
	if creating && value.ConnectionString == "" {
		return errors.New("connectionString is required")
	}
	if creating && value.UseFromLocation == "" {
		return errors.New("useFromLocation is required")
	}
	if value.ConnectionString == "" {
		return errors.New("connectionString cannot be empty")
	}
	if value.UseFromLocation == "" {
		return errors.New("useFromLocation cannot be empty")
	}
	if len(value.ConnectionString) > 300 {
		return errors.New("connectionString must be at most 300 characters")
	}
	if len(value.UseFromLocation) > 256 {
		return errors.New("useFromLocation must be at most 256 characters")
	}
	if len(value.Description) > 2000 {
		return errors.New("description must be at most 2000 characters")
	}
	if len(value.ResourceID) > 2000 {
		return errors.New("resourceId must be at most 2000 characters")
	}
	return nil
}

func sanitizeCacheDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "connectionString")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "connectionString")
}

func cacheWire(v model.Cache) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/caches"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["connectionString"] = cacheConnectionReference(v.ConnectionString)
	properties["useFromLocation"] = v.UseFromLocation
	properties["description"] = v.Description
	properties["resourceId"] = v.ResourceID
	properties["region"] = v.UseFromLocation
	return result
}

func cacheConnectionReference(value string) string {
	if strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}") {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("{{Cache-ConnectionString-%x}}", digest[:8])
}
