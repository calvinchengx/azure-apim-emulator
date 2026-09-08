package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) tag(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListTags(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, tagWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if (len(rt.Tail) == 3 || len(rt.Tail) == 4) &&
		isLinkSegment(rt.Tail[2], "apiLinks", "operationLinks", "productLinks") {
		tag := model.Tag{ServiceID: scope, Name: rt.Tail[1]}
		if _, err := h.Store.GetTag(tag.ID()); err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		surface, err := h.tagLinkSurface(tag, rt.Tail[2])
		if err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		surface.armType = linkType(rt.Workspace != "", "tags", rt.Tail[2])
		name := ""
		if len(rt.Tail) == 4 {
			name = rt.Tail[3]
		}
		h.linkRoute(w, r, surface, name)
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested tag resource was not found.", r.URL.Path)
		return
	}
	value := model.Tag{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetTag(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, tagWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetTag(value.ID())
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
				DisplayName *string `json:"displayName"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = tagWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if strings.TrimSpace(value.DisplayName) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
			return
		}
		got, err := h.Store.UpsertTag(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, tagWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteTag(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) resourceTagCollection(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListResourceTags(resourceID)
	if err != nil {
		h.storeError(w, err, resourceID)
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, tagWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) resourceTag(w http.ResponseWriter, r *http.Request, serviceID, resourceID, tagName string) {
	tag := model.Tag{ServiceID: serviceID, Name: tagName}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetResourceTag(resourceID, tag.ID())
		if err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, tagWire(got), got.ETag)
	case http.MethodPut:
		got, err := h.Store.GetTag(tag.ID())
		if err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		_, existingErr := h.Store.GetResourceTag(resourceID, tag.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, tag.ID())
			return
		}
		if err := h.Store.AssignTag(resourceID, tag.ID()); err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, tagWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DetachTag(resourceID, tag.ID()); err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func tagWire(v model.Tag) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/tags"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"] = v.DisplayName
	return result
}
