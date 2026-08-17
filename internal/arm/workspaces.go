package arm

import (
	"errors"
	"net/http"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type workspacePayload struct {
	Properties struct {
		DisplayName *string `json:"displayName"`
		Description *string `json:"description"`
	} `json:"properties"`
}

func (h *Handler) workspaceCollection(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListWorkspaces(rt.service().ID())
	if err != nil {
		h.storeError(w, err, rt.service().ID())
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, workspaceWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) workspaceResource(w http.ResponseWriter, r *http.Request, rt route, value model.Workspace) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetWorkspace(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, workspaceWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetWorkspace(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		// The service must exist: a workspace with no service is a scope
		// nothing can reach. The foreign key would reject it anyway, but as a
		// 409 rather than the 404 a missing parent deserves.
		if _, err := h.Store.GetService(rt.service().ID()); err != nil {
			h.storeError(w, err, rt.service().ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body workspacePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.Description != nil {
			value.Description = *body.Properties.Description
		}
		if value.DisplayName == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.displayName is required.", "properties.displayName")
			return
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		got, err := h.Store.UpsertWorkspace(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, workspaceWire(got), got.ETag)
	case http.MethodDelete:
		// Deleting a workspace takes its contents with it. The store cascades
		// on the foreign key, which is what Azure does too: a workspace is the
		// parent of its resources, not a label on them.
		if err := h.Store.DeleteWorkspace(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func workspaceWire(v model.Workspace) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/workspaces"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"] = v.DisplayName
	if v.Description != "" {
		properties["description"] = v.Description
	} else {
		delete(properties, "description")
	}
	return result
}
