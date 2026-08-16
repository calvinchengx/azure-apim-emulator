package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// resolverPayload is the ARM body of a GraphQL resolver.
//
// Azure carries the schema coordinate in a single `path` of the form
// "Type/field". It is split on store so the gateway can index by coordinate
// without re-parsing a string on every request, and rejoined on the wire so a
// caller reads back exactly the shape it sent.
type resolverPayload struct {
	Properties struct {
		DisplayName *string `json:"displayName"`
		Description *string `json:"description"`
		Path        *string `json:"path"`
	} `json:"properties"`
}

func (h *Handler) apiResolverCollection(w http.ResponseWriter, r *http.Request, api model.API) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListAPIResolvers(api.ID())
	if err != nil {
		h.storeError(w, err, api.ID())
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, apiResolverWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) apiResolverResource(w http.ResponseWriter, r *http.Request, value model.APIResolver) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAPIResolver(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, apiResolverWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAPIResolver(value.ID())
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
		var body resolverPayload
		var document map[string]any
		if decodeErr := decodeDocument(r, &body, &document); decodeErr != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", decodeErr.Error(), "")
			return
		}
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.Description != nil {
			value.Description = *body.Properties.Description
		}
		if body.Properties.Path != nil {
			typeName, field, ok := splitResolverPath(*body.Properties.Path)
			if !ok {
				writeError(w, http.StatusBadRequest, "ValidationError",
					"properties.path must be \"Type/field\", naming the schema coordinate this resolver binds.", "properties.path")
				return
			}
			value.Type, value.Field = typeName, field
		}
		if value.Type == "" || value.Field == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.path is required.", "properties.path")
			return
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		got, storeErr := h.Store.UpsertAPIResolver(value)
		if storeErr != nil {
			h.storeError(w, storeErr, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		// A resolver changes what the gateway serves, so the snapshot is
		// republished here for the same reason a schema import is.
		if activateErr := h.activate(); activateErr != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", activateErr.Error(), value.ID())
			return
		}
		writeResource(w, status, apiResolverWire(got), got.ETag)
	case http.MethodDelete:
		if deleteErr := h.Store.DeleteAPIResolver(value.ID()); deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
			h.storeError(w, deleteErr, value.ID())
			return
		}
		if activateErr := h.activate(); activateErr != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", activateErr.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

// splitResolverPath parses Azure's "Type/field" coordinate. Both halves must be
// non-empty: a half-formed path would bind a resolver to a field nobody can
// name, and the resolver would simply never run.
func splitResolverPath(path string) (string, string, bool) {
	typeName, field, found := strings.Cut(strings.TrimSpace(path), "/")
	typeName, field = strings.TrimSpace(typeName), strings.TrimSpace(field)
	if !found || typeName == "" || field == "" || strings.Contains(field, "/") {
		return "", "", false
	}
	return typeName, field, true
}

func apiResolverWire(v model.APIResolver) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apis/resolvers"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"] = v.DisplayName
	properties["path"] = v.Type + "/" + v.Field
	if v.Description != "" {
		properties["description"] = v.Description
	} else {
		delete(properties, "description")
	}
	return result
}
