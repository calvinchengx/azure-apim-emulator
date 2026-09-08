package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// policyRestriction serves `/policyRestrictions` and its members.
//
// Ordinary CRUD, unlike the tenant singletons: PUT declares 200 AND 201, DELETE
// declares 200 and 204, and the only unusual bit is that `ifMatch` is REQUIRED
// on PATCH (`ifMatch1` in the generated client) while it is optional on PUT and
// DELETE.
//
// `requireBase` is the string "true" or "false", not a boolean. Microsoft's
// `PolicyRestrictionRequireBase` is a string enum and the client maps the field
// as a String, so emitting a JSON boolean would be a different value than the
// one the contract names, and the SDK would hand the caller something its own
// type says cannot occur.
func (h *Handler) policyRestriction(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListPolicyRestrictions(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, policyRestrictionWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested policy restriction was not found.", r.URL.Path)
		return
	}
	if rt.Tail[1] == "" || len(rt.Tail[1]) > 80 {
		writeError(w, http.StatusBadRequest, "ValidationError", "policyRestrictionId must be 1-80 characters.", "policyRestrictionId")
		return
	}
	value := model.PolicyRestriction{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetPolicyRestriction(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, policyRestrictionWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetPolicyRestriction(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch && errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body struct {
			Properties struct {
				Scope       *string `json:"scope"`
				RequireBase *string `json:"requireBase"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		// PATCH is a MERGE: Azure's own update example sends `scope` alone and
		// its response still carries the `requireBase` set by the create. PUT
		// replaces, so an omitted field falls back to the contract's default
		// rather than to whatever was there before.
		if r.Method == http.MethodPatch {
			value.Scope, value.RequireBase = existing.Scope, existing.RequireBase
			value.Document = existing.Document
		} else {
			// `defaultValue: "false"` on the generated mapper.
			value.RequireBase = "false"
			value.Document = document
		}
		if body.Properties.Scope != nil {
			value.Scope = *body.Properties.Scope
		}
		if body.Properties.RequireBase != nil {
			requireBase := strings.ToLower(strings.TrimSpace(*body.Properties.RequireBase))
			if requireBase != "true" && requireBase != "false" {
				writeError(w, http.StatusBadRequest, "ValidationError",
					"properties.requireBase must be the string true or false.", "properties.requireBase")
				return
			}
			value.RequireBase = requireBase
		}
		cleanResourceDocument(value.Document)
		got, err := h.Store.UpsertPolicyRestriction(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, policyRestrictionWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeletePolicyRestriction(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func policyRestrictionWire(v model.PolicyRestriction) map[string]any {
	result := cloneObject(v.Document)
	// `Microsoft.ApiManagement/service/policyRestrictions`, per the Get and List
	// examples. Azure's CREATE example says `.../policyFragments` and names the
	// resource `policyRestrictions1` for a request that asked for
	// `policyRestriction1`, so that example contradicts its own neighbours twice
	// and is not followed.
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/policyRestrictions"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["scope"] = v.Scope
	properties["requireBase"] = v.RequireBase
	return result
}
