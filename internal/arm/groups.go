package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) group(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListGroups(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, groupWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) >= 3 && equal(rt.Tail[2], "users") {
		group := model.Group{ServiceID: scope, Name: rt.Tail[1]}
		if _, err := h.Store.GetGroup(group.ID()); err != nil {
			h.storeError(w, err, group.ID())
			return
		}
		if len(rt.Tail) == 3 {
			if r.Method != http.MethodGet {
				methodNotAllowed(w)
				return
			}
			values, err := h.Store.ListGroupUsers(group.ID())
			if err != nil {
				h.storeError(w, err, group.ID())
				return
			}
			resources := make([]map[string]any, 0, len(values))
			for _, value := range values {
				resources = append(resources, userWire(value))
			}
			writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
			return
		}
		if len(rt.Tail) == 4 {
			// The GROUP is scoped, the MEMBER is not: a workspace group draws
			// its members from the service's user directory, which is why Azure
			// has WorkspaceGroupUser but no WorkspaceUser. Resolving the user at
			// the workspace scope instead would make a workspace group
			// unfillable, because no user exists at that scope to name.
			//
			// This is the only cross-family link of that shape in the emulator
			// today, and the shape is worth recognising before writing the next
			// one: a workspace-scoped PARENT resolving a child from a family in
			// serviceOnlyFamilies must resolve it at the SERVICE. Notifications
			// are where it recurs — the SDK has WorkspaceNotification and
			// WorkspaceNotificationRecipientUser — so if that family is ever
			// implemented, its recipientUsers is this line again.
			h.groupUser(w, r, group, model.User{ServiceID: rt.service().ID(), Name: rt.Tail[3]})
			return
		}
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested group resource was not found.", r.URL.Path)
		return
	}
	value := model.Group{ServiceID: scope, Name: rt.Tail[1], Type: "custom"}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetGroup(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, groupWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetGroup(value.ID())
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
				Description *string `json:"description"`
				Type        *string `json:"type"`
				ExternalID  *string `json:"externalId"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = groupWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.Description != nil {
			value.Description = *body.Properties.Description
		}
		if body.Properties.Type != nil {
			value.Type = *body.Properties.Type
		}
		if body.Properties.ExternalID != nil {
			value.ExternalID = *body.Properties.ExternalID
		}
		properties, _ := document["properties"].(map[string]any)
		if field, present := properties["description"]; present && field == nil {
			value.Description = ""
		}
		if field, present := properties["externalId"]; present && field == nil {
			value.ExternalID = ""
		}
		if strings.TrimSpace(value.DisplayName) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
			return
		}
		if value.Type != "custom" && value.Type != "external" && value.Type != "system" {
			writeError(w, http.StatusBadRequest, "ValidationError", "type must be custom, external, or system.", "properties.type")
			return
		}
		if value.Type == "system" && !value.BuiltIn {
			writeError(w, http.StatusBadRequest, "ValidationError", "system groups are managed by the service.", "properties.type")
			return
		}
		if value.Type == "external" && strings.TrimSpace(value.ExternalID) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "externalId is required for external groups.", "properties.externalId")
			return
		}
		got, err := h.Store.UpsertGroup(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, groupWire(got), got.ETag)
	case http.MethodDelete:
		got, err := h.Store.GetGroup(value.ID())
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err == nil && got.BuiltIn {
			writeError(w, http.StatusBadRequest, "ValidationError", "Built-in groups cannot be deleted.", value.ID())
			return
		}
		if err := h.Store.DeleteGroup(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) groupUser(w http.ResponseWriter, r *http.Request, group model.Group, user model.User) {
	if _, err := h.Store.GetUser(user.ID()); err != nil {
		h.storeError(w, err, user.ID())
		return
	}
	exists, err := h.Store.HasGroupUser(group.ID(), user.ID())
	if err != nil {
		h.storeError(w, err, user.ID())
		return
	}
	switch r.Method {
	case http.MethodHead:
		if !exists {
			h.storeError(w, store.ErrNotFound, user.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		if err := h.Store.LinkGroupUser(group.ID(), user.ID()); err != nil {
			h.storeError(w, err, user.ID())
			return
		}
		status := http.StatusCreated
		if exists {
			status = http.StatusOK
		}
		got, _ := h.Store.GetUser(user.ID())
		writeResource(w, status, userWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.UnlinkGroupUser(group.ID(), user.ID()); err != nil {
			h.storeError(w, err, user.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func groupWire(v model.Group) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/groups"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["description"], properties["type"] = v.DisplayName, v.Description, v.Type
	properties["externalId"], properties["builtIn"] = nullableString(v.ExternalID), v.BuiltIn
	return result
}
