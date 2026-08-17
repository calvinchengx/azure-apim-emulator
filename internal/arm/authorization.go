package arm

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/rbac"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// authorizationRoute is a `Microsoft.Authorization` request: a scope, and what
// is being addressed under it.
//
// Role assignments hang off ANY scope, not just APIM ones, which is why they
// need their own parser. A subscription and a workspace are equally valid
// parents, and the provider segment is what separates the scope from the rest.
type authorizationRoute struct {
	Scope    string
	Resource string
	Name     string
}

// parseAuthorization splits a path at its `providers/Microsoft.Authorization`
// segment. Everything before is the scope; everything after names the resource.
func parseAuthorization(path string) (authorizationRoute, bool) {
	parts := split(path)
	for i := 0; i+1 < len(parts); i++ {
		if !equal(parts[i], "providers") || !equal(parts[i+1], "Microsoft.Authorization") {
			continue
		}
		tail := parts[i+2:]
		if len(tail) == 0 {
			return authorizationRoute{}, false
		}
		route := authorizationRoute{Scope: "/" + strings.Join(parts[:i], "/"), Resource: tail[0]}
		if len(tail) > 1 {
			route.Name = tail[1]
		}
		// A bare `/providers/Microsoft.Authorization/...` has no scope, which
		// is the tenant root. Nothing here is assignable there, so it is not a
		// scope this emulator recognises.
		if route.Scope == "/" {
			return authorizationRoute{}, false
		}
		return route, true
	}
	return authorizationRoute{}, false
}

// authorization serves role assignments and role definitions.
func (h *Handler) authorization(w http.ResponseWriter, r *http.Request, rt authorizationRoute) {
	switch {
	case equal(rt.Resource, "roleDefinitions"):
		h.roleDefinitions(w, r, rt)
	case equal(rt.Resource, "roleAssignments"):
		if rt.Name == "" {
			h.roleAssignmentCollection(w, r, rt)
			return
		}
		h.roleAssignmentResource(w, r, rt)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested Microsoft.Authorization resource is not implemented.", r.URL.Path)
	}
}

func (h *Handler) roleDefinitions(w http.ResponseWriter, r *http.Request, rt authorizationRoute) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	roles := rbac.BuiltInRoles()
	if rt.Name != "" {
		role, ok := roles[strings.ToLower(rt.Name)]
		if !ok {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The role definition was not found.", rt.Name)
			return
		}
		writeJSON(w, http.StatusOK, roleDefinitionWire(role))
		return
	}
	names := make([]string, 0, len(roles))
	for name := range roles {
		names = append(names, name)
	}
	sort.Strings(names)
	resources := make([]map[string]any, 0, len(names))
	for _, name := range names {
		resources = append(resources, roleDefinitionWire(roles[name]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources})
}

func (h *Handler) roleAssignmentCollection(w http.ResponseWriter, r *http.Request, rt authorizationRoute) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	all, err := h.Store.ListRoleAssignments()
	if err != nil {
		h.storeError(w, err, rt.Scope)
		return
	}
	resources := make([]map[string]any, 0)
	for _, assignment := range all {
		// ARM lists what applies AT the scope, which includes assignments made
		// above it. Listing only exact matches would hide the inherited grant
		// that is actually letting a caller in.
		if !rbac.ScopeCovers(assignment.Scope, rt.Scope) && !rbac.ScopeCovers(rt.Scope, assignment.Scope) {
			continue
		}
		resources = append(resources, roleAssignmentWire(assignment))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources})
}

func (h *Handler) roleAssignmentResource(w http.ResponseWriter, r *http.Request, rt authorizationRoute) {
	value := rbac.Assignment{Scope: rt.Scope, Name: rt.Name}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetRoleAssignment(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, roleAssignmentWire(got), got.ETag)
	case http.MethodPut:
		var body struct {
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				PrincipalID      string `json:"principalId"`
				PrincipalType    string `json:"principalType"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Properties.RoleDefinitionID == "" || body.Properties.PrincipalID == "" {
			writeError(w, http.StatusBadRequest, "InvalidRoleAssignmentRequest",
				"properties.roleDefinitionId and properties.principalId are required.", "properties")
			return
		}
		// An assignment naming a role that does not exist can never grant
		// anything, so it is refused rather than stored as a grant nobody can
		// explain.
		if _, ok := rbac.BuiltInRoles()[strings.ToLower(rbac.RoleDefinitionName(body.Properties.RoleDefinitionID))]; !ok {
			writeError(w, http.StatusBadRequest, "RoleDefinitionDoesNotExist",
				"The specified role definition does not exist.", "properties.roleDefinitionId")
			return
		}
		_, existingErr := h.Store.GetRoleAssignment(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		value.RoleDefinitionID = body.Properties.RoleDefinitionID
		value.PrincipalID = body.Properties.PrincipalID
		value.PrincipalType = body.Properties.PrincipalType
		if value.PrincipalType == "" {
			value.PrincipalType = "User"
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		got, err := h.Store.UpsertRoleAssignment(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, roleAssignmentWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteRoleAssignment(value.ID()); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// ARM answers a delete of an absent assignment with 204, so a
				// caller tearing down twice does not have to special-case it.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		methodNotAllowed(w)
	}
}

func roleAssignmentWire(v rbac.Assignment) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.Authorization/roleAssignments"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["scope"] = v.Scope
	properties["roleDefinitionId"] = v.RoleDefinitionID
	properties["principalId"] = v.PrincipalID
	properties["principalType"] = v.PrincipalType
	return result
}

func roleDefinitionWire(v rbac.RoleDefinition) map[string]any {
	permissions := make([]any, 0, len(v.Permissions))
	for _, permission := range v.Permissions {
		actions := permission.Actions
		if actions == nil {
			actions = []string{}
		}
		notActions := permission.NotActions
		if notActions == nil {
			notActions = []string{}
		}
		permissions = append(permissions, map[string]any{
			"actions": actions, "notActions": notActions,
			"dataActions": []any{}, "notDataActions": []any{},
		})
	}
	return map[string]any{
		"id":   "/providers/Microsoft.Authorization/roleDefinitions/" + v.Name,
		"name": v.Name,
		"type": "Microsoft.Authorization/roleDefinitions",
		"properties": map[string]any{
			"roleName": v.RoleName, "description": v.Description, "type": v.Type,
			"permissions": permissions, "assignableScopes": []any{"/"},
		},
	}
}
