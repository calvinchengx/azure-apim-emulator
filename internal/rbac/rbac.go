// Package rbac evaluates Azure role assignments over ARM scopes.
//
// This is the CONTROL plane's access model and it is not APIM's own. APIM has a
// second, unrelated one: users, groups, products and subscriptions decide who
// may call an API through the gateway. Azure RBAC decides who may call ARM to
// manage the service at all. Conflating them is the easiest mistake to make
// here, and it would produce an emulator that enforces the wrong thing.
//
// The model Azure uses, and this implements:
//
//	a role DEFINITION lists permitted actions, with wildcards and notActions
//	a role ASSIGNMENT binds a principal to a definition AT A SCOPE
//	a scope is just a resource ID, so assignments INHERIT down the ID prefix
//
// That last property is why workspaces need nothing special: a workspace ID is
// a resource ID like any other, so an assignment made there covers everything
// inside it, and one made at the service covers the workspace.
package rbac

import (
	"strings"
)

// Action is the operation a request is attempting, in ARM's
// `Provider/resourceType/verb` form.
type Action string

// Permission is one grant inside a role definition.
type Permission struct {
	Actions    []string `json:"actions"`
	NotActions []string `json:"notActions"`
}

// RoleDefinition is a named set of permissions.
type RoleDefinition struct {
	Name        string       `json:"name"`
	RoleName    string       `json:"roleName"`
	Description string       `json:"description"`
	Type        string       `json:"type"`
	Permissions []Permission `json:"permissions"`
}

// Assignment binds a principal to a role definition at a scope.
type Assignment struct {
	Name             string
	Scope            string
	PrincipalID      string
	PrincipalType    string
	RoleDefinitionID string
	Document         map[string]any
	ETag             string
}

// ID returns the assignment's ARM resource ID.
func (a Assignment) ID() string {
	return a.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + a.Name
}

// Allows reports whether a definition permits an action.
//
// notActions subtract from actions and are checked second, exactly as Azure
// evaluates them: a role can grant a whole provider and then carve a hole in it,
// and a reader role that forgot the hole would be a writer.
func (d RoleDefinition) Allows(action Action) bool {
	granted := false
	for _, permission := range d.Permissions {
		for _, pattern := range permission.Actions {
			if matches(pattern, string(action)) {
				granted = true
				break
			}
		}
	}
	if !granted {
		return false
	}
	for _, permission := range d.Permissions {
		for _, pattern := range permission.NotActions {
			if matches(pattern, string(action)) {
				return false
			}
		}
	}
	return true
}

// matches implements ARM's action globbing: `*` stands for any run of
// characters, and comparison is case-insensitive.
func matches(pattern, action string) bool {
	pattern, action = strings.ToLower(pattern), strings.ToLower(action)
	if !strings.Contains(pattern, "*") {
		return pattern == action
	}
	segments := strings.Split(pattern, "*")
	// A leading segment must be a prefix, a trailing one a suffix, and the rest
	// must appear in order. Anything looser would let `*/read` match a write.
	if !strings.HasPrefix(action, segments[0]) {
		return false
	}
	remainder := action[len(segments[0]):]
	for i := 1; i < len(segments); i++ {
		segment := segments[i]
		if segment == "" {
			continue
		}
		if i == len(segments)-1 {
			if !strings.HasSuffix(remainder, segment) {
				return false
			}
			continue
		}
		index := strings.Index(remainder, segment)
		if index < 0 {
			return false
		}
		remainder = remainder[index+len(segment):]
	}
	return true
}

// ScopeCovers reports whether an assignment made at `assigned` applies to a
// request against `target`.
//
// Inheritance is by resource-ID prefix, and the boundary check matters: without
// it a scope ending `/service/prod` would cover `/service/prod-canary`, which is
// a different service that shares a name prefix.
func ScopeCovers(assigned, target string) bool {
	assigned, target = strings.ToLower(strings.TrimRight(assigned, "/")), strings.ToLower(strings.TrimRight(target, "/"))
	if assigned == "" || assigned == target {
		return assigned == target
	}
	return strings.HasPrefix(target, assigned+"/")
}

// Decision is the outcome of an authorization check.
type Decision struct {
	Allowed bool
	// Role names the definition that permitted the action, for diagnostics.
	Role string
}

// Authorize evaluates a principal's assignments against an action at a scope.
//
// Azure is deny-by-default with no negative assignments at this level: an action
// is permitted when SOME assignment covering the scope grants it. Returning the
// granting role's name makes a refusal debuggable, because "denied" alone never
// tells anyone which assignment they were missing.
func Authorize(principalID string, action Action, scope string, assignments []Assignment, definitions map[string]RoleDefinition) Decision {
	for _, assignment := range assignments {
		if !strings.EqualFold(assignment.PrincipalID, principalID) {
			continue
		}
		if !ScopeCovers(assignment.Scope, scope) {
			continue
		}
		definition, ok := definitions[strings.ToLower(RoleDefinitionName(assignment.RoleDefinitionID))]
		if !ok {
			continue
		}
		if definition.Allows(action) {
			return Decision{Allowed: true, Role: definition.RoleName}
		}
	}
	return Decision{}
}

// RoleDefinitionName extracts the definition's name from its resource ID. A
// caller may legitimately pass either the full ID or a bare name.
func RoleDefinitionName(id string) string {
	if index := strings.LastIndex(id, "/"); index >= 0 {
		return id[index+1:]
	}
	return id
}
