package rbac

import "strings"

// Built-in role definition IDs. Azure's are fixed GUIDs, identical in every
// tenant, and tooling hard-codes them: a caller assigning "API Management
// Service Reader Role" by GUID must find the same role here, or their script
// works against Azure and fails against the emulator.
const (
	ServiceContributorID    = "312a565d-c81f-4fd8-895a-4e21e48d571c"
	ServiceReaderID         = "71522526-b88f-4d52-b57f-d31fc3546d0d"
	ServiceOperatorID       = "e022efe7-f5ba-4159-bbe4-b44f577e9b61"
	WorkspaceContributorID  = "0c34c906-8d99-4cb7-8df9-b5d5b0e4a5f1"
	WorkspaceReaderID       = "ef579e47-3bd6-4f3e-a5d2-b8b3ecad3ab5"
	WorkspaceAPIDeveloperID = "9565a273-41b9-4368-97d2-aeb0c976a9b3"
	WorkspaceAPIProductID   = "d59a3e9c-6d52-4a5a-aeed-6bf3cf0e31da"
	ReaderID                = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	ContributorID           = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	OwnerID                 = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
)

// BuiltInRoles returns the role definitions the emulator ships, keyed by
// lower-cased definition name.
//
// The APIM-specific roles are modelled on the published built-ins. The generic
// Owner/Contributor/Reader are included because they are how most real
// assignments are actually made, and an emulator that only knew the APIM roles
// would reject the commonest setup there is.
func BuiltInRoles() map[string]RoleDefinition {
	roles := []RoleDefinition{
		{
			Name: OwnerID, RoleName: "Owner", Type: "BuiltInRole",
			Description: "Grants full access to manage all resources.",
			Permissions: []Permission{{Actions: []string{"*"}}},
		},
		{
			Name: ContributorID, RoleName: "Contributor", Type: "BuiltInRole",
			Description: "Grants full access to manage all resources, but does not allow assigning roles.",
			// The notActions are the whole point of this role: it can manage
			// everything except who is allowed to manage it.
			Permissions: []Permission{{
				Actions:    []string{"*"},
				NotActions: []string{"Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/elevateAccess/Action"},
			}},
		},
		{
			Name: ReaderID, RoleName: "Reader", Type: "BuiltInRole",
			Description: "View all resources, but does not allow you to make any changes.",
			Permissions: []Permission{{Actions: []string{"*/read"}}},
		},
		{
			Name: ServiceContributorID, RoleName: "API Management Service Contributor", Type: "BuiltInRole",
			Description: "Can manage service and the APIs.",
			Permissions: []Permission{{
				Actions:    []string{"Microsoft.ApiManagement/service/*", "Microsoft.Authorization/*/read", "Microsoft.Resources/subscriptions/resourceGroups/read"},
				NotActions: []string{},
			}},
		},
		{
			Name: ServiceReaderID, RoleName: "API Management Service Reader Role", Type: "BuiltInRole",
			Description: "Read-only access to service and APIs.",
			Permissions: []Permission{{
				Actions: []string{"Microsoft.ApiManagement/service/*/read", "Microsoft.ApiManagement/service/read"},
				// Listing secrets is a write-shaped read, and a role called
				// "Reader" that hands out subscription keys is the kind of
				// mistake that only shows up after a breach.
				NotActions: []string{"Microsoft.ApiManagement/service/*/listSecrets/action"},
			}},
		},
		{
			Name: ServiceOperatorID, RoleName: "API Management Service Operator Role", Type: "BuiltInRole",
			Description: "Can manage service but not the APIs.",
			Permissions: []Permission{{
				Actions: []string{"Microsoft.ApiManagement/service/*/read", "Microsoft.ApiManagement/service/read", "Microsoft.ApiManagement/service/write"},
				NotActions: []string{
					"Microsoft.ApiManagement/service/apis/write", "Microsoft.ApiManagement/service/apis/delete",
					"Microsoft.ApiManagement/service/apis/*/write", "Microsoft.ApiManagement/service/apis/*/delete",
				},
			}},
		},
		{
			Name: WorkspaceContributorID, RoleName: "API Management Workspace Contributor", Type: "BuiltInRole",
			Description: "Can manage the workspace and view, but not modify, its parent service.",
			Permissions: []Permission{{
				Actions: []string{"Microsoft.ApiManagement/service/workspaces/*", "Microsoft.ApiManagement/service/read"},
			}},
		},
		{
			Name: WorkspaceReaderID, RoleName: "API Management Workspace Reader", Type: "BuiltInRole",
			Description: "Read-only access to the workspace.",
			Permissions: []Permission{{
				Actions:    []string{"Microsoft.ApiManagement/service/workspaces/*/read", "Microsoft.ApiManagement/service/workspaces/read"},
				NotActions: []string{"Microsoft.ApiManagement/service/workspaces/*/listSecrets/action"},
			}},
		},
		{
			Name: WorkspaceAPIDeveloperID, RoleName: "API Management Workspace API Developer", Type: "BuiltInRole",
			Description: "Can manage APIs in the workspace, but not products or subscriptions.",
			Permissions: []Permission{{
				Actions: []string{"Microsoft.ApiManagement/service/workspaces/*/read", "Microsoft.ApiManagement/service/workspaces/apis/*", "Microsoft.ApiManagement/service/read"},
			}},
		},
		{
			Name: WorkspaceAPIProductID, RoleName: "API Management Workspace API Product Manager", Type: "BuiltInRole",
			Description: "Can manage products and subscriptions in the workspace, but not APIs.",
			Permissions: []Permission{{
				Actions: []string{
					"Microsoft.ApiManagement/service/workspaces/*/read",
					"Microsoft.ApiManagement/service/workspaces/products/*",
					"Microsoft.ApiManagement/service/workspaces/subscriptions/*",
					"Microsoft.ApiManagement/service/read",
				},
			}},
		},
	}
	byName := make(map[string]RoleDefinition, len(roles))
	for _, role := range roles {
		byName[strings.ToLower(role.Name)] = role
	}
	return byName
}

// ActionFor renders the ARM action a request is attempting.
//
// ARM names an action after the resource TYPE, not the resource, so the
// instance names have to come out of the path: `.../service/svc/apis/orders`
// with GET becomes `Microsoft.ApiManagement/service/apis/read`. Leaving the
// names in would mean every role had to be written per-resource, which is not
// how any published role is expressed.
func ActionFor(method string, segments []string) Action {
	var types []string
	for i := 0; i < len(segments); i++ {
		types = append(types, segments[i])
		i++ // skip the instance name that follows a type
	}
	verb := "read"
	switch strings.ToUpper(method) {
	case "PUT", "PATCH", "POST":
		verb = "write"
	case "DELETE":
		verb = "delete"
	}
	return Action("Microsoft.ApiManagement/" + strings.Join(types, "/") + "/" + verb)
}
