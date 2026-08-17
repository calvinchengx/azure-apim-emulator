package rbac

import "testing"

func TestActionGlobbing(t *testing.T) {
	cases := map[string]map[string]bool{
		"*":                                    {"Microsoft.ApiManagement/service/read": true},
		"*/read":                               {"Microsoft.ApiManagement/service/read": true, "Microsoft.ApiManagement/service/write": false},
		"Microsoft.ApiManagement/service/*":    {"Microsoft.ApiManagement/service/apis/write": true, "Microsoft.Storage/x/write": false},
		"Microsoft.ApiManagement/service/read": {"Microsoft.ApiManagement/service/read": true, "Microsoft.ApiManagement/service/apis/read": false},
		"Microsoft.ApiManagement/service/*/read": {
			"Microsoft.ApiManagement/service/apis/read":  true,
			"Microsoft.ApiManagement/service/apis/write": false,
		},
		"Microsoft.Authorization/*/Write": {"Microsoft.Authorization/roleAssignments/write": true, "Microsoft.Authorization/roleAssignments/read": false},
	}
	for pattern, expectations := range cases {
		for action, want := range expectations {
			if got := matches(pattern, action); got != want {
				t.Errorf("matches(%q, %q) = %v, want %v", pattern, action, got, want)
			}
		}
	}
	// Case-insensitive, as ARM is.
	if !matches("MICROSOFT.APIMANAGEMENT/SERVICE/*", "microsoft.apimanagement/service/apis/read") {
		t.Error("action matching must be case-insensitive")
	}
}

// notActions subtract from actions. A role that grants a provider and then
// carves a hole in it is the commonest shape there is, and a reader role that
// forgot the hole would be a writer.
func TestNotActionsSubtract(t *testing.T) {
	role := RoleDefinition{Permissions: []Permission{{
		Actions:    []string{"Microsoft.ApiManagement/service/*"},
		NotActions: []string{"Microsoft.ApiManagement/service/apis/delete"},
	}}}
	if !role.Allows("Microsoft.ApiManagement/service/apis/write") {
		t.Error("a granted action must be allowed")
	}
	if role.Allows("Microsoft.ApiManagement/service/apis/delete") {
		t.Error("a notAction must be refused even though the wildcard grants it")
	}
	if role.Allows("Microsoft.Storage/accounts/read") {
		t.Error("an ungranted action must be refused")
	}
}

// Inheritance is by resource-ID prefix, and the boundary check is what stops
// `/service/prod` from covering `/service/prod-canary`, a different service
// that merely shares a name prefix.
func TestScopeCoversRespectsSegmentBoundaries(t *testing.T) {
	cases := map[[2]string]bool{
		{"/subscriptions/s", "/subscriptions/s/resourceGroups/rg"}: true,
		{"/subscriptions/s", "/subscriptions/s"}:                   true,
		{"/s/svc", "/s/svc/apis/a"}:                                true,
		{"/s/svc/workspaces/w", "/s/svc/workspaces/w/apis/a"}:      true,
		{"/s/svc/workspaces/w", "/s/svc/apis/a"}:                   false,
		{"/s/prod", "/s/prod-canary"}:                              false,
		{"/s/svc/apis/a", "/s/svc"}:                                false,
		{"", "/s/svc"}:                                             false,
	}
	for pair, want := range cases {
		if got := ScopeCovers(pair[0], pair[1]); got != want {
			t.Errorf("ScopeCovers(%q, %q) = %v, want %v", pair[0], pair[1], got, want)
		}
	}
	// Trailing slashes must not change the answer.
	if !ScopeCovers("/s/svc/", "/s/svc/apis/a") {
		t.Error("a trailing slash must not break inheritance")
	}
}

func TestAuthorizeIsDenyByDefault(t *testing.T) {
	roles := BuiltInRoles()
	assignments := []Assignment{
		{Name: "a1", Scope: "/subs/s/service/svc/workspaces/team", PrincipalID: "ada",
			RoleDefinitionID: "/providers/Microsoft.Authorization/roleDefinitions/" + WorkspaceContributorID},
	}

	// Granted inside the workspace.
	if d := Authorize("ada", "Microsoft.ApiManagement/service/workspaces/apis/write", "/subs/s/service/svc/workspaces/team/apis/o", assignments, roles); !d.Allowed {
		t.Fatal("a workspace contributor must be able to write workspace APIs")
	} else if d.Role != "API Management Workspace Contributor" {
		t.Fatalf("decision must name the granting role, got %q", d.Role)
	}
	// Refused outside it. This is the isolation property, and it comes from
	// scope inheritance rather than a special case.
	if Authorize("ada", "Microsoft.ApiManagement/service/apis/write", "/subs/s/service/svc/apis/o", assignments, roles).Allowed {
		t.Fatal("a workspace contributor must not reach the service's own APIs")
	}
	// A different principal gets nothing.
	if Authorize("bob", "Microsoft.ApiManagement/service/workspaces/apis/write", "/subs/s/service/svc/workspaces/team/apis/o", assignments, roles).Allowed {
		t.Fatal("an assignment must apply only to its principal")
	}
	// An assignment naming a role that does not exist grants nothing rather
	// than everything.
	unknown := []Assignment{{Scope: "/subs/s", PrincipalID: "ada", RoleDefinitionID: "nope"}}
	if Authorize("ada", "Microsoft.ApiManagement/service/read", "/subs/s/service/svc", unknown, roles).Allowed {
		t.Fatal("an unknown role definition must not grant access")
	}
	// No assignments at all.
	if Authorize("ada", "Microsoft.ApiManagement/service/read", "/subs/s/service/svc", nil, roles).Allowed {
		t.Fatal("deny by default")
	}
}

func TestBuiltInRolesMatchTheirNames(t *testing.T) {
	roles := BuiltInRoles()
	cases := []struct {
		id     string
		action Action
		want   bool
		why    string
	}{
		{ReaderID, "Microsoft.ApiManagement/service/apis/read", true, "Reader reads"},
		{ReaderID, "Microsoft.ApiManagement/service/apis/write", false, "Reader does not write"},
		{ContributorID, "Microsoft.ApiManagement/service/apis/write", true, "Contributor writes"},
		{ContributorID, "Microsoft.Authorization/roleAssignments/write", false, "Contributor cannot grant roles"},
		{OwnerID, "Microsoft.Authorization/roleAssignments/write", true, "Owner can grant roles"},
		{ServiceReaderID, "Microsoft.ApiManagement/service/apis/listSecrets/action", false, "a Reader must not list secrets"},
		{ServiceOperatorID, "Microsoft.ApiManagement/service/write", true, "Operator manages the service"},
		{ServiceOperatorID, "Microsoft.ApiManagement/service/apis/write", false, "Operator does not manage APIs"},
		{WorkspaceAPIDeveloperID, "Microsoft.ApiManagement/service/workspaces/apis/write", true, "API Developer writes APIs"},
		{WorkspaceAPIDeveloperID, "Microsoft.ApiManagement/service/workspaces/products/write", false, "API Developer does not write products"},
		{WorkspaceAPIProductID, "Microsoft.ApiManagement/service/workspaces/products/write", true, "Product Manager writes products"},
		{WorkspaceAPIProductID, "Microsoft.ApiManagement/service/workspaces/apis/write", false, "Product Manager does not write APIs"},
		{WorkspaceReaderID, "Microsoft.ApiManagement/service/workspaces/apis/read", true, "Workspace Reader reads"},
	}
	for _, c := range cases {
		if got := roles[c.id].Allows(c.action); got != c.want {
			t.Errorf("%s: %s on %q = %v, want %v", c.why, roles[c.id].RoleName, c.action, got, c.want)
		}
	}
}

// ARM names an action after the resource TYPE, not the instance, so the names
// have to come out of the path. Leaving them in would force every role to be
// written per-resource, which is not how any published role is expressed.
func TestActionForStripsInstanceNames(t *testing.T) {
	cases := map[string]Action{
		"GET|service|svc":                       "Microsoft.ApiManagement/service/read",
		"GET|service|svc|apis|orders":           "Microsoft.ApiManagement/service/apis/read",
		"PUT|service|svc|apis|orders":           "Microsoft.ApiManagement/service/apis/write",
		"PATCH|service|svc|apis|orders":         "Microsoft.ApiManagement/service/apis/write",
		"POST|service|svc|apis|orders":          "Microsoft.ApiManagement/service/apis/write",
		"DELETE|service|svc|apis|orders":        "Microsoft.ApiManagement/service/apis/delete",
		"HEAD|service|svc|apis|orders":          "Microsoft.ApiManagement/service/apis/read",
		"PUT|service|svc|workspaces|w|apis|o":   "Microsoft.ApiManagement/service/workspaces/apis/write",
		"GET|service|svc|apis|o|operations|get": "Microsoft.ApiManagement/service/apis/operations/read",
	}
	for key, want := range cases {
		parts := splitPipe(key)
		if got := ActionFor(parts[0], parts[1:]); got != want {
			t.Errorf("ActionFor(%q) = %q, want %q", key, got, want)
		}
	}
}

func splitPipe(value string) []string {
	var parts []string
	current := ""
	for _, r := range value {
		if r == '|' {
			parts = append(parts, current)
			current = ""
			continue
		}
		current += string(r)
	}
	return append(parts, current)
}

func TestRoleDefinitionNameAcceptsBothForms(t *testing.T) {
	if got := RoleDefinitionName("/providers/Microsoft.Authorization/roleDefinitions/" + ReaderID); got != ReaderID {
		t.Fatalf("full ID = %q", got)
	}
	if got := RoleDefinitionName(ReaderID); got != ReaderID {
		t.Fatalf("bare name = %q", got)
	}
}

func TestAssignmentID(t *testing.T) {
	a := Assignment{Scope: "/subs/s/service/svc", Name: "r1"}
	if got := a.ID(); got != "/subs/s/service/svc/providers/Microsoft.Authorization/roleAssignments/r1" {
		t.Fatalf("ID = %q", got)
	}
}

// The globbing corners, asserted directly because a role is only as precise as
// its pattern matcher and a false positive here grants access.
func TestGlobbingCorners(t *testing.T) {
	cases := map[[2]string]bool{
		{"a/*/b/*/c", "a/x/b/y/c"}: true,
		{"a/*/b/*/c", "a/x/b/y/d"}: false,
		{"a/*/c", "a/c"}:           false,
		{"*", ""}:                  true,
		{"a*", "ab"}:               true,
		{"*b", "ab"}:               true,
		{"*b", "ba"}:               false,
		{"a**b", "ab"}:             true,
		{"a/*", "b/x"}:             false,
	}
	for pair, want := range cases {
		if got := matches(pair[0], pair[1]); got != want {
			t.Errorf("matches(%q, %q) = %v, want %v", pair[0], pair[1], got, want)
		}
	}
}

// A middle glob segment that never appears must refuse. Without this the
// pattern would match on its prefix and suffix alone, so `a/*/secret/*/read`
// would grant `a/x/read`.
func TestGlobbingRequiresMiddleSegments(t *testing.T) {
	if matches("a/*/secret/*/read", "a/x/read") {
		t.Fatal("a missing middle segment must not match")
	}
	if !matches("a/*/secret/*/read", "a/x/secret/y/read") {
		t.Fatal("a present middle segment must match")
	}
}
