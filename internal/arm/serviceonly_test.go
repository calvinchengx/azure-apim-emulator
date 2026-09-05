package arm

import (
	"net/http"
	"strings"
	"testing"
)

// The families Azure scopes to a SERVICE only must 404 under a workspace, and
// the ones it genuinely scopes to a workspace must not.
//
// Both halves matter. The refusals are the fix; the control below is what stops
// the fix from being a blunt instrument that takes the whole workspace surface
// down with it, which a test asserting only 404s would never notice.
func TestServiceOnlyFamiliesAreRefusedAtWorkspaceScope(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team"+apiQuery,
		`{"properties":{"displayName":"Team"}}`, http.StatusCreated)

	// The workspace exists, so a 404 here is the family's refusal and not a
	// missing parent -- otherwise this test would pass with the guard removed.
	refused := []struct{ family, body string }{
		{"caches", `{"properties":{"connectionString":"host","useFromLocation":"default"}}`},
		{"identityProviders", `{"properties":{"clientId":"id","clientSecret":"secret"}}`},
		{"openidConnectProviders", `{"properties":{"displayName":"o","metadataEndpoint":"https://idp.test/.well-known/openid-configuration","clientId":"id"}}`},
		{"authorizationServers", `{"properties":{"displayName":"a","clientRegistrationEndpoint":"https://idp.test","authorizationEndpoint":"https://idp.test","grantTypes":["authorizationCode"],"clientId":"id"}}`},
		{"documentations", `{"properties":{"title":"t","content":"c"}}`},
		{"gateways", `{"properties":{"locationData":{"name":"dc"}}}`},
		{"users", `{"properties":{"email":"a@b.test","firstName":"A","lastName":"B"}}`},
		{"privateEndpointConnections", `{"properties":{"privateLinkServiceConnectionState":{"status":"Approved"}}}`},
		{"policyRestrictions", `{"properties":{"scope":"/apis","requireBase":"true"}}`},
	}
	for _, family := range refused {
		collection := basePath + "/workspaces/team/" + family.family
		assertStatus(t, handler, http.MethodGet, collection+apiQuery, "", http.StatusNotFound)
		assertStatus(t, handler, http.MethodGet, collection+"/probe"+apiQuery, "", http.StatusNotFound)
		assertStatus(t, handler, http.MethodPut, collection+"/probe"+apiQuery, family.body, http.StatusNotFound)
	}

	// The refusal must come BEFORE the store, or the PUTs above would each
	// have left a resource behind at one scope or the other.
	for _, family := range refused {
		for _, listing := range []string{
			basePath + "/" + family.family + apiQuery,
			basePath + "/workspaces/team/" + family.family + apiQuery,
		} {
			if body := request(t, handler, http.MethodGet, listing, "").Body.String(); strings.Contains(body, "probe") {
				t.Fatalf("a refused %s PUT still wrote something: %s => %s", family.family, listing, body)
			}
		}
	}

	// The read-only networking surfaces are refused the same way. They take no
	// PUT, so only their GET form is meaningful here.
	for _, family := range []string{"privateLinkResources", "networkstatus", "outboundNetworkDependenciesEndpoints", "locations", "skus", "regions", "tenant", "settings", "getssotoken"} {
		assertStatus(t, handler, http.MethodGet, basePath+"/workspaces/team/"+family+apiQuery, "", http.StatusNotFound)
	}

	// The control. These families DO have a Workspace* operation group in the
	// SDK, so they must still be creatable inside a workspace.
	for _, family := range []struct{ family, body string }{
		{"backends", `{"properties":{"url":"https://backend.test","protocol":"http"}}`},
		{"namedValues", `{"properties":{"displayName":"Probe","value":"v"}}`},
		{"tags", `{"properties":{"displayName":"Probe"}}`},
		{"groups", `{"properties":{"displayName":"Probe"}}`},
	} {
		assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team/"+family.family+"/probe"+apiQuery,
			family.body, http.StatusCreated)
	}
}

// Only the FIRST segment after the workspace is checked, and that distinction is
// load-bearing rather than incidental: `users` is service-only as a directory,
// but `WorkspaceGroupUser` exists, so a group's MEMBERSHIP inside a workspace is
// a real Azure surface. Blocking the name at any depth would have taken it out.
func TestServiceOnlyFamiliesAreRefusedByFirstSegmentOnly(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team"+apiQuery,
		`{"properties":{"displayName":"Team"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team/groups/devs"+apiQuery,
		`{"properties":{"displayName":"Devs"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/users/ada"+apiQuery,
		`{"properties":{"email":"ada@example.test","firstName":"Ada","lastName":"L"}}`, http.StatusCreated)

	// The directory entry is refused at workspace scope...
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team/users/ada"+apiQuery,
		`{"properties":{"email":"ada@example.test","firstName":"Ada","lastName":"L"}}`, http.StatusNotFound)
	// ...while the same word deeper in the path is a membership and is not.
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team/groups/devs/users/ada"+apiQuery,
		"", http.StatusCreated)
	if body := request(t, handler, http.MethodGet, basePath+"/workspaces/team/groups/devs/users"+apiQuery, "").Body.String(); !strings.Contains(body, "ada") {
		t.Fatalf("workspace group membership listing = %s", body)
	}
}

// The list is a claim about Azure, so it is asserted rather than left implicit:
// a family added here by accident silently removes a working surface.
func TestServiceOnlyFamilyListIsExact(t *testing.T) {
	want := map[string]bool{
		"caches": true, "identityproviders": true, "openidconnectproviders": true,
		"authorizationproviders": true, "authorizationservers": true,
		"documentations": true, "gateways": true, "users": true,
		// Networking belongs to the service, never to a workspace inside it.
		"privateendpointconnections": true, "privatelinkresources": true,
		"networkstatus": true, "outboundnetworkdependenciesendpoints": true,
		"locations": true,
		// A tier and a region belong to the service; a workspace has neither.
		"skus": true, "regions": true,
		// Tenant access and the public settings describe the service as a
		// whole. Neither has a Workspace* operation group.
		"tenant": true, "settings": true,
		// A policy RESTRICTION is service-wide, and the publisher-portal SSO
		// token is issued for the service. Note the contrast that makes the
		// first one a real claim rather than a guess: every kind of policy
		// DOCUMENT does have a Workspace* group, and this does not.
		"policyrestrictions": true, "getssotoken": true,
	}
	if len(serviceOnlyFamilies) != len(want) {
		t.Fatalf("serviceOnlyFamilies = %v, want %v", serviceOnlyFamilies, want)
	}
	for name := range want {
		if !serviceOnlyFamilies[name] {
			t.Fatalf("%q missing from serviceOnlyFamilies", name)
		}
	}
	// Lowercased, because the lookup lowercases the path segment. A mixed-case
	// key here would never match and the guard would go quiet.
	for name := range serviceOnlyFamilies {
		if name != strings.ToLower(name) {
			t.Fatalf("serviceOnlyFamilies key %q is not lowercase", name)
		}
	}
}
