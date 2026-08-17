package arm

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/rbac"
)

type principalAuth struct{ id string }

func (p principalAuth) ValidateRequest(*http.Request) (*auth.Principal, error) {
	if p.id == "" {
		return &auth.Principal{}, nil
	}
	return &auth.Principal{ID: p.id, Type: "User"}, nil
}

func roleRef(id string) string { return "/providers/Microsoft.Authorization/roleDefinitions/" + id }

func TestRoleDefinitionsAreServed(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	list := request(t, handler, http.MethodGet, basePath+"/providers/Microsoft.Authorization/roleDefinitions"+authQuery, "")
	if list.Code != http.StatusOK {
		t.Fatalf("list = %d", list.Code)
	}
	// The built-in GUIDs are fixed in every Azure tenant and tooling hard-codes
	// them, so a caller assigning by GUID must find the same role here.
	for _, want := range []string{rbac.ServiceContributorID, rbac.WorkspaceContributorID, rbac.ReaderID} {
		if !strings.Contains(list.Body.String(), want) {
			t.Errorf("role definition %s missing from the list", want)
		}
	}
	one := request(t, handler, http.MethodGet, basePath+"/providers/Microsoft.Authorization/roleDefinitions/"+rbac.ServiceReaderID+authQuery, "")
	if !strings.Contains(one.Body.String(), "API Management Service Reader Role") {
		t.Fatalf("role definition GET = %s", one.Body.String())
	}
	if !strings.Contains(one.Body.String(), `"notActions":["Microsoft.ApiManagement/service/*/listSecrets/action"]`) {
		t.Fatalf("notActions must be visible to a caller inspecting the role: %s", one.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/providers/Microsoft.Authorization/roleDefinitions/nope"+authQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/providers/Microsoft.Authorization/roleDefinitions/x"+authQuery, "", http.StatusMethodNotAllowed)
}

func TestRoleAssignmentLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/providers/Microsoft.Authorization/roleAssignments/r1" + authQuery
	collection := basePath + "/providers/Microsoft.Authorization/roleAssignments" + authQuery

	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{}}`, http.StatusBadRequest)
	// A role that does not exist can never grant anything, so it is refused
	// rather than stored as a grant nobody can explain.
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"roleDefinitionId":"nope","principalId":"ada"}}`, http.StatusBadRequest)

	body := `{"properties":{"roleDefinitionId":"` + roleRef(rbac.ServiceReaderID) + `","principalId":"ada"}}`
	assertStatus(t, handler, http.MethodPut, path, body, http.StatusCreated)
	got := request(t, handler, http.MethodGet, path, "")
	for _, want := range []string{`"principalId":"ada"`, `"principalType":"User"`, rbac.ServiceReaderID,
		`"type":"Microsoft.Authorization/roleAssignments"`} {
		if !strings.Contains(got.Body.String(), want) {
			t.Errorf("assignment GET missing %s: %s", want, got.Body.String())
		}
	}
	assertStatus(t, handler, http.MethodPut, path, body, http.StatusOK)
	if !strings.Contains(request(t, handler, http.MethodGet, collection, "").Body.String(), "ada") {
		t.Fatal("assignment missing from the collection")
	}
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusOK)
	// ARM answers a delete of an absent assignment with 204, so tearing down
	// twice does not have to be special-cased by the caller.
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)

	assertStatus(t, handler, http.MethodGet, basePath+"/providers/Microsoft.Authorization/nonsense"+authQuery, "", http.StatusNotFound)
}

// A listing at a scope shows assignments made ABOVE it too, because those are
// the ones actually granting access by inheritance.
func TestRoleAssignmentListingIncludesInherited(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	subscriptionScope := "/subscriptions/sub"
	assertStatus(t, handler, http.MethodPut,
		subscriptionScope+"/providers/Microsoft.Authorization/roleAssignments/high"+authQuery,
		`{"properties":{"roleDefinitionId":"`+roleRef(rbac.ReaderID)+`","principalId":"ada","principalType":"ServicePrincipal"}}`,
		http.StatusCreated)
	assertStatus(t, handler, http.MethodPut,
		basePath+"/workspaces/team/providers/Microsoft.Authorization/roleAssignments/low"+authQuery,
		`{"properties":{"roleDefinitionId":"`+roleRef(rbac.WorkspaceReaderID)+`","principalId":"bob"}}`,
		http.StatusCreated)

	atService := request(t, handler, http.MethodGet, basePath+"/providers/Microsoft.Authorization/roleAssignments"+authQuery, "").Body.String()
	if !strings.Contains(atService, `"name":"high"`) {
		t.Fatalf("a subscription-scoped assignment must appear at the service: %s", atService)
	}
	if !strings.Contains(atService, `"name":"low"`) {
		t.Fatalf("a workspace-scoped assignment must appear when listing above it: %s", atService)
	}
	if !strings.Contains(atService, `"principalType":"ServicePrincipal"`) {
		t.Fatal("an explicit principalType must be preserved")
	}
}

// Enforcement is off by default, and turning it on is opting in to refusal.
func TestRBACEnforcementDecisions(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	handler.Auth = principalAuth{id: "ada"}
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team"+apiQuery, `{"properties":{"displayName":"Team"}}`, http.StatusCreated)

	apiBody := `{"properties":{"displayName":"A","path":"a","serviceUrl":"https://b.test"}}`
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/a"+apiQuery, apiBody, http.StatusCreated)

	handler.EnforceRBAC, handler.RBACOwner = true, "root"
	assertStatus(t, handler, http.MethodGet, basePath+"/apis/a"+apiQuery, "", http.StatusForbidden)

	// The owner's access does not come from an assignment, which is the only
	// way the FIRST assignment can ever be created.
	owner := asPrincipal(handler, "root")
	assertStatus(t, owner, http.MethodPut,
		basePath+"/workspaces/team/providers/Microsoft.Authorization/roleAssignments/r1"+authQuery,
		`{"properties":{"roleDefinitionId":"`+roleRef(rbac.WorkspaceContributorID)+`","principalId":"ada"}}`,
		http.StatusCreated)

	// Granted inside the workspace, refused outside it. The confinement comes
	// from scope inheritance, not from a special case for workspaces.
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team/apis/o"+apiQuery,
		`{"properties":{"displayName":"O","path":"o","serviceUrl":"https://b.test"}}`, http.StatusCreated)
	refused := request(t, handler, http.MethodPut, basePath+"/apis/b"+apiQuery, apiBody)
	if refused.Code != http.StatusForbidden {
		t.Fatalf("a workspace contributor reached the service scope: %d", refused.Code)
	}
	// ARM's own refusal shape, so a client library reports a permissions error
	// rather than a transport failure or a missing resource.
	if !strings.Contains(refused.Body.String(), "AuthorizationFailed") ||
		!strings.Contains(refused.Body.String(), "Microsoft.ApiManagement/service/apis/write") {
		t.Fatalf("refusal must name the action and use ARM's code: %s", refused.Body.String())
	}

	// Enforcement with no identity denies rather than silently allowing.
	anonymous := asPrincipal(handler, "")
	assertStatus(t, anonymous, http.MethodGet, basePath+"/apis/a"+apiQuery, "", http.StatusForbidden)
}

// A path with no APIM resource under it has no APIM action to authorize, so
// enforcement must not invent one and refuse.
func TestRBACIgnoresNonAPIMPaths(t *testing.T) {
	scope, action := scopeAndAction(http.MethodGet, "/subscriptions/sub/resourceGroups/rg")
	if scope != "" || action != "" {
		t.Fatalf("a path with no APIM resource yields no action, got %q %q", scope, action)
	}
}

// Listing services IS an APIM read, so it is subject to the same rules. The
// owner sees the list; an unassigned principal does not.
func TestRBACGovernsTheServiceListing(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	handler.EnforceRBAC, handler.RBACOwner = true, "root"
	handler.Auth = principalAuth{id: "ada"}
	list := "/subscriptions/sub/providers/Microsoft.ApiManagement/service" + apiQuery
	assertStatus(t, handler, http.MethodGet, list, "", http.StatusForbidden)

	owner := asPrincipal(handler, "root")
	assertStatus(t, owner, http.MethodGet, list, "", http.StatusOK)

	// And a Reader assigned at the subscription can list too, which is the
	// inheritance path: the assignment is made above the resource.
	assertStatus(t, owner, http.MethodPut,
		"/subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/r"+authQuery,
		`{"properties":{"roleDefinitionId":"`+roleRef(rbac.ReaderID)+`","principalId":"ada"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, list, "", http.StatusOK)
}

func TestParseAuthorizationPaths(t *testing.T) {
	for path, want := range map[string]authorizationRoute{
		"/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/r": {
			Scope: "/subscriptions/s", Resource: "roleAssignments", Name: "r"},
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.ApiManagement/service/svc/providers/Microsoft.Authorization/roleAssignments": {
			Scope: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ApiManagement/service/svc", Resource: "roleAssignments"},
	} {
		got, ok := parseAuthorization(path)
		if !ok || got != want {
			t.Errorf("parseAuthorization(%q) = %+v %v, want %+v", path, got, ok, want)
		}
	}
	for _, path := range []string{
		"/subscriptions/s/providers/Microsoft.ApiManagement/service/svc",
		"/providers/Microsoft.Authorization/roleAssignments/r",
		"/subscriptions/s/providers/Microsoft.Authorization",
	} {
		if _, ok := parseAuthorization(path); ok {
			t.Errorf("parseAuthorization(%q) must not match", path)
		}
	}
}

func TestRoleAssignmentStoreFailuresAreReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	rt := authorizationRoute{Scope: "/subscriptions/sub", Resource: "roleAssignments", Name: "r1"}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.roleAssignmentCollection(recorder, httptest.NewRequest(http.MethodGet, "/", nil), rt)
	if recorder.Code < 400 {
		t.Fatalf("a failed listing returned %d", recorder.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		recorder = httptest.NewRecorder()
		request := httptest.NewRequest(method, "/", strings.NewReader(
			`{"properties":{"roleDefinitionId":"`+roleRef(rbac.ReaderID)+`","principalId":"ada"}}`))
		request.Header.Set("Content-Type", "application/json")
		handler.roleAssignmentResource(recorder, request, rt)
		if recorder.Code < 400 {
			t.Errorf("%s against a failed store returned %d", method, recorder.Code)
		}
	}
	// And enforcement itself must report a store failure rather than deny.
	handler.EnforceRBAC, handler.RBACOwner = true, "root"
	handler.Auth = principalAuth{id: "ada"}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, basePath+"/apis/a"+apiQuery, nil))
	if recorder.Code < 400 {
		t.Fatalf("enforcement over a failed store returned %d", recorder.Code)
	}
}

func TestRoleAssignmentWireHandlesADocumentWithoutProperties(t *testing.T) {
	wire := roleAssignmentWire(rbac.Assignment{
		Scope: "/s", Name: "r", PrincipalID: "ada",
		Document: map[string]any{"properties": "not an object"},
	})
	properties, _ := wire["properties"].(map[string]any)
	if properties["principalId"] != "ada" {
		t.Fatalf("wire = %v", wire)
	}
}

// A role with no permissions at all renders as empty arrays rather than nulls,
// because a client deserialising `null` into a list is a crash waiting to
// happen and every real role definition carries the four arrays.
func TestRoleDefinitionWireRendersEmptyPermissionArrays(t *testing.T) {
	wire := roleDefinitionWire(rbac.RoleDefinition{Name: "n", RoleName: "R", Permissions: []rbac.Permission{{}}})
	properties, _ := wire["properties"].(map[string]any)
	permissions, _ := properties["permissions"].([]any)
	if len(permissions) != 1 {
		t.Fatalf("permissions = %v", properties["permissions"])
	}
	entry, _ := permissions[0].(map[string]any)
	for _, key := range []string{"actions", "notActions", "dataActions", "notDataActions"} {
		value, ok := entry[key].([]string)
		if !ok {
			if _, okAny := entry[key].([]any); !okAny {
				t.Errorf("%s must be an array, got %#v", key, entry[key])
				continue
			}
			continue
		}
		if value == nil {
			t.Errorf("%s must be empty, not null", key)
		}
	}
}

// A collection listing that shares no scope lineage with the assignment must
// exclude it: a sibling service's grants are not this one's business.
func TestRoleAssignmentListingExcludesUnrelatedScopes(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodPut,
		"/subscriptions/other/providers/Microsoft.Authorization/roleAssignments/elsewhere"+authQuery,
		`{"properties":{"roleDefinitionId":"`+roleRef(rbac.ReaderID)+`","principalId":"ada"}}`, http.StatusCreated)
	listed := request(t, handler, http.MethodGet, basePath+"/providers/Microsoft.Authorization/roleAssignments"+authQuery, "").Body.String()
	if strings.Contains(listed, "elsewhere") {
		t.Fatalf("an unrelated subscription's assignment leaked: %s", listed)
	}
}

// Role assignments are themselves subject to enforcement: reading who has
// access is an action, and an unassigned caller must not learn it.
func TestRBACGovernsTheAuthorizationSurfaceItself(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	handler.EnforceRBAC, handler.RBACOwner = true, "root"
	handler.Auth = principalAuth{id: "ada"}
	assertStatus(t, handler, http.MethodGet,
		basePath+"/providers/Microsoft.Authorization/roleAssignments"+authQuery, "", http.StatusForbidden)

	owner := asPrincipal(handler, "root")
	assertStatus(t, owner, http.MethodGet,
		basePath+"/providers/Microsoft.Authorization/roleAssignments"+authQuery, "", http.StatusOK)
}

// The write can fail after both the role check and the existence check pass.
// A closed store cannot reach it, because the existence check fails first, so
// the write is refused with a trigger the way the repo tests its other writes.
func TestRoleAssignmentWriteFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	handler, st := testHandlerAt(t, dir)
	seedService(t, st)
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_assignment BEFORE INSERT ON role_assignments BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut,
		basePath+"/providers/Microsoft.Authorization/roleAssignments/r1"+authQuery,
		`{"properties":{"roleDefinitionId":"`+roleRef(rbac.ReaderID)+`","principalId":"ada"}}`,
		http.StatusConflict)
}

// asPrincipal returns a handler over the SAME store, seen by a different
// caller. A copy would duplicate the handler's mutex, which go vet rejects and
// which would silently split the lock.
func asPrincipal(h *Handler, id string) *Handler {
	return &Handler{
		Store: h.Store, Auth: principalAuth{id: id},
		EnforceRBAC: h.EnforceRBAC, RBACOwner: h.RBACOwner,
		ValidatePolicy: h.ValidatePolicy, ValidateResolverPolicy: h.ValidateResolverPolicy,
		Activate: h.Activate,
	}
}

// Microsoft.Authorization publishes its own API versions.
const authQuery = "?api-version=2022-04-01"

// Microsoft.Authorization publishes its own API versions, so an authorization
// path is validated against those and not APIM's. Sending APIM's version here
// is the mistake a caller makes when they assume one provider's version works
// for another.
func TestAuthorizationPathsUseTheirOwnAPIVersion(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/providers/Microsoft.Authorization/roleAssignments"
	assertStatus(t, handler, http.MethodGet, path+apiQuery, "", http.StatusBadRequest)
	assertStatus(t, handler, http.MethodGet, path+authQuery, "", http.StatusOK)
	// And an APIM path still rejects an authorization version.
	assertStatus(t, handler, http.MethodGet, basePath+"/apis"+authQuery, "", http.StatusBadRequest)
}
