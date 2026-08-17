package arm

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

func TestWorkspaceLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	collection := basePath + "/workspaces" + apiQuery
	path := basePath + "/workspaces/team-a" + apiQuery

	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, path, `{"properties":{}}`, http.StatusBadRequest)

	body := `{"id":"malicious","name":"malicious","properties":{"displayName":"Team A","description":"the A team","custom":{"kept":true}}}`
	assertStatus(t, handler, http.MethodPut, path, body, http.StatusCreated)
	got := request(t, handler, http.MethodGet, path, "")
	for _, want := range []string{`"displayName":"Team A"`, `"description":"the A team"`, `"custom":{"kept":true}`,
		`"type":"Microsoft.ApiManagement/service/workspaces"`} {
		if !strings.Contains(got.Body.String(), want) {
			t.Errorf("workspace GET missing %s: %s", want, got.Body.String())
		}
	}
	if strings.Contains(got.Body.String(), `"id":"malicious"`) {
		t.Fatalf("a caller-supplied id must not be honoured: %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	list := request(t, handler, http.MethodGet, collection, "")
	if !strings.Contains(list.Body.String(), `"count":1`) {
		t.Fatalf("workspace list = %s", list.Body.String())
	}

	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"displayName":"Team A v2"}}`, http.StatusOK)
	got = request(t, handler, http.MethodGet, path, "")
	if !strings.Contains(got.Body.String(), `"displayName":"Team A v2"`) || !strings.Contains(got.Body.String(), `"description":"the A team"`) {
		t.Fatalf("PATCH lost fields: %s", got.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"description":""}}`, http.StatusOK)
	if strings.Contains(request(t, handler, http.MethodGet, path, "").Body.String(), `"description"`) {
		t.Fatal("an emptied description must be absent, not empty")
	}
	assertStatus(t, handler, http.MethodPatch, basePath+"/workspaces/absent"+apiQuery, `{"properties":{}}`, http.StatusNotFound)

	handler.Activate = func() error { return errors.New("activation") }
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusInternalServerError)
	handler.Activate = nil
	assertStatus(t, handler, http.MethodGet, path, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
}

// A workspace is a SCOPE: every family the service exposes is available inside
// it, parented to the workspace, and the two sets never see each other.
func TestWorkspaceScopesEveryResourceFamily(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team-a"+apiQuery, `{"properties":{"displayName":"Team A"}}`, http.StatusCreated)

	// The same name in both scopes, which is only possible if they are
	// genuinely different parents.
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team-a/apis/orders"+apiQuery,
		`{"properties":{"displayName":"WS Orders","path":"ws","serviceUrl":"https://b.test"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/orders"+apiQuery,
		`{"properties":{"displayName":"Service Orders","path":"svc","serviceUrl":"https://b.test"}}`, http.StatusCreated)

	workspaceList := request(t, handler, http.MethodGet, basePath+"/workspaces/team-a/apis"+apiQuery, "").Body.String()
	serviceList := request(t, handler, http.MethodGet, basePath+"/apis"+apiQuery, "").Body.String()
	if !strings.Contains(workspaceList, "WS Orders") || strings.Contains(workspaceList, "Service Orders") {
		t.Fatalf("workspace listing leaked: %s", workspaceList)
	}
	if !strings.Contains(serviceList, "Service Orders") || strings.Contains(serviceList, "WS Orders") {
		t.Fatalf("service listing leaked: %s", serviceList)
	}

	// The ID carries the workspace segment, which is what makes it addressable.
	one := request(t, handler, http.MethodGet, basePath+"/workspaces/team-a/apis/orders"+apiQuery, "").Body.String()
	if !strings.Contains(one, `/service/svc/workspaces/team-a/apis/orders`) {
		t.Fatalf("workspace API id = %s", one)
	}

	// Other families, through handlers that know nothing about workspaces.
	for path, payload := range map[string]string{
		"/products/starter": `{"properties":{"displayName":"Starter"}}`,
		"/namedValues/nv":   `{"properties":{"displayName":"nv","value":"v"}}`,
		"/backends/b":       `{"properties":{"url":"https://b.test","protocol":"http"}}`,
		"/tags/t":           `{"properties":{"displayName":"T"}}`,
	} {
		assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team-a"+path+apiQuery, payload, http.StatusCreated)
	}
	// A workspace-scoped policy hangs off the workspace, not the service.
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team-a/policies/policy"+apiQuery,
		`{"properties":{"value":"<policies><inbound/></policies>"}}`, http.StatusCreated)
	policy := request(t, handler, http.MethodGet, basePath+"/workspaces/team-a/policies/policy"+apiQuery, "").Body.String()
	if !strings.Contains(policy, "service/workspaces/policies") {
		t.Fatalf("workspace policy ARM type = %s", policy)
	}

	// A path naming a workspace that does not exist must 404 rather than
	// silently creating resources in an unreachable scope.
	assertStatus(t, handler, http.MethodGet, basePath+"/workspaces/absent/apis"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/absent/apis/x"+apiQuery,
		`{"properties":{"displayName":"X","path":"x","serviceUrl":"https://b.test"}}`, http.StatusNotFound)

	// Deleting the workspace takes its contents with it.
	assertStatus(t, handler, http.MethodDelete, basePath+"/workspaces/team-a"+apiQuery, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodGet, basePath+"/workspaces/team-a/apis/orders"+apiQuery, "", http.StatusNotFound)
	if after := request(t, handler, http.MethodGet, basePath+"/apis"+apiQuery, "").Body.String(); !strings.Contains(after, "Service Orders") {
		t.Fatalf("deleting a workspace must not touch the service's own resources: %s", after)
	}
}

// A workspace cannot exist without its service, and a nested path cannot be
// created before the workspace it names.
func TestWorkspaceRequiresItsService(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team-a"+apiQuery,
		`{"properties":{"displayName":"Team A"}}`, http.StatusNotFound)
}

func TestWorkspaceStoreFailuresAreReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	rt := route{SubscriptionID: "sub", ResourceGroup: "rg", ServiceName: "svc"}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.workspaceCollection(recorder, httptest.NewRequest(http.MethodGet, "/", nil), rt)
	if recorder.Code < 400 {
		t.Fatalf("a failed workspace list returned %d", recorder.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		recorder = httptest.NewRecorder()
		request := httptest.NewRequest(method, "/", strings.NewReader(`{"properties":{"displayName":"T"}}`))
		request.Header.Set("Content-Type", "application/json")
		handler.workspaceResource(recorder, request, rt, model.Workspace{ServiceID: rt.service().ID(), Name: "team"})
		if recorder.Code < 400 {
			t.Errorf("%s against a failed store returned %d", method, recorder.Code)
		}
	}
}

func TestWorkspaceWireHandlesADocumentWithoutProperties(t *testing.T) {
	wire := workspaceWire(model.Workspace{
		ServiceID: "/s/svc", Name: "team", DisplayName: "Team",
		Document: map[string]any{"properties": "not an object"},
	})
	properties, _ := wire["properties"].(map[string]any)
	if properties["displayName"] != "Team" {
		t.Fatalf("wire = %v", wire)
	}
}

func TestScopeIDComposition(t *testing.T) {
	rt := route{SubscriptionID: "sub", ResourceGroup: "rg", ServiceName: "svc"}
	if got := rt.scopeID(); !strings.HasSuffix(got, "/service/svc") {
		t.Fatalf("service scope = %q", got)
	}
	rt.Workspace = "team"
	if got := rt.scopeID(); !strings.HasSuffix(got, "/service/svc/workspaces/team") {
		t.Fatalf("workspace scope = %q", got)
	}
}

// A workspace policy names a workspace, so the workspace has to exist before
// one can hang off it.
func TestWorkspacePolicyRequiresTheWorkspace(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodGet, basePath+"/workspaces/absent/policies/policy"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/absent/policies/policy"+apiQuery,
		`{"properties":{"value":"<policies><inbound/></policies>"}}`, http.StatusNotFound)
}

// The write itself can fail after both lookups succeed: a workspace whose
// owning service does not exist violates the scope foreign key. Driven through
// the handler directly, because the router composes the two consistently.
func TestWorkspaceWriteFailureIsReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	rt := route{SubscriptionID: "sub", ResourceGroup: "rg", ServiceName: "svc"}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"properties":{"displayName":"Team"}}`))
	request.Header.Set("Content-Type", "application/json")
	handler.workspaceResource(recorder, request, rt, model.Workspace{ServiceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/absent", Name: "team"})
	if recorder.Code < 400 {
		t.Fatalf("a workspace on a non-existent service returned %d", recorder.Code)
	}
}

// The service-scope policy has the same guard: its parent must exist. At
// workspace scope the workspace is checked; at service scope, the service.
func TestServicePolicyRequiresTheService(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodGet, basePath+"/policies/policy"+apiQuery, "", http.StatusNotFound)
}
