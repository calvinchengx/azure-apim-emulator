package arm

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func tenantJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, body)
	}
	return document
}

func tenantProperties(t *testing.T, body string) map[string]any {
	t.Helper()
	properties, ok := tenantJSON(t, body)["properties"].(map[string]any)
	if !ok {
		t.Fatalf("no properties object: %s", body)
	}
	return properties
}

// Both access configurations exist from the moment the service does, because
// nothing in Microsoft's contract creates them. A service whose GET 404s here
// would 404 on a call that cannot fail in Azure.
func TestTenantAccessIsSeededWithTheService(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)

	listed := request(t, handler, http.MethodGet, basePath+"/tenant"+apiQuery, "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", listed.Code, listed.Body.String())
	}
	document := tenantJSON(t, listed.Body.String())
	values, _ := document["value"].([]any)
	if len(values) != 2 {
		t.Fatalf("list returned %d configurations, want access and gitAccess: %s", len(values), listed.Body.String())
	}
	// `count` is present here and absent from the settings collection below.
	// That asymmetry is Microsoft's, not ours: only one of the two response
	// models declares the field.
	if document["count"] != float64(2) {
		t.Errorf("count = %v, want 2", document["count"])
	}
	names := map[string]bool{}
	for _, value := range values {
		resource, _ := value.(map[string]any)
		names[resource["name"].(string)] = true
		if resource["type"] != "Microsoft.ApiManagement/service/tenant" {
			t.Errorf("type = %v", resource["type"])
		}
		properties, _ := resource["properties"].(map[string]any)
		// `properties.id` is the access NAME, not the ARM id one level up.
		if properties["id"] != resource["name"] {
			t.Errorf("properties.id = %v, want %v", properties["id"], resource["name"])
		}
		if properties["enabled"] != false {
			t.Errorf("%v starts enabled; direct access is off on a new service", resource["name"])
		}
	}
	if !names["access"] || !names["gitAccess"] {
		t.Fatalf("names = %v, want both members of AccessIdName", names)
	}

	// The git configuration carries a principal and the management one does
	// not, matching Azure's own two examples.
	git := tenantProperties(t, request(t, handler, http.MethodGet, basePath+"/tenant/gitAccess"+apiQuery, "").Body.String())
	if git["principalId"] != "git" {
		t.Errorf("gitAccess principalId = %v, want git", git["principalId"])
	}
	access := tenantProperties(t, request(t, handler, http.MethodGet, basePath+"/tenant/access"+apiQuery, "").Body.String())
	if _, present := access["principalId"]; present {
		t.Errorf("access carries principalId = %v; Azure omits it", access["principalId"])
	}
}

// The single most important assertion in this file: a GET must never carry the
// keys. Microsoft splits the surface into two models to make that structural,
// and `/listSecrets` is the only door.
func TestTenantAccessKeysLeaveOnlyThroughListSecrets(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)

	secrets := tenantJSON(t, request(t, handler, http.MethodPost, basePath+"/tenant/access/listSecrets"+apiQuery, "").Body.String())
	primary, _ := secrets["primaryKey"].(string)
	secondary, _ := secrets["secondaryKey"].(string)
	if primary == "" || secondary == "" || primary == secondary {
		t.Fatalf("listSecrets = %v, want two distinct keys", secrets)
	}
	// Unwrapped. Every other response in this provider nests under
	// `properties`; `AccessInformationSecretsContract` does not.
	if _, wrapped := secrets["properties"]; wrapped {
		t.Errorf("listSecrets wrapped its body in properties: %v", secrets)
	}
	if secrets["id"] != "access" {
		t.Errorf("listSecrets id = %v, want the access name", secrets["id"])
	}

	// Now the refutation: the same key must not appear anywhere in the read
	// paths. Searching the RAW body rather than a parsed field is deliberate,
	// because a key leaking under an unexpected name would pass a field check.
	for _, path := range []string{
		basePath + "/tenant" + apiQuery,
		basePath + "/tenant/access" + apiQuery,
	} {
		body := request(t, handler, http.MethodGet, path, "").Body.String()
		if strings.Contains(body, primary) || strings.Contains(body, secondary) {
			t.Fatalf("GET %s leaked a key: %s", path, body)
		}
	}
}

// PUT is spelled `Create` and declares ONLY a 200. Answering 201 the way every
// other create in this provider does would be an undeclared status, and a
// generated client refuses to deserialize one.
func TestTenantAccessPutNeverReports201(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	for range 2 {
		created := request(t, handler, http.MethodPut, basePath+"/tenant/access"+apiQuery,
			`{"properties":{"enabled":true}}`)
		if created.Code != http.StatusOK {
			t.Fatalf("PUT = %d, want 200: %s", created.Code, created.Body.String())
		}
	}
	if tenantProperties(t, request(t, handler, http.MethodGet, basePath+"/tenant/access"+apiQuery, "").Body.String())["enabled"] != true {
		t.Error("PUT did not persist enabled")
	}
}

// `ifMatch` is required on both writes, which is unlike every other family
// here. Without the header the request is a 400 before anything is written.
func TestTenantAccessRequiresIfMatchOnBothWrites(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		if !requiresIfMatch(route{Tail: []string{"tenant", "access"}}, method) {
			t.Fatalf("%s does not require If-Match", method)
		}
		recorder := httptest.NewRecorder()
		missing := httptest.NewRequest(method, basePath+"/tenant/access"+apiQuery,
			strings.NewReader(`{"properties":{"enabled":true}}`))
		missing.Header.Set("Authorization", "Bearer token")
		handler.ServeHTTP(recorder, missing)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s without If-Match = %d, want 400: %s", method, recorder.Code, recorder.Body.String())
		}
	}
	// The control: a stale tag is refused, so the header is being COMPARED and
	// not merely counted.
	stale := conditionalRequest(t, handler, http.MethodPatch, basePath+"/tenant/access"+apiQuery,
		`{"properties":{"enabled":true}}`, "If-Match", `"not-the-current-tag"`)
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("a stale If-Match = %d, want 412", stale.Code)
	}
	// And the neighbouring families still do NOT require it on PUT, which is
	// what keeps this from being a blanket rule.
	if requiresIfMatch(route{Tail: []string{"backends", "b"}}, http.MethodPut) {
		t.Error("If-Match became required on an ordinary PUT")
	}
}

// PATCH carries `AccessInformationUpdateParameters`, whose only member is
// `enabled`. Accepting a key there would work here and be silently dropped in
// Azure.
func TestTenantAccessUpdateRefusesFieldsItCannotSet(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	before := request(t, handler, http.MethodPost, basePath+"/tenant/access/listSecrets"+apiQuery, "").Body.String()
	for _, body := range []string{
		`{"properties":{"primaryKey":"k"}}`,
		`{"properties":{"secondaryKey":"k"}}`,
		`{"properties":{"principalId":"someone"}}`,
	} {
		recorder := request(t, handler, http.MethodPatch, basePath+"/tenant/access"+apiQuery, body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("PATCH %s = %d, want 400: %s", body, recorder.Code, recorder.Body.String())
		}
	}
	if after := request(t, handler, http.MethodPost, basePath+"/tenant/access/listSecrets"+apiQuery, "").Body.String(); after != before {
		t.Fatal("a refused PATCH still changed the stored configuration")
	}
	// PUT does carry them, so the refusal is about the update contract and not
	// about the fields being unwritable.
	if request(t, handler, http.MethodPut, basePath+"/tenant/access"+apiQuery,
		`{"properties":{"enabled":true,"principalId":"someone","primaryKey":"p","secondaryKey":"s"}}`).Code != http.StatusOK {
		t.Fatal("PUT refused the fields its own contract declares")
	}
	secrets := tenantJSON(t, request(t, handler, http.MethodPost, basePath+"/tenant/access/listSecrets"+apiQuery, "").Body.String())
	if secrets["primaryKey"] != "p" || secrets["secondaryKey"] != "s" || secrets["principalId"] != "someone" {
		t.Errorf("PUT did not persist its own fields: %v", secrets)
	}
}

// The `git` segment selects the TARGET, not just the route: "Regenerate primary
// access key for GIT" must move the gitAccess key and leave the management one
// alone. Asserting which of the two changed is the whole point; a test that
// only checked for a 204 would pass with both wired to the same row.
func TestTenantAccessGitRegeneratesTheGitKey(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	keys := func(name string) (string, string) {
		t.Helper()
		secrets := tenantJSON(t, request(t, handler, http.MethodPost,
			basePath+"/tenant/"+name+"/listSecrets"+apiQuery, "").Body.String())
		primary, _ := secrets["primaryKey"].(string)
		secondary, _ := secrets["secondaryKey"].(string)
		return primary, secondary
	}
	accessPrimary, accessSecondary := keys("access")
	gitPrimary, gitSecondary := keys("gitAccess")

	if code := request(t, handler, http.MethodPost, basePath+"/tenant/access/git/regeneratePrimaryKey"+apiQuery, "").Code; code != http.StatusNoContent {
		t.Fatalf("git regeneratePrimaryKey = %d, want 204", code)
	}
	if primary, _ := keys("gitAccess"); primary == gitPrimary {
		t.Error("the git primary key did not move")
	}
	if primary, secondary := keys("access"); primary != accessPrimary || secondary != accessSecondary {
		t.Error("a git regeneration moved the management keys")
	}

	if code := request(t, handler, http.MethodPost, basePath+"/tenant/access/git/regenerateSecondaryKey"+apiQuery, "").Code; code != http.StatusNoContent {
		t.Fatalf("git regenerateSecondaryKey = %d, want 204", code)
	}
	if _, secondary := keys("gitAccess"); secondary == gitSecondary {
		t.Error("the git secondary key did not move")
	}
}

// The non-git regenerations move exactly one key each, on the row the path
// names.
func TestTenantAccessRegeneratesOneKeyAtATime(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	read := func() (string, string) {
		t.Helper()
		secrets := tenantJSON(t, request(t, handler, http.MethodPost,
			basePath+"/tenant/access/listSecrets"+apiQuery, "").Body.String())
		primary, _ := secrets["primaryKey"].(string)
		secondary, _ := secrets["secondaryKey"].(string)
		return primary, secondary
	}
	primary, secondary := read()
	if code := request(t, handler, http.MethodPost, basePath+"/tenant/access/regeneratePrimaryKey"+apiQuery, "").Code; code != http.StatusNoContent {
		t.Fatalf("regeneratePrimaryKey = %d, want 204", code)
	}
	newPrimary, unchanged := read()
	if newPrimary == primary {
		t.Error("the primary key did not move")
	}
	if unchanged != secondary {
		t.Error("regenerating the primary key moved the secondary one")
	}
	if code := request(t, handler, http.MethodPost, basePath+"/tenant/access/regenerateSecondaryKey"+apiQuery, "").Code; code != http.StatusNoContent {
		t.Fatalf("regenerateSecondaryKey = %d, want 204", code)
	}
	stillPrimary, newSecondary := read()
	if newSecondary == secondary || stillPrimary != newPrimary {
		t.Error("regenerating the secondary key did not move exactly that key")
	}
}

func TestTenantAccessEntityTagAndConditionalRead(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	head := request(t, handler, http.MethodHead, basePath+"/tenant/access"+apiQuery, "")
	if head.Code != http.StatusOK || head.Header().Get("ETag") == "" {
		t.Fatalf("HEAD = %d etag=%q", head.Code, head.Header().Get("ETag"))
	}
	get := request(t, handler, http.MethodGet, basePath+"/tenant/access"+apiQuery, "")
	if get.Header().Get("ETag") != head.Header().Get("ETag") {
		t.Errorf("HEAD and GET disagree on the entity tag")
	}
	// A write must move it, or a client's conditional request can never fail.
	request(t, handler, http.MethodPatch, basePath+"/tenant/access"+apiQuery, `{"properties":{"enabled":true}}`)
	if after := request(t, handler, http.MethodHead, basePath+"/tenant/access"+apiQuery, ""); after.Header().Get("ETag") == head.Header().Get("ETag") {
		t.Error("the entity tag survived a write")
	}
}

func TestTenantAccessRejectsPathsAzureDoesNotPublish(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	// An accessName outside `AccessIdName`, at every depth that takes one.
	for _, path := range []string{
		basePath + "/tenant/other" + apiQuery,
		basePath + "/tenant/other/listSecrets" + apiQuery,
		basePath + "/tenant/other/git/regeneratePrimaryKey" + apiQuery,
	} {
		if code := request(t, handler, http.MethodGet, path, "").Code; code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", path, code)
		}
	}
	// Depths and verbs the contract has no operation for.
	for _, probe := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, basePath + "/tenant/access/unknown" + apiQuery, http.StatusNotFound},
		{http.MethodGet, basePath + "/tenant/access/git/unknown" + apiQuery, http.StatusNotFound},
		{http.MethodGet, basePath + "/tenant/access/git/regeneratePrimaryKey/more" + apiQuery, http.StatusNotFound},
		// There is no delete and no create: the two rows are permanent.
		{http.MethodDelete, basePath + "/tenant/access" + apiQuery, http.StatusMethodNotAllowed},
		{http.MethodPut, basePath + "/tenant" + apiQuery, http.StatusMethodNotAllowed},
		// listSecrets and the regenerations are POST only.
		{http.MethodGet, basePath + "/tenant/access/listSecrets" + apiQuery, http.StatusMethodNotAllowed},
		{http.MethodPut, basePath + "/tenant/access/regeneratePrimaryKey" + apiQuery, http.StatusMethodNotAllowed},
	} {
		if code := request(t, handler, probe.method, probe.path, "").Code; code != probe.want {
			t.Errorf("%s %s = %d, want %d", probe.method, probe.path, code, probe.want)
		}
	}
	// A malformed body is a 400 rather than a partially applied write.
	if code := request(t, handler, http.MethodPut, basePath+"/tenant/access"+apiQuery, "{").Code; code != http.StatusBadRequest {
		t.Errorf("a malformed PUT body = %d, want 400", code)
	}
}

// Case is not part of the identity, but the CANONICAL spelling is what comes
// back, so a client reading `name` gets what Azure returns.
func TestTenantAccessNameIsCaseInsensitiveButCanonical(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	document := tenantJSON(t, request(t, handler, http.MethodGet, basePath+"/tenant/GITACCESS"+apiQuery, "").Body.String())
	if document["name"] != "gitAccess" {
		t.Fatalf("name = %v, want the canonical gitAccess", document["name"])
	}
	if !strings.HasSuffix(document["id"].(string), "/tenant/gitAccess") {
		t.Errorf("id = %v, want the canonical spelling", document["id"])
	}
}

func TestTenantAccessReportsAMissingServiceAndAFailingStore(t *testing.T) {
	handler, _ := testHandler(t)
	// No service, so the collection has no scope. An empty list here would say
	// "this service has no tenant access", which is not a thing Azure can mean.
	if code := request(t, handler, http.MethodGet, basePath+"/tenant"+apiQuery, "").Code; code != http.StatusNotFound {
		t.Errorf("listing an absent service = %d, want 404", code)
	}
	if code := request(t, handler, http.MethodGet, basePath+"/tenant/access"+apiQuery, "").Code; code != http.StatusNotFound {
		t.Errorf("reading an absent service = %d, want 404", code)
	}

	handler, st := testHandler(t)
	seedService(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct{ method, path, body string }{
		{http.MethodGet, basePath + "/tenant" + apiQuery, ""},
		{http.MethodGet, basePath + "/tenant/access" + apiQuery, ""},
		{http.MethodPut, basePath + "/tenant/access" + apiQuery, `{"properties":{"enabled":true}}`},
		{http.MethodPost, basePath + "/tenant/access/listSecrets" + apiQuery, ""},
		{http.MethodPost, basePath + "/tenant/access/regeneratePrimaryKey" + apiQuery, ""},
		{http.MethodGet, basePath + "/settings" + apiQuery, ""},
		{http.MethodGet, basePath + "/settings/public" + apiQuery, ""},
	} {
		if code := request(t, handler, probe.method, probe.path, probe.body).Code; code >= 200 && code < 300 {
			t.Errorf("%s %s reported %d against a closed store", probe.method, probe.path, code)
		}
	}
}

func TestTenantSettingsAreReadOnlyAndSingleton(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)

	single := request(t, handler, http.MethodGet, basePath+"/settings/public"+apiQuery, "")
	if single.Code != http.StatusOK {
		t.Fatalf("GET settings/public = %d: %s", single.Code, single.Body.String())
	}
	document := tenantJSON(t, single.Body.String())
	if document["type"] != "Microsoft.ApiManagement/service/settings" || document["name"] != "public" {
		t.Errorf("type/name = %v/%v", document["type"], document["name"])
	}
	settings, ok := tenantProperties(t, single.Body.String())["settings"].(map[string]any)
	if !ok {
		t.Fatalf("no settings map: %s", single.Body.String())
	}
	// Six keys, and one of them is null rather than empty. Azure's own example
	// says so, and a `map[string]string` in Go could not have expressed it.
	if len(settings) != 6 {
		t.Errorf("settings has %d keys, want 6: %v", len(settings), settings)
	}
	value, present := settings["CustomPortalSettings.UserRegistrationTerms"]
	if !present || value != nil {
		t.Errorf("UserRegistrationTerms = %v (present=%v), want a present null", value, present)
	}
	if settings["CustomPortalSettings.DelegationUrl"] != "" {
		t.Errorf("DelegationUrl = %v, want an empty string", settings["CustomPortalSettings.DelegationUrl"])
	}

	listed := tenantJSON(t, request(t, handler, http.MethodGet, basePath+"/settings"+apiQuery, "").Body.String())
	values, _ := listed["value"].([]any)
	if len(values) != 1 {
		t.Fatalf("settings list returned %d, want the one public entry", len(values))
	}
	// `TenantSettingsCollection` declares `value` and `nextLink` only. The
	// neighbouring access collection DOES declare `count`, so this is a real
	// difference rather than a rendering choice.
	if _, present := listed["count"]; present {
		t.Errorf("the settings collection carried a count Azure does not: %v", listed)
	}
	if _, present := listed["nextLink"]; !present {
		t.Errorf("the settings collection dropped nextLink: %v", listed)
	}

	// Read-only: the SDK publishes get and listByService and nothing else.
	for _, probe := range []struct{ method, path string }{
		{http.MethodPut, basePath + "/settings/public" + apiQuery},
		{http.MethodPatch, basePath + "/settings/public" + apiQuery},
		{http.MethodDelete, basePath + "/settings/public" + apiQuery},
		{http.MethodPut, basePath + "/settings" + apiQuery},
	} {
		if code := request(t, handler, probe.method, probe.path, `{"properties":{}}`).Code; code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", probe.method, probe.path, code)
		}
	}
	// One settingsType, and nothing nested under it.
	for _, path := range []string{
		basePath + "/settings/private" + apiQuery,
		basePath + "/settings/public/more" + apiQuery,
	} {
		if code := request(t, handler, http.MethodGet, path, "").Code; code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, code)
		}
	}
	if code := request(t, handler, http.MethodHead, basePath+"/settings"+apiQuery, "").Code; code != http.StatusMethodNotAllowed {
		t.Errorf("HEAD on the settings collection = %d, want 405", code)
	}
	head := request(t, handler, http.MethodHead, basePath+"/settings/public"+apiQuery, "")
	if head.Code != http.StatusOK || head.Header().Get("ETag") != single.Header().Get("ETag") {
		t.Errorf("HEAD = %d etag=%q, want the same tag as GET %q", head.Code, head.Header().Get("ETag"), single.Header().Get("ETag"))
	}
}

func TestTenantSettingsReportsAMissingService(t *testing.T) {
	handler, _ := testHandler(t)
	for _, path := range []string{basePath + "/settings" + apiQuery, basePath + "/settings/public" + apiQuery} {
		if code := request(t, handler, http.MethodGet, path, "").Code; code != http.StatusNotFound {
			t.Errorf("GET %s without a service = %d, want 404", path, code)
		}
	}
}

// The store failures that the conditional layer would otherwise hide.
//
// A closed store is NOT enough here, and finding that out is the point: with
// the store closed, every one of these requests already fails earlier, in
// requireScope or in the If-Match probe, so the handler's own error branches
// never run and a test asserting "not 2xx" passes without reaching them. The
// coverage gate named all four. Failing one table, and rejecting one statement,
// is what actually reaches them.
func TestTenantAccessReportsStoreFailuresItCannotSeeEarlier(t *testing.T) {
	// The service survives, so requireScope succeeds and the LIST is what fails.
	directory := t.TempDir()
	handler, st := testHandlerAt(t, directory)
	seedService(t, st)
	alongside(t, directory, "DROP TABLE tenant_access")
	listed := request(t, handler, http.MethodGet, basePath+"/tenant"+apiQuery, "")
	if listed.Code >= 200 && listed.Code < 300 {
		t.Errorf("a failing list reported %d rather than the store's error", listed.Code)
	}
	// A write whose lookup fails. The conditional layer answers 412 before the
	// handler is called at all, so this goes to the route directly, the same
	// way assertStatus does for the families that require an entity tag.
	if code := routeDirectly(t, handler, http.MethodPut, basePath+"/tenant/access"+apiQuery,
		`{"properties":{"enabled":true}}`); code >= 200 && code < 300 {
		t.Errorf("a failing lookup reported %d", code)
	}

	// Now the other half: the read succeeds and the WRITE fails, which is the
	// only arrangement that reaches the upsert's error branch.
	directory = t.TempDir()
	handler, st = testHandlerAt(t, directory)
	seedService(t, st)
	alongside(t, directory, `CREATE TRIGGER reject_tenant_access_update BEFORE UPDATE ON tenant_access
	    BEGIN SELECT RAISE(FAIL, 'rejected'); END`)
	if code := request(t, handler, http.MethodPut, basePath+"/tenant/access"+apiQuery,
		`{"properties":{"enabled":true}}`).Code; code >= 200 && code < 300 {
		t.Errorf("a failing write reported %d", code)
	}
	if code := request(t, handler, http.MethodPost, basePath+"/tenant/access/regeneratePrimaryKey"+apiQuery, "").Code; code >= 200 && code < 300 {
		t.Errorf("a failing regeneration reported %d", code)
	}
	// The refusal must not have been reported as a success in disguise: the
	// key is unchanged, because nothing was written.
	secrets := tenantJSON(t, request(t, handler, http.MethodPost, basePath+"/tenant/access/listSecrets"+apiQuery, "").Body.String())
	if secrets["primaryKey"] == "" {
		t.Error("listSecrets stopped working after a refused write")
	}
}

// routeDirectly bypasses the conditional layer, reaching a handler branch that
// an If-Match precondition would otherwise answer first.
func routeDirectly(t *testing.T, handler *Handler, method, path, body string) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer token")
	rt, ok := parse(split(req.URL.Path))
	if !ok {
		t.Fatalf("%s is not a routable path", path)
	}
	handler.routeRequest(recorder, req, rt)
	return recorder.Code
}

// alongside runs one DDL statement against the same database file the handler
// under test is using, so a specific statement can be made to fail without the
// store growing an exported hook that exists only for tests.
func alongside(t *testing.T, directory, statement string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(directory, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}
