package arm

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const providerPath = "/subscriptions/sub/providers/Microsoft.ApiManagement"

func TestPolicyRestrictionRoundTrips(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/policyRestrictions/pr1" + apiQuery

	// 201 on create and 200 on replace. Unlike tenant access, this PUT declares
	// both, so the distinction is real and a client may branch on it.
	if code := request(t, handler, http.MethodPut, path, `{"properties":{"scope":"/apis","requireBase":"true"}}`).Code; code != http.StatusCreated {
		t.Fatalf("first PUT = %d, want 201", code)
	}
	if code := request(t, handler, http.MethodPut, path, `{"properties":{"scope":"/apis","requireBase":"true"}}`).Code; code != http.StatusOK {
		t.Fatalf("second PUT = %d, want 200", code)
	}

	document := tenantJSON(t, request(t, handler, http.MethodGet, path, "").Body.String())
	if document["type"] != "Microsoft.ApiManagement/service/policyRestrictions" {
		t.Errorf("type = %v", document["type"])
	}
	if document["name"] != "pr1" || !strings.HasSuffix(document["id"].(string), "/policyRestrictions/pr1") {
		t.Errorf("id/name = %v/%v", document["id"], document["name"])
	}
	properties := tenantProperties(t, request(t, handler, http.MethodGet, path, "").Body.String())
	if properties["scope"] != "/apis" {
		t.Errorf("scope = %v", properties["scope"])
	}
	// The STRING "true", not the boolean. `PolicyRestrictionRequireBase` is a
	// string enum and the generated client maps the field as a String, so a
	// JSON boolean is a different value than the contract names.
	if got, ok := properties["requireBase"].(string); !ok || got != "true" {
		t.Errorf("requireBase = %#v, want the string \"true\"", properties["requireBase"])
	}

	listed := tenantJSON(t, request(t, handler, http.MethodGet, basePath+"/policyRestrictions"+apiQuery, "").Body.String())
	values, _ := listed["value"].([]any)
	if len(values) != 1 {
		t.Fatalf("list returned %d", len(values))
	}
	// `PolicyRestrictionCollection` declares `value` and `nextLink` only, the
	// same asymmetry the tenant settings collection has.
	if _, present := listed["count"]; present {
		t.Errorf("the collection carried a count Azure does not: %v", listed)
	}

	head := request(t, handler, http.MethodHead, path, "")
	if head.Code != http.StatusOK || head.Header().Get("ETag") == "" {
		t.Errorf("HEAD = %d etag=%q", head.Code, head.Header().Get("ETag"))
	}
	if code := request(t, handler, http.MethodDelete, path, "").Code; code != http.StatusNoContent {
		t.Errorf("DELETE = %d, want 204", code)
	}
	if code := request(t, handler, http.MethodGet, path, "").Code; code != http.StatusNotFound {
		t.Errorf("GET after delete = %d, want 404", code)
	}
	// Deleting what is already gone is not an error, matching the rest of the
	// provider.
	if code := request(t, handler, http.MethodDelete, path, "").Code; code != http.StatusNoContent {
		t.Errorf("second DELETE = %d, want 204", code)
	}
}

// PATCH is a MERGE and PUT is a REPLACE, and Azure's own examples are what say
// so: the update example sends `scope` alone and its response still carries the
// `requireBase` the create set.
func TestPolicyRestrictionUpdateMergesAndPutReplaces(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/policyRestrictions/pr1" + apiQuery
	request(t, handler, http.MethodPut, path, `{"properties":{"scope":"/apis","requireBase":"true"}}`)

	patched := tenantProperties(t, request(t, handler, http.MethodPatch, path, `{"properties":{"scope":"/apis/two"}}`).Body.String())
	if patched["scope"] != "/apis/two" {
		t.Errorf("PATCH did not apply scope: %v", patched)
	}
	if patched["requireBase"] != "true" {
		t.Errorf("PATCH dropped a field it did not mention: %v", patched)
	}

	// PUT omitting requireBase falls back to the contract's own default
	// (`defaultValue: "false"` on the generated mapper) rather than to the
	// stored value, because a replace that silently keeps old fields is not a
	// replace.
	replaced := tenantProperties(t, request(t, handler, http.MethodPut, path, `{"properties":{"scope":"/apis/two"}}`).Body.String())
	if replaced["requireBase"] != "false" {
		t.Errorf("PUT kept a field the caller omitted: %v", replaced)
	}

	// PATCH on something that does not exist is not an implicit create. Through
	// the full stack a caller sees 412, because If-Match is required here and
	// `*` cannot match a resource that is not there; the handler's own answer
	// underneath is the 404, and both are asserted so that neither can quietly
	// become a create.
	if code := request(t, handler, http.MethodPatch, basePath+"/policyRestrictions/never"+apiQuery,
		`{"properties":{"scope":"/x"}}`).Code; code != http.StatusPreconditionFailed {
		t.Errorf("PATCH of a missing restriction = %d, want 412", code)
	}
	if code := routeDirectly(t, handler, http.MethodPatch, basePath+"/policyRestrictions/never"+apiQuery,
		`{"properties":{"scope":"/x"}}`); code != http.StatusNotFound {
		t.Errorf("the handler's own answer for a missing restriction = %d, want 404", code)
	}
	if code := request(t, handler, http.MethodGet, basePath+"/policyRestrictions/never"+apiQuery, "").Code; code != http.StatusNotFound {
		t.Errorf("a refused PATCH created something: GET = %d", code)
	}
}

func TestPolicyRestrictionRequiresIfMatchOnUpdateOnly(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/policyRestrictions/pr1" + apiQuery
	request(t, handler, http.MethodPut, path, `{"properties":{"scope":"/apis"}}`)

	// Required on PATCH (`ifMatch1`), optional on PUT and DELETE (`ifMatch`).
	if !requiresIfMatch(route{Tail: []string{"policyRestrictions", "pr1"}}, http.MethodPatch) {
		t.Error("PATCH does not require If-Match")
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if requiresIfMatch(route{Tail: []string{"policyRestrictions", "pr1"}}, method) {
			t.Errorf("%s requires If-Match, but the contract marks it optional", method)
		}
	}
	recorder := httptest.NewRecorder()
	missing := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(`{"properties":{"scope":"/x"}}`))
	missing.Header.Set("Authorization", "Bearer token")
	handler.ServeHTTP(recorder, missing)
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("PATCH without If-Match = %d, want 400", recorder.Code)
	}
	stale := conditionalRequest(t, handler, http.MethodPatch, path, `{"properties":{"scope":"/x"}}`, "If-Match", `"stale"`)
	if stale.Code != http.StatusPreconditionFailed {
		t.Errorf("a stale If-Match = %d, want 412", stale.Code)
	}
}

func TestPolicyRestrictionRejectsWhatTheContractCannotExpress(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/policyRestrictions/pr1" + apiQuery

	// `requireBase` has exactly two members. A JSON boolean is the interesting
	// case, because it is what a caller reaching for the obvious type sends and
	// it decodes to nothing here.
	for _, body := range []string{
		`{"properties":{"scope":"/apis","requireBase":"maybe"}}`,
		`{"properties":{"scope":"/apis","requireBase":""}}`,
	} {
		if code := request(t, handler, http.MethodPut, path, body).Code; code != http.StatusBadRequest {
			t.Errorf("PUT %s = %d, want 400", body, code)
		}
	}
	if code := request(t, handler, http.MethodPut, path, "{").Code; code != http.StatusBadRequest {
		t.Errorf("a malformed body = %d, want 400", code)
	}
	for _, probe := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPut, basePath + "/policyRestrictions" + apiQuery, http.StatusMethodNotAllowed},
		{http.MethodPost, basePath + "/policyRestrictions/pr1" + apiQuery, http.StatusMethodNotAllowed},
		{http.MethodGet, basePath + "/policyRestrictions/pr1/more" + apiQuery, http.StatusNotFound},
		{http.MethodGet, basePath + "/policyRestrictions/" + strings.Repeat("x", 81) + apiQuery, http.StatusBadRequest},
	} {
		if code := request(t, handler, probe.method, probe.path, `{"properties":{}}`).Code; code != probe.want {
			t.Errorf("%s %s = %d, want %d", probe.method, probe.path, code, probe.want)
		}
	}
}

func TestPolicyRestrictionReportsStoreFailures(t *testing.T) {
	handler, _ := testHandler(t)
	// No service, so the write has no scope to hang off. The lookup answers
	// "not found" cleanly and it is the WRITE that fails on the foreign key.
	if code := request(t, handler, http.MethodPut, basePath+"/policyRestrictions/pr1"+apiQuery,
		`{"properties":{"scope":"/apis"}}`).Code; code >= 200 && code < 300 {
		t.Errorf("an unparented write reported %d", code)
	}

	handler, st := testHandler(t)
	seedService(t, st)
	request(t, handler, http.MethodPut, basePath+"/policyRestrictions/pr1"+apiQuery, `{"properties":{"scope":"/apis"}}`)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct{ method, path, body string }{
		{http.MethodGet, basePath + "/policyRestrictions" + apiQuery, ""},
		{http.MethodGet, basePath + "/policyRestrictions/pr1" + apiQuery, ""},
		{http.MethodPut, basePath + "/policyRestrictions/pr1" + apiQuery, `{"properties":{"scope":"/x"}}`},
		{http.MethodDelete, basePath + "/policyRestrictions/pr1" + apiQuery, ""},
	} {
		if code := request(t, handler, probe.method, probe.path, probe.body).Code; code >= 200 && code < 300 {
			t.Errorf("%s %s reported %d against a closed store", probe.method, probe.path, code)
		}
	}
}

// checkNameAvailability answers for real: it validates against Microsoft's own
// `serviceName` constraint and then looks in the store.
func TestCheckNameAvailabilityAnswersAllThreeReasons(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	ask := func(name string) map[string]any {
		t.Helper()
		recorder := request(t, handler, http.MethodPost, providerPath+"/checkNameAvailability"+apiQuery,
			`{"name":`+quote(name)+`}`)
		if recorder.Code != http.StatusOK {
			t.Fatalf("checkNameAvailability(%q) = %d: %s", name, recorder.Code, recorder.Body.String())
		}
		return tenantJSON(t, recorder.Body.String())
	}

	free := ask("brand-new-service")
	if free["nameAvailable"] != true || free["reason"] != "Valid" {
		t.Errorf("an unused name = %v", free)
	}
	taken := ask("svc")
	if taken["nameAvailable"] != false || taken["reason"] != "AlreadyExists" {
		t.Errorf("the seeded service's name = %v", taken)
	}
	// Case-insensitively taken, because the name becomes a DNS label.
	if upper := ask("SVC"); upper["nameAvailable"] != false {
		t.Errorf("the seeded name in another case = %v", upper)
	}

	// Every clause of Microsoft's pattern, one probe each, so a loosened rule
	// shows up as a specific failure rather than as "some name got through".
	for _, name := range []string{
		"",                      // minLength 1
		strings.Repeat("a", 51), // maxLength 50
		"1starts-with-a-digit",  // must start with a letter
		"-starts-with-a-hyphen", //
		"ends-with-a-hyphen-",   // must end alphanumeric
		"has spaces",            // letters, digits and hyphens only
		"has_underscore",        //
		"has.dot",               //
	} {
		invalid := ask(name)
		if invalid["nameAvailable"] != false || invalid["reason"] != "Invalid" {
			t.Errorf("checkNameAvailability(%q) = %v, want Invalid", name, invalid)
		}
		if invalid["message"] == nil || invalid["message"] == "" {
			t.Errorf("checkNameAvailability(%q) gave no message", name)
		}
	}
	// The boundary on the allowed side, so the length rule is not simply
	// rejecting everything long.
	if long := ask(strings.Repeat("a", 50)); long["nameAvailable"] != true {
		t.Errorf("a 50-character name = %v, want available", long)
	}

	if code := request(t, handler, http.MethodPost, providerPath+"/checkNameAvailability"+apiQuery, "{").Code; code != http.StatusBadRequest {
		t.Errorf("a malformed body = %d, want 400", code)
	}
	if code := request(t, handler, http.MethodGet, providerPath+"/checkNameAvailability"+apiQuery, "").Code; code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", code)
	}
}

// A name is unavailable if it is taken in ANY subscription. The service name
// becomes `<name>.azure-api.net`, and DNS has no idea whose subscription it is,
// so a per-subscription check would report a name free that a create refuses.
func TestCheckNameAvailabilityIsGlobalAcrossSubscriptions(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	recorder := request(t, handler, http.MethodPost,
		"/subscriptions/a-different-subscription/providers/Microsoft.ApiManagement/checkNameAvailability"+apiQuery,
		`{"name":"svc"}`)
	document := tenantJSON(t, recorder.Body.String())
	if document["nameAvailable"] != false || document["reason"] != "AlreadyExists" {
		t.Fatalf("a name taken in another subscription = %v", document)
	}
}

// A failing lookup must not report the name FREE. The caller's next move is to
// create, and the create is what fails.
func TestCheckNameAvailabilityDoesNotReportFreeWhenItCannotLook(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	document := tenantJSON(t, request(t, handler, http.MethodPost, providerPath+"/checkNameAvailability"+apiQuery,
		`{"name":"brand-new-service"}`).Body.String())
	if document["nameAvailable"] != false {
		t.Fatalf("a failing lookup reported the name available: %v", document)
	}
}

// The identifier is published in a DNS TXT record and checked later, so it must
// be the same value every time. One that changed per call would be useless in
// the only workflow it exists for.
func TestDomainOwnershipIdentifierIsStablePerSubscription(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	read := func(path string) string {
		t.Helper()
		recorder := request(t, handler, http.MethodPost, path+"/getDomainOwnershipIdentifier"+apiQuery, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("getDomainOwnershipIdentifier = %d: %s", recorder.Code, recorder.Body.String())
		}
		value, _ := tenantJSON(t, recorder.Body.String())["domainOwnershipIdentifier"].(string)
		return value
	}
	first := read(providerPath)
	if first == "" {
		t.Fatal("no identifier returned")
	}
	if second := read(providerPath); second != first {
		t.Errorf("the identifier moved between calls: %q then %q", first, second)
	}
	// And it is DERIVED from the subscription, so two subscriptions differ.
	if other := read("/subscriptions/another/providers/Microsoft.ApiManagement"); other == first {
		t.Error("two subscriptions share one domain ownership identifier")
	}
	if code := request(t, handler, http.MethodGet, providerPath+"/getDomainOwnershipIdentifier"+apiQuery, "").Code; code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", code)
	}
}

// The redirect URI points at THIS emulator's portal and resolves. Azure's shape
// (`https://<service>.portal.azure-api.net/signin-sso?token=...`) would hand a
// caller a link to a service that does not exist.
func TestSsoTokenReturnsAResolvableRedirect(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	recorder := request(t, handler, http.MethodPost, basePath+"/getssotoken"+apiQuery, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("getssotoken = %d: %s", recorder.Code, recorder.Body.String())
	}
	uri, _ := tenantJSON(t, recorder.Body.String())["redirectUri"].(string)
	if !strings.Contains(uri, "/_emulator/portal/") || !strings.Contains(uri, "token=") {
		t.Fatalf("redirectUri = %q, want this emulator's portal carrying a token", uri)
	}
	if !strings.Contains(uri, "example.com") {
		t.Errorf("redirectUri = %q, want the host the request arrived on", uri)
	}
	// A fresh token per call, so it is not a constant dressed up as one.
	second, _ := tenantJSON(t, request(t, handler, http.MethodPost, basePath+"/getssotoken"+apiQuery, "").Body.String())["redirectUri"].(string)
	if second == uri {
		t.Error("two calls returned the same token")
	}

	if code := request(t, handler, http.MethodGet, basePath+"/getssotoken"+apiQuery, "").Code; code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", code)
	}
	if code := request(t, handler, http.MethodPost, basePath+"/getssotoken/more"+apiQuery, "").Code; code != http.StatusNotFound {
		t.Errorf("a deeper path = %d, want 404", code)
	}
	handler, _ = testHandler(t)
	if code := request(t, handler, http.MethodPost, basePath+"/getssotoken"+apiQuery, "").Code; code != http.StatusNotFound {
		t.Errorf("a token for a service that does not exist = %d, want 404", code)
	}
}

// The four ApiManagementService operations that are NOT implemented must stay
// 404, not answer a fabricated success. This is a test that something is
// ABSENT, and it is here so that adding one of them is a deliberate act that
// updates this list rather than a quiet change in what the emulator claims.
func TestUnimplementedServiceOperationsStayAbsent(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	for _, action := range []string{"backup", "restore", "migrateToStv2", "applynetworkconfigurationupdates"} {
		if code := request(t, handler, http.MethodPost, basePath+"/"+action+apiQuery, "{}").Code; code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404 until it is really implemented", action, code)
		}
	}
}

func quote(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	return `"` + strings.ReplaceAll(escaped, `"`, `\"`) + `"`
}

// A stored ARM document whose `properties` is not an object must still project
// a resource a client can read. The projection rebuilds it rather than writing
// the two fields into a string and producing something no client can parse.
func TestPolicyRestrictionProjectionRebuildsAMalformedProperties(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	path := basePath + "/policyRestrictions/pr1" + apiQuery
	if code := request(t, handler, http.MethodPut, path, `{"properties":"not an object"}`).Code; code != http.StatusCreated {
		t.Fatalf("PUT = %d", code)
	}
	properties := tenantProperties(t, request(t, handler, http.MethodGet, path, "").Body.String())
	if properties["requireBase"] != "false" || properties["scope"] != "" {
		t.Errorf("properties = %v, want a rebuilt object carrying the defaults", properties)
	}
}
