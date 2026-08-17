package arm

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

// seedLinkFixtures creates a product, an API with one operation, and a group,
// which is the smallest set that exercises all five link families.
func seedLinkFixtures(t *testing.T, handler *Handler) {
	t.Helper()
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders"+apiQuery,
		`{"properties":{"displayName":"Orders"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/billing"+apiQuery,
		`{"properties":{"displayName":"Billing","path":"billing","protocols":["https"],"serviceUrl":"https://backend.invalid"}}`,
		http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/billing/operations/get-invoice"+apiQuery,
		`{"properties":{"displayName":"Get invoice","method":"GET","urlTemplate":"/invoice"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/groups/partners"+apiQuery,
		`{"properties":{"displayName":"Partners"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/tags/public"+apiQuery,
		`{"properties":{"displayName":"Public"}}`, http.StatusCreated)
}

func linkBody(property, target string) string {
	payload, _ := json.Marshal(map[string]any{"properties": map[string]string{property: target}})
	return string(payload)
}

func TestProductAPILinkLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)

	apiID := basePath + "/apis/billing"
	link := basePath + "/products/orders/apiLinks/primary" + apiQuery

	assertStatus(t, handler, http.MethodPut, link, linkBody("apiId", apiID), http.StatusCreated)
	// A second PUT of the same link is an update, not a create.
	assertStatus(t, handler, http.MethodPut, link, linkBody("apiId", apiID), http.StatusOK)

	response := request(t, handler, http.MethodGet, link, "")
	if response.Code != http.StatusOK {
		t.Fatalf("get link = %d: %s", response.Code, response.Body.String())
	}
	var got struct {
		Name       string            `json:"name"`
		Type       string            `json:"type"`
		Properties map[string]string `json:"properties"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "primary" || got.Properties["apiId"] != apiID {
		t.Fatalf("link = %+v", got)
	}
	if got.Type != "Microsoft.ApiManagement/service/products/apiLinks" {
		t.Fatalf("type = %q", got.Type)
	}

	assertStatus(t, handler, http.MethodHead, link, "", http.StatusOK)
	assertStatus(t, handler, http.MethodDelete, link, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodGet, link, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, link, "", http.StatusNotFound)
}

// TestLinkAndAssociationAreOneThing is the point of the whole design: the link
// surface and the older association path describe the same association, so a
// change through either is visible through the other. Two stores would pass
// every other test in this file and fail this one.
func TestLinkAndAssociationAreOneThing(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	apiID := basePath + "/apis/billing"

	// Created through the OLD path, it must appear as a link.
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders/apis/billing"+apiQuery, "", http.StatusCreated)
	links := listLinks(t, handler, basePath+"/products/orders/apiLinks"+apiQuery)
	if len(links) != 1 || links[0].Properties["apiId"] != apiID {
		t.Fatalf("association is invisible as a link: %+v", links)
	}
	// With no name of its own it is named after the target.
	if links[0].Name != "billing" {
		t.Fatalf("derived link name = %q, want billing", links[0].Name)
	}

	// Deleted through the LINK path, it must disappear from the association.
	assertStatus(t, handler, http.MethodDelete, basePath+"/products/orders/apiLinks/billing"+apiQuery, "", http.StatusNoContent)
	response := request(t, handler, http.MethodGet, basePath+"/products/orders/apis"+apiQuery, "")
	var listed struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Value) != 0 {
		t.Fatalf("link delete left the association behind: %+v", listed.Value)
	}
}

func TestProductGroupLink(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	groupID := basePath + "/groups/partners"
	link := basePath + "/products/orders/groupLinks/partners" + apiQuery

	assertStatus(t, handler, http.MethodPut, link, linkBody("groupId", groupID), http.StatusCreated)
	links := listLinks(t, handler, basePath+"/products/orders/groupLinks"+apiQuery)
	if len(links) != 1 || links[0].Properties["groupId"] != groupID {
		t.Fatalf("group links = %+v", links)
	}
	assertStatus(t, handler, http.MethodDelete, link, "", http.StatusNoContent)
}

// TestTagLinksAreFilteredByKind guards the one thing a shared tag association
// can get wrong: a tag holds APIs, operations and products at once, and each
// collection must publish only its own kind.
func TestTagLinksAreFilteredByKind(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)

	apiID := basePath + "/apis/billing"
	operationID := basePath + "/apis/billing/operations/get-invoice"
	productID := basePath + "/products/orders"

	assertStatus(t, handler, http.MethodPut, basePath+"/tags/public/apiLinks/a"+apiQuery,
		linkBody("apiId", apiID), http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/tags/public/operationLinks/o"+apiQuery,
		linkBody("operationId", operationID), http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/tags/public/productLinks/p"+apiQuery,
		linkBody("productId", productID), http.StatusCreated)

	for _, probe := range []struct {
		segment, property, want string
	}{
		{"apiLinks", "apiId", apiID},
		{"operationLinks", "operationId", operationID},
		{"productLinks", "productId", productID},
	} {
		links := listLinks(t, handler, basePath+"/tags/public/"+probe.segment+apiQuery)
		if len(links) != 1 {
			t.Fatalf("%s = %d links, want 1: %+v", probe.segment, len(links), links)
		}
		if links[0].Properties[probe.property] != probe.want {
			t.Fatalf("%s carried %+v", probe.segment, links[0].Properties)
		}
	}
}

func TestLinkValidation(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	apiID := basePath + "/apis/billing"

	// A missing property is a bad request, and so is a target that does not
	// exist: neither is a missing route.
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders/apiLinks/x"+apiQuery,
		`{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders/apiLinks/x"+apiQuery,
		linkBody("apiId", basePath+"/apis/absent"), http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders/apiLinks/x"+apiQuery,
		`{`, http.StatusBadRequest)

	// One association is one link. Naming the same target under a new URL
	// RENAMES the link rather than creating a second identity for it: the new
	// URL is a 201 because nothing was there, the old name stops resolving, and
	// the collection still holds exactly one entry. Two links pointing at one
	// association would mean deleting either leaves the other dangling.
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders/apiLinks/first"+apiQuery,
		linkBody("apiId", apiID), http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders/apiLinks/second"+apiQuery,
		linkBody("apiId", apiID), http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, basePath+"/products/orders/apiLinks/first"+apiQuery, "", http.StatusNotFound)
	if links := listLinks(t, handler, basePath+"/products/orders/apiLinks"+apiQuery); len(links) != 1 {
		t.Fatalf("rename produced %d links, want 1: %+v", len(links), links)
	}

	// A name already used by a DIFFERENT target is refused.
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/shipping"+apiQuery,
		`{"properties":{"displayName":"Shipping","path":"shipping","protocols":["https"],"serviceUrl":"https://backend.invalid"}}`,
		http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders/apiLinks/second"+apiQuery,
		linkBody("apiId", basePath+"/apis/shipping"), http.StatusBadRequest)

	// The parent must exist.
	assertStatus(t, handler, http.MethodGet, basePath+"/products/absent/apiLinks"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/tags/absent/apiLinks"+apiQuery, "", http.StatusNotFound)

	// A collection takes GET only.
	assertStatus(t, handler, http.MethodPost, basePath+"/products/orders/apiLinks"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPatch, basePath+"/products/orders/apiLinks/first"+apiQuery, "", http.StatusMethodNotAllowed)
}

func TestLinkNameCollisionIsDeterministic(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/shipping"+apiQuery,
		`{"properties":{"displayName":"Shipping","path":"shipping","protocols":["https"],"serviceUrl":"https://backend.invalid"}}`,
		http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, basePath+"/apis/shipping/operations/get-invoice"+apiQuery,
		`{"properties":{"displayName":"Get invoice","method":"GET","urlTemplate":"/invoice"}}`, http.StatusCreated)

	// Two operations called `get-invoice` under different APIs, both tagged
	// through the older path so neither carries a chosen name.
	for _, api := range []string{"billing", "shipping"} {
		assertStatus(t, handler, http.MethodPut,
			basePath+"/apis/"+api+"/operations/get-invoice/tags/public"+apiQuery, "", http.StatusCreated)
	}
	links := listLinks(t, handler, basePath+"/tags/public/operationLinks"+apiQuery)
	if len(links) != 2 {
		t.Fatalf("want 2 operation links, got %d: %+v", len(links), links)
	}
	names := map[string]bool{links[0].Name: true, links[1].Name: true}
	if len(names) != 2 {
		t.Fatalf("colliding names were not disambiguated: %+v", links)
	}
	// Disambiguation must reach the API NAME, not the literal `operations`
	// segment, which would be identical for both and disambiguate nothing.
	if !names["get-invoice"] || !names["shipping-get-invoice"] {
		t.Fatalf("derived names = %+v, want get-invoice and shipping-get-invoice", names)
	}
}

func TestWorkspaceLinkType(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team"+apiQuery,
		`{"properties":{"displayName":"Team"}}`, http.StatusCreated)
	workspace := basePath + "/workspaces/team"
	assertStatus(t, handler, http.MethodPut, workspace+"/products/orders"+apiQuery,
		`{"properties":{"displayName":"Orders"}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodPut, workspace+"/apis/billing"+apiQuery,
		`{"properties":{"displayName":"Billing","path":"billing","protocols":["https"],"serviceUrl":"https://backend.invalid"}}`,
		http.StatusCreated)

	link := workspace + "/products/orders/apiLinks/primary" + apiQuery
	assertStatus(t, handler, http.MethodPut, link, linkBody("apiId", workspace+"/apis/billing"), http.StatusCreated)

	response := request(t, handler, http.MethodGet, link, "")
	var got struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// A workspace link is a different ARM type, not the same type relocated.
	if got.Type != "Microsoft.ApiManagement/service/workspaces/products/apiLinks" {
		t.Fatalf("workspace link type = %q", got.Type)
	}
}

func TestTaggedResourceKindIgnoresUnknownScopes(t *testing.T) {
	if kind := taggedResourceKind(basePath + "/backends/legacy"); kind != "" {
		t.Fatalf("unexpected kind %q", kind)
	}
}

func TestEffectiveLinkNamesPrefersStoredNames(t *testing.T) {
	targets := []string{"/a/apis/one", "/a/apis/two"}
	names := effectiveLinkNames(targets, map[string]string{"/a/apis/one": "chosen"})
	if names["/a/apis/one"] != "chosen" || names["/a/apis/two"] != "two" {
		t.Fatalf("names = %+v", names)
	}
}

func TestSetLinkNameOnMissingAssociation(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	_ = handler
	if err := st.SetLinkName(0, basePath+"/products/orders", basePath+"/apis/absent", "x"); err == nil {
		t.Fatal("naming a link on an association that does not exist should fail")
	}
}

func TestProductLinkSurfaceUsesModelIDs(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	product := model.Product{ServiceID: basePath, Name: "orders"}
	surface, err := handler.productLinkSurface(product, "groupLinks")
	if err != nil {
		t.Fatal(err)
	}
	if surface.property != "groupId" {
		t.Fatalf("surface = %+v", surface)
	}
}

// effectiveLinkNamesFor reports the names a surface currently publishes.
func effectiveLinkNamesFor(t *testing.T, handler *Handler, surface linkSurface) map[string]string {
	t.Helper()
	stored, err := handler.Store.LinkNames(surface.kind, surface.parentID)
	if err != nil {
		t.Fatal(err)
	}
	return effectiveLinkNames(surface.targets, stored)
}

type wireLink struct {
	Name       string            `json:"name"`
	Properties map[string]string `json:"properties"`
}

func listLinks(t *testing.T, handler http.Handler, path string) []wireLink {
	t.Helper()
	response := request(t, handler, http.MethodGet, path, "")
	if response.Code != http.StatusOK {
		t.Fatalf("list %s = %d: %s", path, response.Code, response.Body.String())
	}
	var listed struct {
		Value []wireLink `json:"value"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	return listed.Value
}

// TestLinkStoreFailuresAreReported drives every link path against a closed
// store. The point is that a broken store is reported, never mistaken for an
// empty collection or an absent link: "no links" and "cannot tell" must not
// look the same to a caller.
func TestLinkStoreFailuresAreReported(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	product := model.Product{ServiceID: basePath, Name: "orders"}
	tag := model.Tag{ServiceID: basePath, Name: "public"}
	apiID := basePath + "/apis/billing"

	// Surfaces built while the store still works, so the failure lands on the
	// link operation rather than on constructing the surface.
	surface, err := handler.productLinkSurface(product, "apiLinks")
	if err != nil {
		t.Fatal(err)
	}
	surface.armType = "Microsoft.ApiManagement/service/products/apiLinks"

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	for _, probe := range []struct {
		name, segment string
	}{
		{"product api links", "apiLinks"},
		{"product group links", "groupLinks"},
	} {
		if _, err := handler.productLinkSurface(product, probe.segment); err == nil {
			t.Errorf("%s: building a surface on a closed store succeeded", probe.name)
		}
	}
	if _, err := handler.tagLinkSurface(tag, "apiLinks"); err == nil {
		t.Error("building a tag surface on a closed store succeeded")
	}

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/", strings.NewReader(linkBody("apiId", apiID)))
		request.Header.Set("Content-Type", "application/json")
		handler.linkRoute(recorder, request, surface, "primary")
		if recorder.Code < 400 {
			t.Errorf("%s against a failed store returned %d", method, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	handler.linkRoute(recorder, httptest.NewRequest(http.MethodGet, "/", nil), surface, "")
	if recorder.Code < 400 {
		t.Errorf("listing against a failed store returned %d", recorder.Code)
	}
}

// TestLinkRouteReportsVerificationFailures covers the case where checking the
// target itself fails for a reason other than the target being absent.
func TestLinkRouteReportsVerificationFailures(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	product := model.Product{ServiceID: basePath, Name: "orders"}
	surface, err := handler.productLinkSurface(product, "apiLinks")
	if err != nil {
		t.Fatal(err)
	}
	surface.armType = "Microsoft.ApiManagement/service/products/apiLinks"
	surface.verify = func(string) error { return errors.New("verification exploded") }

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(linkBody("apiId", basePath+"/apis/billing")))
	request.Header.Set("Content-Type", "application/json")
	handler.linkRoute(recorder, request, surface, "primary")
	if recorder.Code < 400 {
		t.Fatalf("a failing verification returned %d", recorder.Code)
	}

	// An attach that fails must be reported too, not silently named.
	surface.verify = func(string) error { return nil }
	surface.attach = func(string) error { return errors.New("attach exploded") }
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPut, "/", strings.NewReader(linkBody("apiId", basePath+"/apis/billing")))
	request.Header.Set("Content-Type", "application/json")
	handler.linkRoute(recorder, request, surface, "primary")
	if recorder.Code < 400 {
		t.Fatalf("a failing attach returned %d", recorder.Code)
	}
	_ = st
}

// TestLinkActivationAndDetachFailures covers the two ways a link change can
// fail AFTER the request itself is valid: the association write is rejected, or
// republishing the gateway snapshot fails. Neither may report success, because
// a caller that got 2xx will assume the runtime now reflects the change.
func TestLinkActivationAndDetachFailures(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	apiID := basePath + "/apis/billing"
	link := basePath + "/products/orders/apiLinks/primary" + apiQuery

	handler.Activate = func() error { return errors.New("activation exploded") }
	assertStatus(t, handler, http.MethodPut, link, linkBody("apiId", apiID), http.StatusBadRequest)

	// NOTE, and it is deliberate rather than overlooked: the association is
	// written BEFORE the gateway snapshot is republished, so a failed
	// activation reports 400 with the link already stored. The next PUT is
	// therefore an update, not a create. This matches every other association
	// handler in this package (see the product-API path), and making links
	// alone roll back would leave two rules for the same situation.
	handler.Activate = nil
	assertStatus(t, handler, http.MethodPut, link, linkBody("apiId", apiID), http.StatusOK)
	handler.Activate = func() error { return errors.New("activation exploded") }
	assertStatus(t, handler, http.MethodDelete, link, "", http.StatusInternalServerError)
	handler.Activate = nil

	// A detach that fails for a reason other than "already gone" is reported.
	product := model.Product{ServiceID: basePath, Name: "orders"}
	surface, err := handler.productLinkSurface(product, "apiLinks")
	if err != nil {
		t.Fatal(err)
	}
	surface.armType = "Microsoft.ApiManagement/service/products/apiLinks"
	// The failed-activation DELETE above still detached, so the link is gone:
	// put it back before probing the detach failure. Without this the probe
	// asserts a 404 and never reaches the detach at all, which is how the
	// first version of this test passed while covering nothing.
	assertStatus(t, handler, http.MethodPut, link, linkBody("apiId", apiID), http.StatusCreated)
	surface, err = handler.productLinkSurface(product, "apiLinks")
	if err != nil {
		t.Fatal(err)
	}
	surface.armType = "Microsoft.ApiManagement/service/products/apiLinks"
	if _, ok := linkNameOwner(effectiveLinkNamesFor(t, handler, surface), "primary"); !ok {
		t.Fatal("fixture lost the link before the detach probe")
	}
	surface.detach = func(string) error { return errors.New("detach exploded") }
	recorder := httptest.NewRecorder()
	handler.linkRoute(recorder, httptest.NewRequest(http.MethodDelete, "/", nil), surface, "primary")
	if recorder.Code != http.StatusConflict {
		t.Fatalf("a failing detach returned %d, want 409: %s", recorder.Code, recorder.Body.String())
	}
}

// TestTagLinkDetachRemovesTheTag exercises the tag surface's own detach, which
// is a different closure from the product one.
func TestTagLinkDetachRemovesTheTag(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	link := basePath + "/tags/public/apiLinks/a" + apiQuery

	assertStatus(t, handler, http.MethodPut, link, linkBody("apiId", basePath+"/apis/billing"), http.StatusCreated)
	assertStatus(t, handler, http.MethodDelete, link, "", http.StatusNoContent)
	if links := listLinks(t, handler, basePath+"/tags/public/apiLinks"+apiQuery); len(links) != 0 {
		t.Fatalf("tag link survived deletion: %+v", links)
	}
}

// TestLinkSurfaceQueryFailures drives the paths where the PARENT resolves but
// the association query behind the surface does not, and where naming the link
// is rejected after the association was written. Both are reached through the
// router rather than by calling the helpers, so the dispatch wiring is covered
// with them.
func TestLinkSurfaceQueryFailures(t *testing.T) {
	dir := t.TempDir()
	handler, st := testHandlerAt(t, dir)
	seedService(t, st)
	seedLinkFixtures(t, handler)
	apiID := basePath + "/apis/billing"

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Naming a link fails while the association write succeeds.
	if _, err := db.Exec(
		`CREATE TRIGGER reject_link_name BEFORE UPDATE ON product_apis BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, basePath+"/products/orders/apiLinks/primary"+apiQuery,
		linkBody("apiId", apiID), http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_link_name`); err != nil {
		t.Fatal(err)
	}

	// The product exists, but the association query behind its links does not.
	if _, err := db.Exec(`DROP TABLE product_apis`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/products/orders/apiLinks"+apiQuery, "", http.StatusConflict)

	// Same for a tag, whose surface reads a different table.
	if _, err := db.Exec(`DROP TABLE resource_tags`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/tags/public/apiLinks"+apiQuery, "", http.StatusConflict)
}
