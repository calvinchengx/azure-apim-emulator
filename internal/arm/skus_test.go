package arm

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func premiumService(capacity string) string {
	return `{"location":"local","sku":{"name":"Premium","capacity":` + capacity +
		`},"properties":{"publisherName":"Contoso","publisherEmail":"ops@contoso.test"}}`
}

// A tier is not just a price: it bounds how far the service scales. Accepting a
// capacity Azure refuses would let a caller build a topology locally that does
// not exist.
func TestSKUCapacityRules(t *testing.T) {
	handler, _ := testHandler(t)
	for _, test := range []struct {
		name, body string
		want       int
	}{
		{"unknown tier", `{"location":"local","sku":{"name":"Titanium","capacity":1},"properties":{"publisherName":"a","publisherEmail":"b@c.test"}}`, http.StatusBadRequest},
		{"developer scaled", `{"location":"local","sku":{"name":"Developer","capacity":3},"properties":{"publisherName":"a","publisherEmail":"b@c.test"}}`, http.StatusBadRequest},
		{"premium over ceiling", premiumService("99"), http.StatusBadRequest},
		{"premium at ceiling", premiumService("12"), http.StatusCreated},
	} {
		assertStatus(t, handler, http.MethodPut, basePath+apiQuery, test.body, test.want)
	}

	// Consumption runs zero units, so a capacity of 1 is wrong there while
	// being right everywhere else. The two refusals read differently, because
	// "cannot be scaled" and "out of range" are different problems.
	handler2, _ := testHandler(t)
	got := request(t, handler2, http.MethodPut, basePath+apiQuery,
		`{"location":"local","sku":{"name":"Consumption","capacity":1},"properties":{"publisherName":"a","publisherEmail":"b@c.test"}}`)
	if got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "cannot be scaled") {
		t.Fatalf("consumption capacity = %d %s", got.Code, got.Body.String())
	}
	assertStatus(t, handler2, http.MethodPut, basePath+apiQuery,
		`{"location":"local","sku":{"name":"Consumption","capacity":0},"properties":{"publisherName":"a","publisherEmail":"b@c.test"}}`,
		http.StatusCreated)
}

// Multi-region is Premium only, and each extra region carries its own SKU.
func TestAdditionalLocations(t *testing.T) {
	handler, _ := testHandler(t)
	body := func(sku string, locations string) string {
		return `{"location":"local","sku":` + sku + `,"properties":{"publisherName":"a","publisherEmail":"b@c.test",` +
			`"additionalLocations":[` + locations + `]}}`
	}
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery,
		body(`{"name":"Developer","capacity":1}`, `{"location":"westeurope","sku":{"name":"Developer","capacity":1}}`),
		http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery,
		body(`{"name":"Premium","capacity":1}`, `{"sku":{"name":"Premium","capacity":1}}`),
		http.StatusBadRequest)
	// A region's own SKU is validated too, or a caller could ask for a topology
	// whose second region cannot exist.
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery,
		body(`{"name":"Premium","capacity":1}`, `{"location":"westeurope","sku":{"name":"Developer","capacity":9}}`),
		http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery,
		body(`{"name":"Premium","capacity":1}`, `{"location":"westeurope","sku":{"name":"Premium","capacity":2}}`),
		http.StatusCreated)

	got := request(t, handler, http.MethodGet, basePath+apiQuery, "").Body.String()
	// Each region reports where it is reachable, which is what a caller uses to
	// address it.
	if !strings.Contains(got, "westeurope.regional.azure-api.localhost") {
		t.Fatalf("gatewayRegionalUrl missing: %s", got)
	}
	if !strings.Contains(got, `"disableGateway":false`) {
		t.Fatalf("disableGateway missing: %s", got)
	}

	regions := request(t, handler, http.MethodGet, basePath+"/regions"+apiQuery, "")
	var listing struct {
		Value []struct {
			Name           string `json:"name"`
			IsMasterRegion bool   `json:"isMasterRegion"`
		} `json:"value"`
	}
	if err := json.Unmarshal(regions.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Value) != 2 || !listing.Value[0].IsMasterRegion || listing.Value[1].IsMasterRegion {
		t.Fatalf("regions = %s", regions.Body.String())
	}
}

func TestSKUCatalogues(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)

	available := request(t, handler, http.MethodGet, basePath+"/skus"+apiQuery, "").Body.String()
	// A dedicated service is not offered Consumption: the move always fails, so
	// listing it would be an offer that cannot be taken.
	if strings.Contains(available, "Consumption") {
		t.Fatalf("a dedicated service was offered Consumption: %s", available)
	}
	if !strings.Contains(available, "Premium") || !strings.Contains(available, `"scaleType":"None"`) {
		t.Fatalf("available skus = %s", available)
	}

	catalogue := request(t, handler, http.MethodGet, "/subscriptions/sub/providers/Microsoft.ApiManagement/skus"+apiQuery, "").Body.String()
	// The subscription-wide catalogue lists everything, including Consumption,
	// and says what each tier can do.
	for _, want := range []string{"Consumption", "Premium", "workspaces", "self-hosted-gateway"} {
		if !strings.Contains(catalogue, want) {
			t.Fatalf("catalogue missing %q: %s", want, catalogue)
		}
	}
	assertStatus(t, handler, http.MethodPost, "/subscriptions/sub/providers/Microsoft.ApiManagement/skus"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, basePath+"/skus"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, basePath+"/regions"+apiQuery, "", http.StatusMethodNotAllowed)
}

func TestSKUAndRegionRoutesRequireService(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodGet, basePath+"/skus"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/regions"+apiQuery, "", http.StatusNotFound)
}

// A Consumption service is offered only Consumption, which is the other half of
// the exclusion above.
func TestConsumptionServiceIsNotOfferedDedicatedTiers(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery,
		`{"location":"local","sku":{"name":"Consumption","capacity":0},"properties":{"publisherName":"a","publisherEmail":"b@c.test"}}`,
		http.StatusCreated)
	available := request(t, handler, http.MethodGet, basePath+"/skus"+apiQuery, "").Body.String()
	if strings.Contains(available, "Premium") || !strings.Contains(available, "Consumption") {
		t.Fatalf("consumption skus = %s", available)
	}
}

// Enforcement is OFF by default, which is the emulator being more permissive
// than a tenant. Both directions are asserted so the default cannot drift
// silently.
func TestTierEnforcementIsOptIn(t *testing.T) {
	workspace := basePath + "/workspaces/team" + apiQuery
	gateway := basePath + "/gateways/edge" + apiQuery
	workspaceBody := `{"properties":{"displayName":"Team"}}`
	gatewayBody := `{"properties":{"locationData":{"name":"dc"}}}`

	permissive, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, permissive, http.MethodPut, workspace, workspaceBody, http.StatusCreated)
	assertStatus(t, permissive, http.MethodPut, gateway, gatewayBody, http.StatusCreated)

	strictStore, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = strictStore.Close() })
	strict := &Handler{Store: strictStore, Auth: auth.AllowAll{}, EnforceTiers: true}
	seedService(t, strictStore)

	// Workspaces are Premium only, and the refusal names the tiers that have
	// them so a caller knows what to change.
	refused := request(t, strict, http.MethodPut, workspace, workspaceBody)
	if refused.Code != http.StatusBadRequest || !strings.Contains(refused.Body.String(), "Premium") {
		t.Fatalf("workspace on Developer with enforcement on = %d %s", refused.Code, refused.Body.String())
	}
	assertStatus(t, strict, http.MethodGet, basePath+"/workspaces"+apiQuery, "", http.StatusBadRequest)
	// A self-hosted gateway IS a Developer capability, so enforcement must not
	// refuse it. A gate that refused everything would pass a test that only
	// checked refusals.
	assertStatus(t, strict, http.MethodPut, gateway, gatewayBody, http.StatusCreated)

	// On Premium both are allowed.
	premium, premiumStore := testHandler(t)
	premium.EnforceTiers = true
	assertStatus(t, premium, http.MethodPut, basePath+apiQuery, premiumService("1"), http.StatusCreated)
	_ = premiumStore
	assertStatus(t, premium, http.MethodPut, workspace, workspaceBody, http.StatusCreated)
	assertStatus(t, premium, http.MethodPut, gateway, gatewayBody, http.StatusCreated)
}

// A tier WITHOUT self-hosted gateways refuses them, which is the half the
// Developer case cannot show: Developer has that capability, so a gate that
// never refused would have passed the test above.
func TestTierEnforcementRefusesGatewaysOnALesserTier(t *testing.T) {
	handler, _ := testHandler(t)
	handler.EnforceTiers = true
	assertStatus(t, handler, http.MethodPut, basePath+apiQuery,
		`{"location":"local","sku":{"name":"Basic","capacity":1},"properties":{"publisherName":"a","publisherEmail":"b@c.test"}}`,
		http.StatusCreated)
	refused := request(t, handler, http.MethodPut, basePath+"/gateways/edge"+apiQuery, `{"properties":{"locationData":{"name":"dc"}}}`)
	if refused.Code != http.StatusBadRequest {
		t.Fatalf("a self-hosted gateway on Basic = %d %s", refused.Code, refused.Body.String())
	}
	// The refusal names the tiers that do have it.
	for _, want := range []string{"Developer", "Premium"} {
		if !strings.Contains(refused.Body.String(), want) {
			t.Fatalf("refusal does not say where the capability exists: %s", refused.Body.String())
		}
	}
}

// The gate applies to resources INSIDE a workspace too, not only to the
// workspace resource itself: the peel that makes every family workspace-scoped
// would otherwise route straight past it.
func TestTierEnforcementRefusesWorkspaceScopedResources(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	// Created while permissive, so the refusal below is the gate rather than a
	// missing workspace.
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team"+apiQuery, `{"properties":{"displayName":"Team"}}`, http.StatusCreated)
	handler.EnforceTiers = true
	assertStatus(t, handler, http.MethodGet, basePath+"/workspaces/team/apis"+apiQuery, "", http.StatusBadRequest)
}

// Enforcement on a service that does not exist reports the missing service
// rather than a tier problem.
func TestTierEnforcementReportsAMissingService(t *testing.T) {
	handler, _ := testHandler(t)
	handler.EnforceTiers = true
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team"+apiQuery, `{"properties":{"displayName":"Team"}}`, http.StatusNotFound)
}

// A service stored with a tier the catalogue does not know is refused rather
// than silently granted every capability.
func TestTierEnforcementRefusesAnUnknownStoredTier(t *testing.T) {
	handler, st := testHandler(t)
	handler.EnforceTiers = true
	service := serviceModel()
	service.SKUName = "Titanium"
	if _, err := st.UpsertService(service); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, basePath+"/workspaces/team"+apiQuery, `{"properties":{"displayName":"Team"}}`, http.StatusBadRequest)
}

// A stored region with no name is skipped rather than listed as an empty one:
// a caller reading the region list uses the names to address a gateway.
func TestRegionListSkipsANamelessAdditionalLocation(t *testing.T) {
	handler, st := testHandler(t)
	service := serviceModel()
	service.SKUName, service.Document = "Premium", map[string]any{"properties": map[string]any{
		"additionalLocations": []any{
			map[string]any{"location": "  "},
			map[string]any{"location": "westeurope"},
		},
	}}
	if _, err := st.UpsertService(service); err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	body := request(t, handler, http.MethodGet, basePath+"/regions"+apiQuery, "")
	if err := json.Unmarshal(body.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Value) != 2 || listing.Value[1].Name != "westeurope" {
		t.Fatalf("regions = %s", body.Body.String())
	}
}

func TestTierHelpers(t *testing.T) {
	if got := itoa(0); got != "0" {
		t.Fatalf("itoa(0) = %q", got)
	}
	if got := itoa(120); got != "120" {
		t.Fatalf("itoa(120) = %q", got)
	}
	if names := tiersWith(capabilityWorkspaces); len(names) != 1 || names[0] != "Premium" {
		t.Fatalf("tiersWith(workspaces) = %v", names)
	}
	if _, ok := lookupTier("  PREMIUM "); !ok {
		t.Fatal("tier lookup is not case- and space-insensitive")
	}
	// A document with no additional locations, or a malformed one, is not a
	// crash.
	for _, document := range []map[string]any{
		{}, {"properties": "scalar"},
		{"properties": map[string]any{"additionalLocations": "scalar"}},
		{"properties": map[string]any{"additionalLocations": []any{"scalar"}}},
	} {
		if message := validateAdditionalLocations(document, tiers["premium"]); message != "" {
			t.Fatalf("malformed document refused: %s", message)
		}
		projectAdditionalLocations(document, "svc")
	}
}
