package arm

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func connectionPath(name string) string {
	return basePath + "/privateEndpointConnections/" + name + apiQuery
}

// The approval workflow is the resource: a consumer asks, and the service owner
// decides. A connection that arrived already Approved would grant access nobody
// granted.
func TestPrivateEndpointConnectionApprovalWorkflow(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	collection := basePath + "/privateEndpointConnections" + apiQuery

	assertStatus(t, handler, http.MethodPut, connectionPath("from-vnet"),
		`{"properties":{"privateEndpoint":{"id":"/subscriptions/other/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe"}}}`,
		http.StatusCreated)

	got := request(t, handler, http.MethodGet, connectionPath("from-vnet"), "")
	if !strings.Contains(got.Body.String(), `"status":"Pending"`) {
		t.Fatalf("a new connection must arrive Pending: %s", got.Body.String())
	}
	// The consumer's endpoint lives in another subscription and is echoed, not
	// resolved: this emulator never reaches it.
	if !strings.Contains(got.Body.String(), "Microsoft.Network/privateEndpoints/pe") {
		t.Fatalf("the consumer's endpoint was lost: %s", got.Body.String())
	}
	// A rejected connection is still a successfully provisioned RESOURCE.
	// Conflating the two would make a rejection look like a failed write.
	if !strings.Contains(got.Body.String(), `"provisioningState":"Succeeded"`) {
		t.Fatalf("provisioningState = %s", got.Body.String())
	}

	assertStatus(t, handler, http.MethodPut, connectionPath("from-vnet"),
		`{"properties":{"privateLinkServiceConnectionState":{"status":"approved","description":"reviewed by platform"}}}`,
		http.StatusOK)
	approved := request(t, handler, http.MethodGet, connectionPath("from-vnet"), "").Body.String()
	// Canonicalised, so a caller writing "approved" and one writing "Approved"
	// end up in the same state and neither is stored as typed.
	if !strings.Contains(approved, `"status":"Approved"`) || !strings.Contains(approved, "reviewed by platform") {
		t.Fatalf("approval = %s", approved)
	}
	if !strings.Contains(approved, `"provisioningState":"Succeeded"`) {
		t.Fatalf("provisioningState after approval = %s", approved)
	}

	assertStatus(t, handler, http.MethodPut, connectionPath("from-vnet"),
		`{"properties":{"privateLinkServiceConnectionState":{"status":"Rejected","actionsRequired":"None"}}}`, http.StatusOK)
	rejected := request(t, handler, http.MethodGet, connectionPath("from-vnet"), "").Body.String()
	if !strings.Contains(rejected, `"status":"Rejected"`) || !strings.Contains(rejected, `"actionsRequired":"None"`) {
		t.Fatalf("rejection = %s", rejected)
	}

	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodHead, connectionPath("from-vnet"), "", http.StatusOK)
	assertStatus(t, handler, http.MethodDelete, connectionPath("from-vnet"), "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodGet, connectionPath("from-vnet"), "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, connectionPath("from-vnet"), "", http.StatusNoContent)
}

func TestPrivateEndpointConnectionRefusals(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	assertStatus(t, handler, http.MethodPut, connectionPath("bad"),
		`{"properties":{"privateLinkServiceConnectionState":{"status":"Maybe"}}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, connectionPath("bad"), `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, connectionPath("bad"), "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, basePath+"/privateEndpointConnections"+apiQuery, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, basePath+"/privateEndpointConnections/a/b"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, connectionPath("absent"), "", http.StatusNotFound)
}

// A connection needs a service to belong to.
func TestPrivateEndpointConnectionRequiresService(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodPut, connectionPath("orphan"), `{"properties":{}}`, http.StatusNotFound)
}

// An APIM service exposes exactly one private-link sub-resource. Advertising
// more would send a consumer looking for a group id that does not exist.
func TestPrivateLinkResources(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	listed := request(t, handler, http.MethodGet, basePath+"/privateLinkResources"+apiQuery, "")
	if !strings.Contains(listed.Body.String(), `"groupId":"Gateway"`) {
		t.Fatalf("list = %s", listed.Body.String())
	}
	single := request(t, handler, http.MethodGet, basePath+"/privateLinkResources/Gateway"+apiQuery, "")
	if !strings.Contains(single.Body.String(), "privatelink.azure-api.net") {
		t.Fatalf("get = %s", single.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/privateLinkResources/Portal"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/privateLinkResources/a/b"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/privateLinkResources"+apiQuery, "", http.StatusMethodNotAllowed)
}

func TestPrivateLinkResourcesRequireService(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodGet, basePath+"/privateLinkResources"+apiQuery, "", http.StatusNotFound)
}

func TestNetworkStatus(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)

	// The service-scoped form is a LIST, one entry per location the service
	// runs in, which the SDK unwraps as such.
	listed := request(t, handler, http.MethodGet, basePath+"/networkstatus"+apiQuery, "")
	var byLocation []map[string]any
	if err := json.Unmarshal(listed.Body.Bytes(), &byLocation); err != nil {
		t.Fatalf("service-scoped networkstatus is not a list: %s", listed.Body.String())
	}
	if len(byLocation) != 1 || byLocation[0]["location"] != "local" {
		t.Fatalf("networkstatus = %v", byLocation)
	}

	single := request(t, handler, http.MethodGet, basePath+"/locations/local/networkstatus"+apiQuery, "")
	var status map[string]any
	if err := json.Unmarshal(single.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if _, ok := status["dnsServers"].([]any); !ok {
		t.Fatalf("dnsServers = %v", status)
	}
	connectivity, _ := status["connectivityStatus"].([]any)
	if len(connectivity) == 0 {
		t.Fatalf("connectivityStatus = %v", status)
	}
	// A location the service is not deployed to is a 404, not an empty status:
	// reporting nothing would read as "all clear over there".
	assertStatus(t, handler, http.MethodGet, basePath+"/locations/westeurope/networkstatus"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/locations/local/somethingelse"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, basePath+"/networkstatus"+apiQuery, "", http.StatusMethodNotAllowed)
}

func TestNetworkStatusRequiresService(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodGet, basePath+"/networkstatus"+apiQuery, "", http.StatusNotFound)
}

func TestOutboundNetworkDependencies(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	got := request(t, handler, http.MethodGet, basePath+"/outboundNetworkDependenciesEndpoints"+apiQuery, "")
	var payload struct {
		Value []struct {
			Category  string `json:"category"`
			Endpoints []struct {
				DomainName      string `json:"domainName"`
				EndpointDetails []struct {
					Port int `json:"port"`
				} `json:"endpointDetails"`
			} `json:"endpoints"`
		} `json:"value"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Value) == 0 {
		t.Fatalf("value = %s", got.Body.String())
	}
	for _, entry := range payload.Value {
		if entry.Category == "" || len(entry.Endpoints) == 0 {
			t.Fatalf("an entry carried no category or endpoints: %s", got.Body.String())
		}
		for _, endpoint := range entry.Endpoints {
			if endpoint.DomainName == "" || len(endpoint.EndpointDetails) == 0 {
				t.Fatalf("an endpoint carried no domain or port: %s", got.Body.String())
			}
		}
	}
	assertStatus(t, handler, http.MethodPost, basePath+"/outboundNetworkDependenciesEndpoints"+apiQuery, "", http.StatusMethodNotAllowed)
}

func TestOutboundNetworkDependenciesRequiresService(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodGet, basePath+"/outboundNetworkDependenciesEndpoints"+apiQuery, "", http.StatusNotFound)
}

func TestPrivateEndpointConnectionStoreErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedService(t, st)
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	assertStatus(t, handler, http.MethodPut, connectionPath("from-vnet"), `{"properties":{}}`, http.StatusCreated)

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_pec BEFORE INSERT ON private_endpoint_connections BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, connectionPath("from-vnet"), `{"properties":{}}`, http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_pec; CREATE TRIGGER reject_pec_delete BEFORE DELETE ON private_endpoint_connections BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodDelete, connectionPath("from-vnet"), "", http.StatusConflict)
	if _, err := db.Exec(`DROP TRIGGER reject_pec_delete; DROP TABLE private_endpoint_connections`); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct{ method, path, body string }{
		{http.MethodGet, basePath + "/privateEndpointConnections" + apiQuery, ""},
		{http.MethodGet, connectionPath("from-vnet"), ""},
		{http.MethodPut, connectionPath("from-vnet"), `{"properties":{}}`},
		{http.MethodDelete, connectionPath("from-vnet"), ""},
	} {
		assertStatus(t, handler, call.method, call.path, call.body, http.StatusConflict)
	}

	// A stored document whose properties are not an object must not panic the
	// projection.
	wire := privateEndpointConnectionWire(model.PrivateEndpointConnection{
		ServiceID: "svc", Name: "c", Status: "Approved", Document: map[string]any{"properties": "scalar"},
	})
	if wire["properties"].(map[string]any)["privateLinkServiceConnectionState"].(map[string]any)["status"] != "Approved" {
		t.Fatalf("wire fallback = %#v", wire)
	}
}
