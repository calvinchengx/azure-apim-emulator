package differential_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/pkg/emulator"
)

type serviceInventory struct {
	APIVersion             string   `json:"apiVersion"`
	ResourceFields         []string `json:"resourceFields"`
	PropertyFields         []string `json:"propertyFields"`
	WritablePropertyFields []string `json:"writablePropertyFields"`
}

type fixtureManifest struct {
	SchemaVersion  string   `json:"schemaVersion"`
	Normalizations []string `json:"normalizations"`
	Scenarios      []struct {
		ID            string `json:"id"`
		APIVersion    string `json:"apiVersion"`
		AzureRequired bool   `json:"azureRequired"`
	} `json:"scenarios"`
}

func TestDifferentialFixtureManifest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "fixture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "1" || len(manifest.Normalizations) == 0 || len(manifest.Scenarios) < 5 {
		t.Fatalf("invalid differential fixture manifest: %+v", manifest)
	}
	seen := map[string]bool{}
	for _, scenario := range manifest.Scenarios {
		if scenario.ID == "" || scenario.APIVersion == "" || seen[scenario.ID] {
			t.Fatalf("invalid or duplicate differential scenario: %+v", scenario)
		}
		seen[scenario.ID] = true
	}
}

func TestServiceSchemaInventory(t *testing.T) {
	inventory := loadInventory(t)
	emu := emulator.StartT(t)
	document := completeServiceDocument(inventory)
	actual := putService(t, emu, document)
	assertClassified(t, actual, inventory)
	assertProjectionEqual(t, document, actual, inventory.WritablePropertyFields)
}

func TestAzureServiceDocumentDifferential(t *testing.T) {
	serviceURL := os.Getenv("APIM_AZURE_SERVICE_URL")
	token := os.Getenv("APIM_AZURE_BEARER_TOKEN")
	if serviceURL == "" || token == "" {
		t.Skip("set APIM_AZURE_SERVICE_URL and APIM_AZURE_BEARER_TOKEN to run the live Azure differential")
	}
	inventory := loadInventory(t)
	azure := getJSON(t, serviceURL, token)
	assertClassified(t, azure, inventory)
	location, _ := azure["location"].(string)
	emu := emulator.StartT(t, emulator.WithService("differential", location))
	actual := putService(t, emu, azure)
	assertProjectionEqual(t, azure, actual, inventory.WritablePropertyFields)
}

func loadInventory(t *testing.T) serviceInventory {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "service-2024-05-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory serviceInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	return inventory
}

func completeServiceDocument(inventory serviceInventory) map[string]any {
	properties := make(map[string]any, len(inventory.PropertyFields))
	for _, field := range inventory.PropertyFields {
		properties[field] = nil
	}
	properties["publisherName"] = "Differential"
	properties["publisherEmail"] = "differential@example.test"
	properties["customProperties"] = map[string]any{"Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10": "False"}
	return map[string]any{
		"location": "local", "tags": map[string]any{"fixture": "service-schema"},
		"zones": []any{"1"}, "identity": map[string]any{"type": "SystemAssigned"},
		"sku": map[string]any{"name": "Developer", "capacity": float64(1)}, "properties": properties,
	}
}

func putService(t *testing.T, emu *emulator.Emulator, document map[string]any) map[string]any {
	t.Helper()
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	url := emu.ManagementEndpoint + emu.ServiceID() + "?api-version=2024-05-01"
	request, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	response, err := emu.HTTPClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("emulator PUT = %d: %s", response.StatusCode, body)
	}
	return decodeJSON(t, response.Body)
}

func getJSON(t *testing.T, url, token string) map[string]any {
	t.Helper()
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}
	request, err := http.NewRequest(http.MethodGet, url+separator+"api-version=2024-05-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("Azure GET = %d: %s", response.StatusCode, body)
	}
	return decodeJSON(t, response.Body)
}

func decodeJSON(t *testing.T, reader io.Reader) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.NewDecoder(reader).Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document
}

func assertClassified(t *testing.T, document map[string]any, inventory serviceInventory) {
	t.Helper()
	assertKnownKeys(t, "resource", document, inventory.ResourceFields)
	properties, ok := document["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties is %T", document["properties"])
	}
	assertKnownKeys(t, "properties", properties, inventory.PropertyFields)
}

func assertKnownKeys(t *testing.T, scope string, document map[string]any, known []string) {
	t.Helper()
	allowed := make(map[string]bool, len(known))
	for _, key := range known {
		allowed[key] = true
	}
	var unknown []string
	for key := range document {
		if !allowed[key] {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	if len(unknown) != 0 {
		t.Fatalf("unclassified %s fields: %v", scope, unknown)
	}
}

func assertProjectionEqual(t *testing.T, expected, actual map[string]any, writableProperties []string) {
	t.Helper()
	expectedProjection := projection(expected, writableProperties)
	actualProjection := projection(actual, writableProperties)
	if !reflect.DeepEqual(expectedProjection, actualProjection) {
		expectedJSON, _ := json.MarshalIndent(expectedProjection, "", "  ")
		actualJSON, _ := json.MarshalIndent(actualProjection, "", "  ")
		t.Fatalf("writable service projection differs\nexpected: %s\nactual: %s", expectedJSON, actualJSON)
	}
}

func projection(document map[string]any, writableProperties []string) map[string]any {
	result := map[string]any{}
	for _, field := range []string{"location", "tags", "zones", "sku"} {
		if value, ok := document[field]; ok {
			result[field] = value
		}
	}
	if identity, ok := document["identity"].(map[string]any); ok {
		result["identity"] = map[string]any{"type": identity["type"], "userAssignedIdentities": identity["userAssignedIdentities"]}
	}
	properties, _ := document["properties"].(map[string]any)
	projectedProperties := map[string]any{}
	for _, field := range writableProperties {
		if value, ok := properties[field]; ok {
			projectedProperties[field] = value
		}
	}
	result["properties"] = projectedProperties
	return result
}
