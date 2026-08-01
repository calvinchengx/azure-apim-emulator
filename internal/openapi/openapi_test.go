package openapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

func TestParseOpenAPI3YAML(t *testing.T) {
	document, err := Parse(`
openapi: 3.1.0
info:
  title: Inventory
  description: Inventory API
servers:
  - url: https://inventory.example.test/v1
paths:
  /items/{id}:
    parameters: []
    get:
      operationId: getItem
      summary: Get item
    post:
      operationId: duplicate
  /other:
    get:
      operationId: duplicate
  /:
    delete: {}
components:
  schemas:
    Item:
      type: object
`)
	if err != nil {
		t.Fatal(err)
	}
	if document.Version != "3.1.0" || document.Title != "Inventory" || document.Description != "Inventory API" || document.ServiceURL != "https://inventory.example.test/v1" {
		t.Fatalf("metadata = %+v", document)
	}
	if len(document.Operations) != 4 || document.Operations[0].Name != "delete-root" || document.Operations[1].Name != "getItem" || document.Operations[2].Name != "duplicate" || document.Operations[3].Name != "duplicate-2" {
		t.Fatalf("operations = %+v", document.Operations)
	}
	if len(document.Schemas) != 1 {
		t.Fatalf("schemas = %#v", document.Schemas)
	}
	encoded, err := document.JSON()
	if err != nil || !strings.Contains(encoded, `"openapi":"3.1.0"`) {
		t.Fatalf("JSON = %q, %v", encoded, err)
	}
}

func TestExportFormats(t *testing.T) {
	api := model.API{DisplayName: "Inventory", ServiceURL: "http://backend.test/base"}
	operations := []model.Operation{{Name: "get-item", DisplayName: "Get item", Method: "GET", URLTemplate: "/items/{id}"}}
	schemas := map[string]any{"Item": map[string]any{"type": "object"}}
	for _, format := range []string{"openapi-link", "openapi+json-link", "swagger-link"} {
		value, resultFormat, contentType, err := Export(api, operations, schemas, format)
		if err != nil || len(value) == 0 || resultFormat == "" || contentType == "" {
			t.Fatalf("Export(%s) = %q, %q, %q, %v", format, value, resultFormat, contentType, err)
		}
		if format == "openapi-link" {
			if !strings.Contains(string(value), "openapi: 3.0.3") {
				t.Fatalf("YAML = %s", value)
			}
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(value, &document); err != nil {
			t.Fatal(err)
		}
		if format == "swagger-link" && (document["host"] != "backend.test" || document["basePath"] != "/base") {
			t.Fatalf("Swagger = %#v", document)
		}
	}
	api.ServiceURL = "not a URL"
	if value, _, _, err := Export(api, nil, nil, "swagger-link"); err != nil || !strings.Contains(string(value), `"schemes":["https"]`) {
		t.Fatalf("fallback Swagger = %s, %v", value, err)
	}
	if _, _, _, err := Export(api, nil, nil, "wsdl-link"); err == nil {
		t.Fatal("unsupported export succeeded")
	}
}

func TestParseSwaggerJSON(t *testing.T) {
	document, err := Parse(`{"swagger":"2.0","info":{"title":"Pet API"},"host":"pets.example.test","basePath":"/v2/","schemes":["http"],"paths":{"/pets":{"get":{"summary":"List pets"}}},"definitions":{"Pet":{"type":"object"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if document.Version != "2.0" || document.ServiceURL != "http://pets.example.test/v2" || len(document.Operations) != 1 || document.Operations[0].Name != "get-pets" || document.Operations[0].DisplayName != "List pets" || len(document.Schemas) != 1 {
		t.Fatalf("document = %+v", document)
	}
}

func TestParseDefaultsAndValidation(t *testing.T) {
	valid := `{"openapi":"3.0.0","info":{"title":"API"},"paths":{"/x":{"get":{}}}}`
	document, err := Parse(valid)
	if err != nil || document.ServiceURL != "" || document.Operations[0].DisplayName != "get-x" || len(document.Schemas) != 0 {
		t.Fatalf("defaults = %+v, %v", document, err)
	}
	tests := []string{
		`{`,
		`null`,
		`{"info":{"title":"API"},"paths":{}}`,
		`{"openapi":"3.0.0","info":{},"paths":{}}`,
		`{"openapi":"3.0.0","info":{"title":"API"},"paths":[]}`,
		`{"openapi":"3.0.0","info":{"title":"API"},"paths":{"/x":[]}}`,
		`{"openapi":"3.0.0","info":{"title":"API"},"paths":{"/x":{"get":[]}}}`,
		`{"openapi":"3.0.0","info":{"title":"API"},"paths":{"x":{"get":{}}}}`,
		`{"openapi":"3.0.0","info":{"title":"API"},"paths":{"/x":{"get":{"operationId":1}}}}`,
		`{"openapi":"3.0.0","info":{"title":"API"},"paths":{"/x":{"get":{"summary":false}}}}`,
	}
	for _, source := range tests {
		if _, err := Parse(source); err == nil {
			t.Errorf("Parse(%q) succeeded", source)
		}
	}
}

func TestSwaggerServiceURLDefaults(t *testing.T) {
	document, err := Parse(`{"swagger":"2.0","info":{"title":"API"},"host":"api.test","schemes":[1],"paths":{}}`)
	if err != nil || document.ServiceURL != "https://api.test" {
		t.Fatalf("default scheme = %+v, %v", document, err)
	}
	document, err = Parse(`{"swagger":"2.0","info":{"title":"API"},"paths":{}}`)
	if err != nil || document.ServiceURL != "" {
		t.Fatalf("missing host = %+v, %v", document, err)
	}
}
