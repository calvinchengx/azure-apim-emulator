package mcp

import (
	"encoding/json"
	"testing"
)

func operation(name, method, template string, document map[string]any) OperationSource {
	return OperationSource{Name: name, DisplayName: name, Method: method, URLTemplate: template, Document: document}
}

func TestCompileDerivesToolsFromOperations(t *testing.T) {
	schema := Compile("Orders", "1.0.0", []OperationSource{
		operation("get-order", "GET", "/orders/{orderId}", map[string]any{"properties": map[string]any{
			"description":        "Fetch one order.",
			"templateParameters": []any{map[string]any{"name": "orderId", "type": "string", "description": "The id."}},
			"request": map[string]any{"queryParameters": []any{
				map[string]any{"name": "expand", "type": "boolean", "required": false},
				map[string]any{"name": "tenant", "type": "string", "required": true},
			}},
		}}),
		operation("create-order", "POST", "/orders", nil),
	})
	// Sorted, so a client sees a stable tool list rather than map order.
	if len(schema.Tools) != 2 || schema.Tools[0].Name != "create-order" || schema.Tools[1].Name != "get-order" {
		t.Fatalf("tools = %#v", schema.Tools)
	}
	get, ok := schema.Lookup("get-order")
	if !ok {
		t.Fatal("get-order not bound")
	}
	if get.Tool.Description != "Fetch one order." {
		t.Fatalf("description = %q", get.Tool.Description)
	}
	properties, _ := get.Tool.InputSchema["properties"].(map[string]any)
	orderID, _ := properties["orderId"].(map[string]any)
	if orderID["type"] != "string" || orderID["description"] != "The id." {
		t.Fatalf("orderId schema = %#v", orderID)
	}
	expand, _ := properties["expand"].(map[string]any)
	if expand["type"] != "boolean" {
		t.Fatalf("APIM's boolean did not map to JSON Schema: %#v", expand)
	}
	required, _ := get.Tool.InputSchema["required"].([]string)
	// A path parameter is required because there is no URL without it; an
	// optional query parameter is not; a required one is.
	if len(required) != 2 || required[0] != "orderId" || required[1] != "tenant" {
		t.Fatalf("required = %v", required)
	}
	if _, hasBody := properties["body"]; hasBody {
		t.Fatal("a GET tool advertised a body")
	}
	create, _ := schema.Lookup("create-order")
	if _, hasBody := create.Tool.InputSchema["properties"].(map[string]any)["body"]; !hasBody {
		t.Fatal("a POST tool advertised no body")
	}
	// With nothing declared, a tool still has a schema: an object with no
	// properties, which is what a client validates an empty call against.
	if create.Tool.InputSchema["type"] != "object" {
		t.Fatalf("create input schema = %#v", create.Tool.InputSchema)
	}
	if _, has := create.Tool.InputSchema["required"]; has {
		t.Fatal("a tool with no required arguments advertised a required list")
	}
	if _, ok := schema.Lookup("absent"); ok {
		t.Fatal("an unknown tool resolved")
	}
}

// A placeholder nobody declared is still an argument the call cannot be made
// without, so it is advertised rather than silently dropped.
func TestCompileAdvertisesUndeclaredTemplatePlaceholders(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{
		operation("get", "GET", "/orders/{orderId}/items/{itemId:int}", nil),
	})
	binding, _ := schema.Lookup("get")
	properties, _ := binding.Tool.InputSchema["properties"].(map[string]any)
	if _, ok := properties["orderId"]; !ok {
		t.Fatalf("properties = %#v", properties)
	}
	// APIM allows a format hint after a colon; the argument name is what
	// precedes it, and advertising `itemId:int` would be unusable.
	if _, ok := properties["itemId"]; !ok {
		t.Fatalf("format-hinted placeholder not advertised: %#v", properties)
	}
	path, query, err := binding.ResolvePath(map[string]any{"orderId": "A-1", "itemId": 7})
	if err != nil || path != "/orders/A-1/items/7" || query != "" {
		t.Fatalf("resolved = %q %q %v", path, query, err)
	}
}

// A description falls back to the display name, because a tool with no
// description is one a model has to guess at.
func TestCompileFallsBackToDisplayName(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{
		{Name: "get", DisplayName: "Get an order", Method: "GET", URLTemplate: "/orders"},
	})
	if schema.Tools[0].Description != "Get an order" {
		t.Fatalf("description = %q", schema.Tools[0].Description)
	}
}

func TestResolvePathRefusesAMissingRequiredArgument(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{operation("get", "GET", "/orders/{orderId}", nil)})
	binding, _ := schema.Lookup("get")
	// `/orders/` would reach the backend as a different route and most likely
	// 404 there, which is a confusing way to report a missing argument.
	if _, _, err := binding.ResolvePath(map[string]any{}); err == nil {
		t.Fatal("a missing path argument was tolerated")
	}
}

func TestResolvePathBuildsAStableQueryString(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{
		operation("list", "GET", "/orders", map[string]any{"properties": map[string]any{
			"request": map[string]any{"queryParameters": []any{
				map[string]any{"name": "zeta", "type": "string"},
				map[string]any{"name": "alpha", "type": "integer"},
				map[string]any{"name": "absent", "type": "string"},
			}},
		}}),
	})
	binding, _ := schema.Lookup("list")
	// Sorted, so a recorded backend call is comparable across runs; and an
	// argument the caller omitted is omitted rather than sent empty.
	_, query, err := binding.ResolvePath(map[string]any{"zeta": "z", "alpha": 3})
	if err != nil || query != "alpha=3&zeta=z" {
		t.Fatalf("query = %q %v", query, err)
	}
}

func TestJSONTypeMapping(t *testing.T) {
	for input, want := range map[string]string{
		"integer": "integer", "int32": "integer", "long": "integer",
		"number": "number", "double": "number", "decimal": "number",
		"boolean": "boolean", "bool": "boolean",
		"array": "array", "object": "object",
		"string": "string", "": "string", "guid": "string",
	} {
		if got := jsonType(input); got != want {
			t.Fatalf("jsonType(%q) = %q, want %q", input, got, want)
		}
	}
	// A non-string type declaration is not a crash, it is a string parameter.
	if jsonType(42) != "string" {
		t.Fatal("a non-string type declaration was not defaulted")
	}
}

func TestNegotiateVersion(t *testing.T) {
	if got := NegotiateVersion("2025-06-18"); got != "2025-06-18" {
		t.Fatalf("a supported version was not echoed: %q", got)
	}
	// A client asking for a revision this does not implement is told what it
	// will actually get, and may refuse, rather than being told it has it.
	if got := NegotiateVersion("1999-01-01"); got != ProtocolVersions[0] {
		t.Fatalf("an unsupported version negotiated to %q", got)
	}
}

func TestRequestNotificationDetection(t *testing.T) {
	// JSON-RPC marks a notification by the ABSENCE of an id, not by the method
	// name, and answering one makes the reference client log a protocol error.
	var notification Request
	if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), &notification); err != nil {
		t.Fatal(err)
	}
	if !notification.IsNotification() {
		t.Fatal("a message with no id was not treated as a notification")
	}
	var explicit Request
	_ = json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":null,"method":"x"}`), &explicit)
	if !explicit.IsNotification() {
		t.Fatal("an explicit null id was not treated as a notification")
	}
	var call Request
	_ = json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`), &call)
	if call.IsNotification() {
		t.Fatal("a message with an id was treated as a notification")
	}
}

// Operation names are unique within an APIM API, so a clash cannot come from
// the store. Skipping rather than overwriting keeps that true if it ever does.
func TestCompileSkipsDuplicateToolNames(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{
		operation("get", "GET", "/first", nil),
		operation("get", "GET", "/second", nil),
	})
	if len(schema.Tools) != 1 {
		t.Fatalf("tools = %#v", schema.Tools)
	}
	binding, _ := schema.Lookup("get")
	if binding.URLTemplate != "/first" {
		t.Fatalf("the later duplicate won: %q", binding.URLTemplate)
	}
}

func TestArgumentStringEncoding(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{operation("get", "GET", "/o/{a}/{b}/{c}", nil)})
	binding, _ := schema.Lookup("get")
	path, _, err := binding.ResolvePath(map[string]any{"a": "text", "b": true, "c": nil})
	if err != nil || path != "/o/text/true/" {
		t.Fatalf("path = %q %v", path, err)
	}
}

// A parameter with no name cannot be advertised or supplied, so it is skipped
// rather than becoming an empty-named property a client cannot address.
func TestCompileSkipsNamelessParameters(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{
		operation("get", "GET", "/orders", map[string]any{"properties": map[string]any{
			"templateParameters": []any{
				map[string]any{"type": "string"},
				"not an object",
			},
			"request": map[string]any{"queryParameters": []any{map[string]any{"type": "string"}}},
		}}),
	})
	binding, _ := schema.Lookup("get")
	properties, _ := binding.Tool.InputSchema["properties"].(map[string]any)
	if len(properties) != 0 {
		t.Fatalf("a nameless parameter was advertised: %#v", properties)
	}
	if _, has := binding.Tool.InputSchema["required"]; has {
		t.Fatal("a nameless parameter was marked required")
	}
}

// A malformed template is not a crash. It cannot be resolved either, but the
// failure belongs at the call, not at compile time, where it would take the
// whole API's tool list down over one operation.
func TestCompileToleratesAnUnterminatedPlaceholder(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{operation("get", "GET", "/orders/{orderId", nil)})
	binding, _ := schema.Lookup("get")
	properties, _ := binding.Tool.InputSchema["properties"].(map[string]any)
	if len(properties) != 0 {
		t.Fatalf("an unterminated placeholder was advertised: %#v", properties)
	}
	path, _, err := binding.ResolvePath(map[string]any{})
	if err != nil || path != "/orders/{orderId" {
		t.Fatalf("resolved = %q %v", path, err)
	}
}

// A declared parameter whose placeholder is unterminated leaves the template
// alone rather than looping or truncating it.
func TestResolvePathToleratesAnUnterminatedHintedPlaceholder(t *testing.T) {
	schema := Compile("Orders", "1", []OperationSource{
		operation("get", "GET", "/orders/{orderId:int", map[string]any{"properties": map[string]any{
			"templateParameters": []any{map[string]any{"name": "orderId", "type": "string"}},
		}}),
	})
	binding, _ := schema.Lookup("get")
	path, _, err := binding.ResolvePath(map[string]any{"orderId": "A-1"})
	if err != nil || path != "/orders/{orderId:int" {
		t.Fatalf("resolved = %q %v", path, err)
	}
}
