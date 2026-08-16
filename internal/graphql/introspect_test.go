package graphql

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
)

// introspect runs a query and returns the decoded `data` object.
func introspect(t *testing.T, schema *Schema, query string) map[string]any {
	t.Helper()
	operation := mustOperation(t, schema, query)
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(schema.Introspect(operation), &envelope); err != nil {
		t.Fatalf("Introspect(%q) produced invalid JSON: %v", query, err)
	}
	return envelope.Data
}

func schemaOf(t *testing.T, data map[string]any) map[string]any {
	t.Helper()
	value, ok := data["__schema"].(map[string]any)
	if !ok {
		t.Fatalf("response carries no __schema: %v", data)
	}
	return value
}

func typeNamed(t *testing.T, schemaValue map[string]any, name string) map[string]any {
	t.Helper()
	types, _ := schemaValue["types"].([]any)
	for _, entry := range types {
		value, _ := entry.(map[string]any)
		if value["name"] == name {
			return value
		}
	}
	t.Fatalf("no type %q in introspection", name)
	return nil
}

func TestIntrospectionNamesTheRootTypes(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { description queryType { name } mutationType { name } subscriptionType { name } } }`)
	value := schemaOf(t, data)
	query, _ := value["queryType"].(map[string]any)
	if query["name"] != "Query" {
		t.Fatalf("queryType = %v", value["queryType"])
	}
	mutation, _ := value["mutationType"].(map[string]any)
	if mutation["name"] != "Mutation" {
		t.Fatalf("mutationType = %v", value["mutationType"])
	}
	if value["subscriptionType"] != nil {
		t.Fatalf("a schema with no subscription root must report null, got %v", value["subscriptionType"])
	}
}

// The projection contract: a GraphQL response carries the fields the client
// selected and no others. Returning extras happens to work with
// buildClientSchema and would hide the day a client depends on the real rule.
func TestIntrospectionReturnsOnlyTheSelectedFields(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { queryType { name } } }`)
	value := schemaOf(t, data)
	if len(value) != 1 {
		t.Fatalf("selecting one field returned %d: %v", len(value), value)
	}
	query, _ := value["queryType"].(map[string]any)
	if len(query) != 1 || query["name"] != "Query" {
		t.Fatalf("selecting queryType{name} returned %v", query)
	}
	if _, present := value["types"]; present {
		t.Fatal("types was not selected and must not appear")
	}
}

func TestIntrospectionHonoursAliasesAndTypename(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ root: __schema { kind: __typename qt: queryType { n: name } } }`)
	value, _ := data["root"].(map[string]any)
	if value == nil {
		t.Fatalf("alias `root` was not applied: %v", data)
	}
	if value["kind"] != "__Schema" {
		t.Fatalf("__typename under an alias = %v", value["kind"])
	}
	queryType, _ := value["qt"].(map[string]any)
	if queryType["n"] != "Query" {
		t.Fatalf("nested aliases = %v", value["qt"])
	}
}

func TestIntrospectionDescribesEveryTypeKind(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { types { name kind description } } }`)
	value := schemaOf(t, data)
	for name, want := range map[string]string{
		"Query": "OBJECT", "Item": "OBJECT", "Node": "INTERFACE", "SearchResult": "UNION",
		"Colour": "ENUM", "ItemInput": "INPUT_OBJECT", "String": "SCALAR",
	} {
		if got := typeNamed(t, value, name)["kind"]; got != want {
			t.Errorf("%s kind = %v, want %v", name, got, want)
		}
	}
	if got := typeNamed(t, value, "Item")["description"]; got != "An item." {
		t.Errorf("Item description = %v", got)
	}
	if got := typeNamed(t, value, "Query")["description"]; got != "A catalogue." {
		t.Errorf("Query description = %v", got)
	}
	if got := typeNamed(t, value, "Box")["description"]; got != nil {
		t.Errorf("an undescribed type must report null, got %v", got)
	}
	// The introspection meta-types are part of every real server's type list.
	if typeNamed(t, value, "__Schema")["kind"] != "OBJECT" {
		t.Error("the introspection meta-types must be present")
	}
}

// [Item!]! is NON_NULL(LIST(NON_NULL(Item))). A client rebuilds nullability
// from this chain, so a flattened one silently changes the schema it sees.
func TestIntrospectionRendersTheWrapperChain(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { types { name fields { name type { kind name ofType { kind name ofType { kind name } } } } } } }`)
	value := schemaOf(t, data)
	fields, _ := typeNamed(t, value, "Query")["fields"].([]any)
	var items map[string]any
	for _, entry := range fields {
		field, _ := entry.(map[string]any)
		if field["name"] == "items" {
			items, _ = field["type"].(map[string]any)
		}
	}
	if items == nil {
		t.Fatal("Query.items missing from introspection")
	}
	if items["kind"] != "NON_NULL" || items["name"] != nil {
		t.Fatalf("outer wrapper = %v", items)
	}
	list, _ := items["ofType"].(map[string]any)
	if list["kind"] != "LIST" {
		t.Fatalf("second wrapper = %v", list)
	}
	inner, _ := list["ofType"].(map[string]any)
	if inner["kind"] != "NON_NULL" {
		t.Fatalf("third wrapper = %v", inner)
	}
}

func TestIntrospectionCarriesArgumentsAndDefaults(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { types { name fields { name args { name defaultValue type { kind } } } inputFields { name defaultValue } } } }`)
	value := schemaOf(t, data)
	fields, _ := typeNamed(t, value, "Query")["fields"].([]any)
	found := false
	for _, entry := range fields {
		field, _ := entry.(map[string]any)
		if field["name"] != "item" {
			continue
		}
		found = true
		args, _ := field["args"].([]any)
		if len(args) != 2 {
			t.Fatalf("item args = %v", args)
		}
		id, _ := args[0].(map[string]any)
		locale, _ := args[1].(map[string]any)
		if id["name"] != "id" || id["defaultValue"] != nil {
			t.Errorf("an argument with no default must report null, got %v", id)
		}
		if locale["defaultValue"] != `"en"` {
			t.Errorf("locale defaultValue = %v, want the literal as written", locale["defaultValue"])
		}
	}
	if !found {
		t.Fatal("Query.item missing")
	}
	inputFields, _ := typeNamed(t, value, "ItemInput")["inputFields"].([]any)
	if len(inputFields) != 2 {
		t.Fatalf("ItemInput inputFields = %v", inputFields)
	}
	colour, _ := inputFields[1].(map[string]any)
	if colour["defaultValue"] != "RED" {
		t.Errorf("input field default = %v", colour["defaultValue"])
	}
}

func TestIntrospectionReportsDeprecation(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { types { name fields { name isDeprecated deprecationReason } enumValues { name isDeprecated deprecationReason } } } }`)
	value := schemaOf(t, data)
	fields, _ := typeNamed(t, value, "Query")["fields"].([]any)
	for _, entry := range fields {
		field, _ := entry.(map[string]any)
		switch field["name"] {
		case "legacy":
			if field["isDeprecated"] != true || field["deprecationReason"] != "use item" {
				t.Errorf("legacy deprecation = %v", field)
			}
		case "items":
			if field["isDeprecated"] != false || field["deprecationReason"] != nil {
				t.Errorf("a live field must not report deprecation: %v", field)
			}
		}
	}
	enumValues, _ := typeNamed(t, value, "Colour")["enumValues"].([]any)
	old, _ := enumValues[2].(map[string]any)
	if old["isDeprecated"] != true || old["deprecationReason"] != "No longer supported" {
		t.Errorf("@deprecated with no reason must use the spec default, got %v", old)
	}
}

func TestIntrospectionResolvesInterfacesAndUnions(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { types { name interfaces { name } possibleTypes { name } } } }`)
	value := schemaOf(t, data)

	interfaces, _ := typeNamed(t, value, "Item")["interfaces"].([]any)
	if len(interfaces) != 1 {
		t.Fatalf("Item interfaces = %v", interfaces)
	}
	if first, _ := interfaces[0].(map[string]any); first["name"] != "Node" {
		t.Errorf("Item must implement Node, got %v", interfaces[0])
	}

	// An interface's possibleTypes is derived by scanning implementors, so a
	// second implementor must appear and the order must be stable.
	possible, _ := typeNamed(t, value, "Node")["possibleTypes"].([]any)
	if len(possible) != 2 {
		t.Fatalf("Node possibleTypes = %v", possible)
	}
	box, _ := possible[0].(map[string]any)
	item, _ := possible[1].(map[string]any)
	if box["name"] != "Box" || item["name"] != "Item" {
		t.Errorf("interface possibleTypes must be sorted, got %v", possible)
	}
	if typeNamed(t, value, "Node")["interfaces"] != nil {
		t.Error("an interface reports null interfaces, not an empty list")
	}

	union, _ := typeNamed(t, value, "SearchResult")["possibleTypes"].([]any)
	if len(union) != 2 {
		t.Fatalf("SearchResult possibleTypes = %v", union)
	}
	if first, _ := union[0].(map[string]any); first["name"] != "Item" {
		t.Errorf("a union lists members in declaration order, got %v", union)
	}
	if typeNamed(t, value, "String")["fields"] != nil {
		t.Error("a scalar has no fields and must report null")
	}
}

func TestIntrospectionListsDirectives(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { directives { name description locations isRepeatable args { name } } } }`)
	value := schemaOf(t, data)
	directives, _ := value["directives"].([]any)
	byName := map[string]map[string]any{}
	for _, entry := range directives {
		directive, _ := entry.(map[string]any)
		byName[directive["name"].(string)] = directive
	}
	for _, required := range []string{"skip", "include", "deprecated"} {
		if byName[required] == nil {
			t.Fatalf("the built-in @%s directive must be advertised", required)
		}
	}
	locations, _ := byName["deprecated"]["locations"].([]any)
	if len(locations) == 0 {
		t.Fatal("@deprecated must name its locations")
	}
	args, _ := byName["skip"]["args"].([]any)
	if len(args) != 1 {
		t.Fatalf("@skip takes one argument, got %v", args)
	}
}

func TestTypeLookupByName(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __type(name: "Item") { name kind fields { name } } }`)
	value, _ := data["__type"].(map[string]any)
	if value == nil || value["name"] != "Item" {
		t.Fatalf("__type(name: \"Item\") = %v", data["__type"])
	}
	fields, _ := value["fields"].([]any)
	if len(fields) != 4 {
		t.Fatalf("Item fields = %v", fields)
	}

	if got := introspect(t, schema, `{ __type(name: "Absent") { name } }`)["__type"]; got != nil {
		t.Fatalf("an unknown type must be null, got %v", got)
	}
	// No `name` argument at all: the field is still answered, with null.
	operation := mustOperation(t, schema, `{ __schema { queryType { name } } }`)
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(schema.Introspect(operation), &envelope); err != nil {
		t.Fatal(err)
	}
	if _, present := envelope.Data["__type"]; present {
		t.Fatal("__type was not selected and must not appear")
	}
}

func TestProjectionRules(t *testing.T) {
	document := &ast.QueryDocument{}
	if got := project(document, ast.SelectionSet{}, "scalar"); got != "scalar" {
		t.Fatalf("an empty selection returns the value unchanged, got %v", got)
	}
	if got := project(document, ast.SelectionSet{&ast.Field{Name: "a"}}, nil); got != nil {
		t.Fatalf("null projects to null, got %v", got)
	}
	if got := project(document, ast.SelectionSet{&ast.Field{Name: "a"}}, 42); got != 42 {
		t.Fatalf("a selection against a scalar returns the scalar, got %v", got)
	}
}

// A list distributes the selection over its members rather than consuming it,
// and a selected field the source did not supply is null rather than absent.
func TestProjectionDistributesOverListsAndFillsGaps(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { types { name description } } }`)
	types, _ := schemaOf(t, data)["types"].([]any)
	if len(types) < 10 {
		t.Fatalf("the list was not distributed over, got %d entries", len(types))
	}
	for _, entry := range types {
		value, _ := entry.(map[string]any)
		if len(value) != 2 {
			t.Fatalf("each list member gets the same selection, got %v", value)
		}
	}
}

func TestProjectionFillsUnknownFieldsWithNull(t *testing.T) {
	document := &ast.QueryDocument{}
	set := ast.SelectionSet{&ast.Field{Name: "present"}, &ast.Field{Name: "absent"}}
	got, _ := project(document, set, map[string]any{"present": 1}).(map[string]any)
	if got["present"] != 1 {
		t.Fatalf("present field = %v", got["present"])
	}
	value, ok := got["absent"]
	if !ok || value != nil {
		t.Fatalf("a selected field the source lacks must be present and null, got %v ok=%v", value, ok)
	}
}

func TestInlineFragmentsFlattenIntoTheSelection(t *testing.T) {
	schema := mustSchema(t)
	operation := mustOperation(t, schema, `{ ... on Query { legacy } items { id } }`)
	got := strings.Join(operation.RootFields(), ",")
	if got != "legacy,items" {
		t.Fatalf("RootFields = %q, want the inline fragment flattened in place", got)
	}
}

// Both branches below are unreachable through the public API and are asserted
// directly: a nil type reference and a Definition carrying a kind the schema
// language has no syntax for. They exist so a future caller cannot turn either
// into a panic or a silently wrong kind.
func TestTypeRefAndKindOfDegradeSafely(t *testing.T) {
	schema := mustSchema(t)
	if got := schema.typeRef(nil); got != nil {
		t.Fatalf("typeRef(nil) = %v, want nil", got)
	}
	if got := kindOf(&ast.Definition{Kind: ast.DefinitionKind("nonsense")}); got != "SCALAR" {
		t.Fatalf("kindOf(unknown) = %q, want the SCALAR fallback", got)
	}
}

// Our PARSER's prelude carries @defer, an incremental-delivery directive this
// gateway does not implement. Advertising it would have a client send a
// deferred query and receive a single response its parser cannot reconcile, and
// the failure would land on the client rather than here. Caught by the
// reference implementation, which printed a schema we never imported.
func TestIntrospectionAdvertisesOnlyDirectivesWeHonour(t *testing.T) {
	schema, err := Parse(testSDL + "\ndirective @mine on FIELD\n")
	if err != nil {
		t.Fatal(err)
	}
	data := introspect(t, schema, `{ __schema { directives { name } } }`)
	directives, _ := schemaOf(t, data)["directives"].([]any)
	names := map[string]bool{}
	for _, entry := range directives {
		value, _ := entry.(map[string]any)
		names[value["name"].(string)] = true
	}
	for _, required := range []string{"skip", "include", "deprecated", "mine"} {
		if !names[required] {
			t.Errorf("@%s must be advertised", required)
		}
	}
	if names["defer"] {
		t.Error("@defer comes from the parser prelude and is not implemented; advertising it promises incremental delivery")
	}
}

// Real servers introspect in schema-declaration order, and every tool that
// prints a schema back from introspection reproduces that order. Sorting
// alphabetically yields an equivalent schema that diffs against its own source.
func TestIntrospectionKeepsDeclarationOrder(t *testing.T) {
	schema := mustSchema(t)
	data := introspect(t, schema, `{ __schema { types { name } } }`)
	types, _ := schemaOf(t, data)["types"].([]any)
	var declared []string
	for _, entry := range types {
		value, _ := entry.(map[string]any)
		name, _ := value["name"].(string)
		if strings.HasPrefix(name, "__") || builtInScalars[name] {
			continue
		}
		declared = append(declared, name)
	}
	want := []string{"Query", "Mutation", "Node", "Item", "Box", "SearchResult", "Colour", "ItemInput"}
	if strings.Join(declared, ",") != strings.Join(want, ",") {
		t.Fatalf("types = %v, want SDL declaration order %v", declared, want)
	}
	// The parser's own types sort last, so they can never displace a declared one.
	last, _ := types[len(types)-1].(map[string]any)
	name, _ := last["name"].(string)
	if !strings.HasPrefix(name, "__") && !builtInScalars[name] {
		t.Fatalf("a caller-declared type sorted after the built-ins: %q", name)
	}
}

var builtInScalars = map[string]bool{"String": true, "Int": true, "Float": true, "Boolean": true, "ID": true}
