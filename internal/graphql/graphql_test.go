package graphql

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

const testSDL = `
"A catalogue."
type Query {
  item(id: ID!, locale: String = "en"): Item
  items(first: Int): [Item!]!
  search: SearchResult
  legacy: String @deprecated(reason: "use item")
}
type Mutation { addItem(input: ItemInput!): Item }
interface Node { id: ID! }
"An item."
type Item implements Node {
  id: ID!
  name: String!
  colour: Colour
  tags: [String]
}
type Box implements Node { id: ID! }
union SearchResult = Item | Box
enum Colour { RED GREEN OLD @deprecated }
input ItemInput { name: String! colour: Colour = RED }
`

func mustSchema(t *testing.T) *Schema {
	t.Helper()
	schema, err := Parse(testSDL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return schema
}

func mustOperation(t *testing.T, schema *Schema, query string) *Operation {
	t.Helper()
	operation, errs := schema.Compile(Request{Query: query})
	if len(errs) > 0 {
		t.Fatalf("Compile(%q): %v", query, errs)
	}
	return operation
}

func TestParseRejectsUnusableSchemas(t *testing.T) {
	for name, sdl := range map[string]string{
		"empty":       "   ",
		"not SDL":     "type {{{",
		"no Query":    "type Mutation { go: String }",
		"unknown ref": "type Query { item: Missing }",
	} {
		if _, err := Parse(sdl); err == nil {
			t.Errorf("Parse(%s) accepted an unusable schema", name)
		}
	}
	schema := mustSchema(t)
	if schema.SDL != testSDL {
		t.Fatal("Parse must keep the SDL verbatim, since the ARM schema resource returns what was imported")
	}
	if _, ok := schema.Types()["Item"]; !ok {
		t.Fatal("Types must expose the compiled type map")
	}
}

func TestDecodeRequestReadsEveryTransport(t *testing.T) {
	jsonBody := `{"query":"{ items { id } }","operationName":"","variables":{"n":1}}`
	post := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(jsonBody))
	post.Header.Set("Content-Type", "application/json")
	request, body, err := DecodeRequest(post)
	if err != nil {
		t.Fatalf("JSON POST: %v", err)
	}
	if request.Query != "{ items { id } }" || request.Variables["n"] != float64(1) {
		t.Fatalf("JSON POST decoded to %+v", request)
	}
	if string(body) != jsonBody {
		t.Fatal("the original body must be returned verbatim so pass-through can replay it")
	}

	raw := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("{ items { id } }"))
	raw.Header.Set("Content-Type", "application/graphql; charset=utf-8")
	request, body, err = DecodeRequest(raw)
	if err != nil || request.Query != "{ items { id } }" || string(body) != "{ items { id } }" {
		t.Fatalf("application/graphql POST = %+v %q %v", request, body, err)
	}

	get := httptest.NewRequest(http.MethodGet, `/graphql?query={items{id}}&operationName=Q&variables={"n":2}`, nil)
	request, body, err = DecodeRequest(get)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if request.Query != "{items{id}}" || request.OperationName != "Q" || request.Variables["n"] != float64(2) {
		t.Fatalf("GET decoded to %+v", request)
	}
	if body != nil {
		t.Fatal("a GET has no body to replay, so DecodeRequest must report none")
	}
}

func TestDecodeRequestRefusesWhatItCannotUse(t *testing.T) {
	tests := map[string]*http.Request{
		"GET without a query":  httptest.NewRequest(http.MethodGet, "/graphql", nil),
		"GET bad variables":    httptest.NewRequest(http.MethodGet, "/graphql?query={a}&variables=notjson", nil),
		"unsupported method":   httptest.NewRequest(http.MethodDelete, "/graphql", nil),
		"body is not JSON":     httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("<xml/>")),
		"JSON without a query": httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"  "}`)),
	}
	for name, request := range tests {
		if _, _, err := DecodeRequest(request); err == nil {
			t.Errorf("DecodeRequest accepted %s", name)
		}
	}
	empty := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(" "))
	empty.Header.Set("Content-Type", "application/graphql")
	if _, _, err := DecodeRequest(empty); err == nil {
		t.Error("DecodeRequest accepted an empty application/graphql body")
	}
	oversized := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(strings.Repeat("x", MaxRequestBytes+1)))
	if _, _, err := DecodeRequest(oversized); err == nil {
		t.Error("DecodeRequest accepted a body over the limit")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversized body rejected for the wrong reason: %v", err)
	}
	broken := httptest.NewRequest(http.MethodPost, "/graphql", errReader{})
	if _, _, err := DecodeRequest(broken); err == nil {
		t.Error("DecodeRequest ignored an unreadable body")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, http.ErrBodyReadAfterClose }

func TestEncodeRequestRoundTrips(t *testing.T) {
	encoded := EncodeRequest(Request{Query: "{ items { id } }", OperationName: "Q"})
	var back Request
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back.Query != "{ items { id } }" || back.OperationName != "Q" {
		t.Fatalf("EncodeRequest round-tripped to %+v", back)
	}
}

func TestCompileValidatesAgainstTheSchema(t *testing.T) {
	schema := mustSchema(t)
	if _, errs := schema.Compile(Request{Query: "{ nope }"}); len(errs) == 0 {
		t.Fatal("a field absent from the schema must not compile")
	}
	if _, errs := schema.Compile(Request{Query: "{ item }"}); len(errs) == 0 {
		t.Fatal("a required argument must be enforced")
	}
	if _, errs := schema.Compile(Request{Query: "{ items { id }"}); len(errs) == 0 {
		t.Fatal("a syntax error must not compile")
	}
	if _, errs := schema.Compile(Request{Query: "query A { items { id } } query B { items { id } }"}); len(errs) == 0 {
		t.Fatal("an anonymous request against a two-operation document is ambiguous and must be refused")
	}
	if _, errs := schema.Compile(Request{Query: "query A { items { id } }", OperationName: "Missing"}); len(errs) == 0 {
		t.Fatal("a request naming an absent operation must be refused")
	}
	operation, errs := schema.Compile(Request{Query: "query A { items { id } } query B { legacy }", OperationName: "B"})
	if len(errs) > 0 {
		t.Fatalf("named operation: %v", errs)
	}
	if operation.Definition.Name != "B" {
		t.Fatalf("operationName selected %q", operation.Definition.Name)
	}
}

func TestIsIntrospectionSeparatesMetaFromData(t *testing.T) {
	schema := mustSchema(t)
	cases := map[string]bool{
		"{ __schema { queryType { name } } }":        true,
		"{ __typename }":                             true,
		`{ __type(name: "Item") { name } }`:          true,
		"{ items { id } }":                           false,
		"{ __schema { queryType { name } } legacy }": false,
	}
	for query, want := range cases {
		if got := mustOperation(t, schema, query).IsIntrospection(); got != want {
			t.Errorf("IsIntrospection(%q) = %v, want %v", query, got, want)
		}
	}
}

// A mixed operation is the one that matters: answering it from the schema would
// silently drop `legacy`, returning a response the client cannot tell from a
// complete one.
func TestMixedOperationIsNotTreatedAsIntrospection(t *testing.T) {
	schema := mustSchema(t)
	operation := mustOperation(t, schema, "{ __typename legacy }")
	if operation.IsIntrospection() {
		t.Fatal("an operation selecting real fields alongside meta fields must be forwarded, not answered locally")
	}
}

func TestIsIntrospectionOnAnEmptySelection(t *testing.T) {
	// Reachable only by hand: validation rejects an empty selection set, so this
	// asserts the guard rather than a request any client could send.
	operation := &Operation{Document: &ast.QueryDocument{}, Definition: &ast.OperationDefinition{}}
	if operation.IsIntrospection() {
		t.Fatal("an empty selection is not introspection")
	}
	if len(operation.RootFields()) != 0 {
		t.Fatal("an empty selection has no root fields")
	}
}

func TestRootFieldsFlattensFragments(t *testing.T) {
	schema := mustSchema(t)
	operation := mustOperation(t, schema, "{ ...F legacy } fragment F on Query { items { id } }")
	got := strings.Join(operation.RootFields(), ",")
	if got != "items,legacy" {
		t.Fatalf("RootFields = %q, want the fragment flattened in place", got)
	}
}

// A fragment cycle and a dangling spread cannot survive validation, so they are
// built by parsing without it. Without the guards, the first would recurse
// until the stack died and the second would dereference nil.
func TestFragmentGuardsSurviveInvalidDocuments(t *testing.T) {
	document, err := parser.ParseQuery(&ast.Source{Name: "q", Input: "{ ...Loop } fragment Loop on Query { ...Loop }"})
	if err != nil {
		t.Fatal(err)
	}
	operation := &Operation{Document: document, Definition: document.Operations[0]}
	if fields := operation.RootFields(); len(fields) != 0 {
		t.Fatalf("a self-referential fragment yielded %v", fields)
	}
	document, err = parser.ParseQuery(&ast.Source{Name: "q", Input: "{ ...Missing }"})
	if err != nil {
		t.Fatal(err)
	}
	operation = &Operation{Document: document, Definition: document.Operations[0]}
	if fields := operation.RootFields(); len(fields) != 0 {
		t.Fatalf("a dangling fragment spread yielded %v", fields)
	}
}

func TestErrorBodyCarriesEveryGraphQLErrorMember(t *testing.T) {
	schema := mustSchema(t)
	_, errs := schema.Compile(Request{Query: "{ nope }"})
	if len(errs) == 0 {
		t.Fatal("expected a validation error to render")
	}
	errs[0].Extensions = map[string]any{"code": "GRAPHQL_VALIDATION_FAILED"}
	errs[0].Path = ast.Path{ast.PathName("nope")}
	var decoded struct {
		Errors []struct {
			Message   string           `json:"message"`
			Locations []map[string]int `json:"locations"`
			Path      []any            `json:"path"`
			Ext       map[string]any   `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(ErrorBody(errs), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Errors) != 1 || decoded.Errors[0].Message == "" {
		t.Fatalf("ErrorBody = %+v", decoded)
	}
	if len(decoded.Errors[0].Locations) == 0 || decoded.Errors[0].Locations[0]["line"] == 0 {
		t.Fatal("a validation error must carry its source location")
	}
	if len(decoded.Errors[0].Path) != 1 || decoded.Errors[0].Ext["code"] != "GRAPHQL_VALIDATION_FAILED" {
		t.Fatalf("path and extensions were dropped: %+v", decoded.Errors[0])
	}

	// A FRESH target: unmarshalling into a reused struct merges rather than
	// replaces, so the previous error's locations and extensions would survive
	// and this assertion would be reading the last decode, not this one.
	var plain struct {
		Errors []struct {
			Message   string           `json:"message"`
			Locations []map[string]int `json:"locations"`
			Path      []any            `json:"path"`
			Ext       map[string]any   `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(ErrorMessage("plain %s", "message"), &plain); err != nil {
		t.Fatal(err)
	}
	if plain.Errors[0].Message != "plain message" {
		t.Fatalf("ErrorMessage = %+v", plain.Errors[0])
	}
	if len(plain.Errors[0].Locations) != 0 || len(plain.Errors[0].Path) != 0 || plain.Errors[0].Ext != nil {
		t.Fatalf("ErrorMessage must emit only a message, got %+v", plain.Errors[0])
	}
}
