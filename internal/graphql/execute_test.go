package graphql

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
)

const shopSDL = `
type Query { orders(first: Int = 5): [Order!]! order(ref: ID!): Order lookup(ref: ID): Order note: String }
type Mutation { place(input: OrderInput!): Order }
type Order { ref: ID! total: Int customerId: String customer: Customer }
type Customer { id: ID! name: String! }
input OrderInput { ref: ID! }
`

type recorder struct {
	calls  []string
	args   map[string]map[string]any
	parent map[string]map[string]any
	values map[string]any
	fail   map[string]error
}

func newRecorder() *recorder {
	return &recorder{args: map[string]map[string]any{}, parent: map[string]map[string]any{}, values: map[string]any{}, fail: map[string]error{}}
}

func (r *recorder) has(typeName, field string) bool {
	_, ok := r.values[typeName+"."+field]
	if !ok {
		_, ok = r.fail[typeName+"."+field]
	}
	return ok
}

func (r *recorder) resolve(typeName, field string, arguments, parent map[string]any) (any, error) {
	key := typeName + "." + field
	r.calls = append(r.calls, key)
	r.args[key] = arguments
	r.parent[key] = parent
	if err, ok := r.fail[key]; ok {
		return nil, err
	}
	return r.values[key], nil
}

func execute(t *testing.T, sdl, query string, variables map[string]any, rec *recorder) map[string]any {
	t.Helper()
	schema, err := Parse(sdl)
	if err != nil {
		t.Fatal(err)
	}
	operation, errs := schema.Compile(Request{Query: query, Variables: variables})
	if len(errs) > 0 {
		t.Fatalf("Compile(%q): %v", query, errs)
	}
	var envelope map[string]any
	if err := json.Unmarshal(schema.Execute(operation, rec.resolve, rec.has), &envelope); err != nil {
		t.Fatalf("Execute produced invalid JSON: %v", err)
	}
	return envelope
}

func dataOf(t *testing.T, envelope map[string]any) map[string]any {
	t.Helper()
	value, _ := envelope["data"].(map[string]any)
	if value == nil {
		t.Fatalf("response has no data: %v", envelope)
	}
	return value
}

// A resolver's payload is projected onto the selection, so a REST backend
// returning more than was asked for does not leak the extra fields.
func TestExecuteProjectsResolverPayloadOntoTheSelection(t *testing.T) {
	rec := newRecorder()
	rec.values["Query.orders"] = []any{
		map[string]any{"ref": "A-1", "total": float64(25), "customerId": "c1"},
		map[string]any{"ref": "A-2", "total": float64(40), "customerId": "c2"},
	}
	data := dataOf(t, execute(t, shopSDL, "{ orders { ref } }", nil, rec))
	orders, _ := data["orders"].([]any)
	if len(orders) != 2 {
		t.Fatalf("orders = %v", orders)
	}
	for _, entry := range orders {
		order, _ := entry.(map[string]any)
		if len(order) != 1 || order["ref"] == nil {
			t.Fatalf("unselected fields leaked into %v", order)
		}
	}
}

// Arguments are what a resolver policy reads through context.GraphQL.Arguments.
func TestExecutePassesArgumentsIncludingDefaults(t *testing.T) {
	rec := newRecorder()
	rec.values["Query.orders"] = []any{}
	rec.values["Query.order"] = map[string]any{"ref": "Z-9"}

	execute(t, shopSDL, `{ order(ref: "Z-9") { ref } }`, nil, rec)
	if got := rec.args["Query.order"]["ref"]; got != "Z-9" {
		t.Fatalf("literal argument = %v", got)
	}

	// A schema default the caller omitted still reaches the resolver, because
	// the schema promised it.
	execute(t, shopSDL, "{ orders { ref } }", nil, rec)
	if got := rec.args["Query.orders"]["first"]; got != int64(5) {
		t.Fatalf("default argument = %v (%T), want int64(5)", got, got)
	}

	// An explicit value wins over the default.
	execute(t, shopSDL, "{ orders(first: 2) { ref } }", nil, rec)
	if got := rec.args["Query.orders"]["first"]; got != int64(2) {
		t.Fatalf("explicit argument = %v", got)
	}
}

func TestExecuteSubstitutesVariables(t *testing.T) {
	rec := newRecorder()
	rec.values["Query.order"] = map[string]any{"ref": "V-1"}
	execute(t, shopSDL, "query Get($r: ID!) { order(ref: $r) { ref } }", map[string]any{"r": "V-1"}, rec)
	if got := rec.args["Query.order"]["ref"]; got != "V-1" {
		t.Fatalf("variable argument = %v", got)
	}
	// A variable the caller did not supply is null rather than an error:
	// validation has already rejected a required one that is missing.
	rec2 := newRecorder()
	rec2.values["Query.lookup"] = map[string]any{"ref": "x"}
	execute(t, shopSDL, "query Get($r: ID) { lookup(ref: $r) { ref } }", nil, rec2)
	if got, present := rec2.args["Query.lookup"]["ref"]; !present || got != nil {
		t.Fatalf("absent variable = %v present=%v, want a present null", got, present)
	}
}

// A nested resolver reads its parent object, which is how Order.customer
// resolves from the customerId the Query.orders resolver returned.
func TestExecuteDescendsIntoNestedResolvers(t *testing.T) {
	rec := newRecorder()
	rec.values["Query.orders"] = []any{map[string]any{"ref": "A-1", "customerId": "c1"}}
	rec.values["Order.customer"] = map[string]any{"id": "c1", "name": "Ada"}
	data := dataOf(t, execute(t, shopSDL, "{ orders { ref customer { id name } } }", nil, rec))
	orders, _ := data["orders"].([]any)
	first, _ := orders[0].(map[string]any)
	customer, _ := first["customer"].(map[string]any)
	if customer["id"] != "c1" || customer["name"] != "Ada" {
		t.Fatalf("nested resolver produced %v", customer)
	}
	if got := rec.parent["Order.customer"]["customerId"]; got != "c1" {
		t.Fatalf("the nested resolver's parent was %v; it must be the order object", rec.parent["Order.customer"])
	}
}

// A field with no resolver is served from the parent payload rather than
// triggering a call, which is what lets one resolver satisfy a whole subtree.
func TestExecuteServesUnresolvedFieldsFromTheParent(t *testing.T) {
	rec := newRecorder()
	rec.values["Query.order"] = map[string]any{"ref": "A-1", "total": float64(25)}
	data := dataOf(t, execute(t, shopSDL, `{ order(ref: "A-1") { ref total } }`, nil, rec))
	order, _ := data["order"].(map[string]any)
	if order["total"] != float64(25) {
		t.Fatalf("total = %v", order["total"])
	}
	for _, call := range rec.calls {
		if call == "Order.total" {
			t.Fatal("a field with no resolver must not trigger a resolver call")
		}
	}
}

// The partial-failure contract: a failing field is null and reported by path,
// its siblings still resolve, and the transport stays 200 because execution ran.
func TestExecuteReportsFieldFailuresWithoutFailingTheRequest(t *testing.T) {
	rec := newRecorder()
	rec.values["Query.order"] = map[string]any{"ref": "A-1"}
	rec.fail["Query.note"] = errors.New("backend returned 500")
	envelope := execute(t, shopSDL, `{ ok: order(ref: "A-1") { ref } note }`, nil, rec)
	data := dataOf(t, envelope)
	healthy, _ := data["ok"].(map[string]any)
	if healthy["ref"] != "A-1" {
		t.Fatalf("the healthy sibling must still resolve, got %v", data["ok"])
	}
	if value, present := data["note"]; !present || value != nil {
		t.Fatalf("the failing field must be present and null, got %v present=%v", value, present)
	}
	errs, _ := envelope["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("errors = %v", envelope["errors"])
	}
	entry, _ := errs[0].(map[string]any)
	path, _ := entry["path"].([]any)
	if len(path) != 1 || path[0] != "note" {
		t.Fatalf("error path = %v, want the failing field", entry["path"])
	}
	if message, _ := entry["message"].(string); message == "" {
		t.Fatal("the error must carry a message")
	}
}

// A list distributes the selection and the error path carries the index, so a
// caller can tell WHICH element failed.
func TestExecuteIndexesErrorsInsideLists(t *testing.T) {
	rec := newRecorder()
	rec.values["Query.orders"] = []any{
		map[string]any{"ref": "A-1", "customerId": "c1"},
		map[string]any{"ref": "A-2", "customerId": "c2"},
	}
	rec.fail["Order.customer"] = errors.New("unreachable")
	envelope := execute(t, shopSDL, "{ orders { ref customer { id } } }", nil, rec)
	errs, _ := envelope["errors"].([]any)
	if len(errs) != 2 {
		t.Fatalf("a failure per element expected, got %v", envelope["errors"])
	}
	entry, _ := errs[0].(map[string]any)
	path, _ := entry["path"].([]any)
	if len(path) != 3 || path[0] != "orders" || path[1] != float64(0) || path[2] != "customer" {
		t.Fatalf("error path = %v, want orders/0/customer", entry["path"])
	}
}

func TestExecuteAnswersTypenameAndScalars(t *testing.T) {
	rec := newRecorder()
	rec.values["Query.note"] = "hello"
	data := dataOf(t, execute(t, shopSDL, "{ __typename note }", nil, rec))
	if data["__typename"] != "Query" {
		t.Fatalf("__typename = %v", data["__typename"])
	}
	if data["note"] != "hello" {
		t.Fatalf("scalar resolver = %v", data["note"])
	}
	// A resolver returning a scalar where the schema expects an object is
	// surfaced rather than projected away, so the mismatch is visible.
	rec2 := newRecorder()
	rec2.values["Query.order"] = "not an object"
	data2 := dataOf(t, execute(t, shopSDL, `{ order(ref: "x") { ref } }`, nil, rec2))
	if data2["order"] != "not an object" {
		t.Fatalf("scalar-for-object = %v", data2["order"])
	}
	// And a null resolver result stays null.
	rec3 := newRecorder()
	rec3.values["Query.order"] = nil
	data3 := dataOf(t, execute(t, shopSDL, `{ order(ref: "x") { ref } }`, nil, rec3))
	if value, present := data3["order"]; !present || value != nil {
		t.Fatalf("null resolver result = %v present=%v", value, present)
	}
}

func TestExecuteRunsMutations(t *testing.T) {
	rec := newRecorder()
	rec.values["Mutation.place"] = map[string]any{"ref": "M-1"}
	data := dataOf(t, execute(t, shopSDL, `mutation { place(input: {ref: "M-1"}) { ref } }`, nil, rec))
	order, _ := data["place"].(map[string]any)
	if order["ref"] != "M-1" {
		t.Fatalf("mutation = %v", data["place"])
	}
	if got, _ := rec.args["Mutation.place"]["input"].(map[string]any); got["ref"] != "M-1" {
		t.Fatalf("object argument = %v", rec.args["Mutation.place"]["input"])
	}
}

// A schema with no Mutation type cannot run one. Validation normally catches
// this, so the guard exists for a schema compiled without one.
func TestExecuteRefusesAnAbsentRootType(t *testing.T) {
	schema, err := Parse("type Query { a: String }")
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := Parse("type Query { a: String } type Mutation { b: String }")
	if err != nil {
		t.Fatal(err)
	}
	operation, errs := mutation.Compile(Request{Query: "mutation { b }"})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	rec := newRecorder()
	var envelope map[string]any
	if err := json.Unmarshal(schema.Execute(operation, rec.resolve, rec.has), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["errors"] == nil {
		t.Fatalf("executing a mutation against a schema with no Mutation type must error, got %v", envelope)
	}
}

// A number too large for float64 falls back to its source text rather than
// failing the field, and a nil literal is null. Both are unreachable through
// the parser, so they are asserted directly.
func TestArgumentValueDegradesRatherThanFailing(t *testing.T) {
	huge := "1" + strings.Repeat("0", 400)
	if got := argumentValue(&ast.Value{Kind: ast.FloatValue, Raw: huge}, nil); got != huge {
		t.Fatalf("an unrepresentable number = %v, want its source text", got)
	}
	if got := argumentValue(nil, nil); got != nil {
		t.Fatalf("a nil literal = %v, want null", got)
	}
}

func TestArgumentValueCoversEveryLiteralKind(t *testing.T) {
	rec := newRecorder()
	rec.values["Mutation.place"] = map[string]any{"ref": "L"}
	sdl := `
type Query { a: String }
type Mutation { place(input: Wide!): Order }
type Order { ref: ID! }
input Wide { ref: ID! count: Int ratio: Float on: Boolean off: Boolean missing: String tags: [String] nested: Inner }
input Inner { x: Int }
`
	query := `mutation { place(input: {ref: "R", count: 7, ratio: 1.5, on: true, off: false, missing: null, tags: ["a","b"], nested: {x: 1}}) { ref } }`
	execute(t, sdl, query, nil, rec)
	input, _ := rec.args["Mutation.place"]["input"].(map[string]any)
	if input["ref"] != "R" || input["count"] != int64(7) || input["ratio"] != 1.5 {
		t.Fatalf("scalar literals = %v", input)
	}
	if input["on"] != true || input["off"] != false {
		t.Fatalf("boolean literals = %v", input)
	}
	if value, present := input["missing"]; !present || value != nil {
		t.Fatalf("null literal = %v present=%v", value, present)
	}
	tags, _ := input["tags"].([]any)
	if len(tags) != 2 || tags[0] != "a" {
		t.Fatalf("list literal = %v", input["tags"])
	}
	nested, _ := input["nested"].(map[string]any)
	if nested["x"] != int64(1) {
		t.Fatalf("object literal = %v", input["nested"])
	}
}
