// Package graphql compiles GraphQL schemas and requests for the gateway.
//
// APIM exposes two GraphQL shapes over one API type. A pass-through API keeps a
// GraphQL backend and forwards to it; a synthetic API has no backend at all and
// answers each field from a resolver. Both share the schema, the request
// grammar, validation, and introspection, which is what lives here.
//
// Only pass-through is implemented. Synthetic GraphQL is deliberately absent
// rather than approximated: an APIM resolver reaches its arguments through
// policy expressions (`context.GraphQL.Arguments`), so a resolver that took any
// other syntax would be a shape no Azure user could copy, and an emulator whose
// syntax is nearly right is worse than one that says the feature is missing.
// The parity ledger grades GraphQL `partial` for exactly this reason.
package graphql

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// MaxRequestBytes bounds a decoded GraphQL request body. APIM rejects oversized
// GraphQL payloads before parsing; so do we, because a parser is a far larger
// attack surface than a length check.
const MaxRequestBytes = 1 << 20

// Schema is a parsed GraphQL schema plus the SDL it came from. The SDL is kept
// verbatim because the ARM schema resource returns exactly what was imported,
// not a re-print: re-printing loses comments and reorders, and a caller
// comparing what it PUT against what it GETs would see a spurious difference.
type Schema struct {
	SDL string
	ast *ast.Schema
}

// Parse compiles SDL into a schema. An SDL with no Query type is rejected here
// rather than at request time, so a bad import fails on import.
func Parse(sdl string) (*Schema, error) {
	if strings.TrimSpace(sdl) == "" {
		return nil, errors.New("graphql: schema document is empty")
	}
	compiled, err := gqlparser.LoadSchema(&ast.Source{Name: "schema.graphql", Input: sdl})
	if err != nil {
		return nil, fmt.Errorf("graphql: %w", err)
	}
	if compiled.Query == nil {
		return nil, errors.New("graphql: schema defines no Query type")
	}
	return &Schema{SDL: sdl, ast: compiled}, nil
}

// Types exposes the compiled type map for resolver validation.
func (s *Schema) Types() map[string]*ast.Definition { return s.ast.Types }

// Request is a decoded GraphQL request, whichever transport carried it.
type Request struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
}

// DecodeRequest reads the three transports the GraphQL-over-HTTP spec defines,
// and that APIM accepts: a JSON POST body, a raw application/graphql POST body,
// and a GET with the query in the query string. The body is returned alongside
// so a pass-through API can forward the exact bytes it received rather than a
// re-encoding, which would drop unknown members such as `extensions`.
func DecodeRequest(req *http.Request) (Request, []byte, error) {
	if req.Method == http.MethodGet {
		values := req.URL.Query()
		parsed := Request{Query: values.Get("query"), OperationName: values.Get("operationName")}
		if raw := values.Get("variables"); raw != "" {
			if err := json.Unmarshal([]byte(raw), &parsed.Variables); err != nil {
				return Request{}, nil, fmt.Errorf("graphql: variables is not valid JSON: %w", err)
			}
		}
		if parsed.Query == "" {
			return Request{}, nil, errors.New("graphql: GET request carries no query")
		}
		return parsed, nil, nil
	}
	if req.Method != http.MethodPost {
		return Request{}, nil, fmt.Errorf("graphql: %s is not supported, use GET or POST", req.Method)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxRequestBytes+1))
	if err != nil {
		return Request{}, nil, fmt.Errorf("graphql: cannot read request body: %w", err)
	}
	if len(body) > MaxRequestBytes {
		return Request{}, nil, fmt.Errorf("graphql: request body exceeds %d bytes", MaxRequestBytes)
	}
	mediaType := strings.TrimSpace(strings.SplitN(req.Header.Get("Content-Type"), ";", 2)[0])
	if strings.EqualFold(mediaType, "application/graphql") {
		if strings.TrimSpace(string(body)) == "" {
			return Request{}, nil, errors.New("graphql: request carries no query")
		}
		return Request{Query: string(body)}, body, nil
	}
	var parsed Request
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Request{}, nil, fmt.Errorf("graphql: request body is not valid JSON: %w", err)
	}
	if strings.TrimSpace(parsed.Query) == "" {
		return Request{}, nil, errors.New("graphql: request carries no query")
	}
	return parsed, body, nil
}

// Operation is a request validated against a schema and narrowed to the single
// operation it selects.
type Operation struct {
	Document   *ast.QueryDocument
	Definition *ast.OperationDefinition
	Variables  map[string]any
}

// Compile parses and validates a request against the schema. The returned
// error list is already in GraphQL error shape, so a caller can hand it
// straight to ErrorBody.
func (s *Schema) Compile(request Request) (*Operation, gqlerror.List) {
	// DEFERRED. LoadQuery is deprecated for LoadQueryWithRules, which takes an
	// explicit rule set. Passing the wrong set silently changes which queries
	// this gateway accepts, so it wants its own change with the GraphQL
	// witnesses re-run, not a swap inside a lint sweep.
	//nolint:staticcheck // SA1019: LoadQueryWithRules migration tracked separately
	document, errs := gqlparser.LoadQuery(s.ast, request.Query)
	if len(errs) > 0 {
		return nil, errs
	}
	definition, err := selectOperation(document, request.OperationName)
	if err != nil {
		return nil, gqlerror.List{gqlerror.Errorf("%s", err.Error())}
	}
	return &Operation{Document: document, Definition: definition, Variables: request.Variables}, nil
}

// selectOperation implements the spec's GetOperation: a named request picks by
// name, an anonymous one requires exactly one operation in the document.
func selectOperation(document *ast.QueryDocument, name string) (*ast.OperationDefinition, error) {
	if name == "" {
		if len(document.Operations) != 1 {
			return nil, fmt.Errorf("operationName is required when the document defines %d operations", len(document.Operations))
		}
		return document.Operations[0], nil
	}
	for _, candidate := range document.Operations {
		if candidate.Name == name {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("no operation named %q in the document", name)
}

// IsIntrospection reports whether every root field is an introspection meta
// field. Such an operation is answered from the schema and never reaches a
// backend, which is what makes a pass-through API introspectable even when its
// backend has introspection switched off.
//
// A mixed operation is deliberately NOT introspection: it asks for real data
// too, so answering it locally would silently drop those fields.
func (o *Operation) IsIntrospection() bool {
	fields := collectFields(o.Document, o.Definition.SelectionSet)
	if len(fields) == 0 {
		return false
	}
	for _, field := range fields {
		if !strings.HasPrefix(field.Name, "__") {
			return false
		}
	}
	return true
}

// RootFields names the operation's root fields, for resolver dispatch and for
// naming the operation in traces.
func (o *Operation) RootFields() []string {
	var names []string
	for _, field := range collectFields(o.Document, o.Definition.SelectionSet) {
		names = append(names, field.Name)
	}
	return names
}

// collectFields flattens fragments into the concrete fields of one selection
// set, which is what both projection and resolver dispatch need.
func collectFields(document *ast.QueryDocument, set ast.SelectionSet) []*ast.Field {
	return appendFields(document, set, nil, map[string]bool{})
}

func appendFields(document *ast.QueryDocument, set ast.SelectionSet, into []*ast.Field, visiting map[string]bool) []*ast.Field {
	for _, selection := range set {
		switch value := selection.(type) {
		case *ast.Field:
			into = append(into, value)
		case *ast.InlineFragment:
			into = appendFields(document, value.SelectionSet, into, visiting)
		case *ast.FragmentSpread:
			if visiting[value.Name] {
				continue
			}
			fragment := document.Fragments.ForName(value.Name)
			if fragment == nil {
				continue
			}
			visiting[value.Name] = true
			into = appendFields(document, fragment.SelectionSet, into, visiting)
			delete(visiting, value.Name)
		}
	}
	return into
}

// EncodeRequest renders a request as the canonical JSON POST body, for when the
// caller used a transport the backend may not accept.
func EncodeRequest(request Request) []byte {
	body, _ := json.Marshal(request)
	return body
}

// ErrorBody renders a GraphQL error response body: `{"errors":[...]}`, which is
// the only shape GraphQL defines for reporting failure. The caller chooses the
// HTTP status, because the same body means different things at 200 and at 400,
// and only the caller knows whether execution began.
func ErrorBody(errs gqlerror.List) []byte {
	entries := make([]any, 0, len(errs))
	for _, err := range errs {
		entry := map[string]any{"message": err.Message}
		if len(err.Locations) > 0 {
			locations := make([]any, 0, len(err.Locations))
			for _, location := range err.Locations {
				locations = append(locations, map[string]any{"line": location.Line, "column": location.Column})
			}
			entry["locations"] = locations
		}
		if len(err.Path) > 0 {
			entry["path"] = err.Path
		}
		if len(err.Extensions) > 0 {
			entry["extensions"] = err.Extensions
		}
		entries = append(entries, entry)
	}
	body, _ := json.Marshal(map[string]any{"errors": entries})
	return body
}

// ErrorMessage renders a single-message GraphQL error response.
func ErrorMessage(format string, args ...any) []byte {
	return ErrorBody(gqlerror.List{gqlerror.Errorf(format, args...)})
}

// Introspect answers an introspection operation from the schema, projected onto
// exactly the fields the operation asked for.
//
// Projecting rather than returning the whole document matters: a client is
// entitled to assume a GraphQL response contains the fields it selected and no
// others. Returning extras happens to work with graphql-js buildClientSchema,
// which reads what it needs, and would hide the day a client depends on the
// stricter contract.
func (s *Schema) Introspect(operation *Operation) []byte {
	root := map[string]any{
		"__typename": "Query",
		"__schema":   s.schemaValue(),
		"__type":     nil,
	}
	fields := collectFields(operation.Document, operation.Definition.SelectionSet)
	for _, field := range fields {
		if field.Name != "__type" {
			continue
		}
		name := ""
		for _, argument := range field.Arguments {
			if argument.Name == "name" && argument.Value != nil {
				name = argument.Value.Raw
			}
		}
		if definition, ok := s.ast.Types[name]; ok {
			root["__type"] = s.typeValue(definition)
		}
	}
	data := project(operation.Document, operation.Definition.SelectionSet, root)
	body, _ := json.Marshal(map[string]any{"data": data})
	return body
}

func (s *Schema) schemaValue() map[string]any {
	// Declaration order, not alphabetical.
	//
	// A real server's introspection reflects the order its schema was defined
	// in, and every tool that prints a schema back from introspection
	// (graphql-codegen, get-graphql-schema, printSchema) reproduces that order.
	// Sorting alphabetically produces a schema that is equivalent but not
	// identical, so a caller diffing a generated schema against the source SDL
	// sees churn the emulator invented.
	//
	// The prelude's built-in and introspection types have no place in the
	// source, so they sort after everything declared, alphabetically among
	// themselves for stability.
	names := make([]string, 0, len(s.ast.Types))
	for name := range s.ast.Types {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		left, right := s.ast.Types[names[i]], s.ast.Types[names[j]]
		leftDeclared, rightDeclared := declarationOffset(left), declarationOffset(right)
		if leftDeclared != rightDeclared {
			return leftDeclared < rightDeclared
		}
		return names[i] < names[j]
	})
	types := make([]any, 0, len(names))
	for _, name := range names {
		types = append(types, s.typeValue(s.ast.Types[name]))
	}
	directiveNames := make([]string, 0, len(s.ast.Directives))
	for name, definition := range s.ast.Directives {
		if !advertisedDirective(name, definition) {
			continue
		}
		directiveNames = append(directiveNames, name)
	}
	sort.Strings(directiveNames)
	directives := make([]any, 0, len(directiveNames))
	for _, name := range directiveNames {
		directives = append(directives, s.directiveValue(s.ast.Directives[name]))
	}
	value := map[string]any{
		"__typename":       "__Schema",
		"description":      nullableString(s.ast.Description),
		"types":            types,
		"directives":       directives,
		"queryType":        s.namedRef(s.ast.Query),
		"mutationType":     s.namedRef(s.ast.Mutation),
		"subscriptionType": s.namedRef(s.ast.Subscription),
	}
	return value
}

func (s *Schema) namedRef(definition *ast.Definition) any {
	if definition == nil {
		return nil
	}
	return map[string]any{"__typename": "__Type", "name": definition.Name, "kind": kindOf(definition)}
}

func (s *Schema) typeValue(definition *ast.Definition) map[string]any {
	value := map[string]any{
		"__typename":     "__Type",
		"kind":           kindOf(definition),
		"name":           definition.Name,
		"description":    nullableString(definition.Description),
		"specifiedByURL": nil,
		"ofType":         nil,
		"fields":         nil,
		"inputFields":    nil,
		"interfaces":     nil,
		"enumValues":     nil,
		"possibleTypes":  nil,
	}
	switch definition.Kind {
	case ast.Object, ast.Interface:
		fields := make([]any, 0, len(definition.Fields))
		for _, field := range definition.Fields {
			// __typename is available everywhere but is never listed as a field
			// of a type; listing it makes buildClientSchema construct a schema
			// that disagrees with every real server.
			if strings.HasPrefix(field.Name, "__") {
				continue
			}
			fields = append(fields, s.fieldValue(field))
		}
		value["fields"] = fields
		interfaces := make([]any, 0, len(definition.Interfaces))
		for _, name := range definition.Interfaces {
			if implemented, ok := s.ast.Types[name]; ok {
				interfaces = append(interfaces, s.namedRef(implemented))
			}
		}
		value["interfaces"] = interfaces
		if definition.Kind == ast.Interface {
			value["interfaces"] = nil
			value["possibleTypes"] = s.possibleTypes(definition)
		}
	case ast.Union:
		value["possibleTypes"] = s.possibleTypes(definition)
	case ast.Enum:
		enumValues := make([]any, 0, len(definition.EnumValues))
		for _, enumValue := range definition.EnumValues {
			deprecated, reason := deprecation(enumValue.Directives)
			enumValues = append(enumValues, map[string]any{
				"__typename": "__EnumValue", "name": enumValue.Name,
				"description":  nullableString(enumValue.Description),
				"isDeprecated": deprecated, "deprecationReason": reason,
			})
		}
		value["enumValues"] = enumValues
	case ast.InputObject:
		inputFields := make([]any, 0, len(definition.Fields))
		for _, field := range definition.Fields {
			inputFields = append(inputFields, s.inputValue(field.Name, field.Description, field.Type, field.DefaultValue, field.Directives))
		}
		value["inputFields"] = inputFields
	}
	return value
}

func (s *Schema) possibleTypes(definition *ast.Definition) []any {
	possible := make([]any, 0)
	if definition.Kind == ast.Union {
		for _, name := range definition.Types {
			if member, ok := s.ast.Types[name]; ok {
				possible = append(possible, s.namedRef(member))
			}
		}
		return possible
	}
	names := make([]string, 0)
	for name, candidate := range s.ast.Types {
		if candidate.Kind != ast.Object {
			continue
		}
		for _, implemented := range candidate.Interfaces {
			if implemented == definition.Name {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	for _, name := range names {
		possible = append(possible, s.namedRef(s.ast.Types[name]))
	}
	return possible
}

func (s *Schema) fieldValue(field *ast.FieldDefinition) map[string]any {
	args := make([]any, 0, len(field.Arguments))
	for _, argument := range field.Arguments {
		args = append(args, s.inputValue(argument.Name, argument.Description, argument.Type, argument.DefaultValue, argument.Directives))
	}
	deprecated, reason := deprecation(field.Directives)
	return map[string]any{
		"__typename": "__Field", "name": field.Name,
		"description": nullableString(field.Description), "args": args,
		"type": s.typeRef(field.Type), "isDeprecated": deprecated, "deprecationReason": reason,
	}
}

func (s *Schema) inputValue(name, description string, kind *ast.Type, defaultValue *ast.Value, directives ast.DirectiveList) map[string]any {
	deprecated, reason := deprecation(directives)
	value := map[string]any{
		"__typename": "__InputValue", "name": name,
		"description": nullableString(description), "type": s.typeRef(kind),
		"defaultValue": nil, "isDeprecated": deprecated, "deprecationReason": reason,
	}
	if defaultValue != nil {
		value["defaultValue"] = defaultValue.String()
	}
	return value
}

// typeRef renders a type reference as the spec's nested wrapper chain, which is
// how NON_NULL and LIST are expressed: [Item!]! is NON_NULL(LIST(NON_NULL(Item))).
func (s *Schema) typeRef(kind *ast.Type) map[string]any {
	if kind == nil {
		return nil
	}
	if kind.NonNull {
		inner := *kind
		inner.NonNull = false
		return map[string]any{"__typename": "__Type", "kind": "NON_NULL", "name": nil, "ofType": s.typeRef(&inner)}
	}
	if kind.Elem != nil {
		return map[string]any{"__typename": "__Type", "kind": "LIST", "name": nil, "ofType": s.typeRef(kind.Elem)}
	}
	named := map[string]any{"__typename": "__Type", "name": kind.NamedType, "ofType": nil, "kind": "SCALAR"}
	if definition, ok := s.ast.Types[kind.NamedType]; ok {
		named["kind"] = kindOf(definition)
	}
	return named
}

func (s *Schema) directiveValue(definition *ast.DirectiveDefinition) map[string]any {
	args := make([]any, 0, len(definition.Arguments))
	for _, argument := range definition.Arguments {
		args = append(args, s.inputValue(argument.Name, argument.Description, argument.Type, argument.DefaultValue, argument.Directives))
	}
	locations := make([]any, 0, len(definition.Locations))
	for _, location := range definition.Locations {
		locations = append(locations, string(location))
	}
	return map[string]any{
		"__typename": "__Directive", "name": definition.Name,
		"description": nullableString(definition.Description),
		"locations":   locations, "args": args, "isRepeatable": definition.IsRepeatable,
	}
}

// declarationOffset orders a type by where it was declared in the imported SDL.
// Types the parser supplied rather than the caller sort last, as math.MaxInt.
func declarationOffset(definition *ast.Definition) int {
	if definition.Position == nil || definition.Position.Src == nil || definition.Position.Src.BuiltIn {
		return math.MaxInt
	}
	return definition.Position.Start
}

// specDirectives are the directives the GraphQL specification defines and every
// conforming server advertises.
var specDirectives = map[string]bool{"skip": true, "include": true, "deprecated": true, "specifiedBy": true, "oneOf": true}

// advertisedDirective decides whether introspection should mention a directive.
//
// Everything declared in the imported SDL is advertised, plus the spec's own
// directives. What is filtered out is the extras our PARSER injects into its
// prelude: gqlparser supplies @defer, which belongs to incremental delivery, a
// protocol this gateway does not implement.
//
// Advertising it would be the worst kind of emulator defect. A client reads
// introspection, sees @defer, sends a deferred query, and gets a single
// non-incremental response that its parser cannot reconcile. The failure lands
// on the client, far from the emulator that promised the capability, and it
// would not reproduce against real Azure. An emulator must never claim a
// capability by accident of its dependencies.
func advertisedDirective(name string, definition *ast.DirectiveDefinition) bool {
	if definition.Position == nil || definition.Position.Src == nil || !definition.Position.Src.BuiltIn {
		return true
	}
	return specDirectives[name]
}

func kindOf(definition *ast.Definition) string {
	switch definition.Kind {
	case ast.Scalar:
		return "SCALAR"
	case ast.Object:
		return "OBJECT"
	case ast.Interface:
		return "INTERFACE"
	case ast.Union:
		return "UNION"
	case ast.Enum:
		return "ENUM"
	case ast.InputObject:
		return "INPUT_OBJECT"
	}
	return "SCALAR"
}

func deprecation(directives ast.DirectiveList) (bool, any) {
	directive := directives.ForName("deprecated")
	if directive == nil {
		return false, nil
	}
	reason := "No longer supported"
	if argument := directive.Arguments.ForName("reason"); argument != nil && argument.Value != nil {
		reason = argument.Value.Raw
	}
	return true, reason
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
