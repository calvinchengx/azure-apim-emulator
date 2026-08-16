package graphql

import (
	"encoding/json"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Resolve produces the value of one field. The gateway supplies it, because
// running a resolver means running policy and making an HTTP call, neither of
// which belongs in this package.
//
// arguments are the field's arguments with variables already substituted;
// parent is the object the field is being resolved on, nil at the root.
type Resolve func(typeName, fieldName string, arguments, parent map[string]any) (any, error)

// HasResolver reports whether a resolver is registered for a type and field.
// Execution asks before descending, so a field with no resolver is served from
// its parent's payload rather than triggering a call that would fail.
type HasResolver func(typeName, fieldName string) bool

// Execute runs a synthetic GraphQL operation: every root field is produced by a
// resolver rather than by forwarding the query to a backend.
//
// GraphQL's own error contract is what shapes this. A field that fails does NOT
// fail the request: its value becomes null, an entry is added to `errors` with
// the path to the field, and every other field still resolves. Returning a bare
// 500 instead would be easier and would break every client that relies on
// partial data, which is the property GraphQL exists to provide.
func (s *Schema) Execute(operation *Operation, resolve Resolve, has HasResolver) []byte {
	rootType := s.ast.Query
	if operation.Definition.Operation == ast.Mutation {
		rootType = s.ast.Mutation
	}
	if rootType == nil {
		return ErrorMessage("graphql: the schema defines no %s type", operation.Definition.Operation)
	}
	data, errs := s.resolveSelection(operation, rootType, operation.Definition.SelectionSet, nil, nil, resolve, has)
	envelope := map[string]any{"data": data}
	if len(errs) > 0 {
		entries := make([]any, 0, len(errs))
		for _, err := range errs {
			entry := map[string]any{"message": err.Message}
			if len(err.Path) > 0 {
				entry["path"] = err.Path
			}
			entries = append(entries, entry)
		}
		envelope["errors"] = entries
	}
	body, _ := json.Marshal(envelope)
	return body
}

// resolveSelection walks one selection set against one type.
func (s *Schema) resolveSelection(operation *Operation, owner *ast.Definition, set ast.SelectionSet, parent map[string]any, path ast.Path, resolve Resolve, has HasResolver) (map[string]any, gqlerror.List) {
	result := map[string]any{}
	var errs gqlerror.List
	for _, field := range collectFields(operation.Document, set) {
		key := fieldKey(field)
		fieldPath := append(append(ast.Path{}, path...), ast.PathName(key))

		if field.Name == "__typename" {
			result[key] = owner.Name
			continue
		}
		if !has(owner.Name, field.Name) {
			// No resolver: the value comes from the parent payload, which is
			// how a resolver returning a whole object satisfies its subfields
			// without one HTTP call per leaf.
			result[key] = project(operation.Document, field.SelectionSet, parent[field.Name])
			continue
		}
		value, err := resolve(owner.Name, field.Name, fieldArguments(field, operation.Variables), parent)
		if err != nil {
			result[key] = nil
			errs = append(errs, &gqlerror.Error{Message: err.Error(), Path: fieldPath})
			continue
		}
		child := s.ast.Types[field.Definition.Type.Name()]
		if child == nil || len(field.SelectionSet) == 0 {
			result[key] = value
			continue
		}
		resolved, childErrs := s.resolveValue(operation, child, field.SelectionSet, value, fieldPath, resolve, has)
		result[key] = resolved
		errs = append(errs, childErrs...)
	}
	return result, errs
}

// resolveValue applies a selection set to a resolver's return value, descending
// into nested fields that have resolvers of their own and distributing over
// lists.
func (s *Schema) resolveValue(operation *Operation, owner *ast.Definition, set ast.SelectionSet, value any, path ast.Path, resolve Resolve, has HasResolver) (any, gqlerror.List) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case []any:
		var errs gqlerror.List
		items := make([]any, 0, len(typed))
		for index, element := range typed {
			elementPath := append(append(ast.Path{}, path...), ast.PathIndex(index))
			resolved, elementErrs := s.resolveValue(operation, owner, set, element, elementPath, resolve, has)
			items = append(items, resolved)
			errs = append(errs, elementErrs...)
		}
		return items, errs
	case map[string]any:
		return s.resolveSelection(operation, owner, set, typed, path, resolve, has)
	default:
		// A scalar where the schema expects an object. Projecting would hide
		// the mismatch; returning it lets the client see what the resolver
		// actually produced.
		return typed, nil
	}
}

// fieldArguments evaluates a field's arguments, substituting the operation's
// variables. This is what `context.GraphQL.Arguments` reads.
func fieldArguments(field *ast.Field, variables map[string]any) map[string]any {
	arguments := map[string]any{}
	for _, argument := range field.Arguments {
		arguments[argument.Name] = argumentValue(argument.Value, variables)
	}
	// Defaults come from the schema, not the query, so a resolver reading an
	// omitted argument sees the value the schema promised rather than null.
	if field.Definition != nil {
		for _, defined := range field.Definition.Arguments {
			if _, supplied := arguments[defined.Name]; supplied || defined.DefaultValue == nil {
				continue
			}
			arguments[defined.Name] = argumentValue(defined.DefaultValue, variables)
		}
	}
	return arguments
}

// argumentValue cannot fail. Every literal reaching it has already satisfied
// the GraphQL grammar during validation, and the one case Go could still
// reject, a number too large for float64, falls back to its source text rather
// than failing the field. An error return here would be plumbing for a
// condition the parser makes unreachable.
func argumentValue(value *ast.Value, variables map[string]any) any {
	if value == nil {
		return nil
	}
	switch value.Kind {
	case ast.Variable:
		// An absent variable is null, not an error: validation has already
		// rejected a required variable that was not supplied.
		return variables[value.Raw]
	case ast.IntValue, ast.FloatValue:
		number := json.Number(value.Raw)
		if integer, err := number.Int64(); err == nil {
			return integer
		}
		if decimal, err := number.Float64(); err == nil {
			return decimal
		}
		return value.Raw
	case ast.BooleanValue:
		return strings.EqualFold(value.Raw, "true")
	case ast.NullValue:
		return nil
	case ast.ListValue:
		items := make([]any, 0, len(value.Children))
		for _, child := range value.Children {
			items = append(items, argumentValue(child.Value, variables))
		}
		return items
	case ast.ObjectValue:
		object := map[string]any{}
		for _, child := range value.Children {
			object[child.Name] = argumentValue(child.Value, variables)
		}
		return object
	default:
		// String and enum both arrive as their raw text, which is what a
		// resolver interpolating into a URL needs.
		return value.Raw
	}
}
