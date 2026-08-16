package graphql

import (
	"github.com/vektah/gqlparser/v2/ast"
)

// project narrows a value to exactly the fields a selection set asked for.
//
// This is the half of GraphQL that a REST proxy cannot skip. A resolver returns
// whatever its HTTP backend returns, and the caller asked for a named subset; a
// gateway that forwards the backend's shape unchanged leaks fields nobody
// selected, and every one of those is a field the client did not agree to
// receive. The same function serves introspection, so both paths obey one
// implementation of the rule rather than two that can drift.
//
// Values are decoded JSON: map[string]any for objects, []any for lists, and
// scalars otherwise. A selection against a scalar returns the scalar, which is
// how a resolver returning a plain value still satisfies a leaf field.
func project(document *ast.QueryDocument, set ast.SelectionSet, value any) any {
	if value == nil {
		return nil
	}
	if len(set) == 0 {
		return value
	}
	switch typed := value.(type) {
	case []any:
		// A list distributes the selection over its members rather than
		// consuming it, so [Item!]! and Item share one selection set.
		projected := make([]any, 0, len(typed))
		for _, element := range typed {
			projected = append(projected, project(document, set, element))
		}
		return projected
	case map[string]any:
		result := map[string]any{}
		for _, field := range collectFields(document, set) {
			key := field.Alias
			if key == "" {
				key = field.Name
			}
			if field.Name == "__typename" {
				// __typename is answered from the value's own marker, not from
				// the schema, because a union member's concrete type is only
				// knowable from the value.
				result[key] = typed["__typename"]
				continue
			}
			child, ok := typed[field.Name]
			if !ok {
				// A selected field the resolver did not return is null, per the
				// spec, rather than absent. Absent would let a client tell
				// "missing" from "null" and depend on the difference.
				result[key] = nil
				continue
			}
			result[key] = project(document, field.SelectionSet, child)
		}
		return result
	default:
		return typed
	}
}
