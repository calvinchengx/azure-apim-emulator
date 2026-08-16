package expression

import (
	"encoding/json"
	"fmt"
)

// GraphQLContext is the `context.GraphQL` binding available inside a GraphQL
// resolver's policy.
//
// This is the whole reason synthetic GraphQL could not be approximated. An APIM
// resolver has no other way to read the field arguments it is resolving: the
// documented shape is `context.GraphQL.Arguments["id"]`, and a resolver taking
// any other syntax would be a shape no Azure user could copy into this
// emulator or out of it.
//
// Values are decoded JSON, so an argument is whatever the caller sent:
// string, number, bool, null, list, or object.
type GraphQLContext struct {
	// Arguments are the arguments of the field being resolved, with the
	// operation's variables already substituted.
	Arguments map[string]any
	// Parent is the object the field is being resolved on. It is null at the
	// root, which is why a resolver on Query cannot read it.
	Parent map[string]any
}

type graphQLHost struct {
	ctx *GraphQLContext
}

func (h *graphQLHost) member(name string) (Value, error) {
	switch name {
	case "Arguments":
		return Object(&jsonMapHost{values: h.ctx.Arguments}), nil
	case "Parent":
		if h.ctx.Parent == nil {
			return Null(), nil
		}
		return Object(&jsonMapHost{values: h.ctx.Parent}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

// jsonMapHost exposes a decoded JSON object to expressions, both by index
// (`Arguments["id"]`) and through the C# dictionary members APIM documents.
//
// It is separate from mapHost, which holds map[string]string. Collapsing the
// two would force every argument to a string, and an argument's type is
// load-bearing: `Arguments["first"]` on `first: Int` must compare as a number,
// not as the text "10".
type jsonMapHost struct {
	values map[string]any
}

func (m *jsonMapHost) member(name string) (Value, error) {
	switch name {
	case "ContainsKey":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("ContainsKey requires a string")
			}
			_, ok := m.values[args[0].str]
			return Bool(ok), nil
		}}), nil
	case "Count":
		return Int(int64(len(m.values))), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

// index returns a missing key as null rather than an error, which is what a C#
// dictionary lookup against a JSON object does in APIM, and what an optional
// GraphQL argument requires: a resolver reading an argument the caller omitted
// must see null, not fail.
func (m *jsonMapHost) index(key Value) (Value, error) {
	if key.kind != KindString {
		return Null(), fmt.Errorf("index requires a string key")
	}
	value, ok := m.values[key.str]
	if !ok {
		return Null(), nil
	}
	return jsonValue(value)
}

// jsonValue lifts a decoded JSON value into the expression value model.
//
// A list or nested object is rendered as its JSON text rather than refused.
// Refusing would break the common resolver that interpolates a whole argument
// object into a request body, and inventing a traversable list type here would
// be inventing syntax that real APIM does not accept.
func jsonValue(value any) (Value, error) {
	switch typed := value.(type) {
	case nil:
		return Null(), nil
	case string:
		return String(typed), nil
	case bool:
		return Bool(typed), nil
	case float64:
		// JSON has one number type. An integral value binds as Int so that
		// string interpolation renders `10` rather than `10.0`, which is what
		// a caller building a URL from an Int argument expects to see.
		if typed == float64(int64(typed)) {
			return Int(int64(typed)), nil
		}
		return Double(typed), nil
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return Int(integer), nil
		}
		number, err := typed.Float64()
		if err != nil {
			return Null(), fmt.Errorf("invalid number %q", typed.String())
		}
		return Double(number), nil
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return Null(), fmt.Errorf("value is not representable: %w", err)
		}
		return String(string(encoded)), nil
	}
}
