// Package expression evaluates the Azure API Management policy expression
// language: C#-flavoured expressions written as @(...) in policy documents.
//
// The engine is deliberately pure Go with no generated parser, so every
// statement stays reachable by tests under the repository's exact-100% coverage
// gate. It models .NET value semantics rather than reusing Go's, because the
// two differ in ways that are silently wrong otherwise: bool.ToString() is
// "True" in C# but "false" in Go, integer division by zero throws in .NET but
// panics in Go, and string concatenation with null yields "" rather than
// "<nil>".
package expression

import (
	"fmt"
	"math"
	"strconv"
)

// Kind enumerates the .NET types the engine models.
type Kind uint8

// The modelled .NET types. KindObject carries anything the host binds in that
// the engine treats opaquely (maps, slices, host structs).
const (
	KindNull Kind = iota
	KindBool
	KindInt
	KindDouble
	KindString
	KindObject
)

// Value is one evaluated .NET value. The zero Value is null, which matches C#
// reference-type defaults and keeps "unset" and "null" indistinguishable the
// way APIM expressions expect.
type Value struct {
	kind Kind
	num  int64
	dbl  float64
	str  string
	obj  any
}

// Null returns the .NET null value.
func Null() Value { return Value{kind: KindNull} }

// Bool returns a System.Boolean value.
func Bool(value bool) Value {
	result := Value{kind: KindBool}
	if value {
		result.num = 1
	}
	return result
}

// Int returns a System.Int64 value. C# integer literals are Int32, but the
// engine widens to Int64 so arithmetic on header counts and epoch seconds does
// not silently truncate.
func Int(value int64) Value { return Value{kind: KindInt, num: value} }

// Double returns a System.Double value.
func Double(value float64) Value { return Value{kind: KindDouble, dbl: value} }

// String returns a System.String value.
func String(value string) Value { return Value{kind: KindString, str: value} }

// Object returns an opaque host value. A nil object is null, so callers may
// bind a missing subscription or product without a separate check.
func Object(value any) Value {
	if value == nil {
		return Null()
	}
	return Value{kind: KindObject, obj: value}
}

// Kind reports the modelled .NET type.
func (v Value) Kind() Kind { return v.kind }

// IsNull reports whether the value is .NET null.
func (v Value) IsNull() bool { return v.kind == KindNull }

// Interface unwraps the value into its Go representation. Null becomes nil.
func (v Value) Interface() any {
	switch v.kind {
	case KindBool:
		return v.num == 1
	case KindInt:
		return v.num
	case KindDouble:
		return v.dbl
	case KindString:
		return v.str
	case KindObject:
		return v.obj
	default:
		return nil
	}
}

// Truthy reports the value's boolean reading. Only System.Boolean is genuinely
// truthy in C#; everything else is a type error at the call site, so callers
// that need strictness use AsBool instead.
func (v Value) Truthy() bool { return v.kind == KindBool && v.num == 1 }

// AsBool converts to System.Boolean, reporting whether the conversion is legal
// in C#. Unlike Go, C# does not treat non-empty strings or non-zero numbers as
// true, so those are rejected rather than coerced.
func (v Value) AsBool() (bool, bool) {
	if v.kind != KindBool {
		return false, false
	}
	return v.num == 1, true
}

// AsNumber widens the value to a float64 for mixed arithmetic, reporting
// whether it is numeric at all.
func (v Value) AsNumber() (float64, bool) {
	switch v.kind {
	case KindInt:
		return float64(v.num), true
	case KindDouble:
		return v.dbl, true
	default:
		return 0, false
	}
}

// IsNumeric reports whether the value participates in arithmetic.
func (v Value) IsNumeric() bool { return v.kind == KindInt || v.kind == KindDouble }

// String renders the value the way .NET's ToString would, which is not what Go
// prints: booleans are "True"/"False", null is the empty string, and doubles
// use the shortest round-trippable form.
func (v Value) String() string {
	switch v.kind {
	case KindBool:
		if v.num == 1 {
			return "True"
		}
		return "False"
	case KindInt:
		return strconv.FormatInt(v.num, 10)
	case KindDouble:
		return formatDouble(v.dbl)
	case KindString:
		return v.str
	case KindObject:
		if text, ok := v.obj.(interface{ String() string }); ok {
			return text.String()
		}
		return ""
	default:
		return ""
	}
}

// formatDouble renders a float the way .NET Core's double.ToString() does.
func formatDouble(value float64) string {
	switch {
	case math.IsNaN(value):
		return "NaN"
	case math.IsInf(value, 1):
		return "Infinity"
	case math.IsInf(value, -1):
		return "-Infinity"
	default:
		return strconv.FormatFloat(value, 'G', -1, 64)
	}
}

type memberHost interface {
	member(string) (Value, error)
}

type indexHost interface {
	index(Value) (Value, error)
}

type callHost interface {
	call([]Value) (Value, error)
}

type funcValue struct {
	fn func([]Value) (Value, error)
}

func (f funcValue) call(args []Value) (Value, error) { return f.fn(args) }

func (v Value) member(name string) (Value, error) {
	if host, ok := v.obj.(memberHost); v.kind == KindObject && ok {
		return host.member(name)
	}
	switch name {
	case "ToString":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("ToString takes no arguments")
			}
			return String(v.String()), nil
		}}), nil
	case "Length":
		if v.kind != KindString {
			return Null(), fmt.Errorf("Length requires a string")
		}
		return Int(int64(len(v.str))), nil
	// AsJwt and AsBasic are extension methods on `string`, so they hang off the
	// value rather than off a context type.
	case "AsJwt":
		if v.kind != KindString {
			return Null(), fmt.Errorf("AsJwt requires a string")
		}
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("AsJwt takes no arguments")
			}
			return asJwt(v.str), nil
		}}), nil
	case "AsBasic":
		if v.kind != KindString {
			return Null(), fmt.Errorf("AsBasic requires a string")
		}
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("AsBasic takes no arguments")
			}
			return asBasic(v.str), nil
		}}), nil
	default:
		if v.IsNull() {
			return Null(), fmt.Errorf("member access on null")
		}
		// System.String's own members, which a policy uses constantly. They are
		// tried before the failure so that a member on any OTHER kind still
		// reports as unknown rather than as a string operation.
		if v.kind == KindString {
			return stringHost{text: v.str}.member(name)
		}
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

func (v Value) index(key Value) (Value, error) {
	if host, ok := v.obj.(indexHost); v.kind == KindObject && ok {
		return host.index(key)
	}
	// A null says so, rather than sharing the message a number gets. Indexing
	// an absent variable is a common mistake, and "value is not indexable"
	// sends the author looking for a type problem they do not have. Member
	// access has always distinguished the two.
	if v.IsNull() {
		return Null(), fmt.Errorf("index on null")
	}
	return Null(), fmt.Errorf("value is not indexable")
}

func (v Value) call(args []Value) (Value, error) {
	if host, ok := v.obj.(callHost); v.kind == KindObject && ok {
		return host.call(args)
	}
	return Null(), fmt.Errorf("value is not callable")
}

// equal implements C# equality. Numbers compare across Int and Double, strings
// compare ordinally, and null equals only null.
func equal(left, right Value) bool {
	if left.kind == KindNull || right.kind == KindNull {
		return left.kind == KindNull && right.kind == KindNull
	}
	if left.IsNumeric() && right.IsNumeric() {
		leftNumber, _ := left.AsNumber()
		rightNumber, _ := right.AsNumber()
		return leftNumber == rightNumber
	}
	if left.kind != right.kind {
		return false
	}
	switch left.kind {
	case KindBool:
		return left.num == right.num
	case KindString:
		return left.str == right.str
	default:
		return left.obj == right.obj
	}
}
