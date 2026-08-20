package expression

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// The static types a policy calls into.
//
// Ranked by MEASURING the corpus rather than guessing: `Convert.FromBase64String`
// leads at 38 references, then `Encoding.UTF8` (26), `Convert.ToBase64String`
// (23), `int.Parse` (20), `string.Empty` (13), `Uri.EscapeDataString` (10).
//
// Every type here is on Microsoft's allowed .NET list, so these are `framework`
// entries: available in a tenant, with the member list our reading of .NET.
func staticBindings() map[string]Value {
	return map[string]Value{
		"Convert":          Object(convertHost{}),
		"Encoding":         Object(encodingHost{}),
		"Uri":              Object(uriStaticHost{}),
		"StringComparison": Object(comparisonHost{}),
		// `string` and `String` are the same type, and policies write both.
		"string":         Object(stringStaticHost{}),
		"String":         Object(stringStaticHost{}),
		"int":            Object(intStaticHost{}),
		"DateTime":       Object(dateTimeStaticHost{}),
		"DateTimeOffset": Object(dateTimeOffsetStaticHost{}),
		"Guid":           Object(guidStaticHost{}),
	}
}

// bytesHost is a byte array, which Convert and Encoding pass between them. It
// is its own type rather than a collection of numbers so that `ToBase64String`
// can refuse anything else rather than silently encoding a list of strings.
type bytesHost struct {
	data []byte
}

func (b bytesHost) member(name string) (Value, error) {
	switch name {
	case "Length":
		return Int(int64(len(b.data))), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a byte array", name)
	}
}

func (b bytesHost) index(key Value) (Value, error) {
	position, ok := collectionIndex(key)
	if !ok {
		return Null(), fmt.Errorf("a byte array is indexed by position")
	}
	if position < 0 || position >= len(b.data) {
		return Null(), fmt.Errorf("position %d is outside a byte array of %d", position, len(b.data))
	}
	return Int(int64(b.data[position])), nil
}

type convertHost struct{}

func (convertHost) member(name string) (Value, error) {
	switch name {
	case "FromBase64String":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("FromBase64String takes one string")
			}
			decoded, err := base64.StdEncoding.DecodeString(args[0].str)
			if err != nil {
				return Null(), fmt.Errorf("value is not base64: %w", err)
			}
			return Object(bytesHost{data: decoded}), nil
		}}), nil
	case "ToBase64String":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Null(), fmt.Errorf("ToBase64String takes one byte array")
			}
			bytes, ok := args[0].obj.(bytesHost)
			if !ok {
				return Null(), fmt.Errorf("ToBase64String takes a byte array")
			}
			return String(base64.StdEncoding.EncodeToString(bytes.data)), nil
		}}), nil
	case "ToString":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Null(), fmt.Errorf("ToString takes one value")
			}
			return String(args[0].String()), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on Convert", name)
	}
}

type encodingHost struct{}

func (encodingHost) member(name string) (Value, error) {
	switch name {
	// Only UTF8 is bound. A policy asking for another encoding gets a failure
	// naming it rather than UTF-8 bytes labelled as something else.
	case "UTF8":
		return Object(utf8Host{}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on Encoding; only UTF8 is implemented", name)
	}
}

type utf8Host struct{}

func (utf8Host) member(name string) (Value, error) {
	switch name {
	case "GetBytes":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("GetBytes takes one string")
			}
			return Object(bytesHost{data: []byte(args[0].str)}), nil
		}}), nil
	case "GetString":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Null(), fmt.Errorf("GetString takes one byte array")
			}
			bytes, ok := args[0].obj.(bytesHost)
			if !ok {
				return Null(), fmt.Errorf("GetString takes a byte array")
			}
			return String(string(bytes.data)), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on Encoding.UTF8", name)
	}
}

type uriStaticHost struct{}

func (uriStaticHost) member(name string) (Value, error) {
	switch name {
	case "EscapeDataString", "UnescapeDataString":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("%s takes one string", name)
			}
			if name == "EscapeDataString" {
				// .NET escapes every reserved character, where Go's QueryEscape
				// turns a space into `+`. A policy building a URL needs %20.
				return String(strings.ReplaceAll(url.QueryEscape(args[0].str), "+", "%20")), nil
			}
			unescaped, err := url.QueryUnescape(args[0].str)
			if err != nil {
				return Null(), fmt.Errorf("value is not escaped: %w", err)
			}
			return String(unescaped), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on Uri", name)
	}
}

type stringStaticHost struct{}

func (stringStaticHost) member(name string) (Value, error) {
	switch name {
	case "Empty":
		return String(""), nil
	case "IsNullOrEmpty":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Null(), fmt.Errorf("IsNullOrEmpty takes one value")
			}
			return Bool(args[0].IsNull() || args[0].String() == ""), nil
		}}), nil
	case "IsNullOrWhiteSpace":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Null(), fmt.Errorf("IsNullOrWhiteSpace takes one value")
			}
			return Bool(args[0].IsNull() || strings.TrimSpace(args[0].String()) == ""), nil
		}}), nil
	case "Concat":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			var out strings.Builder
			for _, arg := range args {
				out.WriteString(arg.String())
			}
			return String(out.String()), nil
		}}), nil
	case "Join":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) < 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("join takes a separator and values")
			}
			parts := make([]string, 0, len(args)-1)
			for _, arg := range args[1:] {
				parts = append(parts, arg.String())
			}
			return String(strings.Join(parts, args[0].str)), nil
		}}), nil
	case "Format":
		return Object(funcValue{fn: formatString}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on string", name)
	}
}

// formatString substitutes `{0}`, `{1}` and so on.
//
// Alignment and format specifiers -- `{0,10:F2}` -- are REFUSED rather than
// dropped, the same choice interpolated strings make, because rendering a
// formatted value unformatted is silently wrong.
func formatString(args []Value) (Value, error) {
	if len(args) == 0 || args[0].kind != KindString {
		return Null(), fmt.Errorf("format takes a format string")
	}
	format, values := args[0].str, args[1:]
	var out strings.Builder
	for i := 0; i < len(format); i++ {
		// A doubled brace is a literal one, both ways round. Handling only `{{`
		// leaves `{{0}}` rendering as `{0}}`.
		if format[i] == '}' {
			if i+1 < len(format) && format[i+1] == '}' {
				i++
			}
			out.WriteByte('}')
			continue
		}
		if format[i] != '{' {
			out.WriteByte(format[i])
			continue
		}
		if i+1 < len(format) && format[i+1] == '{' {
			out.WriteByte('{')
			i++
			continue
		}
		end := strings.IndexByte(format[i:], '}')
		if end < 0 {
			return Null(), fmt.Errorf("unclosed placeholder in a format string")
		}
		token := format[i+1 : i+end]
		index, err := strconv.Atoi(token)
		if err != nil {
			return Null(), fmt.Errorf("placeholder %q is not an index; alignment and format specifiers are not implemented", token)
		}
		if index < 0 || index >= len(values) {
			return Null(), fmt.Errorf("placeholder {%d} has no argument", index)
		}
		out.WriteString(values[index].String())
		i += end
	}
	return String(out.String()), nil
}

type intStaticHost struct{}

func (intStaticHost) member(name string) (Value, error) {
	switch name {
	case "Parse":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Null(), fmt.Errorf("Parse takes one value")
			}
			parsed, err := strconv.ParseInt(strings.TrimSpace(args[0].String()), 10, 64)
			if err != nil {
				// .NET throws. Answering zero would send a policy down a branch
				// it never chose, which is worse than failing at the parse.
				return Null(), fmt.Errorf("%q is not an integer", args[0].String())
			}
			return Int(parsed), nil
		}}), nil
	case "MaxValue":
		return Int(2147483647), nil
	case "MinValue":
		return Int(-2147483648), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on int", name)
	}
}
