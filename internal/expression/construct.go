package expression

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

// The objects a policy constructs with `new`.
//
// This is an ALLOWLIST, keyed by type name, for the same reason casts are: a
// type nobody implements is a parse error naming it, rather than something that
// compiles and fails at request time. A policy author finds out when they save
// the policy.
//
// Every type here is one Microsoft's reference lists as available to a policy
// expression, so nothing in this file invents a type Azure does not offer.
var constructors = map[string]func([]Value) (Value, error){
	"Random":         newRandom,
	"Uri":            newUri,
	"JObject":        newJObject,
	"JProperty":      newJProperty,
	"DateTime":       newDateTime,
	"DateTimeOffset": newDateTimeOffset,
	"Guid":           newGuid,
}

// newRandom builds a System.Random. A seed makes it REPRODUCIBLE, which is what
// a policy passing one is asking for; without one it is seeded from the runtime,
// as .NET's parameterless constructor is.
func newRandom(args []Value) (Value, error) {
	switch len(args) {
	case 0:
		return Object(&randomHost{source: rand.New(rand.NewSource(rand.Int63()))}), nil //nolint:gosec // a policy's Random is not a security primitive
	case 1:
		seed, ok := args[0].AsNumber()
		if !ok {
			return Null(), fmt.Errorf("Random takes an integer seed")
		}
		return Object(&randomHost{source: rand.New(rand.NewSource(int64(seed)))}), nil //nolint:gosec // seeded on purpose, so a policy can reproduce a run
	default:
		return Null(), fmt.Errorf("Random takes at most one seed")
	}
}

type randomHost struct {
	source *rand.Rand
}

func (r *randomHost) member(name string) (Value, error) {
	switch name {
	case "Next":
		return Object(funcValue{fn: r.next}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a Random", name)
	}
}

// next mirrors .NET's three overloads. The upper bound is EXCLUSIVE, as it is in
// .NET: a policy writing `Next(1, 100)` expects 1 to 99, and shifting that by
// one would change which bucket a traffic split sends a request to.
func (r *randomHost) next(args []Value) (Value, error) {
	low, high := int64(0), int64(0)
	switch len(args) {
	case 0:
		return Int(r.source.Int63n(1 << 31)), nil
	case 1:
		bound, ok := args[0].AsNumber()
		if !ok {
			return Null(), fmt.Errorf("Next takes integer bounds")
		}
		low, high = 0, int64(bound)
	case 2:
		first, firstOK := args[0].AsNumber()
		second, secondOK := args[1].AsNumber()
		if !firstOK || !secondOK {
			return Null(), fmt.Errorf("Next takes integer bounds")
		}
		low, high = int64(first), int64(second)
	default:
		return Null(), fmt.Errorf("Next takes at most two bounds")
	}
	if high <= low {
		// .NET throws when the bounds are inverted, and answering a number from
		// an empty range would send a policy down a branch it never chose.
		return Null(), fmt.Errorf("Next requires an upper bound above the lower one")
	}
	return Int(low + r.source.Int63n(high-low)), nil
}

// newUri builds a System.Uri, which is NOT the same type as APIM's IUrl: it
// carries .NET's member names, and a policy reaches for it to pick a URL apart.
func newUri(args []Value) (Value, error) {
	if len(args) != 1 || args[0].kind != KindString {
		return Null(), fmt.Errorf("Uri takes one string")
	}
	parsed, err := url.Parse(args[0].str)
	if err != nil {
		return Null(), fmt.Errorf("uri %q is unparsable: %w", args[0].str, err)
	}
	return Object(&uriHost{parsed: parsed}), nil
}

type uriHost struct {
	parsed *url.URL
}

func (u *uriHost) member(name string) (Value, error) {
	switch name {
	case "AbsolutePath":
		return String(u.parsed.Path), nil
	case "AbsoluteUri":
		return String(u.parsed.String()), nil
	case "Host":
		return String(u.parsed.Hostname()), nil
	case "Scheme":
		return String(u.parsed.Scheme), nil
	case "Query":
		// .NET keeps the leading '?', unlike APIM's IUrl.Query, which is a
		// dictionary. Two types, two shapes, and conflating them would answer
		// the wrong one.
		if u.parsed.RawQuery == "" {
			return String(""), nil
		}
		return String("?" + u.parsed.RawQuery), nil
	case "Port":
		return Int(uriPort(u.parsed)), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a Uri", name)
	}
}

func (u *uriHost) String() string { return u.parsed.String() }

// uriPort answers the scheme's default when the URL names none, which is what
// .NET does.
func uriPort(parsed *url.URL) int64 {
	if port := parsed.Port(); port != "" {
		var value int64
		_, _ = fmt.Sscanf(port, "%d", &value)
		return value
	}
	switch parsed.Scheme {
	case "https":
		return 443
	case "http":
		return 80
	}
	return -1
}

// jsonField is one member of a constructed object, kept in SOURCE ORDER so a
// JObject serialises the way the policy wrote it.
type jsonField struct {
	name  string
	value Value
}

// newDateTime builds one from its parts, which is how the corpus writes the
// unix epoch: `new DateTime(1970, 1, 1)`.
func newDateTime(args []Value) (Value, error) {
	if len(args) != 3 && len(args) != 6 {
		return Null(), fmt.Errorf("DateTime takes a year, month and day, and optionally hours, minutes and seconds")
	}
	parts := make([]int, len(args))
	for i, arg := range args {
		number, ok := arg.AsNumber()
		if !ok {
			return Null(), fmt.Errorf("DateTime takes numbers")
		}
		parts[i] = int(number)
	}
	hour, minute, second := 0, 0, 0
	if len(parts) == 6 {
		hour, minute, second = parts[3], parts[4], parts[5]
	}
	return Object(dateTimeHost{at: time.Date(parts[0], time.Month(parts[1]), parts[2], hour, minute, second, 0, time.UTC)}), nil
}

// newDateTimeOffset wraps a DateTime, which is the only form the corpus uses.
func newDateTimeOffset(args []Value) (Value, error) {
	if len(args) != 1 {
		return Null(), fmt.Errorf("DateTimeOffset takes one DateTime")
	}
	moment, ok := args[0].obj.(dateTimeHost)
	if !ok {
		return Null(), fmt.Errorf("DateTimeOffset takes a DateTime")
	}
	return Object(dateTimeOffsetHost{at: moment.at}), nil
}

// newGuid rebuilds one from the bytes ToByteArray produced.
func newGuid(args []Value) (Value, error) {
	if len(args) != 1 {
		return Null(), fmt.Errorf("Guid takes a byte array or a string")
	}
	if text := args[0]; text.kind == KindString {
		return parseGuid(text.str)
	}
	raw, ok := args[0].obj.(bytesHost)
	if !ok {
		return Null(), fmt.Errorf("Guid takes a byte array or a string")
	}
	return guidFromBytes(raw.data)
}

// newJProperty is Newtonsoft's JProperty: a name and a value, which only means
// anything inside a JObject.
func newJProperty(args []Value) (Value, error) {
	if len(args) != 2 || args[0].kind != KindString {
		return Null(), fmt.Errorf("JProperty takes a name and a value")
	}
	return Object(&propertyHost{field: jsonField{name: args[0].str, value: args[1]}}), nil
}

type propertyHost struct {
	field jsonField
}

func (p *propertyHost) member(name string) (Value, error) {
	switch name {
	case "Name":
		return String(p.field.name), nil
	case "Value":
		return p.field.value, nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a JProperty", name)
	}
}

// newJObject builds an object from JProperty arguments, which is how the corpus
// writes one: `new JObject(new JProperty("status", "HTTP 405"), ...)`.
func newJObject(args []Value) (Value, error) {
	fields := make([]jsonField, 0, len(args))
	for _, arg := range args {
		property, ok := arg.obj.(*propertyHost)
		if !ok {
			return Null(), fmt.Errorf("JObject takes JProperty arguments")
		}
		fields = append(fields, property.field)
	}
	return anonymousObject(fields), nil
}

// anonymousObject is the value behind both `new { a = 1 }` and `new JObject(...)`.
// They are the same thing to a policy: a bag of named values it reads members
// off and renders as JSON.
func anonymousObject(fields []jsonField) Value {
	return Object(&objectHost{fields: fields})
}

type objectHost struct {
	fields []jsonField
}

func (o *objectHost) member(name string) (Value, error) {
	switch name {
	case "Count":
		return Double(float64(len(o.fields))), nil
	case "ContainsKey":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("ContainsKey requires a name")
			}
			_, found := o.lookup(args[0].str)
			return Bool(found), nil
		}}), nil
	case "ToString":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("ToString takes no arguments")
			}
			return String(o.String()), nil
		}}), nil
	}
	if value, found := o.lookup(name); found {
		return value, nil
	}
	return Null(), fmt.Errorf("unknown member %s on a constructed object", name)
}

func (o *objectHost) index(key Value) (Value, error) {
	if key.kind != KindString {
		return Null(), fmt.Errorf("a constructed object is indexed by name")
	}
	value, found := o.lookup(key.str)
	if !found {
		return Null(), nil
	}
	return value, nil
}

func (o *objectHost) lookup(name string) (Value, bool) {
	for _, field := range o.fields {
		if field.name == name {
			return field.value, true
		}
	}
	return Null(), false
}

// String renders the object as JSON, which is what a policy does with one: it
// builds a body. Fields keep SOURCE order rather than being sorted, because that
// is the order the author wrote and the order Newtonsoft preserves.
func (o *objectHost) String() string {
	var out strings.Builder
	out.WriteByte('{')
	for i, field := range o.fields {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteString(quoteJSON(field.name))
		out.WriteByte(':')
		out.WriteString(jsonText(field.value))
	}
	out.WriteByte('}')
	return out.String()
}

// jsonText renders one value as JSON. A nested constructed object renders as an
// object rather than as its text, so `new JObject(new JProperty("a", new
// JObject(...)))` nests the way a policy building a body expects.
func jsonText(value Value) string {
	switch value.kind {
	case KindNull:
		return "null"
	case KindBool:
		// JSON spells a boolean lowercase. This evaluator renders one as .NET
		// does, `True`, which is right everywhere a policy compares or
		// interpolates it and WRONG inside a body: `{"x":True}` is not JSON.
		if value.Truthy() {
			return "true"
		}
		return "false"
	case KindInt, KindDouble:
		return value.String()
	case KindObject:
		if nested, ok := value.obj.(*objectHost); ok {
			return nested.String()
		}
	}
	return quoteJSON(value.String())
}

// quoteJSON renders a string as a JSON string. Marshalling a Go string cannot
// fail, which is why this returns no error: the branch handling one would be
// code nothing could ever run.
func quoteJSON(text string) string {
	encoded, _ := json.Marshal(text)
	return string(encoded)
}
