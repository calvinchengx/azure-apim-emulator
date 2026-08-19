package expression

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// The members of System.String a policy reaches for.
//
// Measured rather than guessed: evaluating Microsoft's own corpus and counting
// the members it asks for ranked `Split` (12), `Equals` (5), `StartsWith` (3),
// `Contains` and `Replace` (2 each) ahead of everything else. The siblings of
// those are here too, because a policy that trims one end trims the other.
//
// The .NET type is on Microsoft's allowed list, so these are `framework`
// entries in the ledger: available in a tenant, with the member list our
// reading of .NET rather than of an APIM document.
// stringHost carries the members so the allowlist drift scan can see them: the
// scan reads `member` methods, and a plain function would leave every one of
// these ungated.
type stringHost struct {
	text string
}

func (h stringHost) member(name string) (Value, error) {
	text := h.text
	switch name {
	case "Length":
		return Int(int64(len(text))), nil
	// AsJwt and AsBasic are extension methods on `string`, which is why they
	// sit here rather than on a context type.
	case "AsJwt":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("AsJwt takes no arguments")
			}
			return asJwt(text), nil
		}}), nil
	case "AsBasic":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("AsBasic takes no arguments")
			}
			return asBasic(text), nil
		}}), nil
	case "Split":
		return Object(funcValue{fn: func(args []Value) (Value, error) { return splitString(text, args) }}), nil
	case "Trim", "TrimStart", "TrimEnd":
		return Object(funcValue{fn: func(args []Value) (Value, error) { return trimString(text, name, args) }}), nil
	case "ToLower", "ToUpper":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("%s takes no arguments", name)
			}
			if name == "ToLower" {
				return String(strings.ToLower(text)), nil
			}
			return String(strings.ToUpper(text)), nil
		}}), nil
	case "StartsWith", "EndsWith", "Contains":
		return Object(funcValue{fn: func(args []Value) (Value, error) { return matchString(text, name, args) }}), nil
	case "Equals":
		return Object(funcValue{fn: func(args []Value) (Value, error) { return equalsString(text, args) }}), nil
	case "Replace":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 2 || args[0].kind != KindString || args[1].kind != KindString {
				return Null(), fmt.Errorf("Replace takes two strings")
			}
			return String(strings.ReplaceAll(text, args[0].str, args[1].str)), nil
		}}), nil
	case "Substring":
		return Object(funcValue{fn: func(args []Value) (Value, error) { return substring(text, args) }}), nil
	case "IndexOf":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("IndexOf takes a string")
			}
			return Int(int64(strings.Index(text, args[0].str))), nil
		}}), nil
	case "GetHashCode":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("GetHashCode takes no arguments")
			}
			// .NET does NOT specify this value and randomises it per process,
			// so no policy may depend on a particular number. It is stable here
			// so that a seeded `new Random(x.GetHashCode())` reproduces, which
			// is the only way the corpus uses it.
			sum := fnv.New32a()
			_, _ = sum.Write([]byte(text))
			return Int(int64(int32(sum.Sum32()))), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a string", name)
	}
}

// splitString splits on a separator. .NET's overloads take a char, a string, or
// arrays of either; a policy writes `Split(';')`, so one separator is what this
// accepts and anything else reports rather than guessing which overload was
// meant.
func splitString(text string, args []Value) (Value, error) {
	if len(args) != 1 || args[0].kind != KindString {
		return Null(), fmt.Errorf("Split takes one separator")
	}
	parts := strings.Split(text, args[0].str)
	items := make([]Value, 0, len(parts))
	for _, part := range parts {
		items = append(items, String(part))
	}
	return Object(&listHost{items: items, what: "parts"}), nil
}

func trimString(text, name string, args []Value) (Value, error) {
	if len(args) > 1 {
		return Null(), fmt.Errorf("%s takes at most one set of characters", name)
	}
	cutset := " \t\n\r"
	if len(args) == 1 {
		if args[0].kind != KindString {
			return Null(), fmt.Errorf("%s takes characters to trim", name)
		}
		cutset = args[0].str
	}
	switch name {
	case "TrimStart":
		return String(strings.TrimLeft(text, cutset)), nil
	case "TrimEnd":
		return String(strings.TrimRight(text, cutset)), nil
	default:
		return String(strings.Trim(text, cutset)), nil
	}
}

func matchString(text, name string, args []Value) (Value, error) {
	if len(args) == 0 || len(args) > 2 || args[0].kind != KindString {
		return Null(), fmt.Errorf("%s takes a string", name)
	}
	subject, needle := text, args[0].str
	if len(args) == 2 {
		insensitive, err := ignoresCase(args[1])
		if err != nil {
			return Null(), err
		}
		if insensitive {
			subject, needle = strings.ToLower(subject), strings.ToLower(needle)
		}
	}
	switch name {
	case "StartsWith":
		return Bool(strings.HasPrefix(subject, needle)), nil
	case "EndsWith":
		return Bool(strings.HasSuffix(subject, needle)), nil
	default:
		return Bool(strings.Contains(subject, needle)), nil
	}
}

func equalsString(text string, args []Value) (Value, error) {
	if len(args) == 0 || len(args) > 2 {
		return Null(), fmt.Errorf("Equals takes a value and an optional comparison")
	}
	other := args[0].String()
	if args[0].IsNull() {
		return Bool(false), nil
	}
	if len(args) == 2 {
		insensitive, err := ignoresCase(args[1])
		if err != nil {
			return Null(), err
		}
		if insensitive {
			return Bool(strings.EqualFold(text, other)), nil
		}
	}
	return Bool(text == other), nil
}

func substring(text string, args []Value) (Value, error) {
	if len(args) == 0 || len(args) > 2 {
		return Null(), fmt.Errorf("Substring takes a start and an optional length")
	}
	start, ok := args[0].AsNumber()
	if !ok {
		return Null(), fmt.Errorf("Substring takes a numeric start")
	}
	if start < 0 || int(start) > len(text) {
		// .NET throws here. Answering an empty string would let a policy slice
		// past the end and carry on with nothing, which is harder to find than
		// a failure at the point of the mistake.
		return Null(), fmt.Errorf("Substring start %d is outside a string of %d", int(start), len(text))
	}
	end := len(text)
	if len(args) == 2 {
		length, ok := args[1].AsNumber()
		if !ok {
			return Null(), fmt.Errorf("Substring takes a numeric length")
		}
		end = int(start) + int(length)
		if length < 0 || end > len(text) {
			return Null(), fmt.Errorf("Substring length %d runs past the end of a string of %d", int(length), len(text))
		}
	}
	return String(text[int(start):end]), nil
}

// ignoresCase reads a StringComparison. Only the case-insensitive members
// change behaviour here; the culture-aware ones are treated as ordinal, which
// is stated rather than hidden because this evaluator has no culture data.
func ignoresCase(value Value) (bool, error) {
	if value.kind != KindString {
		return false, fmt.Errorf("expected a StringComparison")
	}
	return strings.Contains(strings.ToLower(value.str), "ignorecase"), nil
}

// comparisonHost binds `StringComparison`, whose members a policy passes to
// Equals and StartsWith. They carry their own names, so an unrecognised one is
// a loud failure rather than a silent ordinal comparison.
type comparisonHost struct{}

func (comparisonHost) member(name string) (Value, error) {
	switch name {
	case "Ordinal", "OrdinalIgnoreCase", "InvariantCulture", "InvariantCultureIgnoreCase",
		"CurrentCulture", "CurrentCultureIgnoreCase":
		return String(name), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on StringComparison", name)
	}
}
