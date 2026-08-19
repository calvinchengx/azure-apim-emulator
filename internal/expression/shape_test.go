package expression

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The type gate.
//
// The member inventory checks that a NAME exists. Every type-level defect this
// package has shipped passed that check while returning the wrong thing:
// `Url.Query` answered the raw query text where Microsoft types a dictionary,
// and request and response headers answered one string where Microsoft types an
// array, silently dropping a repeated `Set-Cookie`. All three were `bound` and
// green. What the inventory could not see was SHAPE.
//
// The vendored toolkit interfaces and reference table both carry the declared
// C# type, so the shape is checkable rather than reviewable. This maps a
// declared type onto the shape a Value must have, and holds every bound member
// to it.

type shape string

const (
	shapeString     shape = "string"
	shapeBool       shape = "bool"
	shapeNumber     shape = "number"
	shapeCollection shape = "collection"
	shapeDictionary shape = "dictionary"
	shapeObject     shape = "object"
	// shapeUnchecked is a type this gate deliberately does not police, listed
	// so the reason is written down rather than inferred from its absence.
	shapeUnchecked shape = ""
)

var (
	collectionType = regexp.MustCompile(`^(IEnumerable|IList|IReadOnlyCollection|ICollection|List)<.*>$|\[\]$`)
	dictionaryType = regexp.MustCompile(`^(IReadOnlyDictionary|IDictionary|Dictionary)<.*>$`)
)

// shapeOf maps a declared C# type onto the shape a Value must have here.
func shapeOf(declared string) shape {
	declared = strings.TrimSpace(strings.TrimSuffix(declared, "?"))
	switch declared {
	case "string":
		return shapeString
	case "bool":
		return shapeBool
	case "int", "long", "double":
		return shapeNumber
	// .NET renders these as values; this evaluator renders them as TEXT, which
	// is a deliberate choice so a policy comparing against a literal sees what
	// it was written for. Checked as strings because that is what is promised.
	case "TimeSpan", "DateTime", "Guid":
		return shapeString
	// A method, a generic, or a delegate. `Action<string>` is context.Trace,
	// `T` is a generic return, `dynamic` is NamedValue: none has a fixed shape.
	case "void", "T", "dynamic", "Action<string>":
		return shapeUnchecked
	}
	switch {
	case dictionaryType.MatchString(declared):
		return shapeDictionary
	case collectionType.MatchString(declared) || strings.HasSuffix(declared, "[]"):
		return shapeCollection
	// An enum renders as its NAME here, which is what a policy comparing
	// against a literal was written for, so it is checked as a string.
	case strings.HasPrefix(declared, "enum "):
		return shapeString
	// Anything left starting with I is one of Microsoft's own interfaces: an
	// object with members. A bare CamelCase name is an enum type the toolkit
	// spells without the keyword, and goes unchecked rather than guessed at.
	case strings.HasPrefix(declared, "I"):
		return shapeObject
	}
	return shapeUnchecked
}

// shapeValue reports what a Value actually is.
func shapeValue(value Value) shape {
	switch value.kind {
	case KindString:
		return shapeString
	case KindBool:
		return shapeBool
	case KindInt, KindDouble:
		return shapeNumber
	case KindObject:
		// A dictionary answers ContainsKey; a collection answers Count and
		// position. Both are objects, and telling them apart is the whole point
		// of this gate, so they are distinguished by what they answer.
		if _, ok := value.obj.(*listHost); ok {
			return shapeCollection
		}
		if host, ok := value.obj.(memberHost); ok {
			if _, err := host.member("ContainsKey"); err == nil {
				return shapeDictionary
			}
		}
		return shapeObject
	}
	return shapeUnchecked
}

// instancePath is an expression yielding an instance of each bound type, so a
// member expression is a path plus a name.
//
// A path per TYPE rather than an expression per member: 29 paths instead of 130
// expressions, and a mechanical join that cannot quietly check the wrong member.
var instancePath = map[string]string{
	"context":              "context",
	"Api":                  "context.Api",
	"Backend":              "context.Backend",
	"Operation":            "context.Operation",
	"Product":              "context.Product",
	"Subscription":         "context.Subscription",
	"User":                 "context.User",
	"Group":                "context.User.Groups[0]",
	"UserIdentity":         "context.User.Identities[0]",
	"Deployment":           "context.Deployment",
	"Gateway":              "context.Deployment.Gateway",
	"Certificates":         "context.Deployment.Certificates",
	"Certificate":          `context.Deployment.Certificates["client"]`,
	"LastError":            "context.LastError",
	"Request":              "context.Request",
	"Response":             "context.Response",
	"Url":                  "context.Request.Url",
	"Query":                "context.Request.Url.Query",
	"Headers":              "context.Request.Headers",
	"Body":                 "context.Request.Body",
	"Variables":            "context.Variables",
	"GraphQL":              "context.GraphQL",
	"Arguments":            "context.GraphQL.GraphQLArguments",
	"Authorization":        `context.Variables["auth-context"]`,
	"Jwt":                  shapeJWT + ".AsJwt()",
	"Claims":               shapeJWT + ".AsJwt().Claims",
	"BasicAuthCredentials": "'Basic YWRhOnMzY3JldA=='.AsBasic()",
	"string":               shapeJWT,
	"value":                "1",
}

// A token whose payload carries every claim the Jwt members read.
const shapeJWT = "'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig'"

func TestBoundMembersMatchTheirDocumentedType(t *testing.T) {
	env, _ := evaluationCases(t)
	checked, skipped := 0, 0
	for _, member := range Allowlist() {
		if member.Status != MemberBound {
			continue
		}
		declared := DocumentedTypes(member.Type, member.Name)
		if len(declared) == 0 {
			continue
		}
		// The sources disagree on some types -- `IUrl.Port` is `int` in the
		// reference and `string` in the toolkit -- so a value matching EITHER
		// passes. A policy written against either Microsoft document is a
		// policy that should work here.
		wanted := map[shape]bool{}
		for _, dotted := range declared {
			if s := shapeOf(dotted); s != shapeUnchecked {
				wanted[s] = true
			}
		}
		if len(wanted) == 0 {
			skipped++
			continue
		}
		path, ok := instancePath[member.Type]
		if !ok {
			t.Fatalf("no instance path for bound type %s; the type gate cannot reach it", member.Type)
		}
		value, err := EvalEnv("@("+path+"."+member.Name+")", env)
		if err != nil {
			t.Fatalf("%s.%s: %v", member.Type, member.Name, err)
		}
		// A METHOD's shape is its return type, and this gate reads members
		// rather than calling them: calling one with the wrong arguments would
		// fail for a reason that has nothing to do with its type.
		if _, isCallable := value.obj.(callHost); isCallable {
			skipped++
			continue
		}
		// Null carries no shape. A nullable member, or one absent from this
		// fixture, is not evidence either way.
		if value.IsNull() {
			skipped++
			continue
		}
		got := shapeValue(value)
		// A dictionary satisfies a declaration of "object": it is one, with
		// more. The REVERSE never holds, and that asymmetry is the whole gate:
		// answering a plain object where Microsoft declares a dictionary is
		// exactly how the header defect passed every other check.
		if got == shapeDictionary && wanted[shapeObject] {
			got = shapeObject
		}
		if !wanted[got] {
			names := make([]string, 0, len(declared))
			for label, dotted := range declared {
				names = append(names, label+"="+dotted)
			}
			sort.Strings(names)
			t.Errorf("%s.%s answers a %s here, but Microsoft declares it %s",
				member.Type, member.Name, got, strings.Join(names, " "))
		}
		checked++
	}
	// The gate must actually gate. A refactor that stopped resolving declared
	// types, or an instance path that started answering null, would otherwise
	// pass by checking nothing at all.
	if checked < 60 {
		t.Fatalf("the type gate checked only %d members (%d skipped); it should cover most of the bound surface", checked, skipped)
	}
	t.Logf("type-checked %d bound members against Microsoft's declared types, %d skipped as methods or null", checked, skipped)
}
