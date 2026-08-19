package expression

import (
	"strings"
	"testing"
)

// The members of System.String a policy reaches for, chosen by MEASURING which
// ones Microsoft's own corpus asks for rather than by guessing: `Split` led at
// twelve expressions, then `Equals`, `StartsWith`, `Contains` and `Replace`.
func TestStringMembers(t *testing.T) {
	env := Bind(Context{})
	for _, test := range []struct {
		source string
		want   any
	}{
		{`@("a;b;c".Split(';').Count)`, float64(3)},
		{`@("a;b;c".Split(';')[1])`, "b"},
		// A separator that is absent leaves the whole string as one part.
		{`@("abc".Split(';')[0])`, "abc"},
		{`@("  x  ".Trim())`, "x"},
		{`@("xxaxx".Trim('x'))`, "a"},
		{`@("  x".TrimStart())`, "x"},
		{`@("x  ".TrimEnd())`, "x"},
		{`@("AbC".ToLower())`, "abc"},
		{`@("AbC".ToUpper())`, "ABC"},
		{`@("hello".StartsWith("he"))`, true},
		{`@("hello".EndsWith("lo"))`, true},
		{`@("hello".Contains("ell"))`, true},
		{`@("hello".Contains("xyz"))`, false},
		{`@("GET".Equals("GET"))`, true},
		{`@("GET".Equals("get"))`, false},
		// The comparison argument is what makes it case-insensitive, and it is
		// the form the corpus writes.
		{`@("GET".Equals("get", StringComparison.OrdinalIgnoreCase))`, true},
		{`@("HELLO".StartsWith("he", StringComparison.OrdinalIgnoreCase))`, true},
		{`@("a-b-c".Replace("-", "+"))`, "a+b+c"},
		{`@("hello".Substring(1))`, "ello"},
		{`@("hello".Substring(1, 3))`, "ell"},
		{`@("hello".IndexOf("ll"))`, int64(2)},
		{`@("hello".IndexOf("zz"))`, int64(-1)},
		{`@("abc".Length)`, int64(3)},
		// A hash is stable within a run, which is all a seeded Random needs.
		{`@("abc".GetHashCode() == "abc".GetHashCode())`, true},
		{`@("abc".GetHashCode() == "abd".GetHashCode())`, false},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.Interface() != test.want {
			t.Fatalf("%s = %#v, want %#v", test.source, got.Interface(), test.want)
		}
	}
}

func TestStringMemberRefusals(t *testing.T) {
	env := Bind(Context{})
	for _, test := range []struct{ source, contains string }{
		{`@("a".Nonexistent)`, "unknown member"},
		{`@("a".Split())`, "one separator"},
		{`@("a".Split(1))`, "one separator"},
		{`@("a".Trim("x", "y"))`, "at most one set"},
		{`@("a".Trim(1))`, "characters to trim"},
		{`@("a".ToLower("x"))`, "takes no arguments"},
		{`@("a".StartsWith())`, "takes a string"},
		{`@("a".Equals())`, "a value and an optional comparison"},
		{`@("a".Replace("x"))`, "two strings"},
		{`@("a".IndexOf(1))`, "takes a string"},
		{`@("a".GetHashCode(1))`, "takes no arguments"},
		// .NET throws when a slice runs past the end. Answering an empty string
		// would let a policy carry on with nothing, which is harder to find.
		{`@("abc".Substring(9))`, "outside a string"},
		{`@("abc".Substring(0, 9))`, "past the end"},
		{`@("abc".Substring(0, -1))`, "past the end"},
		{`@("abc".Substring("x"))`, "numeric start"},
		{`@("abc".Substring(0, "x"))`, "numeric length"},
		{`@("abc".Substring())`, "a start and an optional length"},
		// A comparison argument that is not one reports rather than silently
		// comparing ordinally.
		{`@("a".Equals("a", 1))`, "expected a StringComparison"},
		{`@("a".StartsWith("a", 1))`, "expected a StringComparison"},
		{`@(StringComparison.Nonexistent)`, "unknown member"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
	// Comparing against null is false rather than an error: `x.Equals(y)` where
	// y is an absent variable is a question a policy asks.
	if got, err := EvalEnv(`@("a".Equals(context.Variables["absent"]))`, Bind(Context{})); err != nil || got.Truthy() {
		t.Fatalf("equals null = %v, %v", got.Truthy(), err)
	}
	// A member on a non-string is still unknown rather than a string operation.
	if _, err := EvalEnv(`@(1.Split(';'))`, env); err == nil {
		t.Fatal("Split on a number was accepted")
	}
}
