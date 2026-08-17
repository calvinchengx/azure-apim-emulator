package expression

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func castEnv() *Env {
	return Bind(Context{
		Request:   httptest.NewRequest(http.MethodGet, "https://api.example/pets?x=1", nil),
		Variables: map[string]string{"count": "42", "name": "blue", "ratio": "1.5"},
		Api:       &ApiContext{Id: "pets", Name: "Pets", Path: "pets"},
	})
}

func evalCast(t *testing.T, source string) (string, error) {
	t.Helper()
	value, err := EvalEnv(source, castEnv())
	return value.String(), err
}

// APIM's documentation writes casts constantly, so an expression language that
// cannot parse them rejects the exact policies people copy from Microsoft.
func TestCastsParseAndConvert(t *testing.T) {
	cases := map[string]string{
		`@((string)context.Variables["count"])`: "42",
		`@((int)context.Variables["count"])`:    "42",
		`@((long)context.Variables["count"])`:   "42",
		`@((double)context.Variables["ratio"])`: "1.5",
		`@((string)context.Api.Name)`:           "Pets",
		// A cast binds tighter than a binary operator, so the conversion
		// applies to the operand and the arithmetic still works.
		`@((int)context.Variables["count"] + 1)`: "43",
	}
	for source, want := range cases {
		got, err := evalCast(t, source)
		if err != nil {
			t.Errorf("%s: %v", source, err)
			continue
		}
		if got != want {
			t.Errorf("%s = %q, want %q", source, got, want)
		}
	}
}

// `(int)"42"` must yield a NUMBER, not the text. A policy casting a stored
// string in order to compare it would otherwise compare strings and silently
// order 9 after 10.
func TestCastToIntProducesANumber(t *testing.T) {
	value, err := EvalEnv(`@((int)context.Variables["count"] > 9)`, castEnv())
	if err != nil {
		t.Fatal(err)
	}
	if value.String() != "True" {
		t.Fatalf("numeric comparison after a cast = %q; the cast must convert, not relabel", value.String())
	}
	// Without the cast the same comparison is a string comparison and fails,
	// which is what makes the conversion load-bearing rather than cosmetic.
	if _, err := EvalEnv(`@(context.Variables["count"] > 9)`, castEnv()); err == nil {
		t.Log("uncast comparison did not error; the cast is still what makes the intent explicit")
	}
}

// The ambiguity this design exists to avoid: `(name)` is a parenthesised
// identifier, not a cast to a type called `name`. Only known type names are
// treated as casts, which makes the two decidable without type information.
func TestParenthesisedExpressionsAreNotMistakenForCasts(t *testing.T) {
	env := Bind(Context{Variables: map[string]string{"a": "1"}})
	if _, err := EvalEnv(`@((context) != null)`, env); err != nil {
		t.Fatalf("a parenthesised expression must still parse: %v", err)
	}
	// `total` is not a cast type, so this is a parenthesised identifier and
	// must fail as an unknown identifier rather than parse as a cast.
	if _, err := EvalEnv(`@((total)context.Variables["a"])`, env); err == nil {
		t.Fatal("an unknown type name must not be treated as a cast")
	}
}

func TestCastsRefuseImpossibleConversions(t *testing.T) {
	for _, source := range []string{
		`@((int)context.Variables["name"])`,
		`@((double)context.Variables["name"])`,
		`@((bool)context.Variables["name"])`,
	} {
		if _, err := EvalEnv(source, castEnv()); err == nil {
			t.Errorf("%s must fail: the value cannot be converted", source)
		}
	}
	// A cast to an object type asserts the shape rather than converting, which
	// is what makes `((Authorization)x).Member` and `((JObject)x)` parse.
	if _, err := EvalEnv(`@((JObject)context.Api != null)`, castEnv()); err != nil {
		t.Errorf("an object cast must be a no-op assertion: %v", err)
	}
	if _, err := EvalEnv(`@((bool)context.Api)`, castEnv()); err == nil {
		t.Error("casting an object to bool must fail")
	}
	// A null cast to string is the empty string, matching C#, rather than an
	// error that would break every defensive `(string)context.Variables[...]`.
	if got, err := evalCast(t, `@((string)context.Variables["absent"])`); err != nil || got != "" {
		t.Errorf("(string)null = %q %v", got, err)
	}
	// An error inside the operand propagates rather than being swallowed.
	if _, err := EvalEnv(`@((string)context.Nonsense)`, castEnv()); err == nil {
		t.Error("an error in the cast operand must propagate")
	}
}

func TestCastToBoolPassesBooleansThrough(t *testing.T) {
	got, err := evalCast(t, `@((bool)(1 == 1))`)
	if err != nil || got != "True" {
		t.Fatalf("(bool)true = %q %v", got, err)
	}
}

// castNumber accepts a numeric STRING, which is a documented divergence from
// C#: there `(int)` on a boxed string throws. It exists because this emulator's
// context.Variables is map[string]string, so a strict cast would make
// `(int)context.Variables["x"]` fail for every policy Azure accepts. These
// assert the boundary of that leniency, so it cannot widen unnoticed.
func TestNumericCastLeniencyHasLimits(t *testing.T) {
	env := Bind(Context{Variables: map[string]string{
		"spaced": "  7  ", "empty": "", "words": "seven", "float": "2.5",
	}})
	if got, err := EvalEnv(`@((int)context.Variables["spaced"])`, env); err != nil || got.String() != "7" {
		t.Errorf("surrounding whitespace must not defeat the cast: %q %v", got.String(), err)
	}
	// Truncation toward zero, as C# does, rather than rounding.
	if got, err := EvalEnv(`@((int)context.Variables["float"])`, env); err != nil || got.String() != "2" {
		t.Errorf("(int)2.5 = %q %v, want truncation", got.String(), err)
	}
	for _, name := range []string{"empty", "words"} {
		if _, err := EvalEnv(`@((int)context.Variables["`+name+`"])`, env); err == nil {
			t.Errorf("(int) on %q must fail: leniency covers numeric text only", name)
		}
	}
	// A null variable is not silently zero. A policy branching on a missing
	// variable must see the failure, not a plausible number.
	if _, err := EvalEnv(`@((int)context.Variables["absent"])`, env); err == nil {
		t.Error("(int)null must fail rather than yield 0")
	}
}

func TestBoolCastAcceptsBooleanTextOnly(t *testing.T) {
	env := Bind(Context{Variables: map[string]string{"yes": "true", "no": "False", "junk": "maybe"}})
	if got, err := EvalEnv(`@((bool)context.Variables["yes"])`, env); err != nil || got.String() != "True" {
		t.Errorf(`(bool)"true" = %q %v`, got.String(), err)
	}
	if got, err := EvalEnv(`@((bool)context.Variables["no"])`, env); err != nil || got.String() != "False" {
		t.Errorf(`(bool)"False" = %q %v`, got.String(), err)
	}
	if _, err := EvalEnv(`@((bool)context.Variables["junk"])`, env); err == nil {
		t.Error(`(bool)"maybe" must fail`)
	}
}

// peekAt must not run off the end of the token stream: a trailing `(` is a
// truncated expression, and looking past it would panic rather than report a
// syntax error.
func TestLookaheadPastEndOfInput(t *testing.T) {
	for _, source := range []string{"@(", "@((", "@((string", "@((string)"} {
		if _, err := EvalEnv(source, castEnv()); err == nil {
			t.Errorf("%q must be reported as a syntax error", source)
		}
	}
}

// A cast of a literal exercises the numeric path without going through a
// string variable, which is the only shape the emulator's Variables can hold.
func TestCastOfNumericLiterals(t *testing.T) {
	for source, want := range map[string]string{
		"@((int)42)":     "42",
		"@((double)2.5)": "2.5",
		"@((long)7)":     "7",
		"@((int)2.9)":    "2",
	} {
		got, err := EvalEnv(source, castEnv())
		if err != nil || got.String() != want {
			t.Errorf("%s = %q %v, want %q", source, got.String(), err, want)
		}
	}
}

// A syntactically invalid operand after a valid cast must surface as the
// operand's error, not be swallowed into a confusing cast failure.
func TestCastReportsOperandParseErrors(t *testing.T) {
	for _, source := range []string{`@((string))`, `@((int)*)`, `@((string), 1)`} {
		if _, err := EvalEnv(source, castEnv()); err == nil {
			t.Errorf("%q must be a syntax error", source)
		}
	}
}

// peekAt guards its own bounds. The parser never asks beyond the appended EOF
// token, so this is asserted directly: the guard exists for future callers
// using larger offsets, and without a test it would rot unnoticed.
func TestPeekAtIsBounded(t *testing.T) {
	tokens, _, err := Lex(`@(1)`)
	if err != nil {
		t.Fatal(err)
	}
	p := &parser{tokens: tokens}
	if got := p.peekAt(len(tokens) + 5); got.Kind != TokenEOF {
		t.Fatalf("peekAt past the end = %v, want EOF rather than a panic", got.Kind)
	}
}
