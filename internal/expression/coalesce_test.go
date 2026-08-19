package expression

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// `??` answers its left side unless that is null, and `?[` is the indexing
// counterpart of `?.`. Together with `?.` they are C#'s three null operators,
// and the corpus writes all three in one expression: `...?[1] ?? string.Empty`.
func TestNullCoalescingAndConditionalIndex(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://api.example/a?x=1", nil)
	request.Header.Set("X-Present", "here")
	env := RequestEnv(request, map[string]string{"set": "value"})
	for _, test := range []struct {
		source string
		want   any
	}{
		{`@(context.Variables["set"] ?? "fallback")`, "value"},
		{`@(context.Variables["absent"] ?? "fallback")`, "fallback"},
		// Right-associative, so a chain tries each fallback in turn.
		{`@(context.Variables["absent"] ?? context.Variables["also-absent"] ?? "last")`, "last"},
		{`@(context.Variables["absent"] ?? context.Variables["set"] ?? "last")`, "value"},
		// `??` binds looser than a comparison, so this is `a ?? (b == c)`.
		{`@(context.Variables["absent"] ?? context.Request.Method == "GET")`, true},
		// And tighter than a ternary, so the coalesce is the condition.
		{`@(context.Variables["absent"] ?? "no" == "no" ? "yes" : "nope")`, "yes"},
		// `?[` answers null for a null receiver instead of failing.
		{`@(context.Variables["absent"]?[0] == null)`, true},
		{`@(context.Request.Headers["X-Present"]?[0])`, "here"},
		{`@(context.Request.Headers["X-Absent"]?[0] ?? "none")`, "none"},
		// `?[` guards the REST of the chain, the same rule `?.` follows.
		{`@(context.Request.Headers["X-Absent"]?[0].Length == null)`, true},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.Interface() != test.want {
			t.Fatalf("%s = %#v, want %#v", test.source, got.Interface(), test.want)
		}
	}
	// The right side is evaluated ONLY when needed. A fallback that would fail
	// must not fail an expression that never needed it.
	if got, err := EvalEnv(`@(context.Variables["set"] ?? context.Nonexistent)`, env); err != nil || got.String() != "value" {
		t.Fatalf("short circuit = %q, %v", got.String(), err)
	}
	// A failure on the LEFT surfaces rather than falling through to the
	// fallback: `??` handles null, not errors, and swallowing one would turn a
	// broken expression into a silent default.
	if _, err := EvalEnv(`@(context.Nonexistent ?? "fallback")`, env); err == nil {
		t.Fatal("a failing left side fell through to the fallback")
	}
	// And when the fallback IS needed, its failure surfaces.
	if _, err := EvalEnv(`@(context.Variables["absent"] ?? context.Nonexistent)`, env); err == nil {
		t.Fatal("a failing fallback was accepted")
	}
	// An unguarded index on null still fails: these operators are opt-in.
	if _, err := EvalEnv(`@(context.Variables["absent"][0])`, env); err == nil {
		t.Fatal("an unguarded index on null was accepted")
	}
	for _, source := range []string{`@(1 ??)`, `@(?? 1)`, `@(context.Variables["a"]?[)`} {
		if _, _, err := Parse(source); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	// A lone `?` is still a ternary's, and `? [` with a space is not `?[`.
	if got, err := EvalEnv(`@(context.Request.Method == "GET" ? "y" : "n")`, env); err != nil || got.String() != "y" {
		t.Fatalf("ternary = %q, %v", got.String(), err)
	}
}
