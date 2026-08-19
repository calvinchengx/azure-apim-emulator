package expression

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// C# lets a caller name an argument, and Microsoft's own policies do:
// `Body.As<string>(preserveContent: true)`.
func TestNamedArguments(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=1")), nil)
	for _, test := range []struct{ source, want string }{
		{`@(context.Request.Body.As<string>(preserveContent: true))`, "a=1"},
		{`@(context.Request.Body.AsFormUrlEncodedContent(preserveContent: true).Count)`, "1"},
		// Positional still works, and so does the argument-free form.
		{`@(context.Request.Body.As<string>(true))`, "a=1"},
		{`@(context.Request.Body.As<string>())`, "a=1"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.String() != test.want {
			t.Fatalf("%s = %q, want %q", test.source, got.String(), test.want)
		}
	}
	// The body is readable AGAIN afterwards, which is what preserveContent asks
	// for. This gateway captures a body so it can be replayed, so the flag is
	// accepted and has no effect rather than being refused.
	twice := RequestEnv(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body")), nil)
	if _, err := EvalEnv(`@(context.Request.Body.As<string>(preserveContent: true))`, twice); err != nil {
		t.Fatal(err)
	}
	if got, err := EvalEnv(`@(context.Request.Body.As<string>())`, twice); err != nil || got.String() != "body" {
		t.Fatalf("second read = %q, %v", got.String(), err)
	}
}

func TestNamedArgumentRefusals(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=1")), nil)
	for _, test := range []struct{ source, contains string }{
		// A name nobody documents is a typo, and says so rather than being
		// accepted and ignored.
		{`@(context.Request.Body.As<string>(preserveContnet: true))`, "not a documented parameter name"},
		{`@(context.Request.Body.As<string>(nonsense: true))`, "not a documented parameter name"},
		// C# lets a caller REORDER named arguments. Resolving that needs
		// per-callee parameter metadata this evaluator does not carry, so
		// passing them positionally could bind the wrong value to the wrong
		// parameter. Refused loudly instead.
		{`@(context.Request.Headers.GetValueOrDefault(headerName: "a", defaultValue: "b"))`, "only supported where a call takes one argument"},
		{`@(new Random(key: 1, iv: 2))`, "only supported where a call takes one argument"},
		// The name check runs first, so an undocumented name is named even in a
		// call that would also be refused for its arity.
		{`@(new Random(seed: 1, extra: 2))`, "seed is not a documented parameter name"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
	// The names come from Microsoft's own signatures, derived rather than
	// listed, so this is the set a caller may use.
	names := DocumentedParameterNames()
	if len(names) < 8 {
		t.Fatalf("only %d documented parameter names: %v", len(names), names)
	}
	found := false
	for _, name := range names {
		if name == "preserveContent" {
			found = true
		}
	}
	if !found {
		t.Fatalf("preserveContent is not among the documented parameter names: %v", names)
	}
}
