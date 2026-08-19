package expression

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A local may be declared with an explicit type rather than `var`, which is how
// five of Microsoft's own policy expressions are written.
func TestTypedLocalDeclarations(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://api.example/orders?id=A-1", nil)
	request.Header.Set("X-Tenant", "contoso")
	env := RequestEnv(request, map[string]string{"plainText": "payload"})
	for _, test := range []struct{ source, want string }{
		{`@{ string body = (string)context.Variables["plainText"]; return body; }`, "payload"},
		{`@{ int count = 1 + 1; return count.ToString(); }`, "2"},
		{`@{ bool ok = true; return ok.ToString(); }`, "True"},
		// A namespace-qualified type name.
		{`@{ System.String raw = "text"; return raw; }`, "text"},
		// An array type, which the corpus writes as `byte[] bytes = ...`. The
		// element type is discarded like any other, so what is checked here is
		// that `T[] name =` is read as a declaration at all.
		{`@{ string[] parts = null; return parts == null ? "empty" : "set"; }`, "empty"},
		// Typed and `var` locals mix, in either order.
		{`@{ string first = "a"; var second = "b"; return first + second; }`, "ab"},
		{`@{ var first = "a"; string second = "b"; return first + second; }`, "ab"},
		// A declared type this evaluator knows nothing about is still a valid
		// declaration: the type is discarded, not resolved.
		{`@{ JObject payload = new JObject(new JProperty("a", 1)); return payload.ToString(); }`, `{"a":1}`},
		// And inside an if, which shares the same block parser.
		{`@{ if (context.Request.Method == "GET") { string inner = "yes"; return inner; } else { return "no"; } }`, "yes"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.String() != test.want {
			t.Fatalf("%s = %q, want %q", test.source, got.String(), test.want)
		}
	}
}

// The shape is self-disambiguating, so things that only LOOK like declarations
// must still parse as what they are.
func TestTypedLocalDoesNotSwallowExpressions(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"a": "1"})
	// A member access is not a declaration, even though it starts with an
	// identifier and contains dots.
	if got, err := EvalEnv(`@{ return context.Request.Method; }`, env); err != nil || got.String() != "GET" {
		t.Fatalf("member access = %q, %v", got.String(), err)
	}
	// An indexer is not an array type.
	if got, err := EvalEnv(`@{ return context.Variables["a"]; }`, env); err != nil || got.String() != "1" {
		t.Fatalf("indexer = %q, %v", got.String(), err)
	}
	for _, test := range []struct{ source, contains string }{
		// A statement that is neither a declaration nor a return still reports,
		// naming what it saw, rather than being silently skipped.
		{`@{ string; }`, "not implemented"},
		{`@{ string name; return name; }`, "not implemented"},
		// A declaration missing its value.
		{`@{ string name = ; return name; }`, "unexpected token"},
		// And missing its semicolon.
		{`@{ string name = "x" return name; }`, "expected ';'"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
}
