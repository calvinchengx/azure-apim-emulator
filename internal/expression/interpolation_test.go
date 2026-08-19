package expression

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Interpolated strings, which are the single largest gap Microsoft's own policy
// corpus reported: 47 of its expressions used one and none of them parsed.
func TestInterpolatedStrings(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://api.example/orders?id=A-1", nil)
	request.Header.Set("X-Tenant", "contoso")
	env := RequestEnv(request, map[string]string{"state": "opaque", "empty": ""})
	for _, test := range []struct{ source, want string }{
		{`@($"plain")`, "plain"},
		{`@($"tenant={context.Request.Headers.GetValueOrDefault("X-Tenant", "")}")`, "tenant=contoso"},
		{`@($"{context.Request.Method} {context.Request.Url.Path}")`, "GET /orders"},
		// Text either side of a hole, and two holes running together.
		{`@($"a{context.Variables["state"]}b{context.Variables["state"]}c")`, "aopaquebopaquec"},
		// A doubled brace is a literal brace, which is how C# escapes one.
		{`@($"{{literal}}")`, "{literal}"},
		{`@($"{{{context.Variables["state"]}}}")`, "{opaque}"},
		// A cast inside a hole, which the corpus writes constantly.
		{`@($"{(string)context.Variables["state"]}")`, "opaque"},
		// A hole holding another interpolated string.
		{`@($"outer:{$"inner:{context.Variables["state"]}"}")`, "outer:inner:opaque"},
		// A ternary inside a hole, whose colon must not read as a format specifier.
		{`@($"{(context.Request.Method == "GET" ? "ok" : "no")}")`, "ok"},
		// An escape in the literal text.
		{`@($"line\tend")`, "line\tend"},
		// Numbers render the way they render everywhere else.
		{`@($"n={1 + 2}")`, "n=3"},
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

// A null hole renders as EMPTY, which is what C# does. This is why the node is
// its own thing rather than sugar for `+`: what addition does with a null
// operand is a separate question that should not decide this one.
func TestInterpolatedNullRendersEmpty(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	got, err := EvalEnv(`@($"[{context.Variables["absent"]}]")`, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[]" {
		t.Fatalf("null hole = %q, want %q", got.String(), "[]")
	}
}

func TestInterpolatedStringRefusals(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	for _, test := range []struct{ source, contains string }{
		{`@($"{context.Nonexistent}")`, "unknown member"},
		// An alignment or format specifier is refused rather than dropped:
		// rendering `{value,10:F2}` unformatted would be silently wrong.
		{`@($"{1,10}")`, "not implemented"},
		{`@($"{1:F2}")`, "not implemented"},
		{`@($"{unclosed")`, "unclosed hole"},
		{`@($"stray}")`, "unmatched"},
		{`@($"{}")`, "expected expression"},
		{`@($"bad\q")`, "invalid escape"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
	// `$` on its own is still not a character this language has.
	if _, err := EvalEnv("@($x)", env); err == nil {
		t.Fatal("a bare $ was accepted")
	}
	// An interpolated string with no closing quote cannot be written inside
	// `@(...)`, because the wrapper scanner rejects it first. The scanner that
	// reads the body is checked directly instead.
	if _, _, err := splitInterpolation("no closing quote"); err == nil {
		t.Fatal("an unterminated interpolated string was accepted")
	}
	if _, _, err := splitInterpolation("newline\n\""); err == nil {
		t.Fatal("an interpolated string spanning a newline was accepted")
	}
}

// An interpolated string inside a policy BLOCK must not confuse the wrapper
// scanner: its braces belong to the string, not to the block.
func TestInterpolatedStringInsideABlock(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"who": "ada"})
	got, err := EvalEnv(`@{ var greeting = $"hello {context.Variables["who"]}"; return greeting; }`, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "hello ada" {
		t.Fatalf("block interpolation = %q", got.String())
	}
}

// The lexer validates an interpolated string before the parser re-splits it, so
// these branches cannot be reached through a policy. They are exercised
// directly rather than left as code nothing has ever run.
func TestInterpolationScannerEdges(t *testing.T) {
	// A trailing backslash: an escape with nothing to escape.
	if _, _, err := splitInterpolation(`abc\`); err == nil {
		t.Fatal("a trailing backslash was accepted")
	}
	// The scanner's own error path, reached by tokenising directly.
	if _, err := scan(`$"bad\q"`); err == nil {
		t.Fatal("an invalid escape was accepted by the scanner")
	}
	// The parser's, reached with a token the lexer would never produce.
	sub := &parser{}
	if _, err := sub.interpolation(Token{Kind: TokenInterpolated, Lexeme: `$"bad\q"`}); err == nil {
		t.Fatal("the parser accepted an unscannable interpolated string")
	}
	// And a hole whose source does not tokenise at all.
	if _, err := parseHole(`"unterminated`); err == nil {
		t.Fatal("an untokenisable hole was accepted")
	}
}
