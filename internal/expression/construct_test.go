package expression

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func constructEnv() *Env {
	return RequestEnv(httptest.NewRequest(http.MethodGet, "https://api.example/orders?id=A-1", nil), map[string]string{"seed": "7"})
}

// A seeded Random is REPRODUCIBLE, which is what a policy passing a seed is
// asking for. An unseeded one is not, so it is checked for range instead.
func TestRandomConstruction(t *testing.T) {
	env := constructEnv()
	first, err := EvalEnv("@(new Random(42).Next(1, 100))", env)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvalEnv("@(new Random(42).Next(1, 100))", env)
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("the same seed gave %q then %q", first.String(), second.String())
	}
	// The upper bound is EXCLUSIVE, as it is in .NET. A traffic split written
	// as Next(1, 100) must never answer 100.
	for i := 0; i < 200; i++ {
		got, err := EvalEnv("@(new Random().Next(1, 3))", env)
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != "1" && got.String() != "2" {
			t.Fatalf("Next(1, 3) = %q, outside [1, 3)", got.String())
		}
	}
	// The namespace-qualified spelling names the same type.
	if _, err := EvalEnv("@(new System.Random().Next(1, 100))", env); err != nil {
		t.Fatalf("qualified Random: %v", err)
	}
	for _, test := range []struct{ source, contains string }{
		// An empty or inverted range would send a policy down a branch it never
		// chose, so it reports rather than answering a number.
		{"@(new Random(1).Next(5, 5))", "upper bound above"},
		{"@(new Random(1).Next(9, 2))", "upper bound above"},
		{"@(new Random(1).Next(1, 2, 3))", "at most two bounds"},
		{`@(new Random(1).Next("x"))`, "integer bounds"},
		{`@(new Random("x"))`, "integer seed"},
		{"@(new Random(1, 2))", "at most one seed"},
		{"@(new Random(1).Nonexistent)", "unknown member"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
	// Next with no bound and with one bound both answer within range.
	if got, err := EvalEnv("@(new Random(3).Next(5))", env); err != nil || got.String() == "" {
		t.Fatalf("Next(5) = %q, %v", got.String(), err)
	}
	if got, err := EvalEnv("@(new Random(3).Next())", env); err != nil || got.String() == "" {
		t.Fatalf("Next() = %q, %v", got.String(), err)
	}
}

// System.Uri is NOT APIM's IUrl. It carries .NET's member names, and the corpus
// reaches for it to pick a redirect apart.
func TestUriConstruction(t *testing.T) {
	env := constructEnv()
	for _, test := range []struct{ source, want string }{
		{`@(new Uri("https://host.test:8443/a/b?x=1").AbsolutePath)`, "/a/b"},
		{`@(new Uri("https://host.test:8443/a/b?x=1").Host)`, "host.test"},
		{`@(new Uri("https://host.test:8443/a/b?x=1").Scheme)`, "https"},
		{`@(new Uri("https://host.test:8443/a/b?x=1").Port.ToString())`, "8443"},
		// .NET keeps the leading '?', unlike APIM's IUrl.Query, which is a
		// dictionary. Two types, two shapes.
		{`@(new Uri("https://host.test/a?x=1").Query)`, "?x=1"},
		{`@(new Uri("https://host.test/a").Query)`, ""},
		{`@(new Uri("https://host.test/a").AbsoluteUri)`, "https://host.test/a"},
		// A missing port answers the scheme's default, as .NET does.
		{`@(new Uri("https://host.test/a").Port.ToString())`, "443"},
		{`@(new Uri("http://host.test/a").Port.ToString())`, "80"},
		{`@(new Uri("mailto:someone@host.test").Port.ToString())`, "-1"},
		// A Uri renders as its own text, so it interpolates.
		{`@($"{new Uri("https://host.test/a")}")`, "https://host.test/a"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.String() != test.want {
			t.Fatalf("%s = %q, want %q", test.source, got.String(), test.want)
		}
	}
	for _, test := range []struct{ source, contains string }{
		{`@(new Uri("https://host.test").Nonexistent)`, "unknown member"},
		{`@(new Uri())`, "one string"},
		{`@(new Uri(1))`, "one string"},
		{`@(new Uri("://nonsense"))`, "unparsable"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
}

// `new JObject(new JProperty(...))` is how the corpus builds a response body.
func TestJObjectConstruction(t *testing.T) {
	env := constructEnv()
	for _, test := range []struct{ source, want string }{
		{`@(new JProperty("status", "HTTP 405").Name)`, "status"},
		{`@(new JProperty("status", "HTTP 405").Value)`, "HTTP 405"},
		{`@(new JObject(new JProperty("status", "HTTP 405")).status)`, "HTTP 405"},
		{`@(new JObject(new JProperty("status", "HTTP 405"))["status"])`, "HTTP 405"},
		{`@(new JObject(new JProperty("a", 1), new JProperty("b", 2)).Count)`, "2"},
		{`@(new JObject(new JProperty("a", 1)).ContainsKey("a"))`, "True"},
		{`@(new JObject(new JProperty("a", 1)).ContainsKey("z"))`, "False"},
		// It renders as JSON, in the order the author wrote, because that is a
		// response body and Newtonsoft preserves the order.
		{`@(new JObject(new JProperty("b", "second"), new JProperty("a", 1)).ToString())`, `{"b":"second","a":1}`},
		// A nested object nests rather than collapsing to its text.
		{`@(new JObject(new JProperty("outer", new JObject(new JProperty("inner", true)))).ToString())`, `{"outer":{"inner":true}}`},
		// A boolean is lowercase in JSON even though this evaluator renders one
		// as .NET's True everywhere else.
		{`@(new JObject(new JProperty("yes", true), new JProperty("no", false)).ToString())`, `{"yes":true,"no":false}`},
		// An absent key is null rather than an error, so `== null` is askable.
		{`@(new JObject(new JProperty("a", 1))["z"] == null)`, "True"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.String() != test.want {
			t.Fatalf("%s = %q, want %q", test.source, got.String(), test.want)
		}
	}
	for _, test := range []struct{ source, contains string }{
		{`@(new JObject("not a property"))`, "JProperty arguments"},
		{`@(new JProperty("only"))`, "a name and a value"},
		{`@(new JProperty(1, 2))`, "a name and a value"},
		{`@(new JProperty("a", 1).Nonexistent)`, "unknown member"},
		{`@(new JObject(new JProperty("a", 1)).Nonexistent)`, "unknown member"},
		{`@(new JObject(new JProperty("a", 1))[0])`, "indexed by name"},
		{`@(new JObject(new JProperty("a", 1)).ContainsKey(1))`, "requires a name"},
		{`@(new JObject(new JProperty("a", 1)).ToString("x"))`, "takes no arguments"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
}

// An anonymous object is the same value as a JObject: a policy builds one to
// serialise it.
func TestAnonymousObjectConstruction(t *testing.T) {
	env := constructEnv()
	for _, test := range []struct{ source, want string }{
		{`@(new { typ = "JWT", alg = "RS256" }.typ)`, "JWT"},
		{`@(new { typ = "JWT", alg = "RS256" }.ToString())`, `{"typ":"JWT","alg":"RS256"}`},
		{`@(new { count = 1 + 1 }.count)`, "2"},
		{`@(new { }.Count)`, "0"},
		{`@(new { missing = null }.ToString())`, `{"missing":null}`},
		// A trailing comma is legal in C# and appears in real policies.
		{`@(new { a = 1, }.Count)`, "1"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.String() != test.want {
			t.Fatalf("%s = %q, want %q", test.source, got.String(), test.want)
		}
	}
	for _, test := range []struct{ source, contains string }{
		{`@(new { 1 = "x" })`, "field name"},
		{`@(new { a })`, "expected '='"},
		{`@(new { a = 1 )`, "close an anonymous object"},
		// A type nobody implements is refused BY NAME at parse time, rather
		// than compiling and failing when a request arrives.
		{`@(new XDocument())`, "new XDocument is not implemented"},
		{`@(new 5())`, "expected a type name"},
		{`@(new Random)`, "expected '('"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
}

// A failure inside a constructor's arguments, or inside an anonymous object's
// field, must surface rather than being swallowed into the constructed value.
func TestConstructionPropagatesArgumentFailures(t *testing.T) {
	env := constructEnv()
	for _, source := range []string{
		`@(new Random(context.Nonexistent))`,
		`@(new JProperty("a", context.Nonexistent))`,
		`@(new { a = context.Nonexistent })`,
		`@(new { a = 1, b = context.Nonexistent })`,
	} {
		if _, err := EvalEnv(source, env); err == nil {
			t.Fatalf("accepted %s", source)
		} else if !strings.Contains(err.Error(), "unknown member") {
			t.Fatalf("%s failed with %q", source, err)
		}
	}
	// A malformed field value is a PARSE error, not an evaluation one.
	if _, _, err := Parse(`@(new { a = })`); err == nil {
		t.Fatal("an empty field value was accepted")
	}
	// Both bounds are checked, not just the first.
	if _, err := EvalEnv(`@(new Random(1).Next(1, "x"))`, env); err == nil {
		t.Fatal("a non-numeric upper bound was accepted")
	}
}
