package expression

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A collection answers Count and position, and refuses everything else loudly.
// The loudness matters: this language has no LINQ, so a policy written with
// `.Any(...)` must fail visibly rather than quietly returning false.
func TestCollectionMembersAndRefusals(t *testing.T) {
	env := Bind(Context{User: &UserContext{
		Groups:     []GroupContext{{Id: "devs", Name: "Developers"}, {Id: "ops", Name: "Operations"}},
		Identities: []UserIdentityContext{{Id: "ada@example.test", Provider: "Basic"}},
	}})
	if got, err := EvalEnv("@(context.User.Groups.Count)", env); err != nil || got.String() != "2" {
		t.Fatalf("count = %q, %v", got.String(), err)
	}
	if got, err := EvalEnv("@(context.User.Groups[1].Id)", env); err != nil || got.String() != "ops" {
		t.Fatalf("second group = %q, %v", got.String(), err)
	}
	// Arithmetic yields a double rather than an int, and `Groups[n-1]` is an
	// ordinary thing to write, so both numeric kinds index.
	if got, err := EvalEnv("@(context.User.Groups[2 - 1].Id)", env); err != nil || got.String() != "ops" {
		t.Fatalf("computed index = %q, %v", got.String(), err)
	}
	// A double-valued index reads the same position: integer arithmetic stays
	// integral, so this is the only way that branch is reached, and a policy
	// dividing to compute an index would take it.
	if got, err := EvalEnv("@(context.User.Groups[2.0 / 2.0].Id)", env); err != nil || got.String() != "ops" {
		t.Fatalf("double index = %q, %v", got.String(), err)
	}
	for _, test := range []struct{ source, contains string }{
		// The LINQ refusal says why, so the failure is actionable rather than
		// just "unknown member".
		{"@(context.User.Groups.Any())", "no LINQ operators"},
		{"@(context.User.Identities.Where())", "no LINQ operators"},
		// Out of range is an error rather than null: a null would surface later
		// as a confusing member-access-on-null somewhere else.
		{"@(context.User.Groups[9].Id)", "outside a collection"},
		{"@(context.User.Groups[-1].Id)", "outside a collection"},
		{`@(context.User.Groups["devs"].Id)`, "indexed by position"},
		{"@(context.User.Groups[0].Nonexistent)", "unknown member"},
		{"@(context.User.Identities[0].Nonexistent)", "unknown member"},
		{"@(context.User.Nonexistent)", "unknown member"},
	} {
		_, err := EvalEnv(test.source, env)
		if err == nil {
			t.Fatalf("accepted %s", test.source)
		}
		if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want it to mention %q", test.source, err, test.contains)
		}
	}
}

// `Body.As<T>()` is a generic call, and the `<` that introduces it is the same
// token as the comparison operator. Both readings must keep working.
func TestGenericBodyMembers(t *testing.T) {
	body := func(text string) *Env {
		return Bind(Context{Request: requestWithBody(text)})
	}
	if got, err := EvalEnv(`@(context.Request.Body.As<string>())`, body("payload")); err != nil || got.String() != "payload" {
		t.Fatalf("As<string> = %q, %v", got.String(), err)
	}
	// A parsed body is indexable, which is the whole reason to ask for JObject
	// rather than string.
	if got, err := EvalEnv(`@(context.Request.Body.As<JObject>()["sku"])`, body(`{"sku":"widget"}`)); err != nil || got.String() != "widget" {
		t.Fatalf("As<JObject> = %q, %v", got.String(), err)
	}
	// An array is walked the same way, and its scalars read as scalars rather
	// than as their JSON text.
	if got, err := EvalEnv(`@(context.Request.Body.As<JArray>()[1])`, body(`[10,20]`)); err != nil || got.String() != "20" {
		t.Fatalf("As<JArray> = %q, %v", got.String(), err)
	}
	// A form field may legitimately repeat, so each is a collection.
	form := body("a=1&a=2&b=3")
	if got, err := EvalEnv(`@(context.Request.Body.AsFormUrlEncodedContent()["a"].Count)`, form); err != nil || got.String() != "2" {
		t.Fatalf("repeated field = %q, %v", got.String(), err)
	}
	if got, err := EvalEnv(`@(context.Request.Body.AsFormUrlEncodedContent().Count)`, body("a=1&b=3")); err != nil || got.String() != "2" {
		t.Fatalf("field count = %q, %v", got.String(), err)
	}
	if got, err := EvalEnv(`@(context.Request.Body.AsFormUrlEncodedContent().ContainsKey("b"))`, body("a=1&b=3")); err != nil || !got.Truthy() {
		t.Fatalf("ContainsKey = %v, %v", got.Truthy(), err)
	}
	if got, err := EvalEnv(`@(context.Request.Body.AsFormUrlEncodedContent()["absent"] == null)`, body("a=1")); err != nil || !got.Truthy() {
		t.Fatalf("absent field = %v, %v", got.Truthy(), err)
	}

	for _, test := range []struct{ source, contains string }{
		// A type this emulator cannot produce is refused rather than silently
		// downgraded, or a policy indexing into what it believes is an object
		// would fail somewhere far from the cause.
		{`@(context.Request.Body.As<Widget>())`, "not supported"},
		{`@(context.Request.Body.As)`, "requires a type argument"},
		{`@(context.Request.Body.As<JObject>())`, "not JSON"},
		{`@(context.Request.Body.AsFormUrlEncodedContent()[0])`, "indexed by field name"},
		{`@(context.Request.Body.AsFormUrlEncodedContent().Nonexistent)`, "unknown member"},
		{`@(context.Api.As<string>())`, "not a generic member"},
		{`@(context.Request.Body.AsString<string>())`, "not a generic member"},
		{`@(context.Request.Body.As<JObject>("a", "b"))`, "at most one argument"},
		{`@(context.Request.Body.AsFormUrlEncodedContent("a", "b"))`, "at most one argument"},
		{`@(context.Request.Body.AsFormUrlEncodedContent().ContainsKey(1))`, "requires a string"},
	} {
		env := body("not json at all")
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
	if _, err := EvalEnv(`@(context.Request.Body.AsFormUrlEncodedContent())`, body("%zz=1")); err == nil {
		t.Fatal("a body that is not form-encoded was accepted")
	}
	// A body that cannot be read fails on the way in rather than parsing as empty.
	unreadable := httptest.NewRequest(http.MethodPost, "/", errorReader{})
	for _, source := range []string{
		`@(context.Request.Body.As<JObject>())`,
		`@(context.Request.Body.AsFormUrlEncodedContent())`,
	} {
		if _, err := EvalEnv(source, RequestEnv(unreadable, nil)); err == nil {
			t.Fatalf("%s accepted an unreadable body", source)
		}
	}
	// jsonDocument takes any value, so a value it cannot convert reports rather
	// than reaching a policy as something else.
	if _, err := jsonDocument([]any{make(chan int)}); err == nil {
		t.Fatal("an unconvertible element was accepted")
	}
}

// A type argument is only a type argument when an argument list follows it.
// `a.B < c` and `a.B < c > d` are comparisons, and the parser has to rewind
// rather than read the comparison as a generic call.
func TestComparisonIsNotATypeArgument(t *testing.T) {
	for _, source := range []string{
		`@(context.Response.StatusCode < 200)`,
		`@(context.Response.StatusCode < limit)`,
		`@(context.Response.StatusCode < limit > floor)`,
	} {
		if _, _, err := Parse(source); err != nil {
			t.Fatalf("%s did not parse: %v", source, err)
		}
	}
}

// The comparison operator still parses: a type argument is recognised only when
// `< identifier > (` follows, and anything else rewinds.
func TestLessThanStillParses(t *testing.T) {
	env := Bind(Context{User: &UserContext{Groups: []GroupContext{{Id: "devs"}}}})
	for _, source := range []string{
		"@(context.User.Groups.Count < 3)",
		"@(context.User.Groups.Count < 3 == true)",
		// `<ident>` not followed by a call rewinds and reads as two comparisons.
		"@(1 < 2 == true)",
	} {
		if _, err := EvalEnv(source, env); err != nil {
			t.Fatalf("%s failed: %v", source, err)
		}
	}
}

// requestWithBody builds a request whose body an expression can read.
func requestWithBody(text string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", strings.NewReader(text))
}
