package expression

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleJWT = `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.` +
	`eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig"`

// `?.` answers null for a null receiver instead of failing, and short-circuits
// the REST of the chain as C# does, not merely its own link.
func TestNullConditionalAccess(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://api.example/orders", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Trim(sampleJWT, `"`))
	env := RequestEnv(request, map[string]string{"present": "yes"})
	for _, test := range []struct {
		source string
		want   any
	}{
		// A null receiver answers null rather than failing.
		{`@(context.Variables["absent"]?.Length == null)`, true},
		// A present one behaves as an ordinary access.
		{`@(context.Variables["present"]?.Length)`, int64(3)},
		// The corpus shape: a token that may not be one.
		{`@("not-a-token".AsJwt()?.Subject == null)`, true},
		{`@(` + sampleJWT + `.AsJwt()?.Subject)`, "subject"},
		// C#'s rule: everything AFTER a `?.` is conditional too, so `a?.b.c` is
		// null when `a` is, rather than failing on `.c`.
		{`@("not-a-token".AsJwt()?.Claims.Count == null)`, true},
		{`@("not-a-token".AsJwt()?.Claims["roles"] == null)`, true},
		{`@("not-a-token".AsJwt()?.Claims.ContainsKey("roles") == null)`, true},
		// And chained guards behave the same way.
		{`@("not-a-token".AsJwt()?.Claims?.Count == null)`, true},
		{`@(` + sampleJWT + `.AsJwt()?.Claims?.Count)`, float64(8)},
		// A guard on a non-null receiver leaves the rest of the chain working.
		{`@(` + sampleJWT + `.AsJwt()?.Claims["roles"][0])`, "admin"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.Interface() != test.want {
			t.Fatalf("%s = %#v, want %#v", test.source, got.Interface(), test.want)
		}
	}
	// Without a guard, a null receiver still fails loudly. `?.` is opt-in, and
	// making every access null-tolerant would hide the mistakes it is there to
	// let a policy handle deliberately.
	for _, source := range []string{
		`@(context.Variables["absent"].Length)`,
		`@("not-a-token".AsJwt().Subject)`,
	} {
		if _, err := EvalEnv(source, env); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	// A ternary is still a ternary: `?` only pairs with `.` when they touch.
	if got, err := EvalEnv(`@(context.Request.Method == "GET" ? "yes" : "no")`, env); err != nil || got.String() != "yes" {
		t.Fatalf("ternary = %q, %v", got.String(), err)
	}
	if _, _, err := Parse(`@(context.Variables?.)`); err == nil {
		t.Fatal("a null-conditional with no member was accepted")
	}
}

// `Jwt` joins the castable types. A cast asserts the shape rather than
// converting it, which is what `((Jwt)x).Claims` needs.
func TestJwtCast(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	got, err := EvalEnv(`@(((Jwt)`+sampleJWT+`.AsJwt()).Claims["roles"][0])`, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "admin" {
		t.Fatalf("cast jwt = %q", got.String())
	}
	// The corpus reaches for this through a VARIABLE, and a variable holds text
	// here rather than an object, so that form parses and then fails on the
	// member. The cast is not what blocks it.
	if _, err := EvalEnv(`@(((Jwt)context.Variables["idTokenJwt"]).Claims["name"][0])`, env); err == nil {
		t.Fatal("a jwt cast over a text variable resolved a member")
	}
}
