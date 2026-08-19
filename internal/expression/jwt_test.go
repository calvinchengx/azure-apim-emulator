package expression

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// makeJWT builds a signed-looking JWT. The signature is never checked here:
// AsJwt reads a token, and validate-jwt is what verifies one.
func makeJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	encode := func(value map[string]any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(header) + "." + encode(payload) + ".signature"
}

func TestAsJwtReadsATokenMicrosoftsWay(t *testing.T) {
	jwt := makeJWT(t,
		map[string]any{"alg": "RS256", "typ": "JWT"},
		map[string]any{
			"jti": "id-1", "iss": "issuer", "sub": "subject",
			"aud": []any{"first", "second"},
			"exp": 2000000000, "nbf": 1000000000, "iat": 1000000000,
			"roles": []any{"admin", "auditor"}, "tier": 3,
		})
	env := Bind(Context{})
	for _, test := range []struct {
		source string
		want   any
	}{
		{"@('" + jwt + "'.AsJwt().Id)", "id-1"},
		{"@('" + jwt + "'.AsJwt().Issuer)", "issuer"},
		{"@('" + jwt + "'.AsJwt().Subject)", "subject"},
		// Algorithm and Type come from the HEADER, not the payload.
		{"@('" + jwt + "'.AsJwt().Algorithm)", "RS256"},
		{"@('" + jwt + "'.AsJwt().Type)", "JWT"},
		{"@('" + jwt + "'.AsJwt().Audiences.Count)", float64(2)},
		{"@('" + jwt + "'.AsJwt().Audiences[1])", "second"},
		// The times render as text, and an absent one is null rather than the
		// unix epoch, which a policy comparing against now would read as past.
		{"@('" + jwt + "'.AsJwt().ExpirationTime)", "2033-05-18T03:33:20Z"},
		{"@('" + jwt + "'.AsJwt().NotBefore)", "2001-09-09T01:46:40Z"},
		{"@('" + jwt + "'.AsJwt().IssuedAt)", "2001-09-09T01:46:40Z"},
		// A claim is a COLLECTION of values, because a claim may repeat.
		{"@('" + jwt + "'.AsJwt().Claims[\"roles\"].Count)", float64(2)},
		{"@('" + jwt + "'.AsJwt().Claims[\"roles\"][0])", "admin"},
		{"@('" + jwt + "'.AsJwt().Claims.GetValueOrDefault(\"roles\", \"none\"))", "admin"},
		{"@('" + jwt + "'.AsJwt().Claims.GetValueOrDefault(\"absent\", \"none\"))", "none"},
		{"@('" + jwt + "'.AsJwt().Claims.GetValueOrDefault(\"absent\"))", ""},
		{"@('" + jwt + "'.AsJwt().Claims.ContainsKey(\"tier\"))", true},
		{"@('" + jwt + "'.AsJwt().Claims.ContainsKey(\"absent\"))", false},
		// A non-string claim renders the way this evaluator renders it anywhere.
		{"@('" + jwt + "'.AsJwt().Claims.GetValueOrDefault(\"tier\", \"\"))", "3"},
		{"@('" + jwt + "'.AsJwt().Claims[\"absent\"] == null)", true},
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

// Microsoft documents AsJwt as returning NULL for input that is not a token,
// not as failing. `AsJwt() != null` is how a policy asks the question.
func TestAsJwtAnswersNullRatherThanFailing(t *testing.T) {
	env := Bind(Context{})
	for _, source := range []string{
		"@('not-a-token'.AsJwt() == null)",
		"@(''.AsJwt() == null)",
		"@('a.!!!.c'.AsJwt() == null)",
	} {
		got, err := EvalEnv(source, env)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		if !got.Truthy() {
			t.Fatalf("%s was not null", source)
		}
	}
	// A token whose HEADER is unreadable still yields its claims: the payload
	// is what decides, and validate-jwt has always read the payload alone.
	broken := "!!!." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"still-here"}`)) + ".sig"
	got, err := EvalEnv("@('"+broken+"'.AsJwt().Issuer)", env)
	if err != nil || got.String() != "still-here" {
		t.Fatalf("broken header = %q, %v", got.String(), err)
	}
	// And its Algorithm reads empty rather than inventing one.
	if got, err := EvalEnv("@('"+broken+"'.AsJwt().Algorithm)", env); err != nil || got.String() != "" {
		t.Fatalf("algorithm from a broken header = %q, %v", got.String(), err)
	}
	// An `aud` given as a single string is as valid as an array of them.
	single := makeJWT(t, map[string]any{}, map[string]any{"aud": "only"})
	if got, err := EvalEnv("@('"+single+"'.AsJwt().Audiences[0])", env); err != nil || got.String() != "only" {
		t.Fatalf("string aud = %q, %v", got.String(), err)
	}
	// A claim missing entirely leaves the string members empty and the times null.
	bare := makeJWT(t, map[string]any{}, map[string]any{})
	for _, test := range []struct{ source, want string }{
		{"@('" + bare + "'.AsJwt().Id)", ""},
		{"@('" + bare + "'.AsJwt().ExpirationTime == null)", "True"},
		{"@('" + bare + "'.AsJwt().Audiences.Count)", "0"},
	} {
		if got, err := EvalEnv(test.source, env); err != nil || got.String() != test.want {
			t.Fatalf("%s = %q, %v", test.source, got.String(), err)
		}
	}
}

func TestJwtAndBasicRefusals(t *testing.T) {
	jwt := makeJWT(t, map[string]any{"alg": "HS256"}, map[string]any{"iss": "x"})
	env := Bind(Context{})
	for _, test := range []struct{ source, contains string }{
		{"@('" + jwt + "'.AsJwt().Nonexistent)", "unknown member"},
		{"@('" + jwt + "'.AsJwt().Claims.Nonexistent)", "unknown member"},
		{"@('" + jwt + "'.AsJwt().Claims[0])", "indexed by claim name"},
		{"@('" + jwt + "'.AsJwt().Claims.ContainsKey(1))", "requires a claim name"},
		{"@('" + jwt + "'.AsJwt().Claims.GetValueOrDefault())", "requires a claim name"},
		{"@('" + jwt + "'.AsJwt('extra'))", "takes no arguments"},
		// A number has no AsJwt, and says so the way it does for any other
		// member it lacks. It used to answer "AsJwt requires a string", which
		// was more specific but inconsistent with every other type.
		{"@(1.AsJwt)", "unknown member AsJwt"},
		{"@(1.AsBasic)", "unknown member AsBasic"},
		{"@('Basic YWRhOnMzY3JldA=='.AsBasic('extra'))", "takes no arguments"},
		{"@('Basic YWRhOnMzY3JldA=='.AsBasic().Nonexistent)", "unknown member"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
}

// AsBasic accepts the header value with or without the scheme, and answers null
// for anything that is not a user:password pair.
func TestAsBasic(t *testing.T) {
	env := Bind(Context{})
	for _, test := range []struct {
		source string
		want   any
	}{
		{"@('Basic YWRhOnMzY3JldA=='.AsBasic().Username)", "ada"},
		{"@('Basic YWRhOnMzY3JldA=='.AsBasic().Password)", "s3cret"},
		// The scheme is optional: a policy often passes the decoded portion.
		{"@('YWRhOnMzY3JldA=='.AsBasic().Username)", "ada"},
		// Case does not matter in an HTTP auth scheme.
		{"@('basic YWRhOnMzY3JldA=='.AsBasic().Username)", "ada"},
		{"@('Basic not-base64!'.AsBasic() == null)", true},
		// Valid base64 with no colon is not a credential pair.
		{"@('Basic bm9jb2xvbg=='.AsBasic() == null)", true},
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

// context.Trace records a message, and is a NO-OP rather than a failure where
// nothing is collecting: a policy that traces should not break when tracing off.
func TestContextTrace(t *testing.T) {
	var recorded []string
	env := Bind(Context{Trace: func(message string) { recorded = append(recorded, message) }})
	if _, err := EvalEnv("@(context.Trace('hello'))", env); err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0] != "hello" {
		t.Fatalf("recorded = %#v", recorded)
	}
	if _, err := EvalEnv("@(context.Trace('quiet'))", Bind(Context{})); err != nil {
		t.Fatalf("tracing with no collector failed: %v", err)
	}
	for _, source := range []string{"@(context.Trace())", "@(context.Trace(1))"} {
		if _, err := EvalEnv(source, env); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}

func TestApiProtocols(t *testing.T) {
	env := Bind(Context{Api: &ApiContext{Id: "orders", Protocols: []string{"https"}}})
	if got, err := EvalEnv("@(context.Api.Protocols[0])", env); err != nil || got.String() != "https" {
		t.Fatalf("protocol = %q, %v", got.String(), err)
	}
	// An api with no protocols recorded answers an empty collection rather than
	// failing, so `.Count == 0` is a question a policy can ask.
	empty := Bind(Context{Api: &ApiContext{Id: "orders"}})
	if got, err := EvalEnv("@(context.Api.Protocols.Count)", empty); err != nil || got.String() != "0" {
		t.Fatalf("empty protocols = %q, %v", got.String(), err)
	}
	_ = httptest.NewRequest(http.MethodGet, "/", nil)
}

// claimValues takes `any`, so a value JSON never produces can still reach it.
// It reports rather than rendering something misleading into a claim.
func TestClaimValuesRefusesWhatItCannotRender(t *testing.T) {
	if _, ok := claimValues(map[string]any{"bad": make(chan int)}, "bad"); ok {
		t.Fatal("an unconvertible claim was accepted")
	}
	if _, ok := claimValues(map[string]any{"bad": []any{make(chan int)}}, "bad"); ok {
		t.Fatal("an unconvertible claim element was accepted")
	}
}
