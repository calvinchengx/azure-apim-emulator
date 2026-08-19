package expression

import (
	"encoding/json"
	"testing"
)

func graphQLEnv(arguments, parent map[string]any) *Env {
	return Bind(Context{GraphQL: &GraphQLContext{Arguments: arguments, Parent: parent}})
}

func evalString(t *testing.T, env *Env, source string) string {
	t.Helper()
	value, err := EvalEnv(source, env)
	if err != nil {
		t.Fatalf("EvalEnv(%s): %v", source, err)
	}
	return value.String()
}

// An argument's TYPE is load-bearing, not just its text: a resolver comparing
// `Arguments["first"] > 5` needs a number, and one interpolating it into a URL
// needs `10` rather than `10.0`.
func TestArgumentsKeepTheirJSONTypes(t *testing.T) {
	env := graphQLEnv(map[string]any{
		"ref":    "A-1",
		"first":  float64(10),
		"ratio":  1.5,
		"active": true,
		"absent": nil,
		"tags":   []any{"x", "y"},
		"nested": map[string]any{"k": "v"},
		"big":    json.Number("9007199254740993"),
		"loose":  json.Number("1.25"),
	}, nil)
	cases := map[string]string{
		`@(context.GraphQL.GraphQLArguments["ref"])`:             "A-1",
		`@(context.GraphQL.GraphQLArguments["first"])`:           "10",
		`@(context.GraphQL.GraphQLArguments["ratio"])`:           "1.5",
		`@(context.GraphQL.GraphQLArguments["active"])`:          "True",
		`@(context.GraphQL.GraphQLArguments["tags"])`:            `["x","y"]`,
		`@(context.GraphQL.GraphQLArguments["nested"])`:          `{"k":"v"}`,
		`@(context.GraphQL.GraphQLArguments["big"])`:             "9007199254740993",
		`@(context.GraphQL.GraphQLArguments["loose"])`:           "1.25",
		`@(context.GraphQL.GraphQLArguments["first"] > 5)`:       "True",
		`@(context.GraphQL.GraphQLArguments.ContainsKey('ref'))`: "True",
	}
	for source, want := range cases {
		if got := evalString(t, env, source); got != want {
			t.Errorf("%s = %q, want %q", source, got, want)
		}
	}
	if got := evalString(t, env, "@(context.GraphQL.GraphQLArguments.Count)"); got != "9" {
		t.Errorf("Count = %q", got)
	}
	// An explicit JSON null is null, not the string "null".
	value, err := EvalEnv(`@(context.GraphQL.GraphQLArguments["absent"] == null)`, env)
	if err != nil || value.String() != "True" {
		t.Errorf("explicit null = %v %v", value.String(), err)
	}
}

// An omitted optional argument reads as null rather than failing, which is what
// a resolver on a nullable argument requires.
func TestMissingArgumentIsNullNotAnError(t *testing.T) {
	env := graphQLEnv(map[string]any{"ref": "A-1"}, nil)
	value, err := EvalEnv(`@(context.GraphQL.GraphQLArguments["nope"] == null)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if value.String() != "True" {
		t.Fatalf("a missing key must be null, got %q", value.String())
	}
	if got := evalString(t, env, "@(context.GraphQL.GraphQLArguments.ContainsKey('nope'))"); got != "False" {
		t.Fatalf("ContainsKey on a missing key = %q", got)
	}
}

func TestParentIsNullAtTheRoot(t *testing.T) {
	root := graphQLEnv(map[string]any{}, nil)
	if got := evalString(t, root, "@(context.GraphQL.Parent == null)"); got != "True" {
		t.Fatalf("Parent at the root = %q; a Query resolver has no parent", got)
	}
	nested := graphQLEnv(map[string]any{}, map[string]any{"customerId": "c1"})
	if got := evalString(t, nested, `@(context.GraphQL.Parent["customerId"])`); got != "c1" {
		t.Fatalf("nested Parent = %q", got)
	}
}

// context.GraphQL is bound only inside a resolver. Everywhere else it must be
// null rather than an empty argument set, which would read as "the caller
// passed nothing" and silently produce a wrong URL.
func TestGraphQLIsNullOutsideAResolver(t *testing.T) {
	env := Bind(Context{})
	value, err := EvalEnv("@(context.GraphQL == null)", env)
	if err != nil {
		t.Fatal(err)
	}
	if value.String() != "True" {
		t.Fatalf("context.GraphQL outside a resolver = %q", value.String())
	}
	if _, err := EvalEnv(`@(context.GraphQL.GraphQLArguments["x"])`, env); err == nil {
		t.Fatal("member access on a null context.GraphQL must fail rather than yield empty")
	}
}

func TestGraphQLRejectsUnknownMembersAndBadKeys(t *testing.T) {
	env := graphQLEnv(map[string]any{"ref": "A-1"}, map[string]any{"id": "p"})
	for _, source := range []string{
		"@(context.GraphQL.Nonsense)",
		"@(context.GraphQL.GraphQLArguments.Nonsense)",
		"@(context.GraphQL.GraphQLArguments[1])",
		"@(context.GraphQL.GraphQLArguments.ContainsKey(1))",
		"@(context.GraphQL.GraphQLArguments.ContainsKey())",
	} {
		if _, err := EvalEnv(source, env); err == nil {
			t.Errorf("%s must fail closed", source)
		}
	}
}

// A value the JSON encoder cannot represent is reported rather than rendered as
// something misleading. Unreachable from decoded JSON, so asserted directly.
func TestJSONValueRejectsUnrepresentableValues(t *testing.T) {
	if _, err := jsonValue(make(chan int)); err == nil {
		t.Fatal("an unencodable value must be reported")
	}
	if _, err := jsonValue(json.Number("not-a-number")); err == nil {
		t.Fatal("a malformed json.Number must be reported")
	}
}

// A credential exposes exactly four members. Anything else fails closed, so a
// policy cannot probe for a refresh token that is deliberately not bound.
func TestAuthorizationContextFailsClosed(t *testing.T) {
	env := Bind(Context{AuthorizationContexts: map[string]AuthorizationContext{
		"auth": {AccessToken: "at", ClientID: "cid", Scopes: "api.read", ExpiresIn: 60},
	}})
	for source, want := range map[string]string{
		`@(((Authorization)context.Variables["auth"]).AccessToken)`: "at",
		`@(((Authorization)context.Variables["auth"]).ClientId)`:    "cid",
		`@(((Authorization)context.Variables["auth"]).Scopes)`:      "api.read",
		`@(((Authorization)context.Variables["auth"]).ExpiresIn)`:   "60",
	} {
		got, err := EvalEnv(source, env)
		if err != nil || got.String() != want {
			t.Errorf("%s = %q %v, want %q", source, got.String(), err, want)
		}
	}
	for _, source := range []string{
		`@(((Authorization)context.Variables["auth"]).RefreshToken)`,
		`@(((Authorization)context.Variables["auth"]).Nonsense)`,
	} {
		if _, err := EvalEnv(source, env); err == nil {
			t.Errorf("%s must fail closed", source)
		}
	}
	// A name with no credential falls through to the string variables rather
	// than shadowing them.
	mixed := Bind(Context{
		Variables:             map[string]string{"plain": "text"},
		AuthorizationContexts: map[string]AuthorizationContext{"auth": {AccessToken: "at"}},
	})
	if got, err := EvalEnv(`@(context.Variables["plain"])`, mixed); err != nil || got.String() != "text" {
		t.Fatalf("a string variable must still resolve: %q %v", got.String(), err)
	}
}
