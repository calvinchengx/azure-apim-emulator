package expression

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Azure types a variable `object`, so a policy stores a parsed token and later
// reads members off it. Keeping only the rendering loses exactly what such an
// expression reads.
func TestObjectValuedVariables(t *testing.T) {
	token := makeJWT(t, map[string]any{"alg": "RS256"}, map[string]any{"sub": "ada", "roles": []any{"admin"}})
	parsed := asJwt(token)
	env := Bind(Context{
		Variables:       map[string]string{"idToken": "", "plain": "text"},
		VariableObjects: map[string]Value{"idToken": parsed},
	})
	for _, test := range []struct{ source, want string }{
		// The idiom the corpus uses, which used to read text and fail.
		{`@(((Jwt)context.Variables["idToken"]).Claims["roles"][0])`, "admin"},
		{`@(((Jwt)context.Variables["idToken"]).Subject)`, "ada"},
		// Without the cast too: a variable simply holds the object.
		{`@(context.Variables["idToken"].Subject)`, "ada"},
		// A text variable is unaffected.
		{`@(context.Variables["plain"])`, "text"},
		// ContainsKey sees a variable that exists only as an object.
		{`@(context.Variables.ContainsKey("idToken"))`, "True"},
		{`@(context.Variables.ContainsKey("absent"))`, "False"},
		// GetValueOrDefault reaches the object as well.
		{`@(context.Variables.GetValueOrDefault("idToken", "none").Subject)`, "ada"},
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

// A credential and a stored object share one namespace, because a policy reads
// both through context.Variables.
func TestObjectVariablesAndCredentialsShareANamespace(t *testing.T) {
	env := Bind(Context{
		AuthorizationContexts: map[string]AuthorizationContext{"cred": {AccessToken: "tok"}},
		VariableObjects:       map[string]Value{"obj": Object(&objectHost{fields: []jsonField{{name: "a", value: Int(1)}}})},
	})
	if got, err := EvalEnv(`@(context.Variables["cred"].AccessToken)`, env); err != nil || got.String() != "tok" {
		t.Fatalf("credential = %q, %v", got.String(), err)
	}
	if got, err := EvalEnv(`@(context.Variables["obj"].a)`, env); err != nil || got.String() != "1" {
		t.Fatalf("object = %q, %v", got.String(), err)
	}
	// A stored object wins over a credential of the same name: it was written
	// later, by an explicit set-variable.
	shadowed := Bind(Context{
		AuthorizationContexts: map[string]AuthorizationContext{"same": {AccessToken: "credential"}},
		VariableObjects:       map[string]Value{"same": String("stored")},
	})
	if got, err := EvalEnv(`@(context.Variables["same"])`, shadowed); err != nil || got.String() != "stored" {
		t.Fatalf("shadowed = %q, %v", got.String(), err)
	}
	// With neither map populated a variable is still simply absent.
	empty := Bind(Context{})
	if got, err := EvalEnv(`@(context.Variables["nothing"] == null)`, empty); err != nil || !got.Truthy() {
		t.Fatalf("absent = %v, %v", got.Truthy(), err)
	}
	_ = httptest.NewRequest(http.MethodGet, "/", nil)
}
