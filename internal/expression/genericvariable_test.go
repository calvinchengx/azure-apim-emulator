package expression

import (
	"strings"
	"testing"
)

// `GetValueOrDefault<T>` is how every one of the corpus's twenty-four generic
// calls is written, and all of them are on `context.Variables`. The type
// argument is the point: a variable holding a parsed body reads back as an
// object rather than as its rendering.
func TestGenericGetValueOrDefault(t *testing.T) {
	body := Object(&objectHost{fields: []jsonField{{name: "a", value: Int(1)}}})
	env := Bind(Context{
		Variables:       map[string]string{"s": "hi", "n": "42", "b": "true", "obj": `{"a":1}`},
		VariableObjects: map[string]Value{"obj": body},
	})
	for _, test := range []struct {
		source string
		want   any
	}{
		{`@(context.Variables.GetValueOrDefault<string>("s"))`, "hi"},
		{`@(context.Variables.GetValueOrDefault<int>("n") + 1)`, int64(43)},
		{`@(context.Variables.GetValueOrDefault<bool>("b"))`, true},
		{`@(context.Variables.GetValueOrDefault<string>("absent", "fallback"))`, "fallback"},
		// An object variable comes back as the OBJECT, which is the whole
		// reason a policy writes the JObject form.
		{`@(context.Variables.GetValueOrDefault<JObject>("obj").a)`, int64(1)},
		// `default(T)`: zero for a number, false for a bool, null otherwise.
		// Answering null for an absent int would make `... + 1` fail here and
		// give 1 in a tenant.
		{`@(context.Variables.GetValueOrDefault<int>("absent") + 1)`, int64(1)},
		{`@(context.Variables.GetValueOrDefault<long>("absent") + 1)`, int64(1)},
		{`@(context.Variables.GetValueOrDefault<double>("absent") + 1)`, float64(1)},
		{`@(context.Variables.GetValueOrDefault<bool>("absent"))`, false},
		{`@(context.Variables.GetValueOrDefault<JObject>("absent") == null)`, true},
		{`@(context.Variables.GetValueOrDefault<string>("absent") == null)`, true},
		// The non-generic form is untouched.
		{`@(context.Variables.GetValueOrDefault("s", "x"))`, "hi"},
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

func TestGenericGetValueOrDefaultRefusals(t *testing.T) {
	env := Bind(Context{Variables: map[string]string{"s": "text"}})
	for _, test := range []struct{ source, contains string }{
		// A type this evaluator cannot convert to is refused rather than
		// silently passed through as whatever the variable happened to hold.
		{`@(context.Variables.GetValueOrDefault<Widget>("s"))`, "is not supported"},
		{`@(context.Variables.GetValueOrDefault<int>("s"))`, "cannot cast"},
		{`@(context.Variables.GetValueOrDefault<bool>("s"))`, "cannot cast"},
		{`@(context.Variables.GetValueOrDefault<string>())`, "requires a variable name"},
		{`@(context.Variables.GetValueOrDefault<string>(1))`, "requires a variable name"},
		{`@(context.Variables.GetValueOrDefault<string>("a", "b", "c"))`, "requires a variable name"},
		// Only GetValueOrDefault is generic on Variables.
		{`@(context.Variables.ContainsKey<string>("s"))`, "not a generic member"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
	// A cast and the generic form agree about what a type is, because they
	// share one conversion.
	both := Bind(Context{Variables: map[string]string{"n": "7"}})
	cast, err := EvalEnv(`@((int)context.Variables["n"])`, both)
	if err != nil {
		t.Fatal(err)
	}
	generic, err := EvalEnv(`@(context.Variables.GetValueOrDefault<int>("n"))`, both)
	if err != nil {
		t.Fatal(err)
	}
	if cast.Interface() != generic.Interface() {
		t.Fatalf("cast gave %#v, generic gave %#v", cast.Interface(), generic.Interface())
	}
}
