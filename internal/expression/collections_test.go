package expression

import (
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
