package expression

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A policy block is a sequence of statements. This is the shape Microsoft's own
// policies use for a fallback: declare, test, assign in a branch, then return.
func TestAssignmentStatements(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"present": "yes"})
	for _, test := range []struct{ source, want string }{
		{`@{ var x = 1; x = 2; return x.ToString(); }`, "2"},
		{`@{ string s = "a"; s = s + "b"; return s; }`, "ab"},
		// The corpus shape: a branch that only assigns, and whose effect is
		// visible to the statements after it.
		{`@{ var token = context.Variables["absent"]; if (token == null) { token = "fallback"; } return token; }`, "fallback"},
		{`@{ var token = context.Variables["present"]; if (token == null) { token = "fallback"; } return token; }`, "yes"},
		// An if with no else simply falls through.
		{`@{ var n = 1; if (false) { n = 9; } return n.ToString(); }`, "1"},
		// else-if chains.
		{`@{ var n = 2; if (n == 1) { return "one"; } else if (n == 2) { return "two"; } else { return "many"; } }`, "two"},
		// A return inside a branch stops the whole block, not just the branch.
		{`@{ var n = 1; if (n == 1) { return "early"; } return "late"; }`, "early"},
		{`@{ var n = 2; if (n == 1) { return "early"; } return "late"; }`, "late"},
		// Assignment runs in order, so the last write wins.
		{`@{ var n = 1; n = 2; n = 3; return n.ToString(); }`, "3"},
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

func TestAssignmentRefusals(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	for _, test := range []struct{ source, contains string }{
		// Assigning to a name nobody declared is an error rather than an
		// implicit declaration, so a policy's typo does not quietly become a
		// new variable that reads as null everywhere else.
		{`@{ undeclared = 1; return undeclared; }`, "not declared"},
		// A declaration inside a branch is scoped to it. Letting one escape
		// would make a policy work here that fails in a tenant.
		{`@{ var n = 1; if (n == 1) { var inner = 2; } return inner.ToString(); }`, "unbound identifier"},
		// A block that can fall off its end is refused at parse time.
		{`@{ var n = 1; if (n == 1) { n = 2; } }`, "must return a value"},
		// An if without an else does not make the block return.
		{`@{ var n = 1; if (n == 1) { return "yes"; } }`, "must return a value"},
		{`@{ var n = 1; n = 2; }`, "must return a value"},
		{`@{ var n = 1; n = ; return n; }`, "unexpected token"},
		{`@{ var n = 1; n = 2 return n; }`, "expected ';'"},
		// A condition that is not a boolean reports rather than guessing.
		{`@{ var n = 1; if ("text") { n = 2; } return n; }`, "true or false"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
	// A branch that never closes cannot be written inside `@{ }`, because the
	// wrapper's own brace matching rejects it first. The statement parser is
	// checked directly so the branch is not code nothing has ever run.
	tokens, err := scan("if (true) { return 1;")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&parser{tokens: tokens}).statement(); err == nil {
		t.Fatal("an unclosed branch was accepted")
	}
}

// A branch that shadows an outer local must restore it, not leave the branch's
// value behind.
func TestBranchScopingRestoresOuterLocals(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	got, err := EvalEnv(`@{ var name = "outer"; if (true) { var name = "inner"; } return name; }`, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "outer" {
		t.Fatalf("shadowed local = %q, want %q", got.String(), "outer")
	}
	// And an ASSIGNMENT in the same position writes through to the outer one.
	got, err = EvalEnv(`@{ var name = "outer"; if (true) { name = "inner"; } return name; }`, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "inner" {
		t.Fatalf("assigned local = %q, want %q", got.String(), "inner")
	}
}

// Failures inside a statement surface rather than being swallowed, and a
// malformed branch reports where it broke.
func TestStatementParseAndEvalEdges(t *testing.T) {
	env := RequestEnv(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	// An assignment whose value fails reports that failure.
	if _, err := EvalEnv(`@{ var x = 1; x = context.Nonexistent; return x; }`, env); err == nil {
		t.Fatal("a failing assignment was accepted")
	}
	for _, test := range []struct{ source, contains string }{
		// A malformed `else if`.
		{`@{ var n = 1; if (n == 1) { return "a"; } else if () { return "b"; } else { return "c"; } }`, "unexpected token"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
}
